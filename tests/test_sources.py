"""R06 provenance: catalog records bind to exact frozen source bytes via a manifest.

Offline only. ``forgeguard scan`` never fetches these sources; the manifest and
frozen bytes committed under tests/fixtures/sources let anyone re-verify the
recorded hashes without network access.
"""

import hashlib
import json
from pathlib import Path

import pytest

from forgeguard.advisories.evaluator import catalog

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "tests" / "fixtures" / "sources"
REQUIRED_FIELDS = [
    "source_id",
    "canonical_advisory_url",
    "retrieval_url",
    "resolved_url",
    "retrieved_at_utc",
    "media_type",
    "upstream_revision_or_tag",
    "raw_bytes_sha256",
    "selected_record_id",
    "selected_record_location",
    "supported_conclusion",
    "limitations",
    "catalog_record_id",
]


def manifest():
    return json.loads((SOURCES / "manifest.json").read_text())


def test_manifest_entries_hash_exact_frozen_bytes():
    for entry in manifest()["entries"]:
        for field in REQUIRED_FIELDS:
            assert entry.get(field), f"{entry.get('source_id')} missing {field}"
        raw = (SOURCES / entry["file"]).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == entry["raw_bytes_sha256"], (
            f"{entry['source_id']} frozen bytes {digest} != manifest {entry['raw_bytes_sha256']}"
        )


@pytest.mark.parametrize("product", ["gitea", "forgejo"])
def test_catalog_source_hashes_match_manifest(product):
    entries = {e["raw_bytes_sha256"]: e for e in manifest()["entries"]}
    records, _ = catalog(product)
    for record in records:
        assert record.source_sha256, record.id
        assert record.selected_record_id, record.id
        assert record.selected_record_location, record.id
        assert record.retrieval_url, record.id
        # every hash the catalog record claims must be backed by a frozen source
        for digest in record.source_sha256:
            assert digest in entries, (
                f"{record.id} hash {digest} not frozen in manifest"
            )
            assert entries[digest]["catalog_record_id"] == record.id


def test_no_record_binds_to_a_volatile_collection_listing():
    # The prior candidate bound FG-CVE-78433 to a security-advisories collection
    # listing whose hash drifts; guard against that regression returning.
    for product in ("gitea", "forgejo"):
        for record in catalog(product)[0]:
            assert "per_page" not in record.retrieval_url, record.id
            assert "security-advisories?" not in record.retrieval_url, record.id


def test_forgejo_record_asserts_no_affected_boundary():
    (record,) = catalog("forgejo")[0]
    assert record.affected == []
    assert "undetermined" in record.limitations


def test_selected_record_ids_are_unique_and_referenced():
    entries = manifest()["entries"]
    ids = [e["selected_record_id"] for e in entries]
    assert len(ids) == len(set(ids))
    catalog_ids = {r.id for p in ("gitea", "forgejo") for r in catalog(p)[0]}
    for entry in entries:
        assert entry["catalog_record_id"] in catalog_ids
