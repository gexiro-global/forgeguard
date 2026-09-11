import json

from ..report import _markdown_text
from ..report import render_markdown as legacy_markdown


def render_markdown(result):
    if not hasattr(result, "schema_id"):
        return legacy_markdown(result)
    esc = _markdown_text
    out = [
        f"# VersionSec — {esc(result.target.url)}",
        "",
        f"Schema: {result.schema_id} | Profile: {esc(result.profile)} | Policy: {esc(result.policy)}",
        f"Score: {result.score.value if result.score.assessed else 'N/A'} ({result.score.grade})",
        f"Requests: {result.request_count}; incomplete: {esc(', '.join(result.score.incomplete_checks) or 'none')}",
        f"Skipped by profile: {esc(', '.join(result.skipped_checks) or 'none')}",
        "",
        "Product and version provenance: "
        + esc(json.dumps(result.identity.model_dump(), sort_keys=True)),
        "",
        "Catalog: " + esc(json.dumps(result.catalog, sort_keys=True)),
        "",
    ]
    for f in result.findings:
        out.extend(
            [
                f"## {esc(f.id)} — {esc(f.title)}",
                f"{f.status.value} | {f.evidence_state.value} | {f.applicability}",
                f"Source: {esc(f.source)}",
                f"Observed: {esc(json.dumps(f.observed, sort_keys=True))}",
                f"Expected: {esc(f.expected)}",
                f"Reason: {esc(f.reason)}",
                f"Action: {esc(f.remediation)}",
                f"References: {esc(', '.join(f.references))}",
                "",
            ]
        )
    out.extend(["## Limits", *("- " + esc(x) for x in result.limitations)])
    return "\n".join(line.rstrip() for line in out) + "\n"
