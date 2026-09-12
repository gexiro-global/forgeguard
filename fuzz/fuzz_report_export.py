#!/usr/bin/env python3
"""Fuzz report serialisation in every export format.

Findings carry operator-supplied strings (instance alias, provenance, version)
straight into JSON, SARIF and Markdown. This harness drives a parsed snapshot
through ``review`` and then through all three exporters, asserting the
properties each format must hold regardless of input bytes.

Run locally:
    python fuzz/fuzz_report_export.py -atheris_runs=100000
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from pydantic import ValidationError

    from versionsec.config_review import Snapshot, review
    from versionsec.exporters.json import render_json
    from versionsec.exporters.markdown import render_markdown
    from versionsec.exporters.sarif import to_sarif

EXPECTED = (ValidationError, ValueError, UnicodeDecodeError)


def one_input(data: bytes) -> None:
    try:
        snapshot = Snapshot.model_validate_json(data)
    except EXPECTED:
        return

    result = review(snapshot, policy="private")

    rendered = render_json(result)
    # The JSON exporter promises ASCII-safe, re-parsable output.
    assert rendered.isascii(), "render_json emitted non-ASCII output"
    json.loads(rendered)

    sarif = to_sarif(result)
    # SARIF must stay serialisable; a non-serialisable value here is the bug.
    json.dumps(sarif)

    markdown = render_markdown(result)
    assert isinstance(markdown, str)


def main() -> None:
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
