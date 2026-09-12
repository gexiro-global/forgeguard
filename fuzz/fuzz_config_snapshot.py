#!/usr/bin/env python3
"""Fuzz the offline config-snapshot parser and its review.

The snapshot is untrusted input: an operator hands VersionSec a JSON file it
did not produce. Rejecting malformed input is correct behaviour, so pydantic
validation errors are not failures. Anything else escaping ``review`` is.

Run locally:
    python fuzz/fuzz_config_snapshot.py -atheris_runs=100000
"""

import sys

import atheris

with atheris.instrument_imports():
    from pydantic import ValidationError

    from versionsec.config_review import Snapshot, review

# Rejecting untrusted input is the documented contract, not a crash.
EXPECTED = (ValidationError, ValueError, UnicodeDecodeError)


def one_input(data: bytes) -> None:
    try:
        snapshot = Snapshot.model_validate_json(data)
    except EXPECTED:
        return

    # A snapshot that parsed must be reviewable and serialisable without error.
    for policy in ("unspecified", "private"):
        result = review(snapshot, policy=policy)
        result.model_dump(mode="json")


def main() -> None:
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
