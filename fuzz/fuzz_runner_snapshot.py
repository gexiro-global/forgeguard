#!/usr/bin/env python3
"""Fuzz the offline runner-snapshot parser and its review.

Same contract as the config snapshot: malformed input must be rejected, and a
snapshot that parses must review and serialise without raising.

Run locally:
    python fuzz/fuzz_runner_snapshot.py -atheris_runs=100000
"""

import sys

import atheris

with atheris.instrument_imports():
    from pydantic import ValidationError

    from versionsec.runner_review import RunnerSnapshot, review

EXPECTED = (ValidationError, ValueError, UnicodeDecodeError)


def one_input(data: bytes) -> None:
    try:
        snapshot = RunnerSnapshot.model_validate_json(data)
    except EXPECTED:
        return

    result = review(snapshot)
    result.model_dump(mode="json")


def main() -> None:
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
