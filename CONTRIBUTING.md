# Contributing

## Development Setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Run Tests

```bash
python -m compileall forgeguard
python -m pytest -q
```

## Style

- Keep checks read-only and scoped to one authorized target.
- Prefer deterministic logic and explicit evidence fields.
- Add focused tests for scoring, CLI behavior, and endpoint allowlists.
- Keep examples synthetic.

## Sign-Off

Contributions should include a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

## Scope Boundaries

ForgeGuard is a defensive security tool. Contributions that add exploit payloads, third-party discovery, protected artifact retrieval, or write-path behavior are out of scope for v0.x.
