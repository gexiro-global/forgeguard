# Migration: ForgeGuard -> VersionSec

**VersionSec was formerly ForgeGuard.** The product, the maintainer
(Gexiro Global Enterprises Ltd), the licence (Apache-2.0) and the scope are unchanged.
Only the name changed, starting with release 0.7.0.

## What changed

| | Up to 0.6.0 | From 0.7.0 |
|---|---|---|
| Product name | ForgeGuard | VersionSec |
| PyPI distribution | `forgeguard` | `versionsec` |
| Import | `import forgeguard` | `import versionsec` |
| CLI | `forgeguard` | `versionsec` |
| GitHub | `gexiro-global/forgeguard` | `gexiro-global/versionsec` |
| Site | product page on gexiro.com | <https://versionsec.com> |
| Token env var | `FORGEGUARD_TOKEN` | `VERSIONSEC_TOKEN` |

## What deliberately did **not** change

- **Finding/check identifiers.** `FG-VER`, `FG-ANON`, `FG-CONFIG-*`, `FG-RUNNER-*`,
  `FG-CVE-*`, `FG-FJ-*` are unchanged. Renaming them would silently break every existing
  report pipeline, suppression list and SARIF baseline, so `FG-*` identifiers are retained
  for report compatibility after the ForgeGuard -> VersionSec migration.
- **Machine-readable schema identifiers.** `forgeguard.assessment.v1`,
  `forgeguard.config-snapshot.v1`, `forgeguard.runner-snapshot.v1` and
  `forgeguard.scan-result.v0.3` keep their existing values. They are stable contract
  identifiers, not branding. The packaged JSON Schema files moved to
  `versionsec/schemas/` but their `$id` values are unchanged.
- **Exit codes**, report structure, scoring, and completeness semantics.
- **Released artifacts.** `forgeguard` 0.2.0, 0.2.1, 0.2.2, 0.5.0 and 0.6.0 remain on PyPI
  exactly as published, with their original hashes and their original release notes. They
  were called ForgeGuard and the historical record still says so.

Human-facing branding did change: the report title, Markdown header/footer, the SARIF
driver name and the User-Agent now read `VersionSec`.

## Upgrading

Recommended - switch to the canonical distribution:

```bash
python -m pip uninstall -y forgeguard
python -m pip install versionsec==0.7.1
versionsec --help
```

No-code-change path - keep installing `forgeguard`:

```bash
python -m pip install forgeguard==0.7.1
forgeguard --help
```

`forgeguard==0.7.1` is a thin compatibility bridge: it depends on `versionsec==0.7.1` and
contains no implementation of its own, so the two can never drift apart.

## Compatibility guarantees from 0.7.0 onward

All of the following are covered by tests in `tests/test_migration_0_7.py`:

- `import forgeguard` works and reports the same version as `versionsec`;
- `import forgeguard.cli` (and the other submodules) works and returns the *same module
  objects* as `versionsec.*`;
- the legacy import is silent - it writes nothing to stdout or stderr, so automation that
  parses command output is unaffected;
- the `forgeguard` console script is still installed and runs the canonical CLI;
- `FORGEGUARD_TOKEN` is still read;
- when both `VERSIONSEC_TOKEN` and `FORGEGUARD_TOKEN` are set, **`VERSIONSEC_TOKEN` wins**
  (deterministic precedence, canonical over legacy);
- report `schema_id` and `FG-*` finding IDs are unchanged.

## Deprecation posture

The compatibility surfaces are quiet and supported for this migration release. Nothing is
removed. Any future removal will be announced in the changelog before it happens,
not silently.
