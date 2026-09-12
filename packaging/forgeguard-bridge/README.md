# ForgeGuard is now VersionSec

This distribution is a **compatibility bridge**. It contains no code of its own: it simply
installs [`versionsec`](https://pypi.org/project/versionsec/) at the matching version.

```bash
python -m pip install forgeguard==0.7.2   # installs versionsec==0.7.2
forgeguard --help                          # still works
```

After installation both of these work and resolve to the same implementation:

```python
import forgeguard
import versionsec
```

## Please switch to the canonical name

```bash
python -m pip install versionsec
versionsec --help
```

## What this is

VersionSec provides read-only security posture review for explicitly authorized self-hosted
Gitea or Forgejo instances, including offline configuration review and offline runner
review, with Markdown, JSON and SARIF 2.1.0 output.

Releases up to and including ForgeGuard 0.6.0 remain published under the `forgeguard` name
and are unchanged. Stable `FG-*` finding identifiers and the machine-readable report schema
identifiers are unchanged, so existing report pipelines keep working.

See the [migration guide](https://github.com/gexiro-global/versionsec/blob/main/MIGRATION.md).

Apache-2.0. Gexiro Global Enterprises Ltd.
