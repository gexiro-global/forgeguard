# OPSEC Publication Checklist

Use this checklist before any public release.

- Confirm every example is synthetic and uses a reserved example domain.
- Confirm no internal hostnames, private IPs, customer names, local paths, or live outputs are present.
- Confirm no credential material or sensitive values are present.
- Confirm target URLs with credentials, query strings, or fragments are rejected without echo.
- Confirm environment and legacy CLI token inputs never appear in terminal output or reports.
- Confirm the distribution version, `forgeguard.__version__`, JSON `tool.version`, and User-Agent match.
- Confirm all remote methods are GET and all paths are in `SAFE_GET_PATHS`.
- Confirm no package, repository, blob, manifest, layer, or private artifact retrieval exists.
- Confirm Gitea-only scope and that Forgejo is not marketed as implemented.
- Confirm CVE results depend only on the documented advisory/version baseline.
- Confirm registration posture is described as not implemented.
- Inspect wheel and sdist contents and metadata.
- Run tests, Ruff, build, `twine check`, truth audit, and secret/identifier scans.
- Use a public-safe/no-reply Git identity for future commits.
- Publish only after final human approval.
