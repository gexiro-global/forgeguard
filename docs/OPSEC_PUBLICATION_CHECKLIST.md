# OPSEC Publication Checklist

Use this checklist before any public release.

- Confirm every example is synthetic, mechanically generated, and uses a reserved example domain.
- Confirm no internal hostnames, private IPs, customer names, local paths, or live outputs are present.
- Confirm no credential material or sensitive values are present.
- Confirm target URLs with credentials, query strings, fragments, or dot segments are rejected without echo.
- Confirm environment and legacy CLI token inputs never appear in terminal output or reports.
- Confirm the distribution version, `forgeguard.__version__`, JSON `tool.version`, and User-Agent match.
- Confirm all remote methods are GET and all paths are in `SAFE_GET_PATHS`.
- Confirm no package, repository, blob, manifest, layer, or private artifact retrieval exists.
- Confirm Gitea-specific results require `--product gitea` and explicit Forgejo markers fail safe.
- Confirm `FG-VER` is informational and CVE-2026-27771 receives no duplicate penalty.
- Confirm unknown product/version and HTTP 404/redirect/429/5xx/no-response cases are N/A, never A.
- Confirm only explicit 401/403 access-control evidence receives the corresponding narrow PASS.
- Confirm the CVE finding uses `CWE-862` and depends only on the documented advisory/version baseline.
- Confirm registration posture is described as not implemented.
- Inspect wheel and sdist contents and metadata.
- Run repository-root Ruff, format, tests, compileall, build, `twine check`, exact-wheel smoke, truth audit, and secret/identifier scans.
- Use a public-safe/no-reply Git identity for commits.
- Publish only after final human approval.
