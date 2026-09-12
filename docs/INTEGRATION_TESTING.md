# Integration testing

Run only on an authorized development Docker host. The helper creates UUID-named
containers and an internal network, uses tmpfs state and resource limits, publishes
no host ports, and removes only resources it created. It accepts a built wheel and
an evidence directory, never a customer target URL.

```bash
python -m pip install -e ".[dev]"
python -m build
python tools/integration_lab.py --wheel dist/versionsec-0.7.1-py3-none-any.whl --evidence-dir /your/private/new-lab-evidence
```

The Python client first installs the exact wheel and runtime dependencies, then
disconnects its install network and joins the internal lab network. The assessor
runs from the installed wheel outside the checkout.

Pinned matrix, verified 2026-09-10:

| Product | Version | Official image digest |
|---|---|---|
| Gitea | 1.26.4 | docker.gitea.com/gitea@sha256:8e25c717b8f748445e15ec46e0390f577cb628101184cb0a150d1dae126c1f39 |
| Gitea | 1.27.3 | docker.gitea.com/gitea@sha256:87a67ee09d3ae0d1df5fda5dcda3e2a1f9236a45b0a59025d6e00e46adc43bef |
| Forgejo | 16.0.4 | codeberg.org/forgejo/forgejo@sha256:a3e33d03e771d3e58b27de5573c3a25dc4f670583a6724c1878a6d0bbecf3556 |
| Forgejo | 15.0.8 | codeberg.org/forgejo/forgejo@sha256:0a2e377fd3c5af3451bfa1f44e6f198f322b6d5e03f04a028b8e672f1ccddc9f |

Each image runs public/private intent and registration enabled/disabled: 16 real
variants. Native observed baseline: public browsing/API 200; private browsing 303
and API 403; registry root 401. The private redirect remains incomplete and is
never a PASS assertion for authentication. Tests assert those exact status
contracts, request count, product/version provenance, no public-by-design warnings,
and JSON/SARIF schemas.

An additional private Gitea variant was assessed through a controlled isolated
TLS proxy under /forge, with a synthetic local CA, token/no-token and six requests
each. Only the version request authenticated. This is a controlled proxy case,
not a claim about every reverse proxy or production TLS configuration.

Unit/contract matrices use local httpx transports for 301/302/303/307/308, 404, 429,
500/502/503, 418, timeouts, invalid JSON, truncation and decompression bounds.
Advisory affected/fixed cases use synthetic versions and perform no exploitation.

Gitea 1.26.4 covers the previous generally maintained line; its known version
advisory must fail. It no longer receives current security fixes; see UPSTREAM.md. The real lab does not test access to existing private artifacts.

Cleanup is verified and an unsuccessful cleanup makes the helper fail.
Cleanup never uses prune or broad container stops. If interrupted, inspect the
UUID names printed/recorded for that run and remove only its resources.
