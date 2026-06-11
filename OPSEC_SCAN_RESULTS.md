# OPSEC Scan Results

## Scope

Scans covered the release tree text files and extracted text from:

- `dist/forgeguard-0.2.0.tar.gz`
- `dist/forgeguard-0.2.0-py3-none-any.whl`

Compressed archives were inspected by reading their member files.

## Tree OPSEC Grep Output

```text
./README.md:77:- v0.3: runner, token, and TLS posture checks.
./docs/SECURITY_MODEL.md:25:Anonymous checks are used for posture inference. If supplied, the optional API token is used only for authenticated version reads.
./docs/USAGE.md:33:- `--token`: optional API token for authenticated version reads when anonymous metadata is hidden.
./forgeguard/client.py:12:    posture signal. The authenticated client is only used when a token is supplied.
./forgeguard/client.py:15:    def __init__(self, base_url: str, token: str | None = None, timeout: float = 10.0,
./forgeguard/client.py:18:        self.has_token = bool(token)
./forgeguard/client.py:22:        if token:
./forgeguard/client.py:23:            auth_headers["Authorization"] = f"token {token}"
./forgeguard/checks.py:32:    response = await client.get("/api/v1/version", auth=client.has_token)
./forgeguard/checks.py:38:        if not client.has_token:
./forgeguard/checks.py:52:                                remediation="Re-run with --token or --known-version to enable patch-currency checks."))
./forgeguard/cli.py:32:async def _run(url: str, token: str | None, known_version: str | None, scan_id: str) -> ScanResult:
./forgeguard/cli.py:33:    client = ForgeClient(url, token=token)
./forgeguard/cli.py:49:    token: str | None = typer.Option(None, "--token", help="Optional API token for authenticated version read"),
./forgeguard/cli.py:64:    result = asyncio.run(_run(url, token, known_version, scan_id))
./tests/test_forgeguard.py:35:    def __init__(self, responses: dict[str, FakeResponse], has_token: bool = False) -> None:
./tests/test_forgeguard.py:37:        self.has_token = has_token
```

Verdict: expected benign `token` hits only. No internal infrastructure markers, host paths, registry socket markers, sensitive value material, or private-key phrases were found.

## Tree IPv4 Grep Output

```text
NO_MATCHES
```

Verdict: clean.

## Artifact OPSEC Text Scan Output

```text
OPSEC
sdist:forgeguard-0.2.0/PKG-INFO:97:- v0.3: runner, token, and TLS posture checks.
sdist:forgeguard-0.2.0/README.md:77:- v0.3: runner, token, and TLS posture checks.
sdist:forgeguard-0.2.0/forgeguard/checks.py:32:    response = await client.get("/api/v1/version", auth=client.has_token)
sdist:forgeguard-0.2.0/forgeguard/checks.py:38:        if not client.has_token:
sdist:forgeguard-0.2.0/forgeguard/checks.py:52:                                remediation="Re-run with --token or --known-version to enable patch-currency checks."))
sdist:forgeguard-0.2.0/forgeguard/cli.py:32:async def _run(url: str, token: str | None, known_version: str | None, scan_id: str) -> ScanResult:
sdist:forgeguard-0.2.0/forgeguard/cli.py:33:    client = ForgeClient(url, token=token)
sdist:forgeguard-0.2.0/forgeguard/cli.py:49:    token: str | None = typer.Option(None, "--token", help="Optional API token for authenticated version read"),
sdist:forgeguard-0.2.0/forgeguard/cli.py:64:    result = asyncio.run(_run(url, token, known_version, scan_id))
sdist:forgeguard-0.2.0/forgeguard/client.py:12:    posture signal. The authenticated client is only used when a token is supplied.
sdist:forgeguard-0.2.0/forgeguard/client.py:15:    def __init__(self, base_url: str, token: str | None = None, timeout: float = 10.0,
sdist:forgeguard-0.2.0/forgeguard/client.py:18:        self.has_token = bool(token)
sdist:forgeguard-0.2.0/forgeguard/client.py:22:        if token:
sdist:forgeguard-0.2.0/forgeguard/client.py:23:            auth_headers["Authorization"] = f"token {token}"
sdist:forgeguard-0.2.0/forgeguard.egg-info/PKG-INFO:97:- v0.3: runner, token, and TLS posture checks.
sdist:forgeguard-0.2.0/tests/test_forgeguard.py:35:    def __init__(self, responses: dict[str, FakeResponse], has_token: bool = False) -> None:
sdist:forgeguard-0.2.0/tests/test_forgeguard.py:37:        self.has_token = has_token
wheel:forgeguard/checks.py:32:    response = await client.get("/api/v1/version", auth=client.has_token)
wheel:forgeguard/checks.py:38:        if not client.has_token:
wheel:forgeguard/checks.py:52:                                remediation="Re-run with --token or --known-version to enable patch-currency checks."))
wheel:forgeguard/cli.py:32:async def _run(url: str, token: str | None, known_version: str | None, scan_id: str) -> ScanResult:
wheel:forgeguard/cli.py:33:    client = ForgeClient(url, token=token)
wheel:forgeguard/cli.py:49:    token: str | None = typer.Option(None, "--token", help="Optional API token for authenticated version read"),
wheel:forgeguard/cli.py:64:    result = asyncio.run(_run(url, token, known_version, scan_id))
wheel:forgeguard/client.py:12:    posture signal. The authenticated client is only used when a token is supplied.
wheel:forgeguard/client.py:15:    def __init__(self, base_url: str, token: str | None = None, timeout: float = 10.0,
wheel:forgeguard/client.py:18:        self.has_token = bool(token)
wheel:forgeguard/client.py:22:        if token:
wheel:forgeguard/client.py:23:            auth_headers["Authorization"] = f"token {token}"
wheel:forgeguard-0.2.0.dist-info/METADATA:97:- v0.3: runner, token, and TLS posture checks.
IPV4
NO_MATCHES
MARKETING
NO_MATCHES
```

Verdict: expected benign `token` hits only; IPv4 and marketing scans are clean.

## Marketing Grep Output

```text
NO_MATCHES
```

Verdict: clean.
