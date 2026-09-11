"""Frozen inputs for real-engine regression; never reads expected reports."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from versionsec.client import ForgeClient
from versionsec.config_review import Snapshot, review
from versionsec.engine import assess

CLOCK = datetime(2026, 9, 10, 18, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


async def execute_case(name, case):
    if case["kind"] == "offline":
        snapshot = Snapshot.model_validate_json((ROOT / case["snapshot"]).read_bytes())
        return review(snapshot, policy=case["policy"], now=CLOCK)
    client = ForgeClient("https://synthetic.invalid/team")

    def respond(request):
        path = request.url.raw_path.decode().removeprefix("/team")
        status = case["responses"][path]
        if status is None:
            raise httpx.ReadTimeout("Synthetic timeout")
        if path == "/api/v1/version":
            return httpx.Response(status, json={"version": case["version"]})
        return httpx.Response(
            status,
            text="SYNTHETIC_PRIVATE_NAME_DO_NOT_RETAIN",
            headers={"content-type": "text/html", "set-cookie": "secret=synthetic"},
        )

    await client._anon.aclose()
    await client._auth.aclose()
    client._anon = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    client._auth = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        result = await assess(
            client,
            product=case["product"],
            profile=case["profile"],
            policy=case["policy"],
            scan_id="synthetic-" + name,
        )
        return result
    finally:
        await client.aclose()


def cases():
    return json.loads((ROOT / "tests/fixtures/golden-inputs.json").read_text())


def execute(name):
    return asyncio.run(execute_case(name, cases()[name]))
