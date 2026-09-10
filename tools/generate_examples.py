"""Generate reviewed synthetic examples. Explicit developer operation, never a scan hook."""

import asyncio
import json
import runpy
from datetime import UTC, datetime
from pathlib import Path

from forgeguard.assessment import Assessment
from forgeguard.config_review import Snapshot, review
from forgeguard.exporters.json import render_json
from forgeguard.exporters.markdown import render_markdown
from forgeguard.exporters.sarif import to_sarif

root = Path(__file__).resolve().parents[1]
helpers = runpy.run_path(str(root / "tests/test_multiforge.py"))
cases = {
    "complete": ("gitea", "1.27.3", {}, "private"),
    "confirmed": ("gitea", "1.26.1", {}, "private"),
    "mixed": (
        "forgejo",
        "16.0.4",
        {"/api/v1/repos/search?limit=1": 200, "/api/v1/users/search?limit=1": 503},
        "private",
    ),
    "unsupported": ("gitea", "99.0.0", {}, "unspecified"),
    "public": (
        "forgejo",
        "16.0.4",
        {
            "/explore/repos": 200,
            "/v2/": 200,
            "/api/v1/repos/search?limit=1": 200,
            "/api/v1/users/search?limit=1": 200,
        },
        "public",
    ),
}
for name, (product, version, statuses, policy) in cases.items():
    result = asyncio.run(
        helpers["with_transport"](product, version, statuses, policy=policy)
    )
    result.run = {"timestamp": "2026-09-10T12:00:00Z", "fixture": "synthetic"}
    result.scan_id = "synthetic-" + name
    (root / "examples" / ("golden-" + name + ".json")).write_text(render_json(result))
    (root / "examples" / ("golden-" + name + ".sarif")).write_text(
        json.dumps(to_sarif(result), sort_keys=True, indent=2) + "\n"
    )
    (root / "examples" / ("golden-" + name + ".md")).write_text(render_markdown(result))
result = review(
    Snapshot.model_validate_json((root / "examples/gitea-snapshot.json").read_bytes()),
    now=datetime(2026, 9, 10, 18, tzinfo=UTC),
    policy="public",
)
(root / "examples/golden-offline.json").write_text(render_json(result))
(root / "examples/golden-offline.sarif").write_text(
    json.dumps(to_sarif(result), sort_keys=True, indent=2) + "\n"
)
(root / "examples/golden-offline.md").write_text(render_markdown(result))
schema = Assessment.model_json_schema()
schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
schema["$id"] = "https://github.com/gexiro-global/forgeguard/schemas/assessment-v1.json"
(root / "forgeguard/schemas/assessment-v1.json").write_text(
    json.dumps(schema, indent=2) + "\n"
)
