"""Explicit developer operation. Review the diff; CI never calls this writer."""

import json
from datetime import datetime

from tools.golden_cases import CLOCK, ROOT, cases, execute
from versionsec import engine
from versionsec.exporters.json import render_json
from versionsec.exporters.markdown import render_markdown
from versionsec.exporters.sarif import to_sarif


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return CLOCK


if __name__ == "__main__":
    engine.datetime = FrozenDatetime
    for name in cases():
        result = execute(name)
        for suffix, text in [
            ("json", render_json(result)),
            ("md", render_markdown(result)),
            ("sarif", json.dumps(to_sarif(result), sort_keys=True, indent=2) + "\n"),
        ]:
            (ROOT / "examples" / ("golden-" + name + "." + suffix)).write_text(text)
