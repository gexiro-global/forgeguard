"""Verify exact wheel/sdist resources and installed behavior outside the checkout."""

import json
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

import jsonschema

dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist").resolve()
root = Path(__file__).resolve().parents[1]
expected_version = tomllib.loads((root / "pyproject.toml").read_text())["project"][
    "version"
]
required = [
    "forgeguard/providers/gitea.py",
    "forgeguard/providers/forgejo.py",
    "forgeguard/advisories/catalog/gitea.json",
    "forgeguard/advisories/catalog/forgejo.json",
    "forgeguard/schemas/assessment-v1.json",
    "forgeguard/schemas/config-snapshot-v1.json",
    "forgeguard/schemas/sarif-2.1.0.json",
    "forgeguard/schemas/OASIS_NOTICE.md",
    "forgeguard/py.typed",
]
snippet = """
import json, importlib.metadata, pathlib, socket
from datetime import datetime, timezone
import forgeguard
from forgeguard.config_review import Snapshot, review
from forgeguard.providers.registry import PROVIDERS
from forgeguard.exporters.sarif import to_sarif
from importlib.resources import files
def denied(*a, **kw): raise AssertionError('offline package attempted DNS')
socket.getaddrinfo=denied
reports=[]
for product,p in PROVIDERS.items():
 s=Snapshot(schema_id='forgeguard.config-snapshot.v1',product=product,version=p.qualified_versions[-1],
 instance_alias='synthetic-'+product,snapshot_at=datetime.now(timezone.utc).isoformat(),
 provenance='Installed distribution synthetic smoke',settings={s.key:s.default for s in p.settings})
 r=review(s,policy='public')
 assert r.score.assessed and r.request_count==0
 reports.append({'json':r.model_dump(mode='json'),'sarif':to_sarif(r)})
print(json.dumps({'module':str(pathlib.Path(forgeguard.__file__).resolve()),
 'version':importlib.metadata.version('forgeguard'),'reports':reports,
 'schemas':{name:json.loads(files('forgeguard').joinpath('schemas',name).read_text())
 for name in ['assessment-v1.json','sarif-2.1.0.json']}}))
"""
artifacts = sorted(dist.glob("*.whl")) + sorted(dist.glob("*.tar.gz"))
assert len(list(dist.glob("*.whl"))) == 1, "Exactly one wheel required"
assert len(list(dist.glob("*.tar.gz"))) == 1, "Exactly one sdist required"
results = []
for artifact in artifacts:
    if not (artifact.name.endswith(".whl") or artifact.name.endswith(".tar.gz")):
        continue
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            names = archive.namelist()
            assert all(path in names for path in required)
            assert any("licenses/LICENSE" in p for p in names)
    else:
        with tarfile.open(artifact) as archive:
            names = archive.getnames()
            assert all(any(p.endswith("/" + path) for p in names) for path in required)
            assert any(p.endswith("/LICENSE") for p in names)
    with tempfile.TemporaryDirectory(prefix="forgeguard-dist-") as tmp:
        tmp = Path(tmp)
        env = tmp / "env"
        subprocess.run([sys.executable, "-m", "venv", str(env)], check=True)
        python = env / "bin/python"
        for args in [["-m", "pip", "install", str(artifact)], ["-m", "pip", "check"]]:
            subprocess.run(
                [str(python), *args], cwd=tmp, check=True, stdout=subprocess.DEVNULL
            )
        raw = subprocess.check_output([str(python), "-c", snippet], cwd=tmp, text=True)
        data = json.loads(raw)
        assert data["version"] == expected_version
        assert not Path(data["module"]).is_relative_to(root)
        for report in data["reports"]:
            for fmt, schema in [
                ("json", "assessment-v1.json"),
                ("sarif", "sarif-2.1.0.json"),
            ]:
                doc = data["schemas"][schema]
                jsonschema.validators.validator_for(doc)(doc).validate(report[fmt])
        for args in [["--help"], ["scan", "--help"], ["checks"], ["providers"]]:
            subprocess.run(
                [str(env / "bin/forgeguard"), *args],
                cwd=tmp,
                check=True,
                stdout=subprocess.DEVNULL,
            )
        results.append(
            {
                "artifact": artifact.name,
                "module": data["module"],
                "version": data["version"],
                "offline_provider_reports": 2,
                "status": "PASS",
            }
        )
assert len(results) == 2, "Exactly one wheel and one sdist required"
print(json.dumps(results, indent=2))
