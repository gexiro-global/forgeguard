import argparse
import json
import subprocess
import time
import uuid
from pathlib import Path

import jsonschema

parser = argparse.ArgumentParser(
    description="Ephemeral, isolated forge integration lab; no production targets"
)
parser.add_argument("--wheel", type=Path, required=True)
parser.add_argument("--evidence-dir", type=Path, required=True)
options = parser.parse_args()
e = options.evidence_dir.resolve()
e.mkdir(parents=True, exist_ok=False)
(e / "logs").mkdir()
prefix = "fg05-" + uuid.uuid4().hex[:12]
client = prefix + "-client"
network = prefix + "-net"
name = prefix + "-server"
matrix = []
cleanup_failures = []
images = [
    (
        "gitea",
        "1.26.4",
        "docker.gitea.com/gitea@sha256:8e25c717b8f748445e15ec46e0390f577cb628101184cb0a150d1dae126c1f39",
    ),
    (
        "gitea",
        "1.27.3",
        "docker.gitea.com/gitea@sha256:87a67ee09d3ae0d1df5fda5dcda3e2a1f9236a45b0a59025d6e00e46adc43bef",
    ),
    (
        "forgejo",
        "16.0.4",
        "codeberg.org/forgejo/forgejo@sha256:a3e33d03e771d3e58b27de5573c3a25dc4f670583a6724c1878a6d0bbecf3556",
    ),
    (
        "forgejo",
        "15.0.8",
        "codeberg.org/forgejo/forgejo@sha256:0a2e377fd3c5af3451bfa1f44e6f198f322b6d5e03f04a028b8e672f1ccddc9f",
    ),
]


def call(args, check=True):
    r = subprocess.run(args, capture_output=True, text=True, timeout=90, check=False)
    if check and r.returncode:
        raise RuntimeError(r.stderr[:500])
    return r


def cleanup_resource(remove, inspect):
    removed = call(remove, False)
    remaining = call(inspect, False)
    if removed.returncode != 0 or remaining.returncode == 0:
        cleanup_failures.append(
            {
                "resource": remove[-1],
                "remove_exit": removed.returncode,
                "inspect_exit": remaining.returncode,
            }
        )


probe = (
    "import urllib.request,urllib.error\ntry:\n r=urllib.request.urlopen('http://"
    + name
    + ":3000/api/v1/version',timeout=2); print(r.read().decode())\nexcept urllib.error.HTTPError as e:\n assert e.code in (401,403); print('{}')"
)
created_client = False
created_network = False
try:
    call(
        [
            "docker",
            "run",
            "-d",
            "--name",
            client,
            "--label",
            "forgeguard.lab=" + prefix,
            "--cpus",
            "1",
            "--memory",
            "768m",
            "--pids-limit",
            "128",
            "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36",
            "sleep",
            "3600",
        ]
    )
    created_client = True
    call(
        [
            "docker",
            "cp",
            str(options.wheel.resolve()),
            client + ":/tmp/" + options.wheel.name,
        ]
    )
    call(
        [
            "docker",
            "exec",
            client,
            "python",
            "-m",
            "pip",
            "install",
            "/tmp/" + options.wheel.name,
        ]
    )
    call(
        [
            "docker",
            "network",
            "create",
            "--internal",
            "--label",
            "forgeguard.lab=" + prefix,
            network,
        ]
    )
    created_network = True
    call(["docker", "network", "disconnect", "bridge", client])
    call(["docker", "network", "connect", network, client])
    for product, version, image in images:
        for private in [False, True]:
            for registration in [False, True]:
                variant = f"{product}-{version}-{'private' if private else 'public'}-reg{int(registration)}"
                args = [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--label",
                    "forgeguard.lab=" + prefix,
                    "--network",
                    network,
                    "--cpus",
                    "1",
                    "--memory",
                    "512m",
                    "--pids-limit",
                    "256",
                    "--tmpfs",
                    "/data:rw,size=384m",
                    "-e",
                    "GITEA__database__DB_TYPE=sqlite3",
                    "-e",
                    "GITEA__security__INSTALL_LOCK=true",
                    "-e",
                    "GITEA__server__DISABLE_SSH=true",
                    "-e",
                    "GITEA__server__ROOT_URL=http://" + name + ":3000/",
                    "-e",
                    "GITEA__service__REQUIRE_SIGNIN_VIEW=" + str(private).lower(),
                    "-e",
                    "GITEA__service__DISABLE_REGISTRATION="
                    + str(not registration).lower(),
                    "-e",
                    "GITEA__mailer__ENABLED=false",
                    "-e",
                    "GITEA__actions__ENABLED=false",
                    image,
                ]
                row = {
                    "product": product,
                    "version": version,
                    "image": image,
                    "private": private,
                    "registration": registration,
                    "variant": variant,
                    "kind": "real-upstream-container",
                    "status": "FAIL",
                }
                created = False
                try:
                    call(args)
                    created = True
                    ready = False
                    for _ in range(40):
                        r = call(
                            ["docker", "exec", client, "python", "-c", probe], False
                        )
                        if r.returncode == 0:
                            observed = (
                                json.loads(r.stdout).get("version")
                                or call(
                                    ["docker", "exec", name, "gitea", "--version"]
                                ).stdout.split()[2]
                            )
                            if not observed.startswith(version):
                                raise RuntimeError(
                                    "Unexpected upstream version " + observed
                                )
                            ready = True
                            break
                        time.sleep(1)
                    if not ready:
                        raise RuntimeError(
                            "Server did not become ready within 40 attempts"
                        )
                    r = call(
                        [
                            "docker",
                            "exec",
                            client,
                            "forgeguard",
                            "scan",
                            "--url",
                            "http://" + name + ":3000/",
                            "--authorized",
                            "--product",
                            product,
                            "--policy",
                            "private" if private else "public",
                            "--known-version",
                            version,
                            "--profile",
                            "extended",
                            "--format",
                            "json",
                        ],
                        False,
                    )
                    report = json.loads(r.stdout)
                    (e / "logs" / (variant + ".json")).write_text(
                        json.dumps(report, indent=2)
                    )
                    assert report["identity"]["normalized_version"] == version, (
                        "normalized version mismatch: " + str(report["identity"])
                    )
                    assert report["request_count"] == 6
                    assert (
                        all(
                            not f["id"].startswith("FG-CVE") for f in report["findings"]
                        )
                        if product == "forgejo"
                        else True
                    )
                    if not private:
                        assert not [
                            f
                            for f in report["findings"]
                            if f["status"] in ["warn", "fail"]
                            and not (version == "1.26.4" and f["id"] == "FG-CVE-78433")
                        ]
                    if version == "1.26.4":
                        assert any(
                            f["id"] == "FG-CVE-78433" and f["status"] == "fail"
                            for f in report["findings"]
                        )
                    statuses = {
                        f["id"]: f["observed"]
                        for f in report["findings"]
                        if f["scope"] == "http"
                    }
                    expected = {
                        "/explore/repos": 303 if private else 200,
                        "/v2/": 401,
                        "/api/v1/repos/search?limit=1": 403 if private else 200,
                        "/api/v1/users/search?limit=1": 403 if private else 200,
                    }
                    actual = {
                        path: obs["status"]
                        for key, values in statuses.items()
                        if key in ("FG-SIGNIN", "FG-REG", "FG-ANON")
                        for path, obs in values.items()
                    }
                    assert actual == expected, "native status contract changed"
                    assert report["score"]["assessed"] is (not private)
                    from importlib.resources import files

                    from forgeguard.assessment import Assessment
                    from forgeguard.exporters.sarif import to_sarif

                    for doc, schema in [
                        (report, "assessment-v1.json"),
                        (
                            to_sarif(Assessment.model_validate(report)),
                            "sarif-2.1.0.json",
                        ),
                    ]:
                        sch = json.loads(
                            files("forgeguard").joinpath("schemas", schema).read_text()
                        )
                        jsonschema.validators.validator_for(sch)(sch).validate(doc)
                    row["expected_statuses"] = expected
                    row.update(
                        status="PASS",
                        exit_code=r.returncode,
                        observed=observed,
                        assessment_complete=report["score"]["assessed"],
                        responses=statuses,
                    )
                    (e / "logs" / (variant + ".json")).write_text(
                        json.dumps(report, indent=2)
                    )
                except (
                    AssertionError,
                    RuntimeError,
                    OSError,
                    ValueError,
                    subprocess.SubprocessError,
                    jsonschema.ValidationError,
                ) as exc:
                    row["error"] = type(exc).__name__ + ": " + str(exc)[:800]
                finally:
                    if created:
                        cleanup_resource(
                            ["docker", "rm", "-f", name],
                            ["docker", "container", "inspect", name],
                        )
                matrix.append(row)
                (e / "04_INTEGRATION_MATRIX.json").write_text(
                    json.dumps(matrix, indent=2)
                )
                print(variant, row["status"], row.get("error", ""), flush=True)
finally:
    if created_client:
        cleanup_resource(
            ["docker", "rm", "-f", client], ["docker", "container", "inspect", client]
        )
    if created_network:
        cleanup_resource(
            ["docker", "network", "rm", network],
            ["docker", "network", "inspect", network],
        )
    (e / "cleanup.json").write_text(
        json.dumps(
            {
                "status": "FAIL" if cleanup_failures else "PASS",
                "failures": cleanup_failures,
            },
            indent=2,
        )
    )
if cleanup_failures or any(row["status"] != "PASS" for row in matrix):
    raise SystemExit(1)
