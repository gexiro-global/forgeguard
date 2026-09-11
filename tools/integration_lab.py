import argparse
import configparser
import hashlib
import json
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import jsonschema

try:
    from tools.lab_contract import evaluate_matrix, expected_exit, qualify
except ImportError:  # invoked as a plain script from the tools/ directory
    from lab_contract import evaluate_matrix, expected_exit, qualify

parser = argparse.ArgumentParser(
    description="Ephemeral, isolated forge integration lab; no production targets"
)
parser.add_argument("--wheel", type=Path, required=True)
parser.add_argument("--evidence-dir", type=Path, required=True)
options = parser.parse_args()
e = options.evidence_dir.resolve()
e.mkdir(parents=True, exist_ok=False)
(e / "logs").mkdir()
(e / "config").mkdir()
wheel_sha256 = hashlib.sha256(options.wheel.resolve().read_bytes()).hexdigest()
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

# Closed list of mapped config keys, explicitly set in every fixture so no
# default is guessed. Product-specific 2FA key. Booleans are coerced on readback.
BOOL_KEYS = {
    "service.DISABLE_REGISTRATION",
    "service.REGISTER_EMAIL_CONFIRM",
    "service.REGISTER_MANUAL_CONFIRM",
    "service.REQUIRE_SIGNIN_VIEW",
    "repository.FORCE_PRIVATE",
}


def mapped_settings(product, private, registration):
    settings = {
        "service.DISABLE_REGISTRATION": (not registration),
        "service.REGISTER_EMAIL_CONFIRM": False,
        "service.REGISTER_MANUAL_CONFIRM": False,
        "service.REQUIRE_SIGNIN_VIEW": private,
        "repository.FORCE_PRIVATE": False,
        "repository.DEFAULT_PRIVATE": "last",
    }
    if product == "gitea":
        settings["security.TWO_FACTOR_AUTH"] = ""
    else:
        settings["security.GLOBAL_TWO_FACTOR_REQUIREMENT"] = "none"
    return settings


def config_env_args(settings):
    args = []
    for key, value in settings.items():
        section, name_ = key.split(".", 1)
        if isinstance(value, bool):
            value = str(value).lower()
        args += ["-e", f"GITEA__{section}__{name_}={value}"]
    return args


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


def readback_config(
    server, product, version, image, private, registration, declared, variant
):
    """R05: read the closed key list from the container's written app.ini, compare
    to the declared fixture, build a snapshot from measured data, run config review
    on the installed wheel offline and assert per-finding. Returns a chain dict."""
    cdir = e / "config" / variant
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "declared_fixture.json").write_text(
        json.dumps(declared, indent=2, default=str)
    )
    raw = call(
        [
            "docker",
            "exec",
            server,
            "sh",
            "-c",
            'cat /data/gitea/conf/app.ini 2>/dev/null || cat "$(find /data /etc -name app.ini 2>/dev/null | head -1)"',
        ],
    ).stdout
    parser_ = configparser.ConfigParser()
    parser_.optionxform = str  # preserve UPPER key case
    parser_.read_string(raw)
    observed = {}
    for key in declared:
        section, opt = key.split(".", 1)
        if parser_.has_option(section, opt):
            val = parser_.get(section, opt)
            observed[key] = (val.lower() == "true") if key in BOOL_KEYS else val
        else:
            observed[key] = "missing"
    (cdir / "observed_config.json").write_text(
        json.dumps(
            {
                "variant": variant,
                "image": image,
                "read_from": "app.ini",
                "keys": observed,
                "read_at_utc": datetime.now(UTC).isoformat(),
            },
            indent=2,
            default=str,
        )
    )
    mismatches = {}
    for k in declared:
        dec, obs = declared[k], observed[k]
        if obs == "missing" and dec == "":
            continue  # an empty optional value may not be persisted to app.ini
        if obs != dec:
            mismatches[k] = {"declared": dec, "observed": obs}
    settings = {k: v for k, v in observed.items() if v != "missing"}
    snapshot = {
        "schema_id": "forgeguard.config-snapshot.v1",
        "product": product,
        "version": version,
        "instance_alias": "lab-" + variant,
        "snapshot_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "provenance": "Measured read-back from lab container app.ini; closed key list only; not a runtime enforcement claim.",
        "settings": settings,
    }
    (cdir / "config_snapshot.json").write_text(json.dumps(snapshot, indent=2))
    call(
        ["docker", "cp", str(cdir / "config_snapshot.json"), client + ":/tmp/snap.json"]
    )
    policy = "private" if private else "public"
    reports = {}
    exit_code = 0
    for fmt in ("json", "md", "sarif"):
        r = call(
            [
                "docker",
                "exec",
                client,
                "forgeguard",
                "config",
                "review",
                "--snapshot",
                "/tmp/snap.json",
                "--product",
                product,
                "--policy",
                policy,
                "--format",
                fmt,
            ],
            False,
        )
        (cdir / f"config_review.{fmt}").write_text(r.stdout)
        reports[fmt] = r.stdout
        exit_code = r.returncode
    review = json.loads(reports["json"])
    per_finding = {f["id"]: f["status"] for f in review.get("findings", [])}
    required = {
        "FG-CONFIG-REGISTRATION",
        "FG-CONFIG-SIGNIN",
        "FG-CONFIG-PRIVACY",
        "FG-CONFIG-MFA",
    }
    missing_findings = sorted(required - set(per_finding))
    chain = {
        "variant_id": variant,
        "container_id": server,
        "image_digest": image,
        "declared_fixture": "config/" + variant + "/declared_fixture.json",
        "observed_config": "config/" + variant + "/observed_config.json",
        "config_snapshot": "config/" + variant + "/config_snapshot.json",
        "installed_artifact_sha256": wheel_sha256,
        "readback_mismatches": mismatches,
        "per_finding": per_finding,
        "config_review_exit": exit_code,
        "assessed": review.get("score", {}).get("assessed"),
    }
    (cdir / "chain.json").write_text(json.dumps(chain, indent=2, default=str))
    if mismatches:
        raise RuntimeError(
            "config readback mismatch: " + json.dumps(mismatches, default=str)
        )
    if missing_findings:
        raise RuntimeError("config review missing findings: " + str(missing_findings))
    if review.get("score", {}).get("assessed") is not True:
        raise RuntimeError(
            "offline config review must be assessed (fully supplied snapshot)"
        )
    return chain


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
                declared = mapped_settings(product, private, registration)
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
                    "GITEA__mailer__ENABLED=false",
                    "-e",
                    "GITEA__actions__ENABLED=false",
                    *config_env_args(declared),
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
                    "expected_exit": expected_exit(private, version),
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
                    statuses = {
                        f["id"]: f["observed"]
                        for f in report["findings"]
                        if f["scope"] == "http"
                    }
                    details = qualify(
                        product=product,
                        version=version,
                        private=private,
                        registration=registration,
                        report=report,
                        exit_code=r.returncode,
                        native_statuses=statuses,
                    )
                    expected = details["expected_statuses"]
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
                    # R05: real config read-back from this container before cleanup
                    chain = readback_config(
                        name,
                        product,
                        version,
                        image,
                        private,
                        registration,
                        declared,
                        variant,
                    )
                    row["expected_statuses"] = expected
                    row.update(
                        status="PASS",
                        expected_exit=details["expected_exit"],
                        exit_code=r.returncode,
                        observed=observed,
                        assessment_complete=report["score"]["assessed"],
                        responses=statuses,
                        config_readback=chain,
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
problems = evaluate_matrix(matrix, cleanup_failures)
(e / "matrix_gate.json").write_text(json.dumps({"problems": problems}, indent=2))
if problems:
    raise SystemExit(1)
