from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .engine import finding, identify, result_for
from .models import EvidenceState, Status, Target
from .providers.base import release_version
from .providers.registry import get_provider

_RUNNER_PRODUCT_FOR = {"gitea": "gitea-runner", "forgejo": "forgejo-runner"}
_BROAD_VOLUME_PATTERNS = {"**", "/**", "/", "/*", "**/*"}
_PLUGIN_MIN_VERSION = (13, 1, 0)


class RunnerSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_id: Literal["forgeguard.runner-snapshot.v1"]
    product: Literal["gitea", "forgejo"]
    server_version: str = Field(min_length=1, max_length=128)
    runner_product: Literal["gitea-runner", "forgejo-runner"]
    runner_version: str = Field(min_length=1, max_length=128)
    instance_alias: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    runner_alias: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    snapshot_at: str
    provenance: str = Field(min_length=1, max_length=256)
    runner_scope: Literal["dedicated", "shared"]
    workload_trust: Literal["trusted-only", "mixed-untrusted"]
    ephemeral: Literal["ephemeral", "once", "persistent"]
    execution_engine: Literal["docker", "lxc", "host", "plugin"]
    privileged: bool
    docker_socket: Literal[
        "not-exposed",
        "host-daemon-exposed-to-job",
        "dedicated-dind",
        "rootless-dind",
        "unknown",
    ]
    valid_volumes: list[str] = Field(default_factory=list, max_length=32)
    network: Literal["isolated", "host", "custom"]
    plugin_usage: Literal["unused", "declared-experimental", "unknown"] = "unused"

    @field_validator("snapshot_at")
    @classmethod
    def timestamp(cls, value):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("Snapshot timestamp must include timezone")
        return value

    @field_validator("valid_volumes")
    @classmethod
    def bounded_volumes(cls, value):
        for v in value:
            if not (0 < len(v) <= 256):
                raise ValueError("Volume entry length out of bounds")
        return value

    @model_validator(mode="after")
    def validate_runner_product(self):
        if self.runner_product != _RUNNER_PRODUCT_FOR[self.product]:
            raise ValueError("runner_product must match the declared server product")
        return self


def _broad_volumes(volumes: list[str]) -> list[str]:
    return sorted(v for v in volumes if v in _BROAD_VOLUME_PATTERNS or v == "..")


def _severity_for(strict_when_untrusted: bool, workload_trust: str) -> Status:
    if not strict_when_untrusted:
        return Status.PASS
    return Status.FAIL if workload_trust == "mixed-untrusted" else Status.WARN


def review(snapshot: RunnerSnapshot, *, now=None):
    provider = get_provider(snapshot.product)
    identity = identify(snapshot.product, snapshot.server_version, None)
    moment = now or datetime.now(UTC)
    age = (moment - datetime.fromisoformat(snapshot.snapshot_at)).total_seconds()
    fresh = 0 <= age <= 30 * 86400
    server_supported = (
        identity.support == "qualified"
        and not identity.product_conflict
        and not identity.version_conflict
    )
    runner_parsed = release_version(snapshot.runner_version)
    runner_qualified = snapshot.runner_version in provider.runner.qualified_versions
    contained = fresh and server_supported
    reason_suffix = ""
    if not fresh:
        reason_suffix += " Snapshot is stale (over 30 days) or from the future."
    if not server_supported:
        reason_suffix += " Server product/version is outside the qualified mapping."

    findings = []
    host_mode = snapshot.execution_engine == "host"

    # FG-RUNNER-VERSION
    version_complete = contained and runner_parsed is not None
    version_notes = []
    if (
        snapshot.runner_product == "gitea-runner"
        and runner_parsed
        and runner_parsed >= (3, 0, 0)
    ):
        version_notes.append(
            "Runner >=3.0.0 strips host-escape container.options (PidMode, CapAdd, "
            "SecurityOpt, Devices, ...) from non-privileged job containers (gitea/runner#1058)."
        )
    if (
        snapshot.runner_product == "forgejo-runner"
        and runner_parsed
        and runner_parsed >= (13, 0, 0)
    ):
        version_notes.append(
            "Runner >=13.0.0 removes implicit DOCKER_USERNAME/DOCKER_PASSWORD registry "
            "auth and the add-path/set-output/set-env workflow commands."
        )
    findings.append(
        finding(
            "FG-RUNNER-VERSION",
            "Runner version provenance",
            {
                "runner_product": snapshot.runner_product,
                "runner_version": snapshot.runner_version,
                "qualified": runner_qualified,
                "notes": version_notes,
            },
            "Runner version is within the qualified list for this provider.",
            scope="operator-snapshot",
            source="operator-declared",
            status=Status.INFO,
            state=EvidenceState.ASSESSED
            if version_complete
            else EvidenceState.INDETERMINATE,
            applicability="applicable" if version_complete else "undetermined",
            reason=(
                "Version identification only; a newer runner version is not itself "
                "asserted to be more secure." + reason_suffix
                if version_complete
                else "Runner version could not be parsed or is outside the qualified "
                "list." + reason_suffix
            ),
            references=(provider.runner.security_source,),
        )
    )

    # FG-RUNNER-EXECUTION
    exec_status = {
        "host": _severity_for(True, snapshot.workload_trust),
        "lxc": _severity_for(True, snapshot.workload_trust)
        if snapshot.workload_trust == "mixed-untrusted"
        else Status.INFO,
        "docker": Status.INFO,
        "plugin": Status.WARN,
    }[snapshot.execution_engine]
    exec_notes = {
        "host": "host label executes steps as the runner's own user with zero container isolation.",
        "lxc": "lxc label has no mechanism to restrict CPU/memory/disk/network I/O.",
        "docker": "docker label provides container isolation; strength depends on privileged/volumes/network below.",
        "plugin": "plugin execution engine is an alpha-stability gRPC protocol with no stability guarantee.",
    }[snapshot.execution_engine]
    findings.append(
        finding(
            "FG-RUNNER-EXECUTION",
            "Execution engine isolation level",
            {
                "execution_engine": snapshot.execution_engine,
                "workload_trust": snapshot.workload_trust,
            },
            "docker (or a fully isolated plugin engine) with trust boundary matching declared workload_trust.",
            scope="operator-snapshot",
            source="operator-declared",
            status=exec_status if contained else Status.INFO,
            state=EvidenceState.ASSESSED if contained else EvidenceState.INDETERMINATE,
            applicability="applicable" if contained else "undetermined",
            reason=exec_notes + reason_suffix,
            references=(provider.runner.config_source,),
        )
    )

    # FG-RUNNER-PRIVILEGED
    priv_applicable = contained and not host_mode
    priv_status = (
        _severity_for(snapshot.privileged, snapshot.workload_trust)
        if priv_applicable
        else Status.INFO
    )
    priv_reason = (
        "Privileged job containers get broad host access via elevated Linux capabilities; "
        "this may be a deliberate, narrowly-scoped Docker-in-Docker configuration, not "
        "automatically a vulnerability."
        if snapshot.privileged
        else "Privileged mode disabled."
    )
    if (
        not snapshot.privileged
        and snapshot.runner_product == "gitea-runner"
        and runner_parsed
        and runner_parsed >= (3, 0, 0)
    ):
        priv_reason += (
            " Runner >=3.0.0 additionally strips host-escape container.options here."
        )
    findings.append(
        finding(
            "FG-RUNNER-PRIVILEGED",
            "Privileged container mode",
            {"privileged": snapshot.privileged},
            "container.privileged=false unless Docker-in-Docker is explicitly required and isolated.",
            scope="operator-snapshot",
            source="operator-declared",
            status=priv_status,
            state=EvidenceState.ASSESSED
            if priv_applicable
            else EvidenceState.INFORMATIONAL,
            applicability="applicable" if priv_applicable else "not_applicable",
            reason=(
                priv_reason
                if priv_applicable
                else "host label has no containers to be privileged."
            )
            + (reason_suffix if priv_applicable else ""),
            references=(provider.runner.config_source,),
        )
    )

    # FG-RUNNER-VOLUMES
    vol_applicable = contained and not host_mode
    broad = _broad_volumes(snapshot.valid_volumes)
    vol_status = (
        _severity_for(bool(broad), snapshot.workload_trust)
        if vol_applicable
        else Status.INFO
    )
    findings.append(
        finding(
            "FG-RUNNER-VOLUMES",
            "Host volume mount allowlist",
            {"valid_volumes": snapshot.valid_volumes, "broad_patterns": broad},
            "valid_volumes is empty or a narrow, explicit allowlist; no wildcard-root pattern.",
            scope="operator-snapshot",
            source="operator-declared",
            status=vol_status,
            state=EvidenceState.ASSESSED
            if vol_applicable
            else EvidenceState.INFORMATIONAL,
            applicability="applicable" if vol_applicable else "not_applicable",
            reason=(
                (
                    "A broad allow pattern lets workflow-declared volumes read/write "
                    "arbitrary host paths."
                    if broad
                    else "No broad allow pattern declared."
                )
                + reason_suffix
                if vol_applicable
                else "host label bypasses container volume mounting entirely."
            ),
            references=(provider.runner.config_source,),
        )
    )

    # FG-RUNNER-DOCKER
    docker_applicable = contained and not host_mode
    docker_status_map = {
        "not-exposed": Status.PASS,
        "host-daemon-exposed-to-job": _severity_for(True, snapshot.workload_trust),
        "dedicated-dind": Status.INFO,
        "rootless-dind": Status.PASS,
        "unknown": Status.WARN,
    }
    docker_state = (
        EvidenceState.INDETERMINATE
        if snapshot.docker_socket == "unknown"
        else (
            EvidenceState.ASSESSED if docker_applicable else EvidenceState.INFORMATIONAL
        )
    )
    findings.append(
        finding(
            "FG-RUNNER-DOCKER",
            "Docker socket exposure to job containers",
            {"docker_socket": snapshot.docker_socket},
            "not-exposed, dedicated-dind, or rootless-dind; the host daemon socket is not mounted into job containers.",
            scope="operator-snapshot",
            source="operator-declared",
            status=docker_status_map[snapshot.docker_socket]
            if docker_applicable
            else Status.INFO,
            state=docker_state,
            applicability=(
                "undetermined"
                if snapshot.docker_socket == "unknown"
                else ("applicable" if docker_applicable else "not_applicable")
            ),
            reason=(
                "docker_host mounts the daemon socket at /var/run/docker.sock inside the "
                "job container, granting root-equivalent host access to workflow code."
                if snapshot.docker_socket == "host-daemon-exposed-to-job"
                else "Declared docker socket exposure state."
            )
            + (reason_suffix if docker_applicable else ""),
            references=(provider.runner.config_source,),
        )
    )

    # FG-RUNNER-NETWORK
    net_applicable = contained and not host_mode
    net_status = {
        "isolated": Status.PASS,
        "host": _severity_for(True, snapshot.workload_trust),
        "custom": Status.INFO,
    }[snapshot.network]
    findings.append(
        finding(
            "FG-RUNNER-NETWORK",
            "Job container network mode",
            {"network": snapshot.network},
            "isolated (default per-job network) rather than host networking.",
            scope="operator-snapshot",
            source="operator-declared",
            status=net_status if net_applicable else Status.INFO,
            state=EvidenceState.ASSESSED
            if net_applicable
            else EvidenceState.INFORMATIONAL,
            applicability="applicable" if net_applicable else "not_applicable",
            reason=(
                (
                    "host networking removes container-to-host network isolation."
                    if snapshot.network == "host"
                    else "Declared network mode."
                )
                + reason_suffix
                if net_applicable
                else "host label has no per-job container network to isolate."
            ),
            references=(provider.runner.config_source,),
        )
    )

    # FG-RUNNER-EPHEMERAL
    ephemeral_status = {
        "ephemeral": Status.PASS,
        "once": Status.INFO,
        "persistent": Status.INFO,
    }[snapshot.ephemeral]
    findings.append(
        finding(
            "FG-RUNNER-EPHEMERAL",
            "Runner credential/registration lifetime",
            {"ephemeral": snapshot.ephemeral},
            "ephemeral (server-enforced single job, credential revoked after assignment) as a defense-in-depth property.",
            scope="operator-snapshot",
            source="operator-declared",
            status=ephemeral_status if contained else Status.INFO,
            state=EvidenceState.ASSESSED if contained else EvidenceState.INDETERMINATE,
            applicability="applicable" if contained else "undetermined",
            reason=(
                "Absence of ephemeral mode is not itself a vulnerability; it is a "
                "credential-lifetime/defense-in-depth property. 'once' stops after one "
                "job but the registration credential remains valid; only 'ephemeral' is "
                "server-enforced and revokes the credential on assignment."
                + reason_suffix
            ),
            references=(provider.runner.config_source,),
        )
    )

    # FG-RUNNER-PLUGIN
    plugin_supported = (
        snapshot.runner_product == "forgejo-runner"
        and runner_parsed is not None
        and runner_parsed >= _PLUGIN_MIN_VERSION
    )
    plugin_applicable = (
        contained and plugin_supported and snapshot.plugin_usage != "unused"
    )
    plugin_status = {
        "unused": Status.INFO,
        "declared-experimental": Status.WARN,
        "unknown": Status.WARN,
    }[snapshot.plugin_usage]
    findings.append(
        finding(
            "FG-RUNNER-PLUGIN",
            "Experimental plugin execution engine usage",
            {
                "plugin_usage": snapshot.plugin_usage,
                "plugin_supported": plugin_supported,
            },
            "unused, or explicitly acknowledged as an alpha-stability trust boundary.",
            scope="operator-snapshot",
            source="operator-declared",
            status=plugin_status if plugin_applicable else Status.INFO,
            state=(
                EvidenceState.ASSESSED
                if plugin_applicable
                else EvidenceState.INFORMATIONAL
            ),
            applicability="applicable" if plugin_applicable else "not_applicable",
            reason=(
                "Forgejo Runner >=13.1.0 plugin protocol is alpha with no stability "
                "guarantee; ForgeGuard does not evaluate a custom plugin implementation "
                "it cannot see." + reason_suffix
                if plugin_applicable
                else "Plugin engine unused or not supported by this runner_product/runner_version."
            ),
            references=(provider.runner.security_source,),
        )
    )

    return result_for(
        identity,
        findings,
        target=Target(
            url=snapshot.instance_alias,
            forge=snapshot.product,
            version=snapshot.server_version,
            scope="operator-snapshot",
            product_confirmed=False,
            product_source="operator-declared",
        ),
        profile="runner-review",
        policy="unspecified",
        metadata={
            "coverage": "Not evaluated in runner review",
            "runner_alias": snapshot.runner_alias,
            "runner_scope": snapshot.runner_scope,
        },
        count=0,
        run={
            "snapshot_at": snapshot.snapshot_at,
            "provenance": snapshot.provenance,
            "reviewed_at": moment.isoformat(),
        },
    )
