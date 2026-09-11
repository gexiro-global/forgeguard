from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .engine import finding, identify, result_for
from .models import EvidenceState, Status, Target
from .providers.registry import get_provider


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_id: Literal["forgeguard.config-snapshot.v1"]
    product: Literal["gitea", "forgejo"]
    version: str = Field(min_length=1, max_length=128)
    instance_alias: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    snapshot_at: str
    provenance: str = Field(min_length=1, max_length=256)
    settings: dict[str, bool | str]
    declared_defaults: list[str] = Field(default_factory=list)

    @field_validator("snapshot_at")
    @classmethod
    def timestamp(cls, value):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("Snapshot timestamp must include timezone")
        return value

    @model_validator(mode="after")
    def validate_settings(self):
        allowed = {s.key: s for s in get_provider(self.product).settings}
        if len(set(self.declared_defaults)) != len(self.declared_defaults):
            raise ValueError("Duplicate default declaration")
        if set(self.settings) & set(self.declared_defaults):
            raise ValueError("Explicit value conflicts with default declaration")
        if not (set(self.settings) | set(self.declared_defaults)) <= set(allowed):
            raise ValueError("Unsupported snapshot key")
        for k, v in self.settings.items():
            if not any(type(v) is type(a) and v == a for a in allowed[k].values):
                raise ValueError("Unsupported snapshot value")
        return self


def review(snapshot: Snapshot, *, policy="unspecified", now=None, product=None):
    provider = get_provider(snapshot.product)
    identity = identify(snapshot.product, snapshot.version, None)
    moment = now or datetime.now(UTC)
    age = (moment - datetime.fromisoformat(snapshot.snapshot_at)).total_seconds()
    fresh = 0 <= age <= 30 * 86400
    supported = (
        identity.support == "qualified"
        and not identity.product_conflict
        and not identity.version_conflict
        and (not product or product == snapshot.product)
    )
    values = dict(snapshot.settings)
    if supported:
        for s in provider.settings:
            if s.key in snapshot.declared_defaults:
                values[s.key] = s.default
    checks = [
        (
            "FG-CONFIG-REGISTRATION",
            (
                "service.DISABLE_REGISTRATION",
                "service.REGISTER_EMAIL_CONFIRM",
                "service.REGISTER_MANUAL_CONFIRM",
            ),
        ),
        ("FG-CONFIG-SIGNIN", ("service.REQUIRE_SIGNIN_VIEW",)),
        (
            "FG-CONFIG-PRIVACY",
            ("repository.FORCE_PRIVATE", "repository.DEFAULT_PRIVATE"),
        ),
        ("FG-CONFIG-MFA", (provider.settings[-1].key,)),
    ]
    findings = []
    for id_, keys in checks:
        data = {k: values.get(k) for k in keys}
        complete = fresh and supported and all(k in values for k in keys)
        reason = "In the supplied snapshot only; loaded runtime configuration is not verified."
        conflict = (
            id_ == "FG-CONFIG-REGISTRATION"
            and values.get("service.REGISTER_EMAIL_CONFIRM") is True
            and values.get("service.REGISTER_MANUAL_CONFIRM") is True
        )
        if conflict:
            complete = False
            reason += (
                " Email and manual confirmation conflict under upstream semantics."
            )
        if not fresh:
            reason += " Snapshot is stale (over 30 days) or from the future."
        if not supported:
            reason += " Product/version is outside the qualified configuration mapping."
        if not all(k in values for k in keys):
            reason += " Missing keys remain unknown; no implicit defaults."
        private_ok = {
            "FG-CONFIG-REGISTRATION": values.get("service.DISABLE_REGISTRATION")
            is True,
            "FG-CONFIG-SIGNIN": values.get("service.REQUIRE_SIGNIN_VIEW") is True,
            "FG-CONFIG-PRIVACY": values.get("repository.FORCE_PRIVATE") is True,
            "FG-CONFIG-MFA": values.get(provider.settings[-1].key)
            in ("enforced", "all"),
        }[id_]
        status = (
            (Status.PASS if private_ok else Status.WARN)
            if complete and policy == "private"
            else Status.INFO
        )
        reason += " Default privacy does not establish existing repository privacy; MFA settings do not establish completed enrollment."
        findings.append(
            finding(
                id_,
                id_.replace("FG-CONFIG-", "") + " declared configuration",
                {
                    "values": data,
                    "declared_defaults": sorted(
                        set(keys) & set(snapshot.declared_defaults)
                    ),
                },
                "Private intent: closed registration, sign-in required, forced new private repositories, MFA required for all.",
                scope="operator-snapshot",
                source="operator-declared",
                status=status,
                state=EvidenceState.ASSESSED
                if complete
                else EvidenceState.INDETERMINATE,
                applicability="applicable" if complete else "undetermined",
                reason=reason,
                references=(provider.config_source,),
            )
        )
    return result_for(
        identity,
        findings,
        target=Target(
            url=snapshot.instance_alias,
            forge=snapshot.product,
            version=snapshot.version,
            scope="operator-snapshot",
            product_confirmed=False,
            product_source="operator-declared",
        ),
        profile="config-review",
        policy=policy,
        metadata={"coverage": "Not evaluated in config review"},
        count=0,
        run={
            "snapshot_at": snapshot.snapshot_at,
            "provenance": snapshot.provenance,
            "reviewed_at": moment.isoformat(),
        },
    )
