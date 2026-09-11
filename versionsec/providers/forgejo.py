from .base import ProviderBase, RunnerInfo, Setting, common_settings, release_version


class ForgejoProvider(ProviderBase):
    id = "forgejo"
    qualified_versions = ("15.0.8", "16.0.4")
    config_source = "https://codeberg.org/forgejo/forgejo/src/tag/v16.0.4/custom/conf/app.example.ini"
    api_source = "https://codeberg.org/forgejo/forgejo/src/tag/v16.0.4/templates/swagger/v1_json.tmpl"
    settings = common_settings(config_source) + (
        Setting(
            "security.GLOBAL_TWO_FACTOR_REQUIREMENT",
            ("none", "all", "admin"),
            "none",
            config_source,
        ),
    )
    runner = RunnerInfo(
        product="forgejo-runner",
        qualified_versions=("13.0.0", "13.1.0"),
        config_source="https://forgejo.org/docs/latest/admin/actions/security/",
        security_source="https://forgejo.org/2026-08-runner-release-v13/",
    )

    def normalize_version(self, raw: str | None) -> tuple[int, int, int] | None:
        # v15/v16 Makefile explicitly appends this Gitea compatibility marker.
        if raw and raw.endswith("+gitea-1.22.0"):
            parsed = release_version(raw)
            return parsed if parsed and parsed[0] in (15, 16) else None
        return super().normalize_version(raw)
