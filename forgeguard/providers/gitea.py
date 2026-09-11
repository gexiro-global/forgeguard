from .base import ProviderBase, RunnerInfo, Setting, common_settings


class GiteaProvider(ProviderBase):
    id = "gitea"
    qualified_versions = ("1.26.4", "1.27.3")
    config_source = (
        "https://github.com/go-gitea/gitea/blob/v1.27.3/custom/conf/app.example.ini"
    )
    api_source = (
        "https://github.com/go-gitea/gitea/blob/v1.27.3/templates/swagger/v1_json.tmpl"
    )
    settings = common_settings(config_source) + (
        Setting("security.TWO_FACTOR_AUTH", ("", "enforced"), "", config_source),
    )
    runner = RunnerInfo(
        product="gitea-runner",
        qualified_versions=("3.4.2",),
        config_source="https://gitea.com/gitea/runner/releases/tag/v3.4.2",
        security_source="https://blog.gitea.com/release-of-runner-3.0.0/",
    )
