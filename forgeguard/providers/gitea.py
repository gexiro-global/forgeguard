from .base import ProviderBase, Setting, common_settings


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
