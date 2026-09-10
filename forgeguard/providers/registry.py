from .base import ForgeProvider
from .forgejo import ForgejoProvider
from .gitea import GiteaProvider

PROVIDERS: dict[str, ForgeProvider] = {
    "gitea": GiteaProvider(),
    "forgejo": ForgejoProvider(),
}


def get_provider(product: str) -> ForgeProvider:
    if product not in PROVIDERS:
        raise ValueError("Unsupported product; expected gitea or forgejo")
    return PROVIDERS[product]
