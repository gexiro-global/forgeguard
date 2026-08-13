from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


class InvalidTargetURL(ValueError):
    """Raised when a target URL could leak credentials or exceed safe scope."""


def normalize_target_url(value: str) -> str:
    """Validate and normalize one HTTP(S) target while preserving a Gitea sub-path."""
    if not value or any(character.isspace() for character in value):
        raise InvalidTargetURL(
            "target URL must be a non-empty HTTP(S) URL without whitespace"
        )
    try:
        parsed = urlsplit(value)
        # Accessing port performs urllib's range and integer validation.
        _ = parsed.port
    except ValueError as exc:
        raise InvalidTargetURL("target URL is invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidTargetURL("target URL scheme must be http or https")
    if not parsed.hostname:
        raise InvalidTargetURL("target URL must include a hostname")
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise InvalidTargetURL("target URL must not contain embedded credentials")
    if parsed.query or "?" in value:
        raise InvalidTargetURL("target URL must not contain a query")
    if parsed.fragment or "#" in value:
        raise InvalidTargetURL("target URL must not contain a fragment")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))
