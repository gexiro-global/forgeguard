from __future__ import annotations

from urllib.parse import unquote, urlsplit, urlunsplit


class InvalidTargetURL(ValueError):
    """Raised when a target URL could leak credentials or exceed safe scope."""


def normalize_target_url(value: str) -> str:
    """Validate and normalize one HTTP(S) target while preserving a legal sub-path."""
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
    decoded_path = parsed.path
    for _decode_layer in range(8):
        decoded_segments = decoded_path.split("/")
        if "\\" in decoded_path or any(
            segment in {".", ".."} for segment in decoded_segments
        ):
            raise InvalidTargetURL(
                "target URL path must not contain dot segments or backslash separators"
            )
        next_path = unquote(decoded_path)
        if next_path == decoded_path:
            break
        decoded_path = next_path
    else:
        raise InvalidTargetURL(
            "target URL path contains excessive nested percent-encoding"
        )
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))
