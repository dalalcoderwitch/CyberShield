"""Central resource limits for check evidence."""

MAX_RESPONSE_HEADER_COUNT = 100
MAX_RESPONSE_HEADER_BYTES = 64 * 1024


def response_header_size_bytes(name: str, value: str) -> int:
    """Estimate the encoded HTTP header line size conservatively."""
    try:
        return (
            len(name.encode("utf-8"))
            + len(value.encode("utf-8"))
            + 4
        )
    except UnicodeEncodeError as exc:
        raise ValueError(
            "Header names and values must be valid UTF-8 text"
        ) from exc
