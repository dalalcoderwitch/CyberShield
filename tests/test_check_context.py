from dataclasses import FrozenInstanceError

import pytest

from security_scanner.checks.context import CheckContext
from security_scanner.checks.limits import (
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADER_COUNT,
)


def test_context_stores_shared_response_metadata():
    context = CheckContext(
        safe_target_url="https://example.com",
        deadline=120.5,
        http_status=200,
        response_headers={"Strict-Transport-Security": "max-age=31536000"},
    )

    assert context.safe_target_url == "https://example.com"
    assert context.deadline == 120.5
    assert context.http_status == 200
    assert context.has_http_response is True


def test_context_copies_headers_and_prevents_mutation():
    original_headers = {"Content-Type": "text/html"}

    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers=original_headers,
    )

    original_headers["Content-Type"] = "changed"

    assert context.response_headers["Content-Type"] == "text/html"

    with pytest.raises(TypeError):
        context.response_headers["Content-Type"] = "changed"


def test_context_repr_does_not_expose_raw_header_values():
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={"Set-Cookie": "session=secret-value"},
    )

    assert "secret-value" not in repr(context)
    assert "session=secret" not in repr(context)
    assert "Set-Cookie" not in context.response_headers


def test_context_is_immutable():
    context = CheckContext(
        safe_target_url="https://example.com",
    )

    with pytest.raises(FrozenInstanceError):
        context.safe_target_url = "https://other.example"


def test_context_without_response_is_not_marked_available():
    context = CheckContext(
        safe_target_url="https://example.com",
        connection_error="timeout",
    )

    assert context.has_http_response is False


@pytest.mark.parametrize("status", [0, 99, 600, True, "200"])
def test_context_rejects_invalid_http_status(status):
    with pytest.raises(ValueError):
        CheckContext(
            safe_target_url="https://example.com",
            http_status=status,
        )


@pytest.mark.parametrize("deadline", [float("inf"), float("-inf"), float("nan"), True])
def test_context_rejects_invalid_deadline(deadline):
    with pytest.raises(ValueError):
        CheckContext(
            safe_target_url="https://example.com",
            deadline=deadline,
        )


def test_context_rejects_non_mapping_headers():
    with pytest.raises(TypeError, match="must be a mapping"):
        CheckContext(
            safe_target_url="https://example.com",
            response_headers=[],
        )


def test_context_rejects_non_string_header_values():
    with pytest.raises(TypeError, match="must be strings"):
        CheckContext(
            safe_target_url="https://example.com",
            response_headers={"Content-Length": 123},
        )


def test_context_accepts_maximum_header_count():
    headers = {
        f"X-Test-{index}": "v"
        for index in range(MAX_RESPONSE_HEADER_COUNT)
    }

    context = CheckContext(
        safe_target_url="https://example.com",
        response_headers=headers,
    )

    assert len(context.response_headers) == MAX_RESPONSE_HEADER_COUNT


def test_context_rejects_excessive_header_count():
    headers = {
        f"X-Test-{index}": "v"
        for index in range(MAX_RESPONSE_HEADER_COUNT + 1)
    }

    with pytest.raises(ValueError, match="maximum header count"):
        CheckContext(
            safe_target_url="https://example.com",
            response_headers=headers,
        )


def test_context_accepts_exact_header_byte_limit():
    value = "x" * (MAX_RESPONSE_HEADER_BYTES - 5)

    context = CheckContext(
        safe_target_url="https://example.com",
        response_headers={"X": value},
    )

    assert len(context.response_headers["X"]) == len(value)


def test_context_rejects_excessive_header_bytes():
    value = "x" * (MAX_RESPONSE_HEADER_BYTES - 4)

    with pytest.raises(ValueError, match="maximum byte limit"):
        CheckContext(
            safe_target_url="https://example.com",
            response_headers={"X": value},
        )


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "https://example.com:443",
        "https://[2001:db8::1]",
    ],
)
def test_context_accepts_sanitized_https_origins(target):
    context = CheckContext(safe_target_url=target)

    assert context.safe_target_url == target


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com",
        "https://example.com/path",
        "https://example.com?token=value",
        "https://example.com#fragment",
        "https://user:password@example.com",
        "https://example.com:8443",
        "https:///missing-host",
        "https://example.com\n.evil",
    ],
)
def test_context_rejects_unsanitized_target_urls(target):
    with pytest.raises(
        ValueError,
        match="sanitized HTTPS origin",
    ):
        CheckContext(safe_target_url=target)
