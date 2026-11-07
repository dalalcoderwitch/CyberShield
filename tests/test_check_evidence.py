from dataclasses import FrozenInstanceError

import pytest

from security_scanner.checks.context import CheckContext
from security_scanner.checks.evidence import EvidenceCollection
from security_scanner.checks.limits import (
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADER_COUNT,
)


def test_evidence_collection_captures_response_metadata():
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000",
        },
    )

    evidence = EvidenceCollection.from_context(context)

    assert evidence.http_status == 200
    assert "content-type" in evidence.header_names
    assert evidence.values_for_header("Content-Type") == ("text/html",)


def test_header_lookup_is_case_insensitive():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Strict-Transport-Security": "max-age=31536000"},
    )

    assert evidence.values_for_header(
        "strict-transport-security"
    ) == ("max-age=31536000",)


def test_collection_preserves_separate_header_values():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={
            "X-Trace": ("first",),
            "x-trace": ("second",),
        },
    )

    assert evidence.values_for_header("X-TRACE") == (
        "first",
        "second",
    )


def test_raw_header_values_are_not_in_repr():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Set-Cookie": "session=secret-value"},
    )

    assert "secret-value" not in repr(evidence)
    assert "session=secret" not in repr(evidence)
    assert evidence.values_for_header("Set-Cookie") == ()


def test_cookie_evidence_retains_only_parsed_attributes():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Set-Cookie": "sensitive-name=sensitive-value; Secure"},
        cookie_evidence_available=True,
        cookie_observations=((True, False, "missing"),),
    )

    assert evidence.values_for_header("Set-Cookie") == ()
    assert evidence.cookie_observations == ((True, False, "missing"),)
    assert "sensitive-name" not in repr(evidence)
    assert "sensitive-value" not in repr(evidence)


def test_collection_headers_cannot_be_mutated():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Content-Type": "text/html"},
    )

    with pytest.raises(TypeError):
        evidence._headers["content-type"] = ("changed",)


def test_collection_is_immutable():
    evidence = EvidenceCollection(http_status=200)

    with pytest.raises(FrozenInstanceError):
        evidence.http_status = 404


def test_collection_from_context_without_response_is_empty():
    context = CheckContext(
        safe_target_url="https://example.com",
        connection_error="timeout",
    )

    evidence = EvidenceCollection.from_context(context)

    assert evidence.http_status is None
    assert evidence.header_names == ()
    assert evidence.values_for_header("Content-Type") == ()


def test_collection_rejects_invalid_context():
    with pytest.raises(TypeError, match="must be a CheckContext"):
        EvidenceCollection.from_context(object())


def test_collection_rejects_invalid_http_status():
    with pytest.raises(ValueError, match="between 100 and 599"):
        EvidenceCollection(http_status=600)


def test_collection_rejects_invalid_header_values():
    with pytest.raises(TypeError, match="must be strings"):
        EvidenceCollection(
            http_status=200,
            _headers={"Content-Length": 123},
        )


def test_collection_rejects_empty_header_name():
    with pytest.raises(ValueError, match="non-empty strings"):
        EvidenceCollection(
            http_status=200,
            _headers={"": "value"},
        )


def test_header_lookup_rejects_empty_name():
    evidence = EvidenceCollection(http_status=200)

    with pytest.raises(ValueError, match="non-empty string"):
        evidence.values_for_header("")


def test_evidence_rejects_excessive_header_value_count():
    values = tuple("v" for _ in range(MAX_RESPONSE_HEADER_COUNT + 1))

    with pytest.raises(ValueError, match="maximum header count"):
        EvidenceCollection(
            http_status=200,
            _headers={"X-Trace": values},
        )


def test_evidence_accepts_exact_header_byte_limit():
    value = "x" * (MAX_RESPONSE_HEADER_BYTES - 5)

    evidence = EvidenceCollection(
        http_status=200,
        _headers={"X": value},
    )

    assert len(evidence.values_for_header("X")[0]) == len(value)


def test_evidence_rejects_excessive_header_bytes():
    value = "x" * (MAX_RESPONSE_HEADER_BYTES - 4)

    with pytest.raises(ValueError, match="maximum byte limit"):
        EvidenceCollection(
            http_status=200,
            _headers={"X": value},
        )


@pytest.mark.parametrize(
    ("http_status", "connection_error"),
    [
        (200, "timeout"),
        (None, None),
    ],
)
def test_failed_context_never_contributes_partial_response_evidence(
    http_status,
    connection_error,
):
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=http_status,
        connection_error=connection_error,
        response_headers={"Cache-Control": "no-store"},
    )

    assert context.has_http_response is False

    evidence = EvidenceCollection.from_context(context)

    assert evidence.http_status is None
    assert evidence.header_names == ()
    assert evidence.values_for_header("Cache-Control") == ()
