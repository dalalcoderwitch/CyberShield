from importlib import import_module

import pytest


report_module = import_module("security_scanner.report")

TARGET_URL = "https://example.com"

WEEK3_RESPONSE_CHECK_IDS = {
    "header_referrer_policy",
    "header_permissions_policy",
    "cookie_secure",
    "cookie_httponly",
    "cookie_samesite",
    "cors_misconfiguration",
    "open_redirect",
    "sensitive_file_exposure",
    "source_maps_exposure",
    "directory_listing",
    "server_information_disclosure",
    "error_information_disclosure",
    "public_security_files",
}

FOUNDATIONAL_CHECK_IDS = {
    "https_connection",
    "header_hsts",
    "header_csp",
    "header_x_content_type_options",
    "header_x_frame_options",
}

TLS_REDIRECT_CHECK_IDS = {
    "tls_certificate_expiry",
    "tls_certificate_chain",
    "tls_protocol_config",
    "http_to_https_redirect",
    "redirect_destination_safety",
}

WEEK3_EXPANDED_CHECK_IDS = TLS_REDIRECT_CHECK_IDS | WEEK3_RESPONSE_CHECK_IDS

DNS_WEEK4_CHECK_IDS = {"dns_dmarc", "dns_spf", "dnssec"}

EXPECTED_REPORT_CHECK_IDS = (
    FOUNDATIONAL_CHECK_IDS
    | TLS_REDIRECT_CHECK_IDS
    | WEEK3_RESPONSE_CHECK_IDS
    | DNS_WEEK4_CHECK_IDS
)


def install_mock_response(monkeypatch, result):
    calls = []

    def fake_safe_get_response(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    monkeypatch.setattr(
        report_module,
        "_safe_get_response",
        fake_safe_get_response,
    )
    return calls


def test_default_report_keeps_five_findings(monkeypatch):
    headers = {
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=()",
        "Cache-Control": "no-store",
    }
    calls = install_mock_response(
        monkeypatch,
        (200, headers, None),
    )

    report = report_module.scan_target(TARGET_URL)

    assert len(calls) == 1
    assert len(report["findings"]) == 5
    assert not (
        WEEK3_RESPONSE_CHECK_IDS
        & {item["check_id"] for item in report["findings"]}
    )


def test_expanded_report_contains_25_findings_from_one_response(monkeypatch):
    headers = {
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=()",
        "Cache-Control": "no-store",
    }
    calls = install_mock_response(
        monkeypatch,
        (200, headers, None),
    )

    report = report_module.scan_target(
        TARGET_URL,
        include_expanded_checks=True,
    )

    findings = report["findings"]
    check_ids = [item["check_id"] for item in findings]

    assert len(calls) == 1
    assert len(findings) == 26
    assert len(set(check_ids)) == 26
    assert set(check_ids) == EXPECTED_REPORT_CHECK_IDS
    assert "cache_security" not in set(check_ids)
    assert {"tls_certificate_expiry", "tls_certificate_chain", "tls_protocol_config", "http_to_https_redirect", "redirect_destination_safety"} <= set(check_ids)
    assert report["summary"]["total"] == 26


def test_expanded_findings_are_not_verified_without_response(monkeypatch):
    install_mock_response(
        monkeypatch,
        (None, {}, "timeout"),
    )

    report = report_module.scan_target(
        TARGET_URL,
        include_expanded_checks=True,
    )

    expanded_findings = [
        item
        for item in report["findings"]
        if item["check_id"] in WEEK3_EXPANDED_CHECK_IDS
    ]

    assert len(report["findings"]) == 26
    assert len(expanded_findings) == 18
    assert all(
        item["status"] == "not_verified"
        for item in expanded_findings
    )


def test_expanded_report_does_not_expose_raw_header_values(monkeypatch):
    secret = "PRIVATE_HEADER_VALUE_MUST_NOT_LEAK"
    headers = {
        "Referrer-Policy": secret,
        "Permissions-Policy": secret,
        "Cache-Control": f'no-store, extension="{secret}"',
    }
    install_mock_response(
        monkeypatch,
        (200, headers, None),
    )

    report = report_module.scan_target(
        TARGET_URL,
        include_expanded_checks=True,
    )

    assert secret not in repr(report["findings"])


def test_expanded_option_rejects_non_boolean_before_http(monkeypatch):
    calls = install_mock_response(
        monkeypatch,
        (200, {}, None),
    )

    with pytest.raises(TypeError):
        report_module.scan_target(
            TARGET_URL,
            include_expanded_checks="yes",
        )

    assert calls == []
