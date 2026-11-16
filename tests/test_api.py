import logging
from threading import BoundedSemaphore
from types import SimpleNamespace

import pytest

import backend.app as api_module


def test_health_endpoint():
    app = api_module.create_app()
    client = app.test_client()

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json["status"] == "ok"
    assert response.json["service"] == "CyberShield API"


def test_scan_rejects_invalid_json():
    app = api_module.create_app()
    client = app.test_client()

    response = client.post(
        "/api/v1/scan",
        json=["invalid", "payload"],
    )

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"target_url": "", "authorization_confirmed": True},
        {"target_url": "   ", "authorization_confirmed": True},
        {"target_url": 123, "authorization_confirmed": True},
        {"target_url": " https://example.com ", "authorization_confirmed": True},
        {"target_url": "https://example.com", "authorization_confirmed": "true"},
        {"target_url": "https://example.com"},
        {
            "target_url": "https://example.com/" + ("a" * 2048),
            "authorization_confirmed": True,
        },
    ],
)
def test_scan_rejects_invalid_request_fields(payload):
    """رفض الحقول المفقودة أو غير الصالحة قبل بدء الفحص."""

    app = api_module.create_app()
    client = app.test_client()

    response = client.post("/api/v1/scan", json=payload)

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_REQUEST"


def test_scan_rejects_malformed_json():
    """رفض JSON غير المكتمل أو غير القابل للتحليل."""

    app = api_module.create_app()
    client = app.test_client()

    response = client.post(
        "/api/v1/scan",
        data='{"target_url":',
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_REQUEST"


def test_scan_rejects_oversized_request_before_target_resolution(monkeypatch):
    """Reject an oversized body at the Flask boundary without starting DNS or a scan."""

    app = api_module.create_app()
    client = app.test_client()

    def unexpected_resolve(*args, **kwargs):
        raise AssertionError("Oversized requests must be rejected before DNS.")

    def unexpected_scan(*args, **kwargs):
        raise AssertionError("Oversized requests must never start a scan.")

    monkeypatch.setattr(api_module, "resolve_target", unexpected_resolve)
    monkeypatch.setattr(api_module, "scan_target", unexpected_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "extra": "x" * 17000,
        },
    )

    assert response.status_code == 413
    assert response.is_json
    assert response.json["error"]["code"] == "REQUEST_TOO_LARGE"


def test_scan_accepts_request_at_exact_flask_body_limit(monkeypatch):
    """The configured 16 KiB Flask body limit is inclusive."""

    app = api_module.create_app()
    client = app.test_client()
    limit = app.config["MAX_CONTENT_LENGTH"]
    body = b'{"target_url":"https://example.com","authorization_confirmed":true}'
    body += b" " * (limit - len(body))

    def reject_target_after_parsing(url, deadline=None):
        assert url == "https://example.com"
        return None

    monkeypatch.setattr(api_module, "resolve_target", reject_target_after_parsing)

    response = client.post(
        "/api/v1/scan",
        data=body,
        content_type="application/json",
    )

    assert len(body) == limit
    assert response.status_code == 403
    assert response.get_json()["error"]["code"] == "TARGET_NOT_ALLOWED"


def test_scan_rejects_request_one_byte_over_flask_body_limit_before_dns(
    monkeypatch,
):
    """A body one byte over 16 KiB is rejected before target resolution."""

    app = api_module.create_app()
    client = app.test_client()
    limit = app.config["MAX_CONTENT_LENGTH"]
    body = b'{"target_url":"https://example.com","authorization_confirmed":true}'
    body += b" " * (limit + 1 - len(body))

    def unexpected_resolve(*args, **kwargs):
        raise AssertionError("Oversized bodies must be rejected before DNS.")

    monkeypatch.setattr(api_module, "resolve_target", unexpected_resolve)

    response = client.post(
        "/api/v1/scan",
        data=body,
        content_type="application/json",
    )

    assert len(body) == limit + 1
    assert response.status_code == 413
    assert response.is_json
    assert response.get_json()["error"]["code"] == "REQUEST_TOO_LARGE"


def test_scan_rejects_unsupported_method_with_json():
    """إرجاع 405 بصيغة JSON عند استخدام GET لمسار الفحص."""

    app = api_module.create_app()
    client = app.test_client()

    response = client.get("/api/v1/scan")

    assert response.status_code == 405
    assert "POST" in response.headers.get("Allow", "")
    assert response.json["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert response.json["error"]["message"]

def test_scan_rejects_when_capacity_is_full_before_dns(monkeypatch):
    """A saturated scan semaphore must reject without resolving or scanning."""

    app = api_module.create_app()
    client = app.test_client()

    class SaturatedSemaphore:
        def acquire(self, blocking=False):
            assert blocking is False
            return False

    def unexpected_resolve(*args, **kwargs):
        raise AssertionError("Capacity rejection must happen before DNS.")

    def unexpected_scan(*args, **kwargs):
        raise AssertionError("Capacity rejection must happen before scanning.")

    monkeypatch.setattr(api_module, "_SCAN_SLOTS", SaturatedSemaphore())
    monkeypatch.setattr(api_module, "resolve_target", unexpected_resolve)
    monkeypatch.setattr(api_module, "scan_target", unexpected_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 503
    assert response.is_json
    assert response.json["error"]["code"] == "SCAN_CAPACITY_EXCEEDED"


def test_scan_requires_authorization():
    app = api_module.create_app()
    client = app.test_client()

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": False,
        },
    )

    assert response.status_code == 403
    assert (
        response.json["error"]["code"]
        == "AUTHORIZATION_REQUIRED"
    )


def test_scan_rejects_disallowed_target(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: None
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 403
    assert response.json["error"]["code"] == "TARGET_NOT_ALLOWED"


def test_scan_endpoint_returns_contract_compatible_report(monkeypatch):
    """اختبار تكامل Flask مع محرك التقرير دون اتصال خارجي."""

    app = api_module.create_app()
    client = app.test_client()

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url, resolved_target=None, deadline=None: (
            200,
            headers,
            None,
        ),
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com/admin?token=private",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200

    report = response.get_json()

    expected_top_level_fields = {
        "scan_id",
        "status",
        "target_url",
        "scanned_at",
        "engine_version",
        "http_status",
        "summary",
        "findings",
        "limitations",
        "notice",
    }

    assert set(report.keys()) == expected_top_level_fields
    assert report["status"] == "completed"
    assert report["target_url"] == "https://example.com"
    assert report["http_status"] == 200
    assert report["engine_version"] == "1.0.0"
    assert report["scanned_at"]
    assert report["notice"]

    expected_check_ids = {
        "https_connection",
        "header_hsts",
        "header_csp",
        "header_x_content_type_options",
        "header_x_frame_options",
    }

    findings = report["findings"]

    assert len(findings) == 5
    assert {item["check_id"] for item in findings} == expected_check_ids

    findings_by_id = {
        item["check_id"]: item
        for item in findings
    }

    assert findings_by_id["https_connection"]["status"] == "passed"
    assert findings_by_id["header_hsts"]["status"] == "passed"
    assert findings_by_id["header_csp"]["status"] == "warning"
    assert findings_by_id["header_x_content_type_options"]["status"] == "passed"
    assert findings_by_id["header_x_frame_options"]["status"] == "passed"

    required_finding_fields = {
        "check_id",
        "title",
        "status",
        "severity",
        "confidence",
        "evidence",
        "explanation",
        "recommendation",
        "limitations",
    }

    for finding in findings:
        assert required_finding_fields.issubset(finding.keys())
        assert finding["title"]
        assert finding["evidence"]
        assert finding["explanation"]
        assert finding["recommendation"]
        assert isinstance(finding["limitations"], list)

    summary = report["summary"]

    expected_summary_fields = {
        "total",
        "passed",
        "warning",
        "not_verified",
        "error",
        "skipped",
    }

    assert set(summary.keys()) == expected_summary_fields
    assert summary["total"] == 5

    for status in (
        "passed",
        "warning",
        "not_verified",
        "error",
        "skipped",
    ):
        actual_count = sum(
            finding["status"] == status
            for finding in findings
        )
        assert summary[status] == actual_count

    assert isinstance(report["limitations"], list)
    assert report["limitations"]
    assert report["target_url"] == "https://example.com"


@pytest.mark.parametrize(
    "probe_status,location,dns_addresses,expected_http_status,expected_safety_status,expected_dns_calls",
    [
        (
            302,
            "https://redirect.example/secure",
            ("93.184.216.34",),
            "passed",
            "passed",
            1,
        ),
        (
            302,
            "https://redirect.example/secure",
            ("93.184.216.34", "10.0.0.8"),
            "passed",
            "warning",
            1,
        ),
        (
            302,
            "https://user:secret@redirect.example/secure",
            ("93.184.216.34",),
            "warning",
            "warning",
            0,
        ),
        (
            200,
            None,
            ("93.184.216.34",),
            "warning",
            "skipped",
            0,
        ),
    ],
)
def test_scan_api_preserves_week2_redirect_outcomes_without_following_destination(
    monkeypatch,
    probe_status,
    location,
    dns_addresses,
    expected_http_status,
    expected_safety_status,
    expected_dns_calls,
):
    """Exercise redirect evidence through Flask without connecting to its destination."""

    from urllib.parse import urlsplit

    from security_scanner.checks.result import CheckResult

    app = api_module.create_app()
    client = app.test_client()
    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    observed = {
        "primary_request_urls": [],
        "http_probe_targets": [],
        "redirect_dns_candidates": [],
        "redirect_dns_calls": [],
    }
    response_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }

    def fake_get_response(
        url,
        resolved_target=None,
        deadline=None,
        tls_metadata=None,
        redirect_dns_answers=None,
        validated_target_capture=None,
        cookie_evidence_capture=None,
        access_evidence_capture=None,
        disclosure_evidence_capture=None,
    ):
        observed["primary_request_urls"].append(url)
        if validated_target_capture is not None:
            validated_target_capture["target"] = (
                urlsplit(url),
                "example.com",
                ["93.184.216.34"],
            )
            validated_target_capture["takeover_hostname"] = "example.com"
        if tls_metadata is not None:
            tls_metadata.update(
                not_before="Jan 01 00:00:00 2020 GMT",
                not_after="Jan 01 00:00:00 2099 GMT",
                chain_available=True,
                version="TLSv1.3",
                cipher="TLS_AES_128_GCM_SHA256",
            )
        if cookie_evidence_capture is not None:
            cookie_evidence_capture.update(available=True, observations=())
        if access_evidence_capture is not None:
            access_evidence_capture.update(available=True, location_values=())
        if disclosure_evidence_capture is not None:
            disclosure_evidence_capture.clear()
        return 200, response_headers, None

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        fake_get_response,
    )

    def fake_http_probe(target, deadline=None, capture=None):
        observed["http_probe_targets"].append(target)
        if capture is not None:
            capture.update(
                status=probe_status,
                location=location,
                request_url="http://93.184.216.34:80/",
            )
        return None

    monkeypatch.setattr(
        "security_scanner.report._safe_http_redirect_probe",
        fake_http_probe,
    )

    def fake_resolve_redirect(destination, deadline=None):
        parsed = urlsplit(destination)
        # Invalid locations are rejected before any destination DNS lookup.
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            return None
        observed["redirect_dns_candidates"].append(destination)
        observed["redirect_dns_calls"].append(destination)
        return dns_addresses

    monkeypatch.setattr(
        "security_scanner.report._resolve_redirect_location_addresses",
        fake_resolve_redirect,
    )

    def isolated_dns_result(check_id, title):
        return CheckResult(
            check_id=check_id,
            title=title,
            status="skipped",
            severity="info",
            confidence="low",
            evidence="DNS evaluator is isolated in this redirect API test.",
            explanation="No DNS policy conclusion is inferred from this fixture.",
            recommendation="Use dedicated DNS evaluator tests.",
            limitations=("Controlled API test fixture.",),
        )

    monkeypatch.setattr(
        "security_scanner.report.evaluate_spf_domain",
        lambda domain, deadline=None: isolated_dns_result("dns_spf", "SPF"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dmarc_domain",
        lambda domain, deadline=None: isolated_dns_result("dns_dmarc", "DMARC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dnssec_domain",
        lambda domain, deadline=None: isolated_dns_result("dnssec", "DNSSEC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_takeover_domain",
        lambda hostname, deadline=None: isolated_dns_result(
            "subdomain_takeover_indicators",
            "Passive takeover indicators",
        ),
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": True,
        },
    )

    assert response.status_code == 200
    report = response.get_json()
    findings_by_id = {
        finding["check_id"]: finding
        for finding in report["findings"]
    }

    assert findings_by_id["http_to_https_redirect"]["status"] == expected_http_status
    assert findings_by_id["redirect_destination_safety"]["status"] == expected_safety_status
    assert len(report["findings"]) == report["summary"]["total"] == 30
    assert len(observed["primary_request_urls"]) == 1
    assert observed["primary_request_urls"] == ["https://example.com"]
    assert len(observed["http_probe_targets"]) == 1
    assert len(observed["redirect_dns_calls"]) == expected_dns_calls
    assert all(
        "user:secret@" not in destination
        for destination in observed["redirect_dns_candidates"]
    )
    assert "10.0.0.8" not in repr(report)

    # The destination is classified from Location and bounded DNS evidence;
    # no second HTTPS request to that destination is created or followed.
    assert observed["primary_request_urls"] == ["https://example.com"]

    for status in ("passed", "warning", "not_verified", "error", "skipped"):
        assert report["summary"][status] == sum(
            finding["status"] == status
            for finding in report["findings"]
        )


@pytest.mark.parametrize(
    "referrer_value,permissions_value,expected_referrer_status,expected_referrer_severity,expected_permissions_status,expected_permissions_severity",
    [
        (
            "strict-origin-when-cross-origin",
            "camera=()",
            "passed",
            "info",
            "warning",
            "info",
        ),
        (
            None,
            None,
            "warning",
            "low",
            "warning",
            "low",
        ),
        (
            "unsafe-url",
            "camera=(",
            "warning",
            "medium",
            "warning",
            "medium",
        ),
    ],
)
def test_scan_api_preserves_week2_header_evaluator_results(
    monkeypatch,
    referrer_value,
    permissions_value,
    expected_referrer_status,
    expected_referrer_severity,
    expected_permissions_status,
    expected_permissions_severity,
):
    """Verify Week 2 header outcomes through Flask and the real report engine."""

    from urllib.parse import urlsplit

    from security_scanner.checks.result import CheckResult
    from security_scanner.checks.disclosure_evidence import DisclosureEvidence

    app = api_module.create_app()
    client = app.test_client()
    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
    if referrer_value is not None:
        headers["Referrer-Policy"] = referrer_value
    if permissions_value is not None:
        headers["Permissions-Policy"] = permissions_value

    def fake_get_response(
        url,
        resolved_target=None,
        deadline=None,
        tls_metadata=None,
        redirect_dns_answers=None,
        validated_target_capture=None,
        cookie_evidence_capture=None,
        access_evidence_capture=None,
        disclosure_evidence_capture=None,
    ):
        if validated_target_capture is not None:
            validated_target_capture["target"] = (
                urlsplit(url),
                "example.com",
                ["93.184.216.34"],
            )
            validated_target_capture["takeover_hostname"] = "example.com"
        if cookie_evidence_capture is not None:
            cookie_evidence_capture.update(available=True, observations=())
        if access_evidence_capture is not None:
            access_evidence_capture.update(available=True, location_values=())
        if disclosure_evidence_capture is not None:
            disclosure_evidence_capture.clear()
        return 200, headers, None

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        fake_get_response,
    )
    monkeypatch.setattr(
        "security_scanner.report._safe_http_redirect_probe",
        lambda target, deadline=None, capture=None: (
            capture.update(available=False, error="connection") or "connection"
        ),
    )
    monkeypatch.setattr(
        "security_scanner.report._safe_cors_preflight",
        lambda target, deadline=None, capture=None: (
            capture.update(available=False, error="connection") or "connection"
        ),
    )
    monkeypatch.setattr(
        "security_scanner.report._collect_disclosure_evidence",
        lambda target, original_status, original_capture, deadline=None: DisclosureEvidence(),
    )

    def isolated_dns_result(check_id, title):
        return CheckResult(
            check_id=check_id,
            title=title,
            status="skipped",
            severity="info",
            confidence="low",
            evidence="DNS evaluator is isolated in this header API test.",
            explanation="No DNS conclusion is inferred from this fixture.",
            recommendation="Use the dedicated DNS evaluator tests.",
            limitations=("Controlled API test fixture.",),
        )

    monkeypatch.setattr(
        "security_scanner.report.evaluate_spf_domain",
        lambda domain, deadline=None: isolated_dns_result("dns_spf", "SPF"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dmarc_domain",
        lambda domain, deadline=None: isolated_dns_result("dns_dmarc", "DMARC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dnssec_domain",
        lambda domain, deadline=None: isolated_dns_result("dnssec", "DNSSEC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_takeover_domain",
        lambda hostname, deadline=None: isolated_dns_result(
            "subdomain_takeover_indicators",
            "Passive takeover indicators",
        ),
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": True,
        },
    )

    assert response.status_code == 200
    report = response.get_json()
    findings_by_id = {
        finding["check_id"]: finding
        for finding in report["findings"]
    }

    referrer = findings_by_id["header_referrer_policy"]
    permissions = findings_by_id["header_permissions_policy"]
    assert referrer["status"] == expected_referrer_status
    assert referrer["severity"] == expected_referrer_severity
    assert permissions["status"] == expected_permissions_status
    assert permissions["severity"] == expected_permissions_severity
    assert len(report["findings"]) == report["summary"]["total"] == 30

    for status in ("passed", "warning", "not_verified", "error", "skipped"):
        assert report["summary"][status] == sum(
            finding["status"] == status
            for finding in report["findings"]
        )

    # Header values are evaluated but are not echoed into API evidence.
    assert referrer_value is None or referrer_value not in repr(referrer)
    assert permissions_value is None or permissions_value not in repr(permissions)


@pytest.mark.parametrize(
    "not_after,expected_status",
    [
        ("Jan 01 00:00:00 2099 GMT", "passed"),
        ("Jan 01 00:00:00 2020 GMT", "warning"),
        ("not-a-valid-asn1-date", "not_verified"),
    ],
)
def test_scan_api_preserves_tls_expiry_outcome_and_other_week2_checks(
    monkeypatch,
    not_after,
    expected_status,
):
    """Exercise certificate-date outcomes through Flask and the real report engine."""

    from security_scanner.checks.result import CheckResult

    app = api_module.create_app()
    client = app.test_client()
    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }

    def fake_get_response(
        url,
        resolved_target=None,
        deadline=None,
        tls_metadata=None,
        redirect_dns_answers=None,
        validated_target_capture=None,
        cookie_evidence_capture=None,
        access_evidence_capture=None,
        disclosure_evidence_capture=None,
    ):
        tls_metadata.update(
            not_before="Jan 01 00:00:00 2020 GMT",
            not_after=not_after,
            chain_available=True,
            version="TLSv1.3",
            cipher="TLS_AES_128_GCM_SHA256",
        )
        if cookie_evidence_capture is not None:
            cookie_evidence_capture.update(
                available=True,
                observations=(),
            )
        if access_evidence_capture is not None:
            access_evidence_capture.update(
                available=True,
                location_values=(),
            )
        if disclosure_evidence_capture is not None:
            disclosure_evidence_capture.clear()
        return 200, headers, None

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        fake_get_response,
    )

    def isolated_dns_result(check_id, title):
        return CheckResult(
            check_id=check_id,
            title=title,
            status="skipped",
            severity="info",
            confidence="low",
            evidence="DNS evaluation is isolated in this TLS API test.",
            explanation="No DNS security conclusion is inferred.",
            recommendation="Use the dedicated DNS evaluator tests.",
            limitations=("Controlled API test fixture.",),
        )

    monkeypatch.setattr(
        "security_scanner.report.evaluate_spf_domain",
        lambda domain, deadline=None: isolated_dns_result("dns_spf", "SPF"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dmarc_domain",
        lambda domain, deadline=None: isolated_dns_result("dns_dmarc", "DMARC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dnssec_domain",
        lambda domain, deadline=None: isolated_dns_result("dnssec", "DNSSEC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_takeover_domain",
        lambda hostname, deadline=None: isolated_dns_result(
            "subdomain_takeover_indicators",
            "Passive takeover indicators",
        ),
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": True,
        },
    )

    assert response.status_code == 200
    report = response.get_json()
    findings_by_id = {
        finding["check_id"]: finding
        for finding in report["findings"]
    }

    assert findings_by_id["tls_certificate_expiry"]["status"] == expected_status
    assert findings_by_id["tls_certificate_chain"]["status"] == "passed"
    assert findings_by_id["tls_protocol_config"]["status"] == "passed"
    assert findings_by_id["https_connection"]["status"] == "passed"
    assert len(report["findings"]) == report["summary"]["total"] == 30
    for status in ("passed", "warning", "not_verified", "error", "skipped"):
        assert report["summary"][status] == sum(
            finding["status"] == status
            for finding in report["findings"]
        )


def test_scan_api_keeps_expanded_tls_checks_unverified_after_handshake_failure(
    monkeypatch,
):
    """A failed TLS handshake must not produce passed metadata checks or drop the report."""

    from security_scanner.checks.result import CheckResult

    app = api_module.create_app()
    client = app.test_client()
    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    def fake_get_response(
        url,
        resolved_target=None,
        deadline=None,
        tls_metadata=None,
        redirect_dns_answers=None,
        validated_target_capture=None,
        cookie_evidence_capture=None,
        access_evidence_capture=None,
        disclosure_evidence_capture=None,
    ):
        # No verified handshake means there is no trusted TLS metadata to evaluate.
        return None, {}, "tls"

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        fake_get_response,
    )

    def isolated_dns_result(check_id, title):
        return CheckResult(
            check_id=check_id,
            title=title,
            status="skipped",
            severity="info",
            confidence="low",
            evidence="DNS evaluation is isolated in this TLS failure test.",
            explanation="No DNS security conclusion is inferred.",
            recommendation="Use the dedicated DNS evaluator tests.",
            limitations=("Controlled API test fixture.",),
        )

    monkeypatch.setattr(
        "security_scanner.report.evaluate_spf_domain",
        lambda domain, deadline=None: isolated_dns_result("dns_spf", "SPF"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dmarc_domain",
        lambda domain, deadline=None: isolated_dns_result("dns_dmarc", "DMARC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dnssec_domain",
        lambda domain, deadline=None: isolated_dns_result("dnssec", "DNSSEC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_takeover_domain",
        lambda hostname, deadline=None: isolated_dns_result(
            "subdomain_takeover_indicators",
            "Passive takeover indicators",
        ),
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": True,
        },
    )

    assert response.status_code == 200
    report = response.get_json()
    findings_by_id = {
        finding["check_id"]: finding
        for finding in report["findings"]
    }

    assert report["status"] == "completed"
    assert report["http_status"] is None
    assert len(report["findings"]) == report["summary"]["total"] == 30
    for check_id in (
        "tls_certificate_expiry",
        "tls_certificate_chain",
        "tls_protocol_config",
    ):
        assert findings_by_id[check_id]["status"] == "not_verified"

    assert findings_by_id["https_connection"]["status"] == "warning"
    assert findings_by_id["header_referrer_policy"]["status"] == "not_verified"
    assert findings_by_id["header_permissions_policy"]["status"] == "not_verified"
    for status in ("passed", "warning", "not_verified", "error", "skipped"):
        assert report["summary"][status] == sum(
            finding["status"] == status
            for finding in report["findings"]
        )


def test_scan_api_preserves_week2_findings_and_partial_results(monkeypatch):
    """The Flask boundary preserves all seven Week 2 checks and partial status."""

    app = api_module.create_app()
    client = app.test_client()
    resolved = object()
    captured = {}

    def make_finding(check_id, status):
        return {
            "check_id": check_id,
            "title": f"Test result for {check_id}",
            "status": status,
            "severity": "medium" if status == "warning" else "info",
            "confidence": "low" if status in ("error", "not_verified", "skipped") else "high",
            "evidence": {"source": "week2-api-fixture", "check_id": check_id},
            "explanation": f"Preserve the engine explanation for {check_id}.",
            "recommendation": f"Preserve the engine recommendation for {check_id}.",
            "limitations": [f"Fixture limitation for {check_id}."],
        }

    base_findings = [
        make_finding("https_connection", "passed"),
        make_finding("header_hsts", "warning"),
        make_finding("header_csp", "passed"),
        make_finding("header_x_content_type_options", "passed"),
        make_finding("header_x_frame_options", "warning"),
    ]
    week2_findings = [
        make_finding("tls_certificate_expiry", "warning"),
        make_finding("tls_certificate_chain", "not_verified"),
        make_finding("tls_protocol_config", "error"),
        make_finding("http_to_https_redirect", "passed"),
        make_finding("redirect_destination_safety", "warning"),
        make_finding("header_referrer_policy", "passed"),
        make_finding("header_permissions_policy", "skipped"),
    ]
    findings = base_findings + week2_findings
    statuses = ("passed", "warning", "not_verified", "error", "skipped")
    summary = {
        status: sum(item["status"] == status for item in findings)
        for status in statuses
    }
    summary["total"] = len(findings)

    engine_report = {
        "scan_id": "week2-api-contract",
        "status": "completed",
        "target_url": "https://example.com",
        "scanned_at": "2026-11-16T12:00:00Z",
        "engine_version": "1.0.0",
        "http_status": 200,
        "summary": summary,
        "findings": findings,
        "limitations": ["Controlled API contract fixture."],
        "notice": "Limited security assessment.",
        "correlations": [],
        "correlation_rules_version": "2.0.0",
    }

    def fake_resolve(url, deadline=None):
        captured["resolve_url"] = url
        return resolved

    def fake_scan(
        url,
        resolved_target=None,
        deadline=None,
        include_expanded_checks=False,
    ):
        captured["scan_url"] = url
        captured["resolved_target"] = resolved_target
        captured["include_expanded_checks"] = include_expanded_checks
        return engine_report

    monkeypatch.setattr(api_module, "resolve_target", fake_resolve)
    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": True,
        },
    )

    assert response.status_code == 200
    assert captured["resolve_url"] == "https://example.com"
    assert captured["scan_url"] == "https://example.com"
    assert captured["resolved_target"] is resolved
    assert captured["include_expanded_checks"] is True

    report = response.get_json()
    assert report == engine_report
    assert len(report["findings"]) == 12
    assert report["summary"]["total"] == 12

    expected_week2_ids = {
        "tls_certificate_expiry",
        "tls_certificate_chain",
        "tls_protocol_config",
        "http_to_https_redirect",
        "redirect_destination_safety",
        "header_referrer_policy",
        "header_permissions_policy",
    }
    findings_by_id = {
        finding["check_id"]: finding
        for finding in report["findings"]
    }
    assert expected_week2_ids.issubset(findings_by_id)

    required_fields = {
        "check_id",
        "title",
        "status",
        "severity",
        "confidence",
        "evidence",
        "explanation",
        "recommendation",
        "limitations",
    }
    for check_id in expected_week2_ids:
        finding = findings_by_id[check_id]
        assert required_fields.issubset(finding)
        assert isinstance(finding["evidence"], dict)
        assert isinstance(finding["limitations"], list)
        assert finding["title"]
        assert finding["explanation"]
        assert finding["recommendation"]

    # A single evaluator error remains attached to its finding; it does not
    # discard the other Week 2 results or change their status values.
    assert findings_by_id["tls_protocol_config"]["status"] == "error"
    assert findings_by_id["tls_certificate_chain"]["status"] == "not_verified"
    assert findings_by_id["http_to_https_redirect"]["status"] == "passed"
    for status in statuses:
        assert report["summary"][status] == sum(
            finding["status"] == status
            for finding in report["findings"]
        )


def test_scan_endpoint_preserves_not_verified_findings_on_connection_failure(
    monkeypatch,
):
    """The API must preserve unverified findings when the connection fails."""

    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url, resolved_target=None, deadline=None: (
            None,
            {},
            "connection",
        ),
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200

    report = response.get_json()

    assert report["status"] == "completed"
    assert report["http_status"] is None
    assert report["summary"]["total"] == 5
    assert report["summary"]["error"] == 1
    assert report["summary"]["not_verified"] == 4
    assert report["summary"]["passed"] == 0

    findings = {
        finding["check_id"]: finding
        for finding in report["findings"]
    }

    assert findings["https_connection"]["status"] == "error"

    for check_id in (
        "header_hsts",
        "header_csp",
        "header_x_content_type_options",
        "header_x_frame_options",
    ):
        assert findings[check_id]["status"] == "not_verified"


def test_scan_returns_report(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    resolved = object()

    expected_report = {
        "target_url": "https://example.com",
        "http_status": None,
        "summary": {
            "total": 1,
            "passed": 0,
            "warning": 0,
            "not_verified": 1,
            "error": 0,
            "skipped": 0,
        },
        "findings": [
            {
                "check_id": "header_hsts",
                "status": "not_verified",
                "evidence": "Connection could not be established.",
            }
        ],
        "limitations": [],
    }

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: resolved
    )

    captured = {}

    def fake_scan(url, resolved_target=None, deadline=None):
        captured["url"] = url
        captured["resolved_target"] = resolved_target
        return expected_report

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json == expected_report
    assert response.json["findings"][0]["status"] == "not_verified"
    assert response.json["summary"]["not_verified"] == 1
    assert response.json["summary"]["total"] == 1
    assert captured["url"] == "https://example.com"
    assert captured["resolved_target"] is resolved


def test_scan_resolves_target_once_and_passes_result(monkeypatch):
    """يجب تمرير نتيجة التحقق نفسها إلى محرك الفحص."""
    app = api_module.create_app()
    client = app.test_client()

    target_url = "https://example.com"
    resolved = object()
    resolution_calls = []

    def fake_resolve(url, deadline=None):
        resolution_calls.append(url)
        return resolved

    def fake_scan(url, resolved_target=None, deadline=None):
        assert url == target_url
        assert resolved_target is resolved
        return {"status": "completed"}

    monkeypatch.setattr(api_module, "resolve_target", fake_resolve)
    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": target_url,
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert resolution_calls == [target_url]


def test_scan_hides_internal_error(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    def fail_scan(url, resolved_target=None, deadline=None):
        raise RuntimeError("private internal details")

    monkeypatch.setattr(api_module, "scan_target", fail_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 500
    assert response.json["error"]["code"] == "INTERNAL_ERROR"
    assert "private internal details" not in response.get_data(
        as_text=True
    )


def test_scan_does_not_log_sensitive_target_url(monkeypatch, caplog):
    """التأكد من عدم تسجيل معاملات URL الحساسة عند حدوث خطأ."""
    app = api_module.create_app()
    client = app.test_client()

    target_url = (
        "https://example.com/scan"
        "?access_token=secret-log-token"
    )

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    scan_calls = []

    def fail_scan(url, resolved_target=None, deadline=None):
        scan_calls.append((url, resolved_target, deadline))
        raise RuntimeError(
            f"Simulated failure for target: {url}"
        )

    monkeypatch.setattr(api_module, "scan_target", fail_scan)

    with caplog.at_level(logging.ERROR, logger=app.logger.name):
        response = client.post(
            "/api/v1/scan",
            json={
                "target_url": target_url,
                "authorization_confirmed": True,
            },
        )

    assert response.status_code == 500
    assert len(scan_calls) == 1
    assert scan_calls[0][0] == target_url
    assert scan_calls[0][2] is not None
    assert "Scan request failed; exception details omitted." in caplog.text
    assert response.json["error"]["code"] == "INTERNAL_ERROR"
    assert "secret-log-token" not in caplog.text
    assert "access_token=" not in caplog.text
    assert "Simulated failure for target" not in caplog.text

def test_scan_rejects_request_when_capacity_is_full(monkeypatch):
    """رفض بدء فحص جديد عند امتلاء السعة المتاحة."""

    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "_SCAN_SLOTS",
        BoundedSemaphore(0),
    )

    def unexpected_resolve(url):
        raise AssertionError(
            "لا يجب بدء التحقق من الهدف عند امتلاء السعة"
        )

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        unexpected_resolve,
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 503
    assert (
        response.json["error"]["code"]
        == "SCAN_CAPACITY_EXCEEDED"
    )
def test_scan_returns_504_when_deadline_expires_during_resolution(
    monkeypatch,
):
    app = api_module.create_app()
    client = app.test_client()

    clock = iter((99.0, 100.0, 126.0))
    monkeypatch.setattr(
        api_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock)),
    )

    def fake_resolve(url, deadline=None):
        assert url == "https://example.com"
        assert deadline == 125.0
        return None

    monkeypatch.setattr(api_module, "resolve_target", fake_resolve)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 504
    assert response.get_json()["error"]["code"] == "SCAN_TIMEOUT"


def test_scan_returns_504_when_deadline_expires_during_scan(
    monkeypatch,
):
    app = api_module.create_app()
    client = app.test_client()

    clock = iter((99.0, 100.0, 126.0))
    monkeypatch.setattr(
        api_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock)),
    )

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    def fake_scan(url, resolved_target=None, deadline=None):
        assert url == "https://example.com"
        assert resolved_target is not None
        assert deadline == 125.0
        return {"status": "completed"}

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 504
    assert response.get_json()["error"]["code"] == "SCAN_TIMEOUT"

def test_scan_rate_limit_returns_429_without_starting_extra_scan(
    monkeypatch,
):
    app = api_module.create_app()
    client = app.test_client()

    scan_calls = []

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    def fake_scan(url, resolved_target=None, deadline=None):
        scan_calls.append(url)
        return {"status": "completed"}

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    for _ in range(5):
        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 200

    response = client.post("/api/v1/scan", json=payload)

    assert response.status_code == 429
    assert response.get_json()["error"]["code"] == (
        "RATE_LIMIT_EXCEEDED"
    )
    assert len(scan_calls) == 5

def test_scan_rate_limit_resets_after_sixty_seconds(monkeypatch):
    from types import SimpleNamespace

    app = api_module.create_app()
    client = app.test_client()

    clock = {"now": 1000.0}

    monkeypatch.setattr(
        api_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock["now"]),
    )

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )
    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url, resolved_target=None, deadline=None: {
            "status": "completed"
        },
    )

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    for _ in range(5):
        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 200

    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 429

    # تجاوز نافذة الستين ثانية.
    clock["now"] = 1061.0

    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200


def test_scan_rate_limit_is_independent_per_source(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )
    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url, resolved_target=None, deadline=None: {
            "status": "completed"
        },
    )

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    source_a = "198.51.100.10"
    source_b = "198.51.100.20"

    for _ in range(5):
        response = client.post(
            "/api/v1/scan",
            json=payload,
            environ_overrides={"REMOTE_ADDR": source_a},
        )
        assert response.status_code == 200

    # المصدر A تجاوز الحد.
    response = client.post(
        "/api/v1/scan",
        json=payload,
        environ_overrides={"REMOTE_ADDR": source_a},
    )
    assert response.status_code == 429

    # المصدر B لديه حد مستقل.
    response = client.post(
        "/api/v1/scan",
        json=payload,
        environ_overrides={"REMOTE_ADDR": source_b},
    )
    assert response.status_code == 200


def test_scan_rate_limit_rejects_new_sources_when_table_is_full(
    monkeypatch,
):
    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "_SCAN_RATE_LIMIT_MAX_SOURCES",
        1,
    )
    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )
    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url, resolved_target=None, deadline=None: {
            "status": "completed"
        },
    )

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    response = client.post(
        "/api/v1/scan",
        json=payload,
        environ_overrides={"REMOTE_ADDR": "198.51.100.10"},
    )
    assert response.status_code == 200

    # لا يسمح بإضافة مصدر جديد عندما يمتلئ الجدول.
    response = client.post(
        "/api/v1/scan",
        json=payload,
        environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert response.status_code == 429
    assert response.get_json()["error"]["code"] == (
        "RATE_LIMIT_EXCEEDED"
    )

    # المصدر الموجود مسبقًا يظل قادرًا على استخدام حصته.
    response = client.post(
        "/api/v1/scan",
        json=payload,
        environ_overrides={"REMOTE_ADDR": "198.51.100.10"},
    )
    assert response.status_code == 200

def test_scan_capacity_is_released_after_scanner_exception(
    monkeypatch,
):
    app = api_module.create_app()
    client = app.test_client()

    scan_calls = []

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    def fake_scan(url, resolved_target=None, deadline=None):
        scan_calls.append(url)

        if len(scan_calls) == 1:
            raise RuntimeError("Simulated scanner failure")

        return {"status": "completed"}

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    first = client.post("/api/v1/scan", json=payload)
    assert first.status_code == 500

    second = client.post("/api/v1/scan", json=payload)
    assert second.status_code == 200

    assert len(scan_calls) == 2

def test_scan_returns_504_when_deadline_expires_after_valid_resolution(
    monkeypatch,
):
    app = api_module.create_app()
    client = app.test_client()

    # الطلب يبدأ عند 99، والمهلة تنتهي عند 125.
    # يعود DNS بعنوان صالح عند الزمن 126.
    clock = iter((99.0, 100.0, 126.0))

    monkeypatch.setattr(
        api_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock)),
    )

    resolved_target = (
        "parsed",
        "example.com",
        ["93.184.216.34"],
    )

    def fake_resolve(url, deadline=None):
        assert url == "https://example.com"
        assert deadline == 125.0
        return resolved_target

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        fake_resolve,
    )

    scan_calls = []

    def fake_scan(*args, **kwargs):
        scan_calls.append((args, kwargs))
        return {}

    monkeypatch.setattr(
        api_module,
        "scan_target",
        fake_scan,
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 504
    assert response.get_json()["error"]["code"] == "SCAN_TIMEOUT"
    assert scan_calls == []

def test_scan_rejects_non_json_content_type():
    app = api_module.create_app()
    client = app.test_client()

    response = client.post(
        "/api/v1/scan",
        data='{"target_url":"https://example.com","authorization_confirmed":true}',
        content_type="text/plain",
    )

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_REQUEST"

def test_scan_rate_limit_ignores_untrusted_forwarded_for(monkeypatch):
    """Untrusted X-Forwarded-For must not bypass the source rate limit."""

    app = api_module.create_app()
    client = app.test_client()
    scan_calls = []

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    def fake_scan(url, resolved_target=None, deadline=None):
        scan_calls.append(url)
        return {"status": "completed"}

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }
    source = "198.51.100.30"

    for index in range(5):
        response = client.post(
            "/api/v1/scan",
            json=payload,
            environ_overrides={"REMOTE_ADDR": source},
            headers={"X-Forwarded-For": f"203.0.113.{index + 1}"},
        )
        assert response.status_code == 200

    response = client.post(
        "/api/v1/scan",
        json=payload,
        environ_overrides={"REMOTE_ADDR": source},
        headers={"X-Forwarded-For": "203.0.113.99"},
    )

    assert response.status_code == 429
    assert response.json["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert len(scan_calls) == 5

def test_scan_requires_authorization_before_target_resolution(monkeypatch):
    """Reject unconfirmed scans before DNS resolution or scanner execution."""

    app = api_module.create_app()
    client = app.test_client()
    calls = {"resolve": 0, "scan": 0}

    def fake_resolve(url, deadline=None):
        calls["resolve"] += 1
        return object()

    def fake_scan(url, resolved_target=None, deadline=None):
        calls["scan"] += 1
        return {"status": "completed"}

    monkeypatch.setattr(api_module, "resolve_target", fake_resolve)
    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": False,
        },
    )

    assert response.status_code == 403
    assert response.json["error"]["code"] == "AUTHORIZATION_REQUIRED"
    assert calls == {"resolve": 0, "scan": 0}

def test_scan_rate_limit_reclaims_expired_source_slots(monkeypatch):
    """Expired source records must not block new sources."""

    app = api_module.create_app()
    client = app.test_client()
    clock = {"now": 1000.0}

    monkeypatch.setattr(
        api_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock["now"]),
    )
    monkeypatch.setattr(
        api_module,
        "_SCAN_RATE_LIMIT_MAX_SOURCES",
        1,
    )
    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )
    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url, resolved_target=None, deadline=None: {
            "status": "completed"
        },
    )

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    first = client.post(
        "/api/v1/scan",
        json=payload,
        environ_overrides={"REMOTE_ADDR": "198.51.100.30"},
    )
    assert first.status_code == 200

    clock["now"] = 1061.0

    second = client.post(
        "/api/v1/scan",
        json=payload,
        environ_overrides={"REMOTE_ADDR": "198.51.100.31"},
    )

    assert second.status_code == 200

def test_scan_accepts_url_at_maximum_length(monkeypatch):
    """Accept a URL whose length is exactly the configured maximum."""

    app = api_module.create_app()
    client = app.test_client()

    target_url = "https://example.com/" + (
        "a" * (2048 - len("https://example.com/"))
    )

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )
    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url, resolved_target=None, deadline=None: {
            "status": "completed"
        },
    )

    assert len(target_url) == 2048

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": target_url,
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200

def test_scan_capacity_is_released_after_resolution_exception(
    monkeypatch,
):
    app = api_module.create_app()
    client = app.test_client()

    resolution_calls = []

    def fake_resolve(url, deadline=None):
        resolution_calls.append(url)

        if len(resolution_calls) == 1:
            raise RuntimeError("Simulated resolution failure")

        return object()

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        fake_resolve,
    )

    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url, resolved_target=None, deadline=None: {
            "status": "completed"
        },
    )

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    first = client.post("/api/v1/scan", json=payload)
    assert first.status_code == 500
    assert first.json["error"]["code"] == "INTERNAL_ERROR"

    second = client.post("/api/v1/scan", json=payload)
    assert second.status_code == 200

    assert len(resolution_calls) == 2

def test_scan_rejects_empty_json_body(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    def fail_if_called(*args, **kwargs):
        pytest.fail("Target resolution or scanning must not run")

    monkeypatch.setattr(api_module, "resolve_target", fail_if_called)
    monkeypatch.setattr(api_module, "scan_target", fail_if_called)

    response = client.post(
        "/api/v1/scan",
        data="",
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_REQUEST"

def test_scan_rejects_numeric_authorization_value(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    def fail_if_called(*args, **kwargs):
        pytest.fail("Target resolution or scanning must not run")

    monkeypatch.setattr(api_module, "resolve_target", fail_if_called)
    monkeypatch.setattr(api_module, "scan_target", fail_if_called)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": 1,
        },
    )

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_REQUEST"

def test_scan_releases_capacity_after_resolution_timeout(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    clock = iter((99.0, 100.0, 126.0, 127.0, 128.0, 129.0, 130.0))
    monkeypatch.setattr(
        api_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock)),
    )
    monkeypatch.setattr(
        api_module,
        "_SCAN_SLOTS",
        BoundedSemaphore(1),
    )

    resolved_target = (
        "parsed",
        "example.com",
        ["93.184.216.34"],
    )

    resolution_calls = []

    def fake_resolve(url, deadline=None):
        resolution_calls.append(url)
        return resolved_target

    monkeypatch.setattr(api_module, "resolve_target", fake_resolve)

    scan_calls = []

    def fake_scan(*args, **kwargs):
        scan_calls.append((args, kwargs))
        return {}

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }
    request_options = {"environ_overrides": {"REMOTE_ADDR": "198.51.100.77"}}

    first = client.post(
        "/api/v1/scan",
        json=payload,
        **request_options,
    )
    assert first.status_code == 504
    assert first.json["error"]["code"] == "SCAN_TIMEOUT"

    second = client.post(
        "/api/v1/scan",
        json=payload,
        **request_options,
    )
    assert second.status_code == 200

    assert len(resolution_calls) == 2
    assert len(scan_calls) == 1

def test_scan_releases_capacity_after_scan_timeout(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    clock = iter((99.0, 100.0, 101.0, 126.0, 127.0, 128.0, 129.0, 130.0))
    monkeypatch.setattr(
        api_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock)),
    )
    monkeypatch.setattr(
        api_module,
        "_SCAN_SLOTS",
        BoundedSemaphore(1),
    )

    resolved_target = (
        "parsed",
        "example.com",
        ["93.184.216.34"],
    )

    resolution_calls = []

    def fake_resolve(url, deadline=None):
        resolution_calls.append(url)
        return resolved_target

    monkeypatch.setattr(api_module, "resolve_target", fake_resolve)

    scan_calls = []

    def fake_scan(url, resolved_target=None, deadline=None):
        scan_calls.append((url, resolved_target, deadline))
        return {"status": "completed"}

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }
    request_options = {"environ_overrides": {"REMOTE_ADDR": "198.51.100.78"}}

    first = client.post(
        "/api/v1/scan",
        json=payload,
        **request_options,
    )
    assert first.status_code == 504
    assert first.json["error"]["code"] == "SCAN_TIMEOUT"
    assert len(scan_calls) == 1

    second = client.post(
        "/api/v1/scan",
        json=payload,
        **request_options,
    )
    assert second.status_code == 200

    assert len(resolution_calls) == 2
    assert len(scan_calls) == 2
def test_scan_does_not_start_scanner_for_disallowed_target(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    scan_calls = []

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: None,
    )

    def fake_scan(*args, **kwargs):
        scan_calls.append((args, kwargs))
        return {"status": "completed"}

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 403
    assert response.json["error"]["code"] == "TARGET_NOT_ALLOWED"
    assert scan_calls == []
def test_scan_releases_capacity_after_report_serialization_error(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "_SCAN_SLOTS",
        BoundedSemaphore(1),
    )
    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    scan_calls = []

    def fake_scan(url, resolved_target=None, deadline=None):
        scan_calls.append(url)

        if len(scan_calls) == 1:
            return {"invalid": object()}

        return {"status": "completed"}

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    first = client.post("/api/v1/scan", json=payload)
    assert first.status_code == 500
    assert first.json["error"]["code"] == "INTERNAL_ERROR"

    second = client.post("/api/v1/scan", json=payload)
    assert second.status_code == 200

    assert len(scan_calls) == 2
def test_health_rejects_unsupported_method_with_json():
    app = api_module.create_app()
    client = app.test_client()

    response = client.post("/api/v1/health")

    assert response.status_code == 405
    assert "GET" in response.headers.get("Allow", "")
    assert response.json["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert response.json["error"]["message"]
def test_scan_rate_limit_expires_at_exactly_sixty_seconds(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    clock = {"now": 1000.0}
    monkeypatch.setattr(
        api_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock["now"]),
    )
    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )
    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url, resolved_target=None, deadline=None: {
            "status": "completed"
        },
    )

    payload = {
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }

    for _ in range(5):
        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 200

    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 429

    clock["now"] = 1060.0
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200


def test_scan_options_does_not_start_scan(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    calls = []

    def unexpected_call(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("OPTIONS must not start a scan")

    monkeypatch.setattr(api_module, "resolve_target", unexpected_call)
    monkeypatch.setattr(api_module, "scan_target", unexpected_call)

    response = client.options("/api/v1/scan")

    assert response.status_code == 200
    assert "POST" in response.headers.get("Allow", "")
    assert "OPTIONS" in response.headers.get("Allow", "")
    assert calls == []

def test_scan_cors_allows_localhost_preflight(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    calls = []

    def unexpected_call(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("CORS preflight must not start a scan")

    monkeypatch.setattr(api_module, "resolve_target", unexpected_call)
    monkeypatch.setattr(api_module, "scan_target", unexpected_call)

    origin = "http://localhost:5173"

    response = client.options(
        "/api/v1/scan",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == origin
    assert "POST" in response.headers.get("Access-Control-Allow-Methods", "")
    assert "content-type" in response.headers.get(
        "Access-Control-Allow-Headers", ""
    ).lower()
    assert calls == []


def test_scan_cors_allows_localhost_post(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    expected_report = {
        "status": "completed",
        "target_url": "https://example.com",
        "summary": {"total": 0},
        "findings": [],
    }

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )
    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url, resolved_target=None, deadline=None: expected_report,
    )

    origin = "http://localhost:5173"

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
        headers={"Origin": origin},
    )

    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == origin
    assert response.json == expected_report

def test_scan_cors_rejects_unallowed_origin():
    app = api_module.create_app()
    client = app.test_client()

    response = client.options(
        "/api/v1/scan",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )

    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers


def test_unhandled_internal_server_error_returns_safe_json():
    from flask import abort

    app = api_module.create_app()

    @app.get("/_test/internal-error")
    def trigger_internal_error():
        abort(500, description="private internal details")

    client = app.test_client()
    response = client.get("/_test/internal-error")

    assert response.status_code == 500
    assert response.is_json
    assert response.json["error"]["code"] == "INTERNAL_ERROR"
    assert response.json["error"]["message"]
    assert "private internal details" not in response.get_data(
        as_text=True
    )


def test_scan_can_request_expanded_checks(monkeypatch):
    """Preserve the documented expanded correlation metadata unchanged."""
    app = api_module.create_app()
    client = app.test_client()
    resolved = object()
    captured = {}
    correlation = {
        "correlation_id": "cookie_defense_gaps",
        "contributing_check_ids": ["cookie_secure", "cookie_httponly"],
        "severity": "low",
        "confidence": "low",
        "explanation": "Two independent cookie observations need review.",
        "recommendation": "Review Secure and HttpOnly for the observed cookies.",
        "rules_version": "2.0.0",
        "rule_version": "1",
        "limitations": ["This context does not establish an exploit chain."],
    }
    findings = (
        [{"check_id": "cookie_secure"}, {"check_id": "cookie_httponly"}]
        + [{}] * 22
    )
    engine_report = {
        "status": "completed",
        "summary": {"total": len(findings)},
        "findings": findings,
        "correlations": [correlation],
        "correlation_rules_version": "2.0.0",
    }

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: resolved,
    )

    def fake_scan(url, resolved_target=None, deadline=None,
                  include_expanded_checks=False):
        captured["include_expanded_checks"] = include_expanded_checks
        captured["resolved_target"] = resolved_target
        return engine_report

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": True,
        },
    )

    assert response.status_code == 200
    assert captured["include_expanded_checks"] is True
    assert captured["resolved_target"] is resolved
    report = response.get_json()
    assert report == engine_report
    assert report["correlation_rules_version"] == "2.0.0"
    assert report["correlations"] == [correlation]
    assert report["correlations"][0]["rules_version"] == (
        report["correlation_rules_version"]
    )
    # Correlations are context, not findings, and do not change summary totals.
    assert report["summary"]["total"] == len(report["findings"]) == 24


def test_scan_expanded_report_keeps_empty_correlations_and_version(
    monkeypatch,
):
    """Expanded mode includes correlation metadata even when no rule matches."""
    app = api_module.create_app()
    client = app.test_client()
    captured = {}
    engine_report = {
        "status": "completed",
        "summary": {"total": 5},
        "findings": [{}] * 5,
        "correlations": [],
        "correlation_rules_version": "2.0.0",
    }

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    def fake_scan(url, resolved_target=None, deadline=None,
                  include_expanded_checks=False):
        captured["include_expanded_checks"] = include_expanded_checks
        return engine_report

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": True,
        },
    )

    assert response.status_code == 200
    assert captured["include_expanded_checks"] is True
    assert response.get_json() == engine_report
    assert response.json["correlations"] == []
    assert response.json["correlation_rules_version"] == "2.0.0"


def test_scan_api_returns_correlation_generated_by_real_report_engine(
    monkeypatch,
):
    """Exercise Flask -> backend adapter -> real report/correlation engine."""

    from security_scanner.checks.result import CheckResult

    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    def fake_get_response(
        url,
        resolved_target=None,
        deadline=None,
        tls_metadata=None,
        redirect_dns_answers=None,
        validated_target_capture=None,
        cookie_evidence_capture=None,
        access_evidence_capture=None,
        disclosure_evidence_capture=None,
    ):
        # Simulate parsed attributes only; raw cookie names/values are never
        # passed into the report engine or its findings.
        if cookie_evidence_capture is not None:
            cookie_evidence_capture.update(
                available=True,
                observations=((False, False, "missing"),),
            )
        if access_evidence_capture is not None:
            access_evidence_capture.update(
                available=True,
                location_values=(),
            )
        if disclosure_evidence_capture is not None:
            disclosure_evidence_capture.clear()
        return 200, headers, None

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        fake_get_response,
    )

    def dns_result(check_id, title):
        return CheckResult(
            check_id=check_id,
            title=title,
            status="skipped",
            severity="info",
            confidence="low",
            evidence="DNS evaluation was isolated in this API integration test.",
            explanation="No DNS security conclusion is inferred by this fixture.",
            recommendation="Run the dedicated DNS evaluator tests.",
            limitations=("This result is specific to the isolated test fixture.",),
        )

    monkeypatch.setattr(
        "security_scanner.report.evaluate_spf_domain",
        lambda domain, deadline=None: dns_result("dns_spf", "SPF"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dmarc_domain",
        lambda domain, deadline=None: dns_result("dns_dmarc", "DMARC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_dnssec_domain",
        lambda domain, deadline=None: dns_result("dnssec", "DNSSEC"),
    )
    monkeypatch.setattr(
        "security_scanner.report.evaluate_takeover_domain",
        lambda hostname, deadline=None: dns_result(
            "subdomain_takeover_indicators",
            "Passive takeover indicators",
        ),
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": True,
        },
    )

    assert response.status_code == 200
    report = response.get_json()

    assert report["status"] == "completed"
    assert len(report["findings"]) == report["summary"]["total"]
    assert report["summary"]["total"] == 30

    findings_by_id = {
        finding["check_id"]: finding
        for finding in report["findings"]
    }
    week2_check_ids = {
        "tls_certificate_expiry",
        "tls_certificate_chain",
        "tls_protocol_config",
        "http_to_https_redirect",
        "redirect_destination_safety",
        "header_referrer_policy",
        "header_permissions_policy",
    }
    assert week2_check_ids.issubset(findings_by_id)
    required_finding_fields = {
        "check_id",
        "title",
        "status",
        "severity",
        "confidence",
        "evidence",
        "explanation",
        "recommendation",
        "limitations",
    }
    for check_id in week2_check_ids:
        finding = findings_by_id[check_id]
        assert required_finding_fields.issubset(finding)
        assert finding["status"] in {
            "passed", "warning", "not_verified", "error", "skipped"
        }
        assert isinstance(finding["limitations"], list)

    assert findings_by_id["cookie_secure"]["status"] == "warning"
    assert findings_by_id["cookie_httponly"]["status"] == "warning"

    assert report["correlation_rules_version"] == "2.0.0"
    assert len(report["correlations"]) == 1
    correlation = report["correlations"][0]
    assert correlation["correlation_id"] == "cookie_defense_gaps"
    assert correlation["contributing_check_ids"] == [
        "cookie_secure",
        "cookie_httponly",
    ]
    assert correlation["rules_version"] == report["correlation_rules_version"]
    assert "limitations" in correlation
    assert report["summary"]["total"] == len(report["findings"])


def test_scan_base_mode_omits_correlation_metadata(monkeypatch):
    """Base mode does not expose expanded-only correlation metadata."""
    app = api_module.create_app()
    client = app.test_client()
    captured = {}
    base_report = {
        "status": "completed",
        "summary": {"total": 1},
        "findings": [{"check_id": "https_connection"}],
    }

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: object(),
    )

    def fake_scan(url, resolved_target=None, deadline=None,
                  include_expanded_checks=False):
        captured["include_expanded_checks"] = include_expanded_checks
        return base_report

    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert captured["include_expanded_checks"] is False
    assert response.get_json() == base_report
    assert "correlations" not in response.json
    assert "correlation_rules_version" not in response.json



def test_scan_rejects_non_boolean_expanded_option():
    """رفض قيمة include_expanded_checks إذا لم تكن Boolean."""
    app = api_module.create_app()
    client = app.test_client()

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "include_expanded_checks": "true",
        },
    )

    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_REQUEST"

@pytest.mark.parametrize(
    ("resolution_error", "expected_status", "expected_code"),
    [
        ("invalid", 403, "TARGET_NOT_ALLOWED"),
        ("not_allowed", 403, "TARGET_NOT_ALLOWED"),
        ("dns_error", 502, "DNS_RESOLUTION_FAILED"),
        ("dns_timeout", 504, "DNS_TIMEOUT"),
        ("dns_capacity", 503, "DNS_CAPACITY_EXCEEDED"),
        ("timeout", 504, "SCAN_TIMEOUT"),
    ],
)
def test_scan_maps_detailed_resolution_errors_to_api_responses(
    monkeypatch,
    resolution_error,
    expected_status,
    expected_code,
):
    """تحويل حالات المحرك التفصيلية إلى استجابات API مستقرة وآمنة."""

    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "resolve_target",
        lambda url, deadline=None: (None, resolution_error),
    )

    def unexpected_scan(*args, **kwargs):
        raise AssertionError(
            "يجب ألا يبدأ الفحص عندما يفشل التحقق من الهدف"
        )

    monkeypatch.setattr(api_module, "scan_target", unexpected_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == expected_status
    assert response.is_json
    assert response.json["error"]["code"] == expected_code
    assert response.json["error"]["message"]


def test_scan_passes_detailed_resolved_target_to_engine(monkeypatch):
    """تمرير نتيجة التحقق التفصيلية نفسها للمحرك دون إعادة DNS."""

    app = api_module.create_app()
    client = app.test_client()

    target_url = "https://example.com"
    resolved = object()
    resolution_calls = []

    def fake_resolve(url, deadline=None):
        resolution_calls.append((url, deadline))
        return resolved, None

    captured = {}

    def fake_scan(url, resolved_target=None, deadline=None):
        captured["url"] = url
        captured["resolved_target"] = resolved_target
        captured["deadline"] = deadline
        return {"status": "completed"}

    monkeypatch.setattr(api_module, "resolve_target", fake_resolve)
    monkeypatch.setattr(api_module, "scan_target", fake_scan)

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": target_url,
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert len(resolution_calls) == 1
    assert resolution_calls[0][0] == target_url
    assert captured["url"] == target_url
    assert captured["resolved_target"] is resolved
    assert captured["deadline"] == resolution_calls[0][1]

