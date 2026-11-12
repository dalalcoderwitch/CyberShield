from uuid import UUID

import pytest

from security_scanner.report import scan_target


def test_scan_target_returns_complete_report(monkeypatch):
    """التحقق من بنية التقرير وحقوله الأساسية."""

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (200, headers, None),
    )

    report = scan_target("https://example.com")

    assert report["target_url"] == "https://example.com"
    assert report["http_status"] == 200
    assert report["status"] == "completed"
    assert report["engine_version"] == "1.0.0"
    assert report["notice"]

    parsed_scan_id = UUID(report["scan_id"])
    assert str(parsed_scan_id) == report["scan_id"]

    assert len(report["findings"]) == 5
    assert report["summary"]["total"] == 5
    assert report["summary"]["passed"] == 4
    assert report["summary"]["warning"] == 1
    assert report["summary"]["not_verified"] == 0
    assert report["summary"]["error"] == 0
    assert report["summary"]["skipped"] == 0

    summary_statuses = (
        "passed",
        "warning",
        "not_verified",
        "error",
        "skipped",
    )
    expected_summary = {
        status: sum(
            finding["status"] == status
            for finding in report["findings"]
        )
        for status in summary_statuses
    }
    expected_summary["total"] = len(report["findings"])
    assert report["summary"] == expected_summary

    expected_ids = {
        "https_connection",
        "header_hsts",
        "header_csp",
        "header_x_content_type_options",
        "header_x_frame_options",
    }

    actual_ids = {
        finding["check_id"]
        for finding in report["findings"]
    }

    assert len(actual_ids) == len(report["findings"]), (
        "Duplicate check_id values found in report findings."
    )
    assert actual_ids == expected_ids

    expected_statuses = {
        "https_connection": "passed",
        "header_hsts": "passed",
        "header_csp": "warning",
        "header_x_content_type_options": "passed",
        "header_x_frame_options": "passed",
    }

    expected_metadata = {
        "https_connection": ("info", "high"),
        "header_hsts": ("info", "high"),
        "header_csp": ("medium", "medium"),
        "header_x_content_type_options": ("info", "high"),
        "header_x_frame_options": ("info", "high"),
    }

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

    for finding in report["findings"]:
        assert set(finding.keys()) == required_fields

        string_fields = (
            "check_id",
            "title",
            "status",
            "severity",
            "confidence",
            "evidence",
            "explanation",
            "recommendation",
        )
        for field in string_fields:
            assert isinstance(finding[field], str)

        assert isinstance(finding["limitations"], list)
        assert all(
            isinstance(item, str)
            for item in finding["limitations"]
        )

        assert finding["status"] in {
            "passed", "warning", "not_verified", "error", "skipped"
        }
        assert finding["severity"] in {"info", "low", "medium", "high"}
        assert finding["confidence"] in {"low", "medium", "high"}
        assert finding["status"] == expected_statuses[finding["check_id"]]
        assert (
            finding["severity"],
            finding["confidence"],
        ) == expected_metadata[finding["check_id"]]
        assert finding["title"]
        assert finding["evidence"]
        assert finding["explanation"]
        assert finding["recommendation"]
        assert isinstance(finding["limitations"], list)
        assert finding["limitations"]

    csp_finding = next(
        finding
        for finding in report["findings"]
        if finding["check_id"] == "header_csp"
    )

    assert csp_finding["severity"] == "medium"
    assert csp_finding["confidence"] == "medium"
    assert "Content-Security-Policy" in csp_finding["evidence"]
    assert "default-src 'self'" not in csp_finding["evidence"]
    assert isinstance(report["limitations"], list)
    assert report["limitations"]
    assert report["scanned_at"]



def test_expanded_report_evaluates_tls_metadata_from_scanner_connection(monkeypatch):
    def fake_safe_get_response(
        url,
        tls_metadata=None,
        validated_target_capture=None,
        cookie_evidence_capture=None,
        access_evidence_capture=None,
        disclosure_evidence_capture=None,
    ):
        assert url == "https://example.com"
        tls_metadata.update({
            "version": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "not_before": "Jan 01 00:00:00 2020 GMT",
            "not_after": "Jan 01 00:00:00 2099 GMT",
            "chain_available": True,
        })
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url)
        validated_target_capture["target"] = (parsed, "example.com", ["93.184.216.34"])
        cookie_evidence_capture.update(available=True, observations=())
        access_evidence_capture.update(available=True, location_values=("https://redirect.example/path",))
        disclosure_evidence_capture.update(header_available=True, sample=b"", sample_complete=False)
        return 302, {"Location": "https://redirect.example/path"}, None

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        fake_safe_get_response,
    )
    def fake_http_probe(target, deadline=None, capture=None):
        capture.update(status=302, location="https://redirect.example/path",
                       request_url="http://93.184.216.34:80/")
        return None
    monkeypatch.setattr("security_scanner.report._safe_http_redirect_probe", fake_http_probe)
    monkeypatch.setattr(
        "security_scanner.report._safe_cors_preflight",
        lambda target, deadline=None, capture=None: (capture.update(available=False, error="connection") or "connection"),
    )
    monkeypatch.setattr(
        "security_scanner.report._collect_disclosure_evidence",
        lambda target, original_status, original_capture, deadline=None: __import__(
            "security_scanner.checks.disclosure_evidence",
            fromlist=["DisclosureEvidence"],
        ).DisclosureEvidence(),
    )
    monkeypatch.setattr("security_scanner.report._resolve_redirect_location_addresses",
                        lambda destination, deadline=None: ("93.184.216.34", "10.0.0.8"))

    from security_scanner.checks.result import CheckResult

    monkeypatch.setattr(
        "security_scanner.report.evaluate_spf_domain",
        lambda domain, deadline=None: CheckResult(
            check_id="dns_spf",
            title="SPF test",
            status="not_verified",
            severity="info",
            confidence="low",
            evidence="Synthetic test evidence.",
            explanation="No live DNS query in this test.",
            recommendation="Test only.",
            limitations=("Test only.",),
        ),
    )

    report = scan_target("https://example.com", include_expanded_checks=True)
    findings = {item["check_id"]: item for item in report["findings"]}

    assert findings["tls_protocol_config"]["status"] == "passed"
    assert "TLSv1.3" in findings["tls_protocol_config"]["evidence"]
    assert findings["tls_certificate_expiry"]["status"] == "passed"
    assert findings["tls_certificate_chain"]["status"] == "passed"
    assert findings["http_to_https_redirect"]["status"] == "passed"
    assert findings["redirect_destination_safety"]["status"] == "warning"
    assert "10.0.0.8" not in repr(findings)
    assert "BEGIN CERTIFICATE" not in repr(findings)


def test_failed_connection_does_not_mark_headers_passed(
    monkeypatch,
):
    """تعذر الاتصال لا يعني نجاح الترويسات أو غيابها."""

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (None, {}, "tls"),
    )

    report = scan_target("https://example.com")

    assert report["http_status"] is None
    assert report["status"] == "completed"
    assert report["summary"]["total"] == 5
    assert report["summary"]["warning"] == 1
    assert report["summary"]["not_verified"] == 4
    assert report["summary"]["passed"] == 0

    https_finding = next(
        finding
        for finding in report["findings"]
        if finding["check_id"] == "https_connection"
    )

    assert https_finding["status"] == "warning"
    assert https_finding["severity"] == "medium"
    assert https_finding["confidence"] == "high"

    header_findings = [
        finding
        for finding in report["findings"]
        if finding["check_id"].startswith("header_")
    ]

    assert len(header_findings) == 4

    for finding in header_findings:
        assert finding["status"] == "not_verified"
        assert finding["severity"] == "info"
        assert finding["confidence"] == "low"
        assert isinstance(finding["limitations"], list)
        assert finding["limitations"]

    assert isinstance(report["limitations"], list)
    assert report["scan_id"]
    assert report["engine_version"]
    assert report["notice"]


def test_report_summary_matches_finding_statuses(monkeypatch):
    """التأكد من أن ملخص التقرير يطابق النتائج الفعلية."""

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (None, {}, "connection"),
    )

    report = scan_target("https://example.com")
    findings = report["findings"]
    summary = report["summary"]

    for status in (
        "passed",
        "warning",
        "not_verified",
        "error",
        "skipped",
    ):
        expected_count = sum(
            finding["status"] == status
            for finding in findings
        )

        assert summary[status] == expected_count

    assert summary["total"] == len(findings)


def test_shared_header_evidence_reaches_expanded_findings_and_summary(monkeypatch):
    """Exercise response-header to context, evaluator, finding and summary flow."""
    referrer_secret = "private-referrer-token"
    permissions_secret = "private-permissions-directive"
    response_headers = {
        "Referrer-Policy": f"strict-origin, {referrer_secret}",
        "Permissions-Policy": f"camera=(\"{permissions_secret}\")",
    }
    calls = []

    def fake_safe_get_response(url, **kwargs):
        calls.append((url, kwargs))
        return 200, response_headers, None

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        fake_safe_get_response,
    )

    report = scan_target(
        "https://example.com",
        include_expanded_checks=True,
    )
    findings = report["findings"]
    by_id = {item["check_id"]: item for item in findings}

    assert len(calls) == 1
    assert len(by_id) == len(findings)
    assert by_id["header_referrer_policy"]["status"] == "passed"
    assert by_id["header_permissions_policy"]["status"] == "warning"
    assert "لم تتم مقارنة هذه المصادر بأصل الهدف" in by_id["header_permissions_policy"]["explanation"]
    assert "قيمة معروفة ذات قيود مناسبة" in by_id["header_referrer_policy"]["evidence"]
    assert by_id["header_permissions_policy"]["severity"] == "info"
    assert referrer_secret not in repr(report)
    assert permissions_secret not in repr(report)

    for status in ("passed", "warning", "not_verified", "error", "skipped"):
        assert report["summary"][status] == sum(
            finding["status"] == status for finding in findings
        )
    assert report["summary"]["total"] == len(findings)


def test_report_redacts_path_query_and_fragment(monkeypatch):
    """التأكد من إخفاء المسار والاستعلام والجزء fragment."""

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (200, headers, None),
    )

    report = scan_target(
        "https://example.com/admin/reset-secret-token"
        "?access_token=secret-test-token"
        "#private-fragment"
    )

    assert report["target_url"] == "https://example.com"

    report_text = repr(report)

    assert "/admin/" not in report_text
    assert "reset-secret-token" not in report_text
    assert "secret-test-token" not in report_text
    assert "private-fragment" not in report_text
    assert "access_token=" not in report_text


def test_report_does_not_echo_invalid_target_url(monkeypatch):
    """الرابط غير الصالح لا يجب أن يظهر خامًا في التقرير."""

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (None, {}, "invalid"),
    )

    report = scan_target(
        "https://user:secret@example.com/admin?token=hidden"
    )

    assert report["target_url"] == "[invalid target URL]"

    report_text = repr(report)

    assert "secret" not in report_text
    assert "hidden" not in report_text
    assert "user:" not in report_text

def test_timeout_is_reported_without_false_success(monkeypatch):
    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (None, {}, "timeout"),
    )

    report = scan_target("https://example.com")
    findings = {
        item["check_id"]: item
        for item in report["findings"]
    }

    assert findings["https_connection"]["status"] == "error"
    assert findings["https_connection"]["severity"] == "medium"
    assert findings["https_connection"]["confidence"] == "high"
    assert "المهلة" in findings["https_connection"]["explanation"]
    assert report["summary"]["passed"] == 0

    for check_id in (
        "header_hsts",
        "header_csp",
        "header_x_content_type_options",
        "header_x_frame_options",
    ):
        assert findings[check_id]["status"] == "not_verified"
        assert findings[check_id]["severity"] == "info"
        assert findings[check_id]["confidence"] == "low"


@pytest.mark.parametrize(
    (
        "error",
        "expected_status",
        "expected_severity",
        "expected_confidence",
    ),
    [
        ("dns_timeout", "error", "info", "high"),
        ("dns_error", "error", "info", "high"),
        ("dns_capacity", "skipped", "info", "low"),
    ],
)
def test_dns_resolution_errors_are_reported_accurately(
    monkeypatch,
    error,
    expected_status,
    expected_severity,
    expected_confidence,
):
    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (None, {}, error),
    )

    report = scan_target("https://example.com")
    findings = {
        item["check_id"]: item
        for item in report["findings"]
    }

    https_finding = findings["https_connection"]

    assert https_finding["status"] == expected_status
    assert https_finding["severity"] == expected_severity
    assert https_finding["confidence"] == expected_confidence
    assert https_finding["evidence"].endswith(error + ".")

    if error == "dns_timeout":
        assert "\u0627\u0646\u062a\u0647\u062a" in https_finding["explanation"]
    elif error == "dns_error":
        assert "\u062a\u0639\u0630\u0631" in https_finding["explanation"]
    else:
        assert "\u0633\u0639\u0629 DNS" in https_finding["explanation"]

    for check_id in (
        "header_hsts",
        "header_csp",
        "header_x_content_type_options",
        "header_x_frame_options",
    ):
        assert findings[check_id]["status"] == "not_verified"

    assert report["http_status"] is None
    assert report["summary"][expected_status] == 1
    assert report["summary"]["not_verified"] == 4
    assert report["summary"]["passed"] == 0
    assert report["summary"]["total"] == 5

def test_report_does_not_expose_sensitive_header_values(monkeypatch):
    secret_nonce = "CYBERSHIELD_PRIVATE_NONCE_91"
    secret_token = "CYBERSHIELD_PRIVATE_REPORT_TOKEN_73"
    secret_cookie = "CYBERSHIELD_PRIVATE_SESSION_52"

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": (
            "default-src 'self'; "
            f"script-src 'nonce-{secret_nonce}'; "
            "report-uri "
            f"https://reports.example/collect?token={secret_token}"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Set-Cookie": f"session={secret_cookie}; Secure; HttpOnly",
    }

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (200, headers, None),
    )

    report = scan_target("https://example.com")
    report_text = repr(report)

    assert secret_nonce not in report_text
    assert secret_token not in report_text
    assert secret_cookie not in report_text
    assert "reports.example" not in report_text
    assert "Set-Cookie" not in report_text

    csp_finding = next(
        item for item in report["findings"]
        if item["check_id"] == "header_csp"
    )
    assert "Content-Security-Policy" in csp_finding["evidence"]

def test_scan_target_passes_resolved_target_and_deadline(monkeypatch):
    target_url = "https://example.com/security-check"
    resolved_target = object()
    deadline = 1234.5
    calls = []

    def fake_safe_get_response(
        url,
        resolved_target=None,
        deadline=None,
    ):
        calls.append({
            "url": url,
            "resolved_target": resolved_target,
            "deadline": deadline,
        })
        return 200, {}, None

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        fake_safe_get_response,
    )

    scan_target(
        target_url,
        resolved_target=resolved_target,
        deadline=deadline,
    )

    assert len(calls) == 1
    assert calls[0]["url"] == target_url
    assert calls[0]["resolved_target"] is resolved_target
    assert calls[0]["deadline"] == deadline

def test_report_does_not_read_unneeded_header_values(monkeypatch):
    class UnreadableHeaderValue:
        def __str__(self):
            raise AssertionError("Unneeded header value was accessed")

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Set-Cookie": UnreadableHeaderValue(),
    }

    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (200, headers, None),
    )

    report = scan_target("https://example.com")

    assert report["http_status"] == 200
    assert len(report["findings"]) == 5

@pytest.mark.parametrize(
    ("error", "expected_https_status"),
    [
        ("invalid", "warning"),
        ("not_allowed", "warning"),
        ("connection", "error"),
        ("unexpected_error", "error"),
    ],
)
def test_connection_errors_keep_headers_unverified(
    monkeypatch,
    error,
    expected_https_status,
):
    monkeypatch.setattr(
        "security_scanner.report._safe_get_response",
        lambda url: (None, {}, error),
    )

    report = scan_target("https://example.com")
    findings = {
        item["check_id"]: item
        for item in report["findings"]
    }

    https_finding = findings["https_connection"]
    assert https_finding["status"] == expected_https_status
    assert https_finding["severity"] == "medium"
    assert https_finding["confidence"] == "high"
    assert https_finding["evidence"].endswith(error + ".")
    assert report["http_status"] is None

    for check_id in (
        "header_hsts",
        "header_csp",
        "header_x_content_type_options",
        "header_x_frame_options",
    ):
        assert findings[check_id]["status"] == "not_verified"
        assert findings[check_id]["severity"] == "info"
        assert findings[check_id]["confidence"] == "low"

    assert report["summary"][expected_https_status] == 1
    assert report["summary"]["not_verified"] == 4
    assert report["summary"]["passed"] == 0
    assert report["summary"]["total"] == 5
