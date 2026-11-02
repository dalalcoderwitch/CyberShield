from uuid import UUID

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
        assert required_fields.issubset(finding.keys())
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
    assert "default-src 'self'" in csp_finding["evidence"]
    assert "مفقودة" not in csp_finding["evidence"]

    assert isinstance(report["limitations"], list)
    assert report["limitations"]
    assert report["scanned_at"]
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