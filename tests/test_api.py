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


def test_scan_rejects_oversized_request():
    """إرجاع JSON موحد عندما يتجاوز جسم الطلب الحد المسموح."""

    app = api_module.create_app()
    client = app.test_client()

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "extra": "x" * 17000,
        },
    )

    assert response.status_code == 413
    assert response.json["error"]["code"] == "REQUEST_TOO_LARGE"


def test_scan_rejects_unsupported_method_with_json():
    """إرجاع 405 بصيغة JSON عند استخدام GET لمسار الفحص."""

    app = api_module.create_app()
    client = app.test_client()

    response = client.get("/api/v1/scan")

    assert response.status_code == 405
    assert "POST" in response.headers.get("Allow", "")
    assert response.json["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert response.json["error"]["message"]

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

def test_scan_returns_report(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    resolved = object()

    expected_report = {
        "target_url": "https://example.com",
        "http_status": 200,
        "summary": {
            "total": 5,
            "passed": 5,
            "warning": 0,
            "not_verified": 0,
            "error": 0,
            "skipped": 0,
        },
        "findings": [],
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
