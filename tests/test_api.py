import logging

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
        lambda url: None,
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
        lambda url: resolved,
    )

    captured = {}

    def fake_scan(url, resolved_target=None):
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

    def fake_resolve(url):
        resolution_calls.append(url)
        return resolved

    def fake_scan(url, resolved_target=None):
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
        lambda url: object(),
    )

    def fail_scan(url, resolved_target=None):
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
        lambda url: object(),
    )

    def fail_scan(url, resolved_target=None):
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
    assert response.json["error"]["code"] == "INTERNAL_ERROR"
    assert "secret-log-token" not in caplog.text
    assert "access_token=" not in caplog.text
    assert "Simulated failure for target" not in caplog.text