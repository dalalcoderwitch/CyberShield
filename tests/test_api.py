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
        "validate_url",
        lambda url: False,
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 403
    assert (
        response.json["error"]["code"]
        == "TARGET_NOT_ALLOWED"
    )


def test_scan_returns_report(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

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
        "validate_url",
        lambda url: True,
    )

    monkeypatch.setattr(
        api_module,
        "scan_target",
        lambda url: expected_report,
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json == expected_report


def test_scan_hides_internal_error(monkeypatch):
    app = api_module.create_app()
    client = app.test_client()

    monkeypatch.setattr(
        api_module,
        "validate_url",
        lambda url: True,
    )

    def fail_scan(url):
        raise RuntimeError("private internal details")

    monkeypatch.setattr(
        api_module,
        "scan_target",
        fail_scan,
    )

    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 500
    assert (
        response.json["error"]["code"]
        == "INTERNAL_ERROR"
    )
    assert "private internal details" not in response.get_data(
        as_text=True
    )