import socket

import requests

from security_scanner.scanner import (
    _safe_get_response,
    check_https,
    check_security_headers,
    validate_url,
)


def mock_public_dns(monkeypatch):
    """محاكاة DNS يعيد عنوان IP عامًا للاختبارات."""
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ],
    )


def test_http_url_warns():
    result = check_https("http://example.com")

    assert result["status"] == "warning"


def test_missing_headers_warn():
    results = check_security_headers({})

    assert results["HSTS"]["status"] == "warning"
    assert results["CSP"]["status"] == "warning"
    assert results["X-Content-Type-Options"]["status"] == "warning"
    assert results["X-Frame-Options"]["status"] == "warning"


def test_present_headers():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    results = check_security_headers(headers)

    assert results["HSTS"]["status"] == "passed"
    assert results["CSP"]["status"] == "passed"
    assert results["X-Content-Type-Options"]["status"] == "passed"
    assert results["X-Frame-Options"]["status"] == "passed"


def test_invalid_header_values_warn():
    headers = {
        "Strict-Transport-Security": "max-age=0",
        "Content-Security-Policy": "",
        "X-Content-Type-Options": "invalid",
        "X-Frame-Options": "ALLOWALL",
    }

    results = check_security_headers(headers)

    assert results["HSTS"]["status"] == "warning"
    assert results["CSP"]["status"] == "warning"
    assert results["X-Content-Type-Options"]["status"] == "warning"
    assert results["X-Frame-Options"]["status"] == "warning"


def test_reject_unsafe_urls():
    assert validate_url("http://example.com") is False
    assert validate_url("https://localhost") is False
    assert validate_url("https://127.0.0.1") is False


def test_reject_private_dns_address(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.168.1.20", 443),
            )
        ],
    )

    assert validate_url("https://example.com") is False


def test_accept_public_dns_address(monkeypatch):
    mock_public_dns(monkeypatch)

    assert validate_url("https://example.com") is True


def test_reject_url_with_credentials():
    assert validate_url("https://user:password@example.com") is False


def test_reject_unsupported_port():
    assert validate_url("https://example.com:8443") is False
    assert validate_url("https://example.com:8080") is False


def test_reject_mixed_public_and_private_dns_addresses(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.168.1.20", 443),
            ),
        ],
    )

    assert validate_url("https://example.com") is False


def test_private_dns_address_never_triggers_http_request(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.168.1.20", 443),
            )
        ],
    )

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            "يجب ألا يُرسل طلب HTTP إلى عنوان خاص"
        )

    monkeypatch.setattr(
        requests.Session,
        "get",
        unexpected_request,
    )

    status, headers, error = _safe_get_response(
        "https://example.com"
    )

    assert status is None
    assert headers == {}
    assert error == "invalid"


def test_redirect_is_not_followed(monkeypatch):
    mock_public_dns(monkeypatch)

    captured = {}
    request_count = 0

    class FakeResponse:
        status_code = 302
        headers = {
            "Location": "http://127.0.0.1/admin"
        }

        def close(self):
            pass

    fake_response = FakeResponse()

    def fake_get(session, url, **kwargs):
        nonlocal request_count
        request_count += 1
        captured.update(kwargs)
        return fake_response

    monkeypatch.setattr(
        requests.Session,
        "get",
        fake_get,
    )

    status, headers, error = _safe_get_response(
        "https://example.com"
    )

    assert status == 302
    assert error is None
    assert headers["Location"] == "http://127.0.0.1/admin"
    assert captured["allow_redirects"] is False
    assert captured["verify"] is True
    assert request_count == 1


def test_tls_error_does_not_pass_https(monkeypatch):
    mock_public_dns(monkeypatch)

    def fake_get(session, url, **kwargs):
        raise requests.exceptions.SSLError(
            "Certificate verification failed"
        )

    monkeypatch.setattr(
        requests.Session,
        "get",
        fake_get,
    )

    result = check_https("https://example.com")

    assert result["status"] == "warning"
    assert "TLS" in result["message"]

def test_request_pins_validated_ip_and_preserves_tls_hostname(
    monkeypatch,
):
    """التحقق من إعداد عنوان الاتصال واسم النطاق المستخدم في TLS."""

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ],
    )

    captured = {}

    class FakeResponse:
        status_code = 200
        headers = {}

        def close(self):
            pass

    def fake_get(session, url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        captured["adapter"] = session.get_adapter(url)
        captured["trust_env"] = session.trust_env
        return FakeResponse()

    monkeypatch.setattr(requests.Session, "get", fake_get)

    status, headers, error = _safe_get_response(
        "https://example.com/security-check"
    )

    assert status == 200
    assert headers == {}
    assert error is None

    # يجب أن يكون عنوان الطلب هو IP الذي تحققنا منه.
    assert captured["url"] == (
        "https://93.184.216.34:443/security-check"
    )

    # يجب إبقاء التحقق من الشهادة وتعطيل التحويل التلقائي.
    assert captured["kwargs"]["verify"] is True
    assert captured["kwargs"]["allow_redirects"] is False
    assert captured["trust_env"] is False

    # يجب أن يحتفظ المحول باسم النطاق الأصلي للتحقق من TLS.
    adapter = captured["adapter"]

    assert adapter.hostname == "example.com"
    assert (
        adapter.poolmanager.connection_pool_kw["server_hostname"]
        == "example.com"
    )
    assert (
        adapter.poolmanager.connection_pool_kw["assert_hostname"]
        == "example.com"
    )
