import socket
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import BoundedSemaphore, Event, Thread

import pytest
import requests
from urllib3.connection import HTTPSConnection

import security_scanner.scanner as scanner_module
from security_scanner.scanner import (
    PinnedIPAdapter,
    _safe_get_response,
    check_https,
    check_security_headers,
    resolve_target,
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
                socket.IPPROTO_TCP,
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
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
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
                socket.IPPROTO_TCP,
                "",
                ("192.168.1.20", 443),
            )
        ],
    )

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            "Unexpected HTTP request to a private address"
        )

    monkeypatch.setattr(requests.Session, "get", unexpected_request)

    status, headers, error = _safe_get_response("https://example.com")

    assert status is None
    assert headers == {}
    assert error == "invalid"


@pytest.mark.parametrize(
    "ip_address",
    [
        "64:ff9b::a9fe:a9fe",
        "::a9fe:a9fe",
        "::ffff:169.254.169.254",
        "2002:a9fe:a9fe::",
    ],
)
def test_reject_ipv6_transition_addresses_before_http_request(
    monkeypatch,
    ip_address,
):
    """رفض عناوين IPv6 الانتقالية المختارة قبل أي طلب HTTP."""
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (ip_address, 443, 0, 0),
            )
        ],
    )

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            f"Unexpected HTTP request for {ip_address}"
        )

    monkeypatch.setattr(requests.Session, "get", unexpected_request)

    status, headers, error = _safe_get_response("https://example.com")

    assert status is None
    assert headers == {}
    assert error == "invalid"


def test_reject_dns_resolution_failure(monkeypatch):
    """فشل DNS يجب أن يؤدي إلى رفض الهدف."""

    def dns_failure(*args, **kwargs):
        raise socket.gaierror("Simulated DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", dns_failure)

    assert validate_url("https://example.com") is False


def test_reject_empty_dns_results(monkeypatch):
    """قائمة عناوين DNS الفارغة لا تسمح بالاتصال."""
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [],
    )

    assert validate_url("https://example.com") is False


def test_reject_excessive_dns_results(monkeypatch):
    """رفض نتائج DNS إذا تجاوز عددها الحد المقرر."""
    record = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("93.184.216.34", 443),
    )

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [record] * 33,
    )

    assert validate_url("https://example.com") is False


def test_reject_unexpected_dns_address_family(monkeypatch):
    """رفض نتيجة DNS التي لا تستخدم IPv4 أو IPv6."""
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
                0,
                "",
                ("unused", 0),
            )
        ],
    )

    assert validate_url("https://example.com") is False


def test_dns_failure_never_triggers_http_request(monkeypatch):
    """فشل DNS يجب أن يمنع الوصول إلى طبقة طلب HTTP."""

    def dns_failure(*args, **kwargs):
        raise socket.gaierror("Simulated DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", dns_failure)

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            "HTTP request must not run after DNS failure"
        )

    monkeypatch.setattr(requests.Session, "get", unexpected_request)

    status, headers, error = _safe_get_response("https://example.com")

    assert status is None
    assert headers == {}
    assert error == "invalid"


def test_reject_mixed_public_and_private_ipv6_results(monkeypatch):
    """وجود IPv6 خاص مع IPv4 عام يجب أن يرفض الهدف كله."""
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
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("fd00::1", 443, 0, 0),
            ),
        ],
    )

    assert validate_url("https://example.com") is False


def test_redirect_is_not_followed(monkeypatch):
    mock_public_dns(monkeypatch)

    captured = {}
    request_count = 0

    class FakeResponse:
        status_code = 302
        headers = {"Location": "http://127.0.0.1/admin"}

        def close(self):
            pass

    fake_response = FakeResponse()

    def fake_get(session, url, **kwargs):
        nonlocal request_count
        request_count += 1
        captured.update(kwargs)
        return fake_response

    monkeypatch.setattr(requests.Session, "get", fake_get)

    status, headers, error = _safe_get_response("https://example.com")

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

    monkeypatch.setattr(requests.Session, "get", fake_get)

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
    assert captured["url"] == "https://93.184.216.34:443/security-check"
    assert captured["kwargs"]["verify"] is True
    assert captured["kwargs"]["allow_redirects"] is False
    assert captured["trust_env"] is False

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


def test_request_uses_pinned_ip_and_tls_hostname_through_http_stack(
    monkeypatch,
):
    """
    اختبار مسار Requests وurllib3 حتى نقطة الاتصال،
    مع منع فتح اتصال شبكي فعلي.
    """
    mock_public_dns(monkeypatch)
    captured = {}

    def intercept_connect(connection, *args, **kwargs):
        captured["host"] = connection.host
        captured["port"] = connection.port
        captured["server_hostname"] = getattr(
            connection, "server_hostname", None
        )
        captured["assert_hostname"] = getattr(
            connection, "assert_hostname", None
        )
        captured["cert_reqs"] = getattr(connection, "cert_reqs", None)
        captured["ssl_context"] = getattr(connection, "ssl_context", None)

        raise OSError("Controlled test interception before socket connect")

    monkeypatch.setattr(HTTPSConnection, "connect", intercept_connect)

    status, headers, error = _safe_get_response(
        "https://example.com/security-check"
    )

    assert status is None
    assert headers == {}
    assert error == "connection"
    assert captured["host"] == "93.184.216.34"
    assert captured["port"] == 443
    assert captured["server_hostname"] == "example.com"
    assert captured["assert_hostname"] == "example.com"

    context = captured["ssl_context"]
    cert_reqs = captured["cert_reqs"]

    assert (
        context is not None
        and context.verify_mode == ssl.CERT_REQUIRED
    ) or cert_reqs in (ssl.CERT_REQUIRED, "CERT_REQUIRED")


def test_resolved_target_is_reused_without_second_dns_lookup(monkeypatch):
    """يتحقق من أن الاتصال يعيد استخدام نتيجة DNS الممررة إليه."""

    dns_calls = 0

    def fake_dns(*args, **kwargs):
        nonlocal dns_calls
        dns_calls += 1
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_dns)

    target_url = "https://example.com/security-check"
    resolved_target = resolve_target(target_url)

    assert resolved_target is not None
    assert dns_calls == 1

    class FakeResponse:
        status_code = 200
        headers = {}

        def close(self):
            pass

    captured = {}

    def fake_get(session, url, **kwargs):
        captured["url"] = url
        return FakeResponse()

    monkeypatch.setattr(requests.Session, "get", fake_get)

    status, headers, error = _safe_get_response(
        target_url,
        resolved_target=resolved_target,
    )

    assert status == 200
    assert headers == {}
    assert error is None
    assert captured["url"] == (
        "https://93.184.216.34:443/security-check"
    )
    assert dns_calls == 1


def test_dns_timeout_rejects_target_before_http_request(monkeypatch):
    """يجب رفض الهدف إذا تجاوز حل DNS المهلة المحددة."""

    dns_started = Event()
    dns_finished = Event()

    # خانة واحدة تجعل اختبار تحرير السعة قابلًا للتحقق.
    monkeypatch.setattr(
        scanner_module,
        "_DNS_TIMEOUT_SECONDS",
        0.01,
    )
    monkeypatch.setattr(
        scanner_module,
        "_DNS_LOOKUP_SLOTS",
        BoundedSemaphore(1),
    )

    def slow_dns(*args, **kwargs):
        dns_started.set()

        try:
            # محاكاة DNS بطيء دون اتصال بموقع خارجي.
            time.sleep(0.15)

            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", 443),
                )
            ]
        finally:
            dns_finished.set()

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        slow_dns,
    )

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            "يجب ألا يُرسل طلب HTTP عند انتهاء مهلة DNS"
        )

    monkeypatch.setattr(
        requests.Session,
        "get",
        unexpected_request,
    )

    status, headers, error = scanner_module._safe_get_response(
        "https://example.com"
    )

    assert status is None
    assert headers == {}
    assert error == "invalid"

    assert dns_started.wait(timeout=1), (
        "لم يبدأ عامل DNS ضمن الوقت المتوقع"
    )

    assert dns_finished.wait(timeout=1), (
        "لم تنتهِ محاكاة DNS ضمن الوقت المتوقع"
    )

    # لا ينجح هذا الاكتساب إلا بعد تحرير العامل للخانة الوحيدة.
    acquired = scanner_module._DNS_LOOKUP_SLOTS.acquire(
        timeout=1
    )
    assert acquired, "لم تتحرر خانة DNS ضمن الوقت المتوقع"

    scanner_module._DNS_LOOKUP_SLOTS.release()

def test_response_body_is_not_read_and_response_is_closed(monkeypatch):
    """التأكد من عدم قراءة الجسم وإغلاق الاستجابة والجلسة."""

    mock_public_dns(monkeypatch)

    class FakeResponse:
        status_code = 200
        headers = {"X-Content-Type-Options": "nosniff"}

        def __init__(self):
            self.closed = False

        @property
        def content(self):
            raise AssertionError("يجب ألا يُقرأ جسم الاستجابة")

        @property
        def raw(self):
            raise AssertionError("يجب ألا تتم قراءة الاستجابة الخام")

        def iter_content(self, *args, **kwargs):
            raise AssertionError("يجب ألا تتم قراءة محتوى الاستجابة")

        def close(self):
            self.closed = True

    fake_response = FakeResponse()
    captured = {}
    created_sessions = []
    original_session_class = requests.Session

    class TrackingSession(original_session_class):
        def __init__(self):
            super().__init__()
            self.was_closed = False
            created_sessions.append(self)

        def get(self, url, **kwargs):
            captured.update(kwargs)
            return fake_response

        def close(self):
            self.was_closed = True
            super().close()

    monkeypatch.setattr(requests, "Session", TrackingSession)

    status, headers, error = _safe_get_response(
        "https://example.com"
    )

    assert status == 200
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert error is None
    assert captured["stream"] is True
    assert fake_response.closed is True
    assert len(created_sessions) == 1
    assert created_sessions[0].was_closed is True


def test_real_tls_rejects_untrusted_self_signed_certificate(tmp_path):
    """
    مصافحة TLS حقيقية مع خادم محلي:
    1. رفض الشهادة الذاتية التوقيع غير الموثوقة.
    2. رفض اسم مضيف غير مطابق مع الثقة بشهادة الاختبار.
    3. قبول الشهادة عندما تكون موثوقة واسم المضيف مطابقًا.
    """

    certificate_pem = """-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJbG9j
YWxob3N0MB4XDTIwMDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowFDESMBAGA1UE
AwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2leY
xkZMuchIpyzc953sv0E1qForPEpyY4i432+ry666w/+yv7/Kr4XG2IKbKmjAElG0
IpmYcF8o1gCAwMVjFA7gtMFfz3RlS3DJ/2aVHx8ozCSgm7fGW9A1SNmxYldBMkJB
vDq3//m9FR+kLgTsdxjfayFQTGWKzC9X6YgZEElmVvGQ67SwZekndLPZFT8SV+v5
nkVL2gdANlkZ7Rp35Cj8ZERTZuPgk+8S8Crp07pNrw/PcWMpTlX9SKc3J3lwr5Qy
gzwBSpFMFN31Ea3SJtFj9HX7ddqNyOalFh1XJGE4kNvCOFRyzo0UH1vr3qd56dPH
hLscsXe3w6KqmxeytwIDAQABo2cwZTAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREEDTALgglsb2NhbGhvc3QwHQYD
VR0OBBYEFAMGvDlavS92hhU2RBUVwGAh5jpIMA0GCSqGSIb3DQEBCwUAA4IBAQBL
ttcb8xbERUKt4ZL9bmhJiS2YhaNO+bTY4eWoBHWn6v+90oqF20wnhMMlYDrFt70b
aDaIvYxnbggtoq/nEmLAst2Ifu9Qrw3fS4PaEfzu0LzcxCXe4Hnovwoz42iqyYwf
eYCuBWo0QGVtFqnLpfA5ZnR7f9y8gR3tTgihJ0qj4TiwCBMB8XFYcmhPnIn1sUY6
cdScMV6zKObs2tCHyEtMQxjFbNMakkd9LYrQK2B0/RcPq4cDLbHbkQD2gFkp70kD
YLdntk79vtX9EL9GFxLqdRXFxF+6D3xwHOnSihyAUV4MUV1OKFPcIQLBS7kqjZ7b
l1DCEvrGt6qinS4NTd73
-----END CERTIFICATE-----"""

    private_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDaV5jGRky5yEin
LNz3ney/QTWoWis8SnJjiLjfb6vLrrrD/7K/v8qvhcbYgpsqaMASUbQimZhwXyjW
AIDAxWMUDuC0wV/PdGVLcMn/ZpUfHyjMJKCbt8Zb0DVI2bFiV0EyQkG8Orf/+b0V
H6QuBOx3GN9rIVBMZYrML1fpiBkQSWZW8ZDrtLBl6Sd0s9kVPxJX6/meRUvaB0A2
WRntGnfkKPxkRFNm4+CT7xLwKunTuk2vD89xYylOVf1IpzcneXCvlDKDPAFKkUwU
3fURrdIm0WP0dft12o3I5qUWHVckYTiQ28I4VHLOjRQfW+vep3np08eEuxyxd7fD
oqqbF7K3AgMBAAECggEALku0kRYG3r2g6hGRKM/LiyIAhpnX4QjICGLNEFNVUfLS
lwx4kj/QcjcjWnUXAX8Eet3oHA4FTI5g0j95DWbNA0vESY9XCV3cvIpFymmt5NNu
ixqZE2t8G6uiILhH7Foj8MwrtAWfTh9eAESdQ0S3/ui/Nq/xnsFJFNJVCadZ6SHC
0lzaGSP5jwVpeeGtn7oN/KeKErxOnKYFOkff62XIvzu++XrLKSAX8KpJ1O7umd1y
RIyGa/oRiqNwAWmQP3KyhWfNoeyff/+UbZNJHhUe1WXmKQzP97d+KS/LCbE9d3qT
uSkut2525Dmudpu4ZInhr3zCHx9h7McrtloSnVnPAQKBgQDw1OXHET1hBZTeZ+Wx
Cump7YSmrlgtS049xB/DM0xI2rVW50ICWYBHooTX8hVGKyIinzr2k8OB9dIrhluF
A8yBa2dVgWd33x9XDPf2dNE35eeQadvbiPMriw0rKnObqS7SKb26f7GMhidA4NW0
9E2cegmZcAHVsrsAnITgnWVOBwKBgQDoGBXgJRN71Hvr6yT5AAXdT+ux9KwZh2pr
0VZ6xhSOJv4R3TdJwio/LJ7yWSbRVPR/6pD/UqJ/6I+1X1/bPWmxXVWhunTcT0/6
Y5MLHWj3NEyBeEWoK0F47PmsvU6E7+vko5mvSBbrPoNAcqghZKKOal2H6V28FgDL
1Os4PgVJ0QKBgFJH+sV7n2Phm04tYy2M0+6JxvOHx3qaKv4xXsS7ZwnRJ3msg0H4
QDq5TPfWruwNWplHm8aZD4f8a7URL32PobRp9KEjGC29XqDIPoPGv6CAfRA7CrHD
5Yjv9izUUTFSqTuGpVrtu8SOJSUma/1qJoYar+LrgMT5TqjT0RZI0E7LAoGBAMeo
gJkUDBDIl9o5rNKvnFvodr/d1XcYsQoTSavQXrpy/LntbbR73c/+2LVu0B/gT30D
Er0yHyydqZLDezilOhkkS5gXSJSFfi3OHx6+rB+M1AvEpVen7mjSo25gY/2kT2+e
9YR+JYk1e7+jYtNnORf+lHto3AQDgafXgIofgHkhAoGBAOv6lvK6SBTNJU0g/mtA
qeCQOYmGyIBaEzpOX3EuDmK2BNNOjMAeLYzO7la1rAVkQvB7TakGijBH031lOQHM
r/tMQQkY72O0hZ8ytX+NR6OWQuTWY9LdcqU6Ssfsao/muao4zWltmIbGcGPzIFTh
Sydvx0FeNWmqPBhmlaj0SqH0
-----END PRIVATE KEY-----"""

    certificate_path = tmp_path / "localhost-cert.pem"
    key_path = tmp_path / "localhost-key.pem"

    certificate_path.write_text(certificate_pem, encoding="ascii")
    key_path.write_text(private_key_pem, encoding="ascii")

    requests_seen = {"count": 0}

    class TestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests_seen["count"] += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(
        certfile=str(certificate_path),
        keyfile=str(key_path),
    )

    class TLSTestServer(HTTPServer):
        def get_request(self):
            raw_socket, client_address = super().get_request()
            try:
                tls_socket = tls_context.wrap_socket(
                    raw_socket,
                    server_side=True,
                )
                return tls_socket, client_address
            except OSError:
                raw_socket.close()
                raise

    server = TLSTestServer(("127.0.0.1", 0), TestHandler)
    server_thread = Thread(
        target=server.serve_forever,
        daemon=True,
    )
    server_thread.start()

    session = requests.Session()
    session.trust_env = False
    session.mount("https://", PinnedIPAdapter("localhost"))

    hostname_session = requests.Session()
    hostname_session.trust_env = False
    hostname_session.mount(
        "https://",
        PinnedIPAdapter("wrong.example"),
    )

    matching_session = requests.Session()
    matching_session.trust_env = False
    matching_session.mount(
        "https://",
        PinnedIPAdapter("localhost"),
    )

    try:
        # الحالة الأولى: الشهادة الذاتية التوقيع غير موثوقة.
        with pytest.raises(requests.exceptions.SSLError):
            session.get(
                f"https://127.0.0.1:{server.server_port}/",
                verify=True,
                timeout=(2, 2),
                allow_redirects=False,
                stream=True,
            )

        assert requests_seen["count"] == 0

        # الحالة الثانية: الشهادة موثوقة، لكن اسم المضيف لا يطابقها.
        with pytest.raises(requests.exceptions.SSLError) as exc_info:
            hostname_session.get(
                f"https://127.0.0.1:{server.server_port}/",
                headers={"Host": "wrong.example"},
                verify=str(certificate_path),
                timeout=(2, 2),
                allow_redirects=False,
                stream=True,
            )

        error_text = str(exc_info.value).lower()

        assert (
            "hostname" in error_text
            or "doesn't match" in error_text
            or "not valid for" in error_text
        ), (
            "لم يكن الخطأ بسبب عدم تطابق اسم المضيف: "
            f"{exc_info.value}"
        )

        assert requests_seen["count"] == 0

        # الحالة الثالثة: الشهادة موثوقة واسم المضيف مطابق.
        response = matching_session.get(
            f"https://127.0.0.1:{server.server_port}/",
            headers={"Host": "localhost"},
            verify=str(certificate_path),
            timeout=(2, 2),
            allow_redirects=False,
            stream=True,
        )

        try:
            assert response.status_code == 200
            assert response.content == b"ok"
        finally:
            response.close()

        assert requests_seen["count"] == 1

    finally:
        session.close()
        hostname_session.close()
        matching_session.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)