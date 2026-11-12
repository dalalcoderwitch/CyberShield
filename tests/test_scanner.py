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
    assert results["CSP"]["status"] == "warning"
    assert "لم يتم تقييم" in results["CSP"]["message"]
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


def test_duplicate_case_insensitive_security_headers_warn():
    headers = {
        "Strict-Transport-Security": "max-age=0",
        "strict-transport-security": "max-age=31536000",
        "X-Content-Type-Options": "invalid",
        "x-content-type-options": "nosniff",
        "X-Frame-Options": "ALLOWALL",
        "x-frame-options": "DENY",
    }

    results = check_security_headers(headers)

    assert results["HSTS"]["status"] == "warning"
    assert results["X-Content-Type-Options"]["status"] == "warning"
    assert results["X-Frame-Options"]["status"] == "warning"


@pytest.mark.parametrize(
    "value",
    [
        "max-age=0",
        "max-age=-1",
        "max-age=+100",
        "max-age=1_0",
        "max-age=١٠",
        "max-age=10abc",
        "max-age=10; max-age=20",
    ],
)
def test_hsts_rejects_malformed_or_non_positive_max_age(value):
    results = check_security_headers(
        {"Strict-Transport-Security": value}
    )

    assert results["HSTS"]["status"] == "warning"


def test_csp_presence_does_not_mean_policy_is_validated():
    results = check_security_headers(
        {"Content-Security-Policy": "default-src 'self'"}
    )

    assert results["CSP"]["status"] == "warning"
    assert "لم يتم تقييم" in results["CSP"]["message"]

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


def test_accept_public_ipv6_dns_address(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2001:4860:4860::8888", 443, 0, 0),
            )
        ],
    )

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
    assert error == "not_allowed"


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
    assert error == "not_allowed"


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
    assert error == "dns_error"

def test_unexpected_dns_exception_never_triggers_http_request(monkeypatch):
    """Unexpected resolver exceptions must not reach the HTTP layer."""

    def dns_failure(*args, **kwargs):
        raise RuntimeError("Simulated unexpected DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", dns_failure)

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            "HTTP request must not run after unexpected DNS failure"
        )

    monkeypatch.setattr(requests.Session, "get", unexpected_request)

    status, headers, error = _safe_get_response("https://example.com")

    assert status is None
    assert headers == {}
    assert error == "dns_error"

def test_dns_capacity_exhaustion_never_triggers_http_request(monkeypatch):
    class BusySlots:
        def acquire(self, blocking=False):
            return False

    monkeypatch.setattr(
        scanner_module,
        "_DNS_LOOKUP_SLOTS",
        BusySlots(),
    )

    def unexpected_request(*args, **kwargs):
        raise AssertionError("HTTP must not run when DNS capacity is full")

    monkeypatch.setattr(requests.Session, "get", unexpected_request)

    status, headers, error = _safe_get_response("https://example.com")

    assert status is None
    assert headers == {}
    assert error == "dns_capacity"


def test_dns_concurrency_is_limited_to_four(monkeypatch):
    """يجب ألا يعمل أكثر من أربعة DNS lookups بالتزامن."""

    from threading import Lock

    expected_limit = 4
    assert scanner_module._DNS_MAX_CONCURRENT_LOOKUPS == expected_limit

    slots = BoundedSemaphore(expected_limit)

    monkeypatch.setattr(
        scanner_module,
        "_DNS_LOOKUP_SLOTS",
        slots,
    )
    monkeypatch.setattr(
        scanner_module,
        "_DNS_TIMEOUT_SECONDS",
        5.0,
    )

    lock = Lock()
    all_started = Event()
    release_dns = Event()
    fifth_finished = Event()

    active = 0
    total_started = 0
    max_active = 0

    record = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("93.184.216.34", 443),
    )

    outcomes = [None] * expected_limit
    fifth_result = []

    def slow_dns(*args, **kwargs):
        nonlocal active, total_started, max_active

        with lock:
            active += 1
            total_started += 1
            max_active = max(max_active, active)

            if total_started == expected_limit:
                all_started.set()

        try:
            if not release_dns.wait(timeout=5):
                raise RuntimeError("DNS test release timed out")

            return [record]

        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        scanner_module.socket,
        "getaddrinfo",
        slow_dns,
    )

    def resolve(index):
        outcomes[index] = scanner_module._resolve_dns_with_status(
            f"worker-{index}.example"
        )

    workers = [
        Thread(target=resolve, args=(index,))
        for index in range(expected_limit)
    ]

    fifth_worker = None

    try:
        for worker in workers:
            worker.start()

        assert all_started.wait(timeout=2), (
            "لم تبدأ عمليات DNS الأربع بالتزامن"
        )

        with lock:
            assert active == expected_limit
            assert max_active == expected_limit
            assert total_started == expected_limit

        def resolve_fifth():
            fifth_result.append(
                scanner_module._resolve_dns_with_status(
                    "fifth.example"
                )
            )
            fifth_finished.set()

        fifth_worker = Thread(target=resolve_fifth)
        fifth_worker.start()

        assert fifth_finished.wait(timeout=2), (
            "الطلب الخامس لم يُرفض بسرعة عند امتلاء سعة DNS"
        )

        assert fifth_result == [(None, "dns_capacity")]

        with lock:
            assert total_started == expected_limit
            assert max_active == expected_limit

    finally:
        release_dns.set()

        for worker in workers:
            worker.join(timeout=3)

        if fifth_worker is not None:
            fifth_worker.join(timeout=3)

    assert all(not worker.is_alive() for worker in workers)
    assert fifth_worker is not None and not fifth_worker.is_alive()

    assert outcomes == [([record], None)] * expected_limit

    with lock:
        assert active == 0

    # التأكد من استعادة خانات DNS الأربع بعد انتهاء العمليات.
    acquired = 0

    try:
        for _ in range(expected_limit):
            assert slots.acquire(timeout=1), (
                "لم تُستعد جميع خانات DNS بعد انتهاء العمليات"
            )
            acquired += 1

    finally:
        for _ in range(acquired):
            slots.release()


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
        resolved_ip = (
            "93.184.216.34" if dns_calls == 1 else "127.0.0.1"
        )
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (resolved_ip, 443),
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
    assert error == "dns_timeout"

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


def test_response_and_session_close_when_header_access_raises(monkeypatch):
    mock_public_dns(monkeypatch)

    class FakeResponse:
        status_code = 200
        closed = False

        @property
        def headers(self):
            raise RuntimeError("Simulated header access failure")

        def close(self):
            self.closed = True

    response = FakeResponse()

    class FakeSession:
        def __init__(self):
            self.trust_env = True
            self.closed = False

        def mount(self, prefix, adapter):
            pass

        def get(self, url, **kwargs):
            return response

        def close(self):
            self.closed = True

    session = FakeSession()
    monkeypatch.setattr(
        scanner_module.requests,
        "Session",
        lambda: session,
    )

    with pytest.raises(RuntimeError, match="Simulated header access failure"):
        scanner_module._safe_get_response("https://example.com")

    assert response.closed is True
    assert session.closed is True


def test_session_closes_when_response_close_raises(monkeypatch):
    mock_public_dns(monkeypatch)

    class FakeResponse:
        status_code = 200
        headers = {}

        def close(self):
            raise RuntimeError("Simulated response close failure")

    class FakeSession:
        def __init__(self):
            self.trust_env = True
            self.closed = False

        def mount(self, prefix, adapter):
            pass

        def get(self, url, **kwargs):
            return FakeResponse()

        def close(self):
            self.closed = True

    session = FakeSession()
    monkeypatch.setattr(
        scanner_module.requests,
        "Session",
        lambda: session,
    )

    with pytest.raises(RuntimeError, match="Simulated response close failure"):
        _safe_get_response("https://example.com")

    assert session.closed is True


def test_real_tls_rejects_untrusted_self_signed_certificate(tmp_path, monkeypatch, caplog):
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
    malformed_headers = {"enabled": False, "oversized": False}
    redirect_mode = {"enabled": False}
    response_policy_headers = {}
    response_cookie_headers = []
    options_seen = {"count": 0, "headers": []}
    disclosure_mode = {"enabled": False}
    error_mode = {"enabled": False}
    disclosure_requests = []

    class TestHandler(BaseHTTPRequestHandler):
        def do_OPTIONS(self):
            options_seen["count"] += 1
            options_seen["headers"].append(dict(self.headers))
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "https://cybershield.invalid")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET")
            self.send_header("Access-Control-Allow-Headers", "x-cybershield-audit")
            self.send_header("Vary", "Origin")
            self.end_headers()

        def do_GET(self):
            requests_seen["count"] += 1

            if disclosure_mode["enabled"]:
                path = self.path.split("?", 1)[0]
                approved_disclosure_paths = {
                    "/.env", "/.git/HEAD", "/.git/config", "/.DS_Store",
                    "/backup.zip", "/database.sql", "/uploads/", "/files/",
                    "/.well-known/security.txt", "/security.txt", "/robots.txt",
                    "/app.js", "/app.js.map",
                }
                if path in approved_disclosure_paths:
                    disclosure_requests.append((path, dict(self.headers)))
                    response_map = {
                        "/.env": (200, "text/plain", b"SECRET_KEY=FAKE_DISCLOSURE_SECRET_31\n"),
                        "/uploads/": (200, "text/html", b"<html><title>Index of /uploads/</title></html>"),
                        "/security.txt": (200, "text/plain", b"Contact: mailto:security@example.invalid\n"),
                        "/robots.txt": (200, "text/plain", b"User-agent: *\nDisallow: /private\n"),
                        "/app.js": (200, "application/javascript", b"console.log('ok');\n//# sourceMappingURL=app.js.map\n"),
                        "/app.js.map": (200, "application/json", b'{"version":3,"sources":["hidden.ts"],"mappings":"AAAA"}'),
                    }
                    status, media_type, body = response_map.get(path, (404, "text/plain", b"not found"))
                    self.send_response(status)
                    self.send_header("Content-Type", media_type)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

            if malformed_headers["oversized"]:
                payload = (
                    b"HTTP/1.1 200 OK\r\n"
                    + b"X-Oversized: " + b"A" * 65537 + b"\r\n"
                    + b"Connection: close\r\n\r\n"
                )
                self.connection.sendall(payload)
                return

            if malformed_headers["enabled"]:
                payload = (
                    b"HTTP/1.1 200 OK\r\n"
                    + b"".join(
                        f"X-Test-{index}: value\r\n".encode("ascii")
                        for index in range(101)
                    )
                    + b"Connection: close\r\n\r\n"
                )
                self.connection.sendall(payload)
                return

            if error_mode["enabled"] and self.path == "/integrated-check":
                body = b"Traceback (most recent call last):\n  File '/srv/app/private.py'\nSQLSTATE[hidden]"
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if redirect_mode["enabled"]:
                self.send_response(302)
                self.send_header("Location", "https://redirect.example/destination")
                self.send_header("Content-Length", "1")
                self.end_headers()
                self.wfile.write(b"x")
                return

            self.send_response(200)
            if disclosure_mode["enabled"] and self.path == "/integrated-check":
                body = b'<html><script src="/app.js"></script></html>'
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
            for header_name, header_value in response_policy_headers.items():
                self.send_header(header_name, header_value)
            for header_name, header_value in response_cookie_headers:
                self.send_header(header_name, header_value)
            self.end_headers()
            if disclosure_mode["enabled"] and self.path == "/integrated-check":
                self.wfile.write(body)
            else:
                self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(
        certfile=str(certificate_path),
        keyfile=str(key_path),
    )

    received_sni = []

    def capture_sni(_tls_socket, server_name, _initial_context):
        received_sni.append(server_name)

    tls_context.set_servername_callback(capture_sni)

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

        assert received_sni == [
            "localhost",
            "wrong.example",
            "localhost",
        ]

        # Integrated local socket and TLS verification through the scanner.
        from requests.adapters import HTTPAdapter
        from urllib3.util import connection as urllib3_connection

        received_sni.clear()

        integrated_url = "https://localhost/integrated-check"
        parsed_target = scanner_module.urlparse(integrated_url)
        validated_target = (
            parsed_target,
            "localhost",
            ["127.0.0.1"],
        )
        resolver_calls = []

        def fake_resolver(url, deadline=None, **kwargs):
            resolver_calls.append((url, deadline))
            return validated_target, None

        monkeypatch.setattr(
            scanner_module,
            "resolve_target_with_status",
            fake_resolver,
        )
        real_ip_policy = scanner_module._is_allowed_ip
        monkeypatch.setattr(
            scanner_module,
            "_is_allowed_ip",
            lambda address: address.is_loopback or real_ip_policy(address),
        )

        real_create_connection = urllib3_connection.create_connection
        socket_observation = {}

        def route_to_test_server(address, *args, **kwargs):
            socket_observation["requested_address"] = address
            assert address == ("127.0.0.1", 443)

            connected_socket = real_create_connection(
                ("127.0.0.1", server.server_port),
                *args,
                **kwargs,
            )
            socket_observation["peer"] = connected_socket.getpeername()
            return connected_socket

        monkeypatch.setattr(
            urllib3_connection,
            "create_connection",
            route_to_test_server,
        )

        real_cert_verify = HTTPAdapter.cert_verify

        def trust_test_certificate(adapter, connection, url, verify, cert):
            return real_cert_verify(
                adapter,
                connection,
                url,
                str(certificate_path),
                cert,
            )

        monkeypatch.setattr(
            HTTPAdapter,
            "cert_verify",
            trust_test_certificate,
        )

        redirect_dns_records = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.8", 443)),
        ]
        redirect_dns_calls = []

        def fake_redirect_dns(hostname, deadline=None):
            redirect_dns_calls.append((hostname, deadline))
            return redirect_dns_records, None

        monkeypatch.setattr(
            scanner_module,
            "_resolve_dns_with_status",
            fake_redirect_dns,
        )
        redirect_mode["enabled"] = True
        # Controlled local TLS fixture explicitly permits its pinned loopback only.
        original_parse = scanner_module._parse_target_url
        monkeypatch.setattr(scanner_module, "_parse_target_url",
                            lambda value: ((scanner_module.urlparse(value), "localhost"), None) if value == integrated_url else original_parse(value))
        original_ip_policy = scanner_module._is_allowed_ip
        monkeypatch.setattr(scanner_module, "_is_allowed_ip",
                            lambda ip: str(ip) == "127.0.0.1" or original_ip_policy(ip))
        integrated_tls_metadata = {}
        redirect_dns_evidence = {}
        integrated_status, integrated_headers, integrated_error = (
            scanner_module._safe_get_response(
                integrated_url,
                tls_metadata=integrated_tls_metadata,
                redirect_dns_answers=redirect_dns_evidence,
            )
        )

        assert resolver_calls == [(integrated_url, None)]
        assert integrated_status == 302
        assert integrated_headers["Location"] == "https://redirect.example/destination"
        assert integrated_error is None
        assert socket_observation["requested_address"] == (
            "127.0.0.1",
            443,
        )
        assert socket_observation["peer"] == (
            "127.0.0.1",
            server.server_port,
        )
        assert received_sni == ["localhost"]
        assert integrated_tls_metadata["version"].startswith("TLSv")
        assert integrated_tls_metadata["cipher"]
        assert integrated_tls_metadata["not_before"]
        assert integrated_tls_metadata["not_after"]
        assert integrated_tls_metadata["chain_available"] is True
        from security_scanner.checks.evidence import EvidenceCollection
        from security_scanner.checks.response_runner import evaluate_week3_evidence
        live_results = {
            result.check_id: result
            for result in evaluate_week3_evidence(EvidenceCollection(
                http_status=integrated_status,
                tls_verified=True,
                tls_metadata=integrated_tls_metadata,
            ))
        }
        assert live_results["tls_certificate_chain"].status == "passed"
        assert live_results["tls_certificate_expiry"].status == "passed"
        assert live_results["tls_protocol_config"].status == "passed"
        assert redirect_dns_calls == []
        assert redirect_dns_evidence == {}
        # HTTPS response Location does not trigger DNS or destination access.
        assert requests_seen["count"] == 2
        redirect_mode["enabled"] = False

        # A real local HTTPS response exceeding Python's header limit.
        malformed_headers["enabled"] = True

        bad_status, bad_headers, bad_error = (
            scanner_module._safe_get_response(integrated_url)
        )

        assert bad_status is None
        assert bad_headers == {}
        assert bad_error == "connection"
        assert requests_seen["count"] == 3
        assert received_sni == ["localhost", "localhost"]

        # Reject a single HTTP header exceeding Python's line limit.
        malformed_headers["enabled"] = False
        malformed_headers["oversized"] = True

        oversized_status, oversized_headers, oversized_error = (
            scanner_module._safe_get_response(integrated_url)
        )

        assert oversized_status is None
        assert oversized_headers == {}
        assert oversized_error == "connection"
        assert requests_seen["count"] == 4
        assert received_sni == ["localhost", "localhost", "localhost"]

        # End-to-end verified local HTTPS response -> expanded report.
        malformed_headers["oversized"] = False
        response_policy_headers.update({
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Cache-Control": 'no-store, extension="LOCAL_CACHE_SECRET_711"',
        })
        cookie_secrets = (
            "LIVE_FAKE_COOKIE_SECRET_103",
            "LIVE_FAKE_COOKIE_SECRET_204",
        )
        response_cookie_headers.extend((
            ("Set-Cookie", f"first={cookie_secrets[0]}; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure; HttpOnly; SameSite=None"),
            ("Set-Cookie", f"second={cookie_secrets[1]}; Expires=Thu, 22 Oct 2031 08:29:00 GMT; Secure; HttpOnly; SameSite=Lax"),
        ))
        import security_scanner.report as report_module

        monkeypatch.setattr(
            report_module,
            "_safe_http_redirect_probe",
            lambda target, deadline=None, capture=None: "connection",
        )
        disclosure_mode["enabled"] = True
        integrated_report = report_module.scan_target(
            integrated_url,
            include_expanded_checks=True,
        )
        report_findings = {
            item["check_id"]: item
            for item in integrated_report["findings"]
        }
        assert integrated_report["http_status"] == 200
        assert report_findings["header_referrer_policy"]["status"] == "passed"
        assert report_findings["header_permissions_policy"]["status"] == "warning"
        assert report_findings["header_permissions_policy"]["severity"] == "info"
        assert report_findings["cookie_secure"]["status"] == "passed"
        assert report_findings["cache_security"]["status"] == "passed"
        assert sum(item["check_id"] == "cache_security" for item in integrated_report["findings"]) == 1
        assert len(integrated_report["findings"]) == 30
        assert "LOCAL_CACHE_SECRET_711" not in repr(integrated_report) + caplog.text
        assert report_findings["cookie_httponly"]["status"] == "passed"
        assert report_findings["cookie_samesite"]["status"] == "passed"
        assert report_findings["cors_misconfiguration"]["status"] == "warning"
        assert report_findings["open_redirect"]["status"] == "skipped"
        assert report_findings["sensitive_file_exposure"]["status"] == "warning"
        assert report_findings["source_maps_exposure"]["status"] == "warning"
        assert report_findings["directory_listing"]["status"] == "warning"
        assert report_findings["server_information_disclosure"]["status"] == "warning"
        assert report_findings["error_information_disclosure"]["status"] == "skipped"
        assert report_findings["public_security_files"]["status"] == "passed"
        assert len(report_findings) == len(integrated_report["findings"])
        assert integrated_report["summary"]["total"] == len(integrated_report["findings"])
        for finding_status in ("passed", "warning", "not_verified", "error", "skipped"):
            assert integrated_report["summary"][finding_status] == sum(
                finding["status"] == finding_status
                for finding in integrated_report["findings"]
            )
        assert all(secret not in repr(integrated_report) for secret in cookie_secrets)
        assert all(secret not in caplog.text for secret in cookie_secrets)
        assert "FAKE_DISCLOSURE_SECRET_31" not in repr(integrated_report)
        assert "hidden.ts" not in repr(integrated_report)
        assert "BaseHTTP/0.6" not in repr(integrated_report)
        assert "Python/3.14" not in repr(integrated_report)
        assert len(disclosure_requests) == 13
        assert {path for path, _headers in disclosure_requests} == {
            "/.env", "/.git/HEAD", "/.git/config", "/.DS_Store", "/backup.zip",
            "/database.sql", "/app.js", "/app.js.map", "/uploads/", "/files/",
            "/.well-known/security.txt", "/security.txt", "/robots.txt",
        }
        assert all(headers["Accept-Encoding"] == "identity" for _path, headers in disclosure_requests)
        assert all(headers["Range"] == "bytes=0-4095" for _path, headers in disclosure_requests)
        assert all("Cookie" not in headers and "Authorization" not in headers for _path, headers in disclosure_requests)
        assert requests_seen["count"] == 18
        assert options_seen["count"] == 1
        assert len(options_seen["headers"]) == 1
        assert options_seen["headers"][0]["Origin"] == "https://cybershield.invalid"
        assert options_seen["headers"][0]["Access-Control-Request-Method"] == "GET"
        assert options_seen["headers"][0]["Access-Control-Request-Headers"] == "x-cybershield-audit"
        assert "Cookie" not in options_seen["headers"][0]
        assert "Authorization" not in options_seen["headers"][0]
        assert received_sni == ["localhost"] * 18

        # The original HTTPS response is evaluated without following its external Location.
        redirect_mode["enabled"] = True
        redirect_report = report_module.scan_target(
            integrated_url,
            include_expanded_checks=True,
        )
        redirect_findings = {item["check_id"]: item for item in redirect_report["findings"]}
        assert redirect_findings["open_redirect"]["status"] == "warning"
        assert len(redirect_report["findings"]) == 30
        assert redirect_report["summary"]["total"] == 30
        assert "redirect.example" not in repr(redirect_report["findings"])
        assert options_seen["count"] == 2
        assert len(disclosure_requests) == 24
        assert requests_seen["count"] == 30
        redirect_mode["enabled"] = False

        error_mode["enabled"] = True
        error_report = report_module.scan_target(
            integrated_url,
            include_expanded_checks=True,
        )
        error_findings = {item["check_id"]: item for item in error_report["findings"]}
        assert error_report["http_status"] == 500
        assert error_findings["error_information_disclosure"]["status"] == "warning"
        assert error_findings["sqli_passive_indicators"]["status"] == "warning"
        assert error_findings["sqli_passive_indicators"]["severity"] == "low"
        assert error_findings["xss_passive_indicators"]["status"] == "not_verified"
        assert "does not prove SQL injection" in error_findings["sqli_passive_indicators"]["explanation"]
        assert "private.py" not in repr(error_report["findings"])
        assert "SQLSTATE" not in repr(error_report["findings"])
        assert len(error_report["findings"]) == error_report["summary"]["total"] == 30
        assert len(disclosure_requests) == 35
        assert requests_seen["count"] == 42
        error_mode["enabled"] = False

    finally:
        session.close()
        hostname_session.close()
        matching_session.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

def test_real_tls_rejects_expired_certificate(tmp_path, monkeypatch):
    certificate_pem = """-----BEGIN CERTIFICATE-----
MIICwzCCAaugAwIBAgIJAOiIHCj7Xto5MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMTCWxvY2FsaG9zdDAeFw0wNjExMDcxMjQ1MzdaFw0wNzExMDcxMjQ1MzdaMBQx
EjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBANil2JCjHU5qGeGSBfn3pF9klFMcmASt3xaoq2qOW5l13VUhchWFHxeqn0mW
ewyfpMAiHAIU3kpaoxyjvoL9gGHx9SMAc+qQQuOGA8vgJF6bcodynfaAXDlxFXsr
poi9wff7QXntVva/wM/3U+wwxlOTgR0dkAS5+UT5fQon6WxO51IkelnqN3rqE/nT
sXsUE4do8XePDQtdplp310cGTUHorkv7dWyltNS6pbw0v0OjSEPHO5DKumbFFtNA
ymkq2K4h9Tq83JtEdLznLfVGYFpFvUY6QFxF5OCc3UOWG7a3ZxgPRXOfXl58xo3s
a3ZOzi3a7xZbohYxpc+xcMCRKg0CAwEAAaMYMBYwFAYDVR0RBA0wC4IJbG9jYWxo
b3N0MA0GCSqGSIb3DQEBCwUAA4IBAQDMfMppZjuhcqkVUWDgRKFDFM3JPBDpON7P
lm5bb3SGuFGFWQtcyCSKoqlDSl+KXHZ/InUVTavP+qf84kejaHVSTx+n5p8zT3H+
Cab3YUg6sqGKFMcD+Nxe9bV1sQBZJ0jQp8+uZ68dVyJkZWEOb7aTfO0KzITJ1zVk
tvG6qoHlzvlioarg9ii9T5soBOcYfggqEZYmSJ9SIa3tYwm7r2+/iXcV2hCmCoEK
TE9kt3x2O+vsnka0CZPFNTQ321Wp6GgyGFHGVuYV3uxTu217uWg8vKM2k5/IIc9S
8xQRphag6JJGF3Szm2mlxs/3u8AkezenZcM7HNkkF4VHk0Qlyibr
-----END CERTIFICATE-----
"""
    private_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA2KXYkKMdTmoZ4ZIF+fekX2SUUxyYBK3fFqirao5bmXXdVSFy
FYUfF6qfSZZ7DJ+kwCIcAhTeSlqjHKO+gv2AYfH1IwBz6pBC44YDy+AkXptyh3Kd
9oBcOXEVeyumiL3B9/tBee1W9r/Az/dT7DDGU5OBHR2QBLn5RPl9CifpbE7nUiR6
Weo3euoT+dOxexQTh2jxd48NC12mWnfXRwZNQeiuS/t1bKW01LqlvDS/Q6NIQ8c7
kMq6ZsUW00DKaSrYriH1Orzcm0R0vOct9UZgWkW9RjpAXEXk4JzdQ5YbtrdnGA9F
c59eXnzGjexrdk7OLdrvFluiFjGlz7FwwJEqDQIDAQABAoIBAFslSvtu5IF8+e6A
tKr5mNnZQt3EheBSFi0+QP/PbJIfmEKck5aiLvaR/fnDqXkiIPoEX6wwg2TcxQrj
iN8rL7wFQ5C6PApPLxTx6N75KdPzqjd57SMr1aEFBniPYLzeuKBPwLg/NfsRqVjV
QSV5T7cRs5xAN7sFUu3F2OlQ6U97DHtwZuBWNa8Wvxe8jIxt5RgVGWL5YaLBpRDV
FGciVS3BtXpMGGrNLR1CQQHYBNpHKXbB2vJzxgUawaC0ft0AKasPi6mcW/7cvZUC
GIKVRDwgslZbO2OoWrdMjlELfG3eZlZdoCS6ANlRjQrSPHCUu8u+VojxWg7ilxxf
0spFPDECgYEA5r1yY+1aXsuh7fy/ArKk516tL5O56/1xA18+rCWV3tyxngTHcEXV
sGNl+vUveF8A3egBfXayWj8WczwJNSl081MxCyI9jI3zQStqaCAv0GIyuxomnv76
9yXh9lqVs47DcOCobWdlCaZxJ7sz9nBtMTZzHYrvHMlci4npqe6S2QcCgYEA8F12
KSKlG77zVuo3qkev91Qz9o11V3ZBPcEUpjUr+x1ceESDu41WwkZ6YSEvVJz+MErO
YVNWp04wMSuH9MG+YEF9T+uiD1zmRhWho0lkMbJuA3sYG6MBVX/VjYnfHdP+Bkph
UvTY8AEAYelYT4+CDPk+IJVXUtNrKc5s1Kdbg0sCgYAv+U+hSyYw83G1g4lLTE1Q
9bRYYgST9lva8aCcNixU69naGvBEfaCSTfhUF0pJYqdRe/1jUpx+ewN17hOUBAyW
0sMtp27YnGLpN9el0pteXixiDmvdPvJ7FFtI10iszpAAFhWuuYKeYQbB1gBVysZJ
JyMED3DrsUoWkRQOCtZpXQKBgCNO51uVjkFsJFzBHRozW6LuSI/QKcuGQIEsyra7
mtFRd9Lm5Z74XSU+qx13fXdldGVtp7FeR51d+/BNH7SRfUCwfhLuXyj4kY78AHl2
/3PZbRWv0FPG9xwzIhCfjxnXmTodVPyVoQRocUDwwRs2znjPaBPrPB+blONYQl5e
ky/PAoGAVpZ53gVeROtcmxcRN77A9SAnMPBy06c9ZuTXtqvMwYRcR0537jJ0C4rk
jie7dpLtO+arMWbBa8uTzRTj6WFkpvv7CCmi0sATOqVLBllfVMQjR337FGrf8LCh
K6GLNhcbjHUoWFSCqcdxTRb9dk6WPSFJk84TdbtE2/KKY8Qpi5k=
-----END RSA PRIVATE KEY-----
"""
    certificate_path = tmp_path / "expired-localhost-cert.pem"
    private_key_path = tmp_path / "expired-localhost-key.pem"
    certificate_path.write_text(certificate_pem, encoding="ascii")
    private_key_path.write_text(private_key_pem, encoding="ascii")

    class Handler(BaseHTTPRequestHandler):
        requests_seen = 0

        def do_GET(self):
            type(self).requests_seen += 1
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=str(certificate_path),
        keyfile=str(private_key_path),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = "https://localhost/expired-certificate"
    target = (scanner_module.urlparse(url), "localhost", ["127.0.0.1"])
    monkeypatch.setattr(
        scanner_module,
        "resolve_target_with_status",
        lambda requested_url, deadline=None: (target, None),
    )

    from urllib3.util import connection as urllib3_connection
    from requests.adapters import HTTPAdapter

    real_create_connection = urllib3_connection.create_connection

    def route_to_local_tls_server(address, *args, **kwargs):
        assert address == ("127.0.0.1", 443)
        return real_create_connection(
            ("127.0.0.1", server.server_port),
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        urllib3_connection,
        "create_connection",
        route_to_local_tls_server,
    )

    real_cert_verify = HTTPAdapter.cert_verify

    def trust_expired_test_certificate(adapter, connection, request_url, verify, cert):
        return real_cert_verify(
            adapter,
            connection,
            request_url,
            str(certificate_path),
            cert,
        )

    monkeypatch.setattr(
        HTTPAdapter,
        "cert_verify",
        trust_expired_test_certificate,
    )

    original_parse = scanner_module._parse_target_url
    monkeypatch.setattr(scanner_module, "_parse_target_url",
                        lambda value: ((scanner_module.urlparse(value), "localhost"), None) if value == url else original_parse(value))
    original_ip_policy = scanner_module._is_allowed_ip
    monkeypatch.setattr(scanner_module, "_is_allowed_ip",
                        lambda ip: str(ip) == "127.0.0.1" or original_ip_policy(ip))
    try:
        status, headers, error = scanner_module._safe_get_response(url)
        assert status is None
        assert headers == {}
        assert error == "tls"
        assert Handler.requests_seen == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_safe_get_response_applies_remaining_deadline(monkeypatch):
    import time
    from urllib3.util import Timeout

    parsed = scanner_module.urlparse("https://example.com/")
    resolved_target = (
        parsed,
        "example.com",
        ["93.184.216.34"],
    )

    captured = {}

    class FakeResponse:
        status_code = 200
        headers = {"X-Test": "1"}

        def close(self):
            captured["response_closed"] = True

    class FakeSession:
        def __init__(self):
            self.trust_env = True

        def mount(self, prefix, adapter):
            captured["adapter"] = adapter

        def get(self, url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return FakeResponse()

        def close(self):
            captured["session_closed"] = True

    monkeypatch.setattr(
        scanner_module.requests,
        "Session",
        FakeSession,
    )

    deadline = time.monotonic() + 12.0

    status, headers, error = scanner_module._safe_get_response(
        "https://example.com/",
        resolved_target=resolved_target,
        deadline=deadline,
    )

    assert status == 200
    assert headers == {"X-Test": "1"}
    assert error is None

    request_options = captured["kwargs"]
    timeout = request_options["timeout"]

    assert isinstance(timeout, Timeout)
    assert 0 < timeout.total <= 12.0
    assert 0 < timeout.connect_timeout <= 3.0
    assert 0 < timeout._read <= 5.0

    assert request_options["verify"] is True
    assert request_options["allow_redirects"] is False
    assert captured["response_closed"] is True
    assert captured["session_closed"] is True

@pytest.mark.parametrize(
    "ip_address",
    [
        # IPv4: private, loopback, link-local, reserved, multicast
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",

        # IPv6: unspecified, loopback, ULA, link-local,
        # documentation, multicast
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "ff02::1",
        "5f00::1",
        "100:0:0:1::1",
        "fec0::1",
        "4000::1",
        "8000::1",
    ],
)
def test_reject_non_global_ips_before_http_request(
    monkeypatch,
    ip_address,
):
    if ":" in ip_address:
        family = socket.AF_INET6
        sockaddr = (ip_address, 443, 0, 0)
    else:
        family = socket.AF_INET
        sockaddr = (ip_address, 443)

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                family,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                sockaddr,
            )
        ],
    )

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            f"HTTP request must not run for {ip_address}"
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
    assert error == "not_allowed"

def test_http_timeout_returns_timeout_and_closes_session(monkeypatch):
    import time
    from urllib3.util import Timeout

    parsed = scanner_module.urlparse("https://example.com/")
    resolved_target = (
        parsed,
        "example.com",
        ["93.184.216.34"],
    )

    captured = {}

    class FakeSession:
        def __init__(self):
            self.trust_env = True

        def mount(self, prefix, adapter):
            pass

        def get(self, url, **kwargs):
            captured["timeout"] = kwargs["timeout"]
            raise requests.exceptions.ReadTimeout(
                "Simulated read timeout"
            )

        def close(self):
            captured["session_closed"] = True

    monkeypatch.setattr(
        scanner_module.requests,
        "Session",
        FakeSession,
    )

    status, headers, error = scanner_module._safe_get_response(
        "https://example.com/",
        resolved_target=resolved_target,
        deadline=time.monotonic() + 10,
    )

    assert status is None
    assert headers == {}
    assert error == "timeout"
    assert isinstance(captured["timeout"], Timeout)
    assert captured["session_closed"] is True


def test_expired_deadline_prevents_http_session_creation(monkeypatch):
    import time

    parsed = scanner_module.urlparse("https://example.com/")
    resolved_target = (
        parsed,
        "example.com",
        ["93.184.216.34"],
    )

    def unexpected_session():
        raise AssertionError(
            "HTTP session must not be created after deadline"
        )

    monkeypatch.setattr(
        scanner_module.requests,
        "Session",
        unexpected_session,
    )

    status, headers, error = scanner_module._safe_get_response(
        "https://example.com/",
        resolved_target=resolved_target,
        deadline=time.monotonic() - 1,
    )

    assert status is None
    assert headers == {}
    assert error == "timeout"

def test_http_connect_timeout_returns_timeout_and_closes_session(
    monkeypatch,
):
    import time
    from urllib3.util import Timeout

    parsed = scanner_module.urlparse("https://example.com/")
    resolved_target = (
        parsed,
        "example.com",
        ["93.184.216.34"],
    )

    captured = {}

    class FakeSession:
        def __init__(self):
            self.trust_env = True

        def mount(self, prefix, adapter):
            pass

        def get(self, url, **kwargs):
            captured["timeout"] = kwargs["timeout"]
            raise requests.exceptions.ConnectTimeout(
                "Simulated connection timeout"
            )

        def close(self):
            captured["session_closed"] = True

    monkeypatch.setattr(
        scanner_module.requests,
        "Session",
        FakeSession,
    )

    status, headers, error = scanner_module._safe_get_response(
        "https://example.com/",
        resolved_target=resolved_target,
        deadline=time.monotonic() + 10,
    )

    assert status is None
    assert headers == {}
    assert error == "timeout"
    assert isinstance(captured["timeout"], Timeout)
    assert captured["session_closed"] is True

def test_dns_timeout_uses_remaining_scan_budget(monkeypatch):
    import time
    from queue import Empty

    captured = {}

    class FakeSlots:
        def acquire(self, blocking=False):
            return True

        def release(self):
            pass

    class FakeQueue:
        def __init__(self, maxsize=0):
            pass

        def get(self, timeout=None):
            captured["timeout"] = timeout
            raise Empty

    class FakeThread:
        def __init__(self, target, name=None, daemon=None):
            self.target = target

        def start(self):
            pass

    monkeypatch.setattr(
        scanner_module,
        "_DNS_LOOKUP_SLOTS",
        FakeSlots(),
    )
    monkeypatch.setattr(scanner_module, "Queue", FakeQueue)
    monkeypatch.setattr(scanner_module, "Thread", FakeThread)

    deadline = time.monotonic() + 0.5

    result = scanner_module._resolve_dns_with_timeout(
        "example.com",
        deadline=deadline,
    )

    assert result is None
    assert 0 < captured["timeout"] <= 0.5
    assert captured["timeout"] < scanner_module._DNS_TIMEOUT_SECONDS


def test_https_timeout_is_error(monkeypatch):
    """لا يجوز اعتبار انتهاء المهلة نجاحًا."""

    monkeypatch.setattr(
        scanner_module,
        "_safe_get_response",
        lambda url: (None, {}, "timeout"),
    )

    result = check_https("https://example.com")

    assert result["status"] == "error"
    assert "المهلة" in result["message"]


def test_https_unknown_error_is_not_passed(monkeypatch):
    """الأخطاء غير المعروفة لا تتحول إلى passed."""

    monkeypatch.setattr(
        scanner_module,
        "_safe_get_response",
        lambda url: (None, {}, "unexpected_error"),
    )

    result = check_https("https://example.com")

    assert result["status"] == "error"
    assert result["status"] != "passed"

def test_http_request_exception_returns_connection_and_closes_session(monkeypatch):
    parsed = scanner_module.urlparse("https://example.com/")
    resolved_target = (
        parsed,
        "example.com",
        ["93.184.216.34"],
    )

    class FakeSession:
        def __init__(self):
            self.trust_env = True
            self.closed = False

        def mount(self, prefix, adapter):
            pass

        def get(self, url, **kwargs):
            raise requests.exceptions.ConnectionError(
                "Simulated malformed HTTP response"
            )

        def close(self):
            self.closed = True

    session = FakeSession()

    monkeypatch.setattr(
        scanner_module.requests,
        "Session",
        lambda: session,
    )

    status, headers, error = scanner_module._safe_get_response(
        "https://example.com/",
        resolved_target=resolved_target,
    )

    assert status is None
    assert headers == {}
    assert error == "connection"
    assert session.closed is True



def test_requests_combined_duplicate_security_headers_warn():
    from urllib3._collections import HTTPHeaderDict
    from requests.structures import CaseInsensitiveDict

    headers = HTTPHeaderDict()
    headers.add("Strict-Transport-Security", "max-age=31536000")
    headers.add("Strict-Transport-Security", "max-age=0")
    headers.add("X-Frame-Options", "DENY")
    headers.add("X-Frame-Options", "SAMEORIGIN")
    headers.add("X-Content-Type-Options", "invalid")
    headers.add("X-Content-Type-Options", "nosniff")

    requests_headers = CaseInsensitiveDict(headers)
    results = check_security_headers(requests_headers)

    assert results["HSTS"]["status"] == "warning"
    assert results["X-Frame-Options"]["status"] == "warning"
    assert results["X-Content-Type-Options"]["status"] == "warning"



def test_security_header_normalization_ignores_unneeded_headers():
    class UnusedHeaderValue:
        def __str__(self):
            raise AssertionError("Unneeded header value was accessed")

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Set-Cookie": UnusedHeaderValue(),
        "Server": UnusedHeaderValue(),
    }

    results = check_security_headers(headers)

    assert results["HSTS"]["status"] == "passed"
    assert results["X-Content-Type-Options"]["status"] == "warning"
    assert results["X-Frame-Options"]["status"] == "warning"
    assert results["CSP"]["status"] == "warning"

@pytest.mark.parametrize(
    "target_url",
    [
        "https://example.com:",
        "https://example.com:invalid",
        "https://example.com:443:444",
        "https://example.com/\r\nX-Test: injected",
        r"https://example.com\@127.0.0.1",
        "https://example.com/" + ("a" * 2049),
    ],
)
def test_malformed_urls_are_rejected_before_dns(
    monkeypatch,
    target_url,
):
    def unexpected_dns(*args, **kwargs):
        pytest.fail("DNS must not run for a malformed URL")

    monkeypatch.setattr(
        scanner_module.socket,
        "getaddrinfo",
        unexpected_dns,
    )

    assert validate_url(target_url) is False

@pytest.mark.parametrize(
    ("family", "ip_address"),
    [
        (socket.AF_INET, "2001:4860:4860::8888"),
        (socket.AF_INET6, "93.184.216.34"),
    ],
)
def test_reject_dns_family_and_ip_version_mismatch(
    monkeypatch,
    family,
    ip_address,
):
    sockaddr = (
        (ip_address, 443)
        if family == socket.AF_INET
        else (ip_address, 443, 0, 0)
    )

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                family,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                sockaddr,
            )
        ],
    )

    assert validate_url("https://example.com") is False

@pytest.mark.parametrize(
    "dns_error",
    ["dns_timeout", "dns_error", "dns_capacity", "timeout"],
)
def test_public_resolver_preserves_dns_failure_reason(
    monkeypatch,
    dns_error,
):
    calls = []

    def fake_dns(hostname, deadline=None):
        calls.append((hostname, deadline))
        return None, dns_error

    monkeypatch.setattr(
        scanner_module,
        "_resolve_dns_with_status",
        fake_dns,
    )

    target, error = scanner_module.resolve_target_with_status(
        "https://example.com",
        deadline=123.0,
    )

    assert target is None
    assert error == dns_error
    assert calls == [("example.com", 123.0)]

@pytest.mark.parametrize(
    ("target_url", "expected_error", "expected_dns_calls"),
    [
        ("http://example.com", "invalid", 0),
        ("https://user:password@example.com", "invalid", 0),
        ("https://example.com:8443", "invalid", 0),
        ("https://localhost", "not_allowed", 0),
        ("https://api.internal", "not_allowed", 0),
        ("https://example.com", "not_allowed", 1),
    ],
)
def test_public_resolver_separates_invalid_and_not_allowed(
    monkeypatch,
    target_url,
    expected_error,
    expected_dns_calls,
):
    dns_calls = []

    def fake_dns(hostname, deadline=None):
        dns_calls.append((hostname, deadline))
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("192.168.1.20", 443),
            )
        ], None

    monkeypatch.setattr(
        scanner_module,
        "_resolve_dns_with_status",
        fake_dns,
    )

    target, error = scanner_module.resolve_target_with_status(target_url)

    assert target is None
    assert error == expected_error
    assert len(dns_calls) == expected_dns_calls


def test_public_resolver_success_and_legacy_wrapper(monkeypatch):
    dns_calls = []

    def fake_dns(hostname, deadline=None):
        dns_calls.append((hostname, deadline))
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ], None

    monkeypatch.setattr(
        scanner_module,
        "_resolve_dns_with_status",
        fake_dns,
    )

    target_url = "https://example.com/security-check"

    resolved_target, error = scanner_module.resolve_target_with_status(
        target_url,
        deadline=123.0,
    )

    assert error is None
    assert resolved_target is not None
    assert resolved_target[1] == "example.com"
    assert resolved_target[2] == ["93.184.216.34"]

    legacy_target = scanner_module.resolve_target(
        target_url,
        deadline=456.0,
    )

    assert legacy_target == resolved_target
    assert dns_calls == [
        ("example.com", 123.0),
        ("example.com", 456.0),
    ]


def test_https_not_allowed_is_warning(monkeypatch):
    monkeypatch.setattr(
        scanner_module,
        "_safe_get_response",
        lambda url: (None, {}, "not_allowed"),
    )

    result = check_https("https://example.com")

    assert result["status"] == "warning"
    assert "\u0645\u062d\u0638\u0648\u0631" in result["message"]


@pytest.mark.parametrize("addresses", [
    ["127.0.0.1"], ["10.0.0.1"], ["169.254.169.254"], ["::1"],
    ["8.8.8.8", "127.0.0.1"], ["invalid"], [], ["fe80::1%eth0"],
])
def test_supplied_target_reapplies_ip_policy(monkeypatch, addresses):
    from urllib.parse import urlparse
    from security_scanner import scanner
    def forbidden(*args, **kwargs):
        pytest.fail("No DNS or HTTP allowed for rejected supplied target")
    monkeypatch.setattr(scanner, "_resolve_dns_with_status", forbidden)
    monkeypatch.setattr(scanner.requests, "Session", forbidden)
    captures = [{"secret": "stale"} for _ in range(5)]
    result = scanner._safe_get_response(
        "https://example.com/", (urlparse("https://example.com/"), "example.com", addresses),
        tls_metadata=captures[0], redirect_dns_answers=captures[1],
        cookie_evidence_capture=captures[2], access_evidence_capture=captures[3],
        disclosure_evidence_capture=captures[4])
    assert result[2] is not None
    assert all(not capture for capture in captures)


def test_supplied_target_consistency_and_public_literals():
    from urllib.parse import urlparse
    from security_scanner.scanner import _validate_resolved_target
    url = "https://8.8.8.8/"
    valid = (urlparse(url), "8.8.8.8", ["8.8.8.8"])
    assert _validate_resolved_target(url, valid)[1] is None
    assert _validate_resolved_target(url, (urlparse(url), "8.8.8.8", ["1.1.1.1"]))[0] is None
    assert _validate_resolved_target(url, (urlparse("https://example.com/"), "example.com", ["8.8.8.8"]))[0] is None
    for malformed in ((), {}, "bad", (None, None, None)):
        assert _validate_resolved_target(url, malformed)[0] is None


@pytest.mark.parametrize("helper", ["_safe_cors_preflight", "_safe_http_redirect_probe", "_safe_disclosure_get"])
@pytest.mark.parametrize("target_kind", ["private", "mixed", "mismatch", "malformed", "unresolved"])
def test_all_internal_http_paths_reject_forged_pins(monkeypatch, helper, target_kind):
    from urllib.parse import urlparse
    from security_scanner import scanner
    targets = {
        "private": (urlparse("https://example.com/"), "example.com", ["127.0.0.1"]),
        "mixed": (urlparse("https://example.com/"), "example.com", ["8.8.8.8", "10.0.0.1"]),
        "mismatch": (urlparse("https://example.com/"), "other.example", ["8.8.8.8"]),
        "malformed": (None,),
        "unresolved": (urlparse("https://example.com/"), "example.com", []),
    }
    def forbidden(*args, **kwargs):
        pytest.fail("Forged target must never cause DNS or HTTP")
    monkeypatch.setattr(scanner.requests, "Session", forbidden)
    monkeypatch.setattr(scanner, "_resolve_dns_with_status", forbidden)
    capture = {"location": "SECRET stale", "available": True}
    if helper == "_safe_disclosure_get":
        result = getattr(scanner, helper)(targets[target_kind], "/.env")
        assert result["attempted"] is False
        assert result["error"] is not None
    else:
        assert getattr(scanner, helper)(targets[target_kind], capture=capture) is not None
        assert capture["available"] is False
        assert "SECRET" not in str(capture)


@pytest.mark.parametrize("url,hostname,addresses", [
    ("https://example.com/path?x=1", "example.com", ["8.8.8.8", "1.1.1.1"]),
    ("https://8.8.8.8/", "8.8.8.8", ["8.8.8.8"]),
    ("https://[2606:4700:4700::1111]/", "2606:4700:4700::1111", ["2606:4700:4700::1111"]),
])
def test_valid_supplied_pins_are_copied_without_dns(monkeypatch, url, hostname, addresses):
    from urllib.parse import urlparse
    from security_scanner import scanner
    def forbidden(*args, **kwargs):
        pytest.fail("Cached validation must not resolve DNS")
    monkeypatch.setattr(scanner, "_resolve_dns_with_status", forbidden)
    original = list(addresses)
    result, error = scanner._validate_resolved_target(url, (urlparse(url), hostname, addresses))
    assert error is None
    addresses.clear()
    assert result[2] == original


def test_supplied_target_url_mismatch_and_address_limit_are_rejected():
    from urllib.parse import urlparse
    from security_scanner.scanner import _validate_resolved_target
    url = "https://example.com/"
    for target in ((urlparse(url + "other"), "example.com", ["8.8.8.8"]),
                   (urlparse(url), "example.com", ["8.8.8.8"] * 33),
                   (urlparse(url), "example.com", [123]),
                   (urlparse(url), "example.com", ["192.0.2.1"]),
                   (urlparse(url), "example.com", ["0.0.0.0"]),
                   (urlparse(url), "example.com", ["224.0.0.1"])):
        assert _validate_resolved_target(url, target)[0] is None
