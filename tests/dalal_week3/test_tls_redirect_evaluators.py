from datetime import datetime, timedelta, timezone
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlparse
from urllib3.util import connection as urllib3_connection

from security_scanner.checks.evidence import EvidenceCollection
from security_scanner.checks.response_runner import evaluate_week3_evidence
from security_scanner import scanner as scanner_module


def _result(check_id, **kwargs):
    return next(item for item in evaluate_week3_evidence(EvidenceCollection(**kwargs)) if item.check_id == check_id)


def _date(value):
    return value.astimezone(timezone.utc).strftime("%b %d %H:%M:%S %Y") + " GMT"


def test_certificate_expiry_policy_covers_expired_not_yet_valid_near_and_valid():
    now = datetime.now(timezone.utc)
    cases = (
        (now - timedelta(days=1), now - timedelta(seconds=1), "warning", "high"),
        (now + timedelta(days=1), now + timedelta(days=40), "warning", "high"),
        (now - timedelta(days=1), now + timedelta(days=30), "warning", "medium"),
        (now - timedelta(days=1), now + timedelta(days=31), "passed", "info"),
    )
    for start, expiry, status, severity in cases:
        result = _result("tls_certificate_expiry", http_status=200, tls_verified=True,
                         tls_metadata={"not_before": _date(start), "not_after": _date(expiry)})
        assert (result.status, result.severity) == (status, severity)


def test_certificate_expiry_missing_data_or_unverified_tls_is_not_verified():
    assert _result("tls_certificate_expiry", http_status=200, tls_verified=True).status == "not_verified"
    assert _result("tls_certificate_expiry", http_status=200, tls_verified=False,
                   tls_metadata={"not_after": _date(datetime.now(timezone.utc) + timedelta(days=90))}).status == "not_verified"


def test_chain_requires_verified_connection_and_exposed_chain():
    assert _result("tls_certificate_chain", http_status=200, tls_verified=True,
                   tls_metadata={"chain_available": True}).status == "passed"
    assert _result("tls_certificate_chain", http_status=200, tls_verified=True).status == "not_verified"
    assert _result("tls_certificate_chain", http_status=200, tls_verified=False,
                   tls_metadata={"chain_available": True}).status == "not_verified"


def test_tls_protocol_and_cipher_policy():
    def evaluate(version, cipher):
        return _result("tls_protocol_config", http_status=200, tls_verified=True,
                       tls_metadata={"version": version, "cipher": cipher})
    assert evaluate("TLSv1.3", "TLS_AES_128_GCM_SHA256").status == "passed"
    assert evaluate("TLSv1.3", "TLS_CHACHA20_POLY1305_SHA256").status == "passed"
    assert evaluate("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256").status == "passed"
    assert (evaluate("TLSv1.1", "ECDHE-RSA-AES128-GCM-SHA256").status,
            evaluate("TLSv1.1", "ECDHE-RSA-AES128-GCM-SHA256").severity) == ("warning", "high")
    for cipher in ("ECDHE-RSA-AES128-SHA256", "AES128-GCM-SHA256", "TLS_AES_128_CCM_SHA256"):
        assert evaluate("TLSv1.2", cipher).status == "not_verified"
    for cipher in ("ECDHE-RSA-AES128-CBC-SHA", "RC4-SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256"):
        assert (evaluate("TLSv1.2", cipher).status, evaluate("TLSv1.2", cipher).severity) == ("warning", "high")
    assert evaluate("TLSv1.2", "AES256-GCM-SHA384").status == "not_verified"
    assert evaluate("TLSv1.3", "TLS_AES_128_CCM_SHA256").status == "not_verified"
    assert _result("tls_protocol_config", http_status=200, tls_verified=True).status == "not_verified"


def test_http_redirect_statuses_missing_invalid_and_relative_location():
    for status in (301, 302, 303, 307, 308):
        assert _result("http_to_https_redirect", http_status=200, http_probe_status=status,
                       http_probe_location="https://example.com/", redirect_destination_url="https://example.com/").status == "passed"
    assert _result("http_to_https_redirect", http_status=200, http_probe_status=301).status == "warning"
    assert _result("http_to_https_redirect", http_status=200, http_probe_status=200).severity == "medium"
    assert _result("http_to_https_redirect", http_status=200, http_probe_status=302,
                   http_probe_location="/secure", redirect_destination_url="https://93.184.216.34/secure").status == "passed"
    assert _result("http_to_https_redirect", http_status=200, http_probe_error="timeout").status == "not_verified"


def test_redirect_destination_policy_rejects_private_mixed_and_bad_shapes():
    def evaluate(url, answers=(), code=302):
        return _result("redirect_destination_safety", http_status=200, http_probe_status=code,
                       http_probe_location=url, redirect_destination_url=url,
                       redirect_dns_answers=answers)
    assert (evaluate("https://127.0.0.1/a").status, evaluate("https://127.0.0.1/a").severity) == ("warning", "high")
    assert evaluate("https://redirect.example/a", ("93.184.216.34", "10.0.0.8")).status == "warning"
    assert evaluate("https://redirect.example/a", ("93.184.216.34",)).status == "passed"
    for url in ("http://redirect.example", "https://redirect.example:8443", "https://user:secret@redirect.example"):
        assert evaluate(url).status == "warning"
    assert evaluate("https://redirect.example").status == "not_verified"
    assert _result("redirect_destination_safety", http_status=200, http_probe_status=200).status == "skipped"


def test_redirect_dns_collection_keeps_mixed_answers_for_rejection(monkeypatch):
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.8", 443)),
    ]
    calls = []
    monkeypatch.setattr(scanner_module, "_resolve_dns_with_status", lambda host, deadline=None: (calls.append((host, deadline)) or records, None))
    assert scanner_module._resolve_redirect_location_addresses("https://redirect.example/x", 12) == ("93.184.216.34", "10.0.0.8")
    assert calls == [("redirect.example", 12)]


def test_redirect_destination_is_never_connected(monkeypatch):
    calls = []
    monkeypatch.setattr(scanner_module, "_resolve_dns_with_status", lambda *a, **kw: calls.append((a, kw)))
    for value in ("/relative", "http://redirect.example", "https://redirect.example:8443", "https://user@redirect.example", "https://localhost"):
        assert scanner_module._resolve_redirect_location_addresses(value) is None
    assert not calls


def test_bounded_http_probe_performs_one_local_root_get_without_following(monkeypatch):
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append((self.path, dict(self.headers)))
            self.send_response(302)
            self.send_header("Location", "../secure")
            self.send_header("Content-Length", "100")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    real_connect = urllib3_connection.create_connection

    def route_local(address, *args, **kwargs):
        if address == ("93.184.216.34", 80):
            address = ("127.0.0.1", server.server_port)
        return real_connect(address, *args, **kwargs)

    monkeypatch.setattr(urllib3_connection, "create_connection", route_local)
    try:
        parsed = urlparse("https://example.com/private/path?token=secret#frag")
        capture = {}
        error = scanner_module._safe_http_redirect_probe((parsed, "example.com", ["93.184.216.34"]), capture=capture)
        assert error is None
        assert capture["status"] == 302
        assert capture["location"] == "../secure"
        assert capture["request_url"] == "http://93.184.216.34:80/"
        assert len(observed) == 1 and observed[0][0] == "/"
        headers = {key.lower(): value for key, value in observed[0][1].items()}
        assert headers["host"] == "example.com"
        assert "authorization" not in headers and "cookie" not in headers
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_week3_runner_executes_five_new_checks():
    results = evaluate_week3_evidence(EvidenceCollection(http_status=200))
    assert {"tls_certificate_expiry", "tls_certificate_chain", "tls_protocol_config", "http_to_https_redirect", "redirect_destination_safety"} <= {item.check_id for item in results}
