"""Backend-owned regression coverage for real scanner/API boundaries."""

import http.client
import socket
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
import requests

import backend.app as api_module
import security_scanner.report as report_module
import security_scanner.scanner as scanner_module


def test_bounded_identity_sample_handles_chunked_body_without_content_length():
    class ChunkedRaw:
        def __init__(self):
            self.chunks = [b"first-", b"second-", b"third"]
            self.requested_amounts = []

        def stream(self, amt, decode_content=False):
            assert decode_content is False
            self.requested_amounts.append(amt)
            if self.chunks:
                yield self.chunks.pop(0)

    raw = ChunkedRaw()
    response = SimpleNamespace(
        headers={"Content-Encoding": "identity"},
        raw=raw,
    )

    sample, complete = scanner_module._read_bounded_identity_sample(
        response,
        limit=64,
    )

    assert sample == b"first-second-third"
    assert complete is True
    assert raw.requested_amounts
    assert all(amount <= 64 for amount in raw.requested_amounts)


def test_bounded_identity_sample_never_exceeds_limit_for_large_chunks():
    class LargeChunkRaw:
        def __init__(self):
            self.requested_amounts = []

        def stream(self, amt, decode_content=False):
            assert decode_content is False
            self.requested_amounts.append(amt)
            yield b"x" * (amt + 4096)

    raw = LargeChunkRaw()
    response = SimpleNamespace(
        headers={"Content-Encoding": "identity"},
        raw=raw,
    )

    sample, complete = scanner_module._read_bounded_identity_sample(
        response,
        limit=1024,
    )

    assert sample == b"x" * 1024
    assert len(sample) == 1024
    assert complete is False
    assert raw.requested_amounts == [1024]


def test_bounded_identity_sample_marks_truncated_content_length_incomplete():
    class InterruptedRaw:
        def stream(self, amt, decode_content=False):
            assert decode_content is False
            yield b"partial"
            raise http.client.IncompleteRead(b"", 20)

    response = SimpleNamespace(
        headers={
            "Content-Encoding": "identity",
            "Content-Length": "27",
        },
        raw=InterruptedRaw(),
    )

    sample, complete = scanner_module._read_bounded_identity_sample(
        response,
        limit=4096,
    )

    assert sample == b""
    assert complete is False


def test_response_and_session_are_closed_after_body_read_failure(monkeypatch):
    class RawHeaders:
        def keys(self):
            return ["Content-Type", "Content-Length"]

        def getlist(self, name):
            values = {
                "Content-Type": ["text/html"],
                "Content-Length": ["100"],
            }
            return values.get(name, [])

    class BrokenRaw:
        headers = RawHeaders()

        def stream(self, amt, decode_content=False):
            yield b"partial"
            raise http.client.IncompleteRead(b"", 93)

    class FakeResponse:
        status_code = 200
        headers = {
            "Content-Type": "text/html",
            "Content-Length": "100",
        }
        raw = BrokenRaw()

        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    response = FakeResponse()

    class FakeSession:
        def __init__(self):
            self.trust_env = True
            self.closed = False

        def mount(self, _prefix, _adapter):
            pass

        def get(self, _url, **_kwargs):
            return response

        def close(self):
            self.closed = True

    session = FakeSession()
    monkeypatch.setattr(
        scanner_module.requests,
        "Session",
        lambda: session,
    )

    parsed = urlparse("https://example.com/")
    resolved_target = (parsed, "example.com", ["93.184.216.34"])
    capture = {}

    status, _headers, error = scanner_module._safe_get_response(
        "https://example.com/",
        resolved_target=resolved_target,
        disclosure_evidence_capture=capture,
    )

    assert status == 200
    assert error is None
    assert capture["sample"] == b""
    assert capture["sample_complete"] is False
    assert response.closed is True
    assert session.closed is True


def test_flask_expanded_scan_pins_dns_ip_and_verifies_tls_on_real_socket(
    tmp_path,
    monkeypatch,
):
    from requests.adapters import HTTPAdapter
    from urllib3.util import connection as urllib3_connection
    from security_scanner.checks.disclosure_evidence import DisclosureEvidence
    from security_scanner.checks.result import CheckResult

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
cdScMV6zKObs2tCHyEtMQxjFbNMakkd9LYrQKBgDw
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

    body = b"RAW_RESPONSE_SECRET_DO_NOT_LEAK|" + (b"x" * 20000)
    body_samples = []
    dns_lookups = []
    received_sni = []
    requested_socket_addresses = []
    connected_peers = []
    requests_seen = []
    tls_metadata = []

    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(
        certfile=str(certificate_path),
        keyfile=str(key_path),
    )
    tls_context.set_servername_callback(
        lambda _sock, server_name, _context: received_sni.append(server_name)
    )

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            requests_seen.append(self.path)
            self.send_response(200)
            self.send_header(
                "Strict-Transport-Security",
                "max-age=31536000",
            )
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # Deliberately use chunked transfer encoding with no Content-Length.
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            try:
                for offset in range(0, len(body), 1024):
                    chunk = body[offset:offset + 1024]
                    self.wfile.write(
                        f"{len(chunk):X}\r\n".encode("ascii")
                        + chunk
                        + b"\r\n"
                    )
                    self.wfile.flush()
                    time.sleep(0.001)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except OSError:
                # The scanner may close the stream as soon as its sample cap is reached.
                pass

        def log_message(self, *_args):
            pass

    class TLSServer(HTTPServer):
        def get_request(self):
            raw_socket, address = super().get_request()
            try:
                return tls_context.wrap_socket(raw_socket, server_side=True), address
            except OSError:
                raw_socket.close()
                raise

        def handle_error(self, _request, _client_address):
            # A hostname-mismatch test deliberately closes the TLS handshake.
            pass

    server = TLSServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    original_getaddrinfo = socket.getaddrinfo

    def controlled_getaddrinfo(
        host,
        port,
        family=0,
        type=0,
        proto=0,
        flags=0,
    ):
        if host in ("localhost", "wrong.example"):
            dns_lookups.append((host, port))
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", port),
                )
            ]
        if host == "127.0.0.1":
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", port),
                )
            ]
        return original_getaddrinfo(host, port, family, type, proto, flags)

    monkeypatch.setattr(socket, "getaddrinfo", controlled_getaddrinfo)

    original_parse_target = scanner_module._parse_target_url

    def parse_local_test_target(url):
        parsed = urlparse(url)
        if (
            parsed.scheme == "https"
            and parsed.hostname in ("localhost", "wrong.example")
            and parsed.port in (None, 443)
        ):
            return (parsed, parsed.hostname), None
        return original_parse_target(url)

    monkeypatch.setattr(
        scanner_module,
        "_parse_target_url",
        parse_local_test_target,
    )

    original_ip_policy = scanner_module._is_allowed_ip
    monkeypatch.setattr(
        scanner_module,
        "_is_allowed_ip",
        lambda address: address.is_loopback or original_ip_policy(address),
    )

    real_create_connection = urllib3_connection.create_connection

    def route_pinned_connection(address, *args, **kwargs):
        requested_socket_addresses.append(address)
        assert address == ("127.0.0.1", 443)
        connected_socket = real_create_connection(
            ("127.0.0.1", server.server_port),
            *args,
            **kwargs,
        )
        connected_peers.append(connected_socket.getpeername())
        return connected_socket

    monkeypatch.setattr(
        urllib3_connection,
        "create_connection",
        route_pinned_connection,
    )

    real_cert_verify = HTTPAdapter.cert_verify

    def trust_only_the_local_test_certificate(
        adapter,
        connection,
        request_url,
        _verify,
        cert,
    ):
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
        trust_only_the_local_test_certificate,
    )

    original_sample_reader = scanner_module._read_bounded_identity_sample

    def observe_bounded_sample(response, limit):
        sample, complete = original_sample_reader(response, limit)
        body_samples.append((sample, complete, limit))
        return sample, complete

    monkeypatch.setattr(
        scanner_module,
        "_read_bounded_identity_sample",
        observe_bounded_sample,
    )

    original_tls_capture = scanner_module._capture_tls_socket_metadata

    def observe_tls_metadata(tls_socket, destination):
        original_tls_capture(tls_socket, destination)
        tls_metadata.append(dict(destination))

    monkeypatch.setattr(
        scanner_module,
        "_capture_tls_socket_metadata",
        observe_tls_metadata,
    )

    def skipped_dns_result(check_id, title):
        return CheckResult(
            check_id=check_id,
            title=title,
            status="skipped",
            severity="info",
            confidence="low",
            evidence="DNS evaluator isolated in the local TLS integration fixture.",
            explanation="No public DNS conclusion is inferred from this local test.",
            recommendation="Run the dedicated DNS evaluator tests.",
            limitations=("This result belongs only to the controlled test fixture.",),
        )

    monkeypatch.setattr(
        report_module,
        "_safe_cors_preflight",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        report_module,
        "_safe_http_redirect_probe",
        lambda *_args, **_kwargs: "connection",
    )
    monkeypatch.setattr(
        report_module,
        "_collect_disclosure_evidence",
        lambda *_args, **_kwargs: DisclosureEvidence(),
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_spf_domain",
        lambda *_args, **_kwargs: skipped_dns_result("dns_spf", "SPF"),
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_dmarc_domain",
        lambda *_args, **_kwargs: skipped_dns_result("dns_dmarc", "DMARC"),
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_dnssec_domain",
        lambda *_args, **_kwargs: skipped_dns_result("dnssec", "DNSSEC"),
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_takeover_domain",
        lambda *_args, **_kwargs: skipped_dns_result(
            "subdomain_takeover_indicators",
            "Subdomain takeover indicators",
        ),
    )

    app = api_module.create_app()
    client = app.test_client()
    payload = {
        "target_url": "https://localhost/",
        "authorization_confirmed": True,
        "include_expanded_checks": True,
    }

    try:
        response = client.post("/api/v1/scan", json=payload)

        assert response.status_code == 200
        report = response.get_json()
        assert report["status"] == "completed"
        assert report["http_status"] == 200

        findings = {item["check_id"]: item for item in report["findings"]}
        assert findings["https_connection"]["status"] == "passed"
        assert findings["header_hsts"]["status"] == "passed"
        assert findings["header_csp"]["status"] == "passed"

        assert dns_lookups.count(("localhost", 443)) == 1
        assert requested_socket_addresses == [("127.0.0.1", 443)]
        assert connected_peers == [("127.0.0.1", server.server_port)]
        assert received_sni == ["localhost"]
        assert tls_metadata and tls_metadata[0]["version"].startswith("TLSv")
        assert tls_metadata[0]["cipher"]
        assert requests_seen == ["/"]

        assert len(body_samples) == 1
        sample, complete, limit = body_samples[0]
        assert limit == 16 * 1024
        assert len(sample) == limit
        assert sample == body[:limit]
        assert complete is False
        assert b"RAW_RESPONSE_SECRET_DO_NOT_LEAK" not in response.get_data()

        # A trusted certificate for localhost must still fail for a different
        # requested hostname through the same Flask -> scanner -> TLS path.
        mismatch = client.post(
            "/api/v1/scan",
            json={
                "target_url": "https://wrong.example/",
                "authorization_confirmed": True,
            },
        )
        assert mismatch.status_code == 200
        mismatch_report = mismatch.get_json()
        mismatch_findings = {
            item["check_id"]: item for item in mismatch_report["findings"]
        }
        assert mismatch_report["http_status"] is None
        assert mismatch_findings["https_connection"]["status"] == "warning"
        assert mismatch_findings["header_hsts"]["status"] == "not_verified"
        assert received_sni == ["localhost", "wrong.example"]
        assert dns_lookups.count(("wrong.example", 443)) == 1
        assert requests_seen == ["/"]
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
