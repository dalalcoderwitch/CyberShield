import logging
import time
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from security_scanner.checks.disclosure_evidence import (
    DIRECTORY_PATHS,
    PUBLIC_SECURITY_PATHS,
    SENSITIVE_PATHS,
    DisclosureEvidence,
    classify_error_sample,
    classify_sensitive_sample,
    classify_server_headers,
    has_directory_index_marker,
    is_same_https_origin,
    is_source_map_json,
    local_asset_references,
    source_map_reference,
)
from security_scanner.checks.response_runner import evaluate_week3_evidence
from security_scanner.checks.evidence import EvidenceCollection
from security_scanner.checks.context import CheckContext
import security_scanner.scanner as scanner


def results_for(data, status=200):
    return {
        result.check_id: result
        for result in evaluate_week3_evidence(EvidenceCollection(
            http_status=status,
            tls_verified=True,
            disclosure_evidence=data,
        ))
    }


@pytest.mark.parametrize(("path", "sample", "kind"), [
    ("/.env", b"SECRET_KEY=PRIVATE_123\n", "dotenv"),
    ("/.git/HEAD", b"ref: refs/heads/main\n", "git_head"),
    ("/.git/config", b'[core]\n\trepositoryformatversion = 0\n', "git_config"),
    ("/.DS_Store", b"\x00\x00\x00\x01Bud1payload", "ds_store"),
    ("/backup.zip", b"PK\x03\x04payload", "zip_archive"),
    ("/database.sql", b"-- MySQL dump\nCREATE TABLE users (id int);", "sql_dump"),
])
def test_fixed_sensitive_path_signatures(path, sample, kind):
    assert path in SENSITIVE_PATHS
    assert classify_sensitive_sample(path, sample) == kind
    assert classify_sensitive_sample(path, b"<html>Not Found</html>") is None


def test_sensitive_file_statuses_soft_404_and_privacy(monkeypatch):
    secret = "SECRET_VALUE_NEVER_IN_REPORT_581"
    statuses = {
        "/.env": (200, f"API_KEY={secret}\n".encode()),
        "/.git/HEAD": (206, b"ref: refs/heads/main\n"),
        "/.git/config": (403, b""),
        "/.DS_Store": (404, b""),
        "/backup.zip": (410, b""),
        "/database.sql": (None, b""),
    }
    seen = []

    def fake_probe(_target, path, **_kwargs):
        seen.append(path)
        status, body = statuses.get(path, (404, b""))
        return {"status": status, "sample": body, "complete": True,
                "media_type": "text/plain", "attempted": True, "error": None}

    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://local.invalid/a"), "local.invalid", ["93.184.216.34"])
    evidence = scanner._collect_disclosure_evidence(target, 500, {
        "sample": b"Traceback (most recent call last):\n  File '/srv/app/private.py'\nSQLSTATE[secret]",
        "sample_complete": True, "media_type": "text/html", "header_available": True,
        "server_header_names": (), "server_info_types": (),
    })
    findings = results_for(evidence, status=500)
    assert tuple(seen[:6]) == SENSITIVE_PATHS
    assert evidence.request_count == 11
    assert findings["sensitive_file_exposure"].status == "warning"
    assert findings["error_information_disclosure"].status == "warning"
    assert secret not in repr(findings)
    assert "private.py" not in repr(findings)
    assert "SQLSTATE" not in repr(findings)


def test_sensitive_soft_404_and_incomplete_content_do_not_pass(monkeypatch):
    def fake_probe(_target, path, **_kwargs):
        return {"status": 200, "sample": b"<html><title>Not Found</title></html>",
                "complete": True, "media_type": "text/html", "attempted": True}

    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://local.invalid/"), "local.invalid", ["93.184.216.34"])
    data = scanner._collect_disclosure_evidence(target, 200, {
        "sample": b"", "sample_complete": False, "media_type": "text/html",
        "header_available": True, "server_header_names": (), "server_info_types": (),
    })
    assert results_for(data)["sensitive_file_exposure"].status == "not_verified"
    assert all(state == "unknown" for _status, state, _marker in data.sensitive_results)


def test_sensitive_only_404_410_passes_with_fixed_scope_limitation(monkeypatch):
    def fake_probe(_target, path, **_kwargs):
        status = 404 if path in ("/.env", "/.git/HEAD", "/.DS_Store") else 410
        return {"status": status, "sample": b"", "complete": False,
                "media_type": "unknown", "attempted": True}

    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://local.invalid/"), "local.invalid", ["93.184.216.34"])
    data = scanner._collect_disclosure_evidence(target, 200, {})
    finding = results_for(data)["sensitive_file_exposure"]
    assert finding.status == "passed"
    assert "ستة" in finding.limitations[0]


def test_one_probe_internal_failure_does_not_abort_remaining_disclosure_checks(monkeypatch):
    seen = []

    def fake_probe(_target, path, **_kwargs):
        seen.append(path)
        if path == "/.env":
            raise RuntimeError("SENSITIVE_BODY_MUST_NOT_BE_LOGGED")
        return {"status": 404, "sample": b"", "complete": False,
                "media_type": "unknown", "attempted": True}

    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://local.invalid/"), "local.invalid", ["93.184.216.34"])
    evidence = scanner._collect_disclosure_evidence(target, 200, {})
    findings = results_for(evidence)
    assert len(seen) == 11
    assert findings["sensitive_file_exposure"].status == "not_verified"
    assert findings["directory_listing"].status == "passed"
    assert "SENSITIVE_BODY_MUST_NOT_BE_LOGGED" not in repr(findings)


@pytest.mark.parametrize(("status", "body", "expected"), [
    (206, b"API_KEY=private\n", "found"),
    (403, b"", "unknown"),
    (404, b"", "not_found"),
    (410, b"", "not_found"),
    (302, b"", "unknown"),
    (None, b"", "unknown"),
])
def test_sensitive_path_http_statuses_are_interpreted_conservatively(monkeypatch, status, body, expected):
    def fake_probe(_target, path, **_kwargs):
        if path == "/.env":
            return {"status": status, "sample": body, "complete": True,
                    "media_type": "text/plain", "attempted": True}
        return {"status": 404, "sample": b"", "complete": False,
                "media_type": "unknown", "attempted": True}

    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://local.invalid/"), "local.invalid", ["93.184.216.34"])
    data = scanner._collect_disclosure_evidence(target, 200, {})
    assert data.sensitive_results[0][1] == expected
    if expected in {"unknown", "found"}:
        assert results_for(data)["sensitive_file_exposure"].status == (
            "warning" if expected == "found" else "not_verified"
        )


def test_source_map_helpers_and_same_origin_policy():
    html = b'<script src="/static/app.js"></script><link rel="stylesheet" href="/site.css">'
    assert local_asset_references(html) == ("/static/app.js", "/site.css")
    assert source_map_reference(b"//# sourceMappingURL=app.js.map\n") == "app.js.map"
    assert is_source_map_json(b'{"version":3,"sources":["private.ts"],"mappings":"AAAA","sourcesContent":["secret"]}')
    assert not is_source_map_json(b'{"version":3,"sources":["x"]}')
    assert is_same_https_origin("https://site.invalid/a/index.html", "/app.js")
    assert is_same_https_origin("https://site.invalid/a/index.html", "//site.invalid:443/app.js")
    for value in (
        "https://outside.invalid/app.js", "http://site.invalid/app.js",
        "https://user:pass@site.invalid/app.js", "https://site.invalid:8443/app.js",
        "javascript:alert(1)", r"\\outside.invalid\app.js",
    ):
        assert not is_same_https_origin("https://site.invalid/", value)


def test_source_map_reference_without_readable_map_is_not_reported_as_confirmed(monkeypatch):
    def fake_probe(_target, path, **_kwargs):
        if path == "/app.js":
            return {"status": 200, "sample": b"//# sourceMappingURL=app.js.map",
                    "complete": True, "media_type": "application/javascript", "attempted": True}
        if path == "/app.js.map":
            return {"status": 404, "sample": b"", "complete": False,
                    "media_type": "unknown", "attempted": True}
        return {"status": 404, "sample": b"", "complete": False,
                "media_type": "unknown", "attempted": True}

    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://site.invalid/index.html"), "site.invalid", ["93.184.216.34"])
    data = scanner._collect_disclosure_evidence(target, 200, {
        "sample": b'<script src="/app.js"></script>', "sample_complete": True,
        "media_type": "text/html", "header_available": True,
    })
    assert data.source_map_state == "reference_only"
    assert results_for(data)["source_maps_exposure"].status == "not_verified"


def test_incomplete_html_without_references_is_not_passed(monkeypatch):
    def fake_probe(_target, _path, **_kwargs):
        return {"status": 404, "sample": b"", "complete": False,
                "media_type": "unknown", "attempted": True}
    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://site.invalid/index.html"), "site.invalid", ["93.184.216.34"])
    data = scanner._collect_disclosure_evidence(target, 200, {
        "sample": b"<html>", "sample_complete": False,
        "media_type": "text/html", "header_available": True,
    })
    assert data.source_map_state == "unknown"
    assert results_for(data)["source_maps_exposure"].status == "not_verified"


def test_directory_listing_uses_only_clear_index_markers():
    assert DIRECTORY_PATHS == ("/uploads/", "/files/")
    assert has_directory_index_marker(b"<html><title>Index of /uploads/</title></html>")
    assert has_directory_index_marker(b"<h1>Index of /files/</h1>")
    assert not has_directory_index_marker(b"<html><title>Not Found</title><h1>404</h1></html>")
    data = DisclosureEvidence(directory_results=((200, "listing"), (403, "unknown")))
    finding = results_for(data)["directory_listing"]
    assert finding.status == "warning"
    assert "uploads" not in finding.evidence.lower()


def test_server_header_evidence_redacts_values_and_only_specific_details_warn():
    names, types = classify_server_headers({
        "server": ("Apache/2.4.99",),
        "x-powered-by": ("PHP/8.9.1",),
        "via": ("1.1 proxy",),
    })
    assert names == ("Server", "X-Powered-By", "Via")
    assert set(types) == {"version", "technology", "runtime", "proxy"}
    finding = results_for(DisclosureEvidence(
        server_headers_available=True,
        server_header_names=names,
        server_info_types=types,
    ))["server_information_disclosure"]
    assert (finding.status, finding.severity) == ("warning", "low")
    assert "Apache" not in repr(finding) and "2.4.99" not in repr(finding)
    generic_names, generic_types = classify_server_headers({"server": ("internal",), "via": ("proxy",)})
    generic = results_for(DisclosureEvidence(
        server_headers_available=True,
        server_header_names=generic_names,
        server_info_types=generic_types,
    ))["server_information_disclosure"]
    assert generic.status == "passed"
    missing = results_for(DisclosureEvidence(
        server_headers_available=True,
        server_header_names=(),
        server_info_types=(),
    ))["server_information_disclosure"]
    unavailable = results_for(DisclosureEvidence(
        server_headers_available=None,
    ))["server_information_disclosure"]
    assert missing.status == "passed"
    assert unavailable.status == "not_verified"


@pytest.mark.parametrize(("sample", "expected"), [
    (b"Traceback (most recent call last):", "stack_trace"),
    (b"failed at /var/www/app/private.py", "internal_path"),
    (b"SQLSTATE[42S02] table missing", "sql_error"),
    (b"Werkzeug Debugger is active", "framework_debug"),
    (b"<html><h1>Internal Server Error</h1></html>", None),
])
def test_error_signatures_store_only_generic_categories(sample, expected):
    patterns = classify_error_sample(sample)
    if expected:
        assert expected in patterns
    else:
        assert patterns == ()
    assert all(len(item) < 30 for item in patterns)


def test_error_information_skips_non_errors_and_not_verifies_short_samples():
    assert results_for(DisclosureEvidence(error_status=None), status=200)["error_information_disclosure"].status == "skipped"
    short = results_for(DisclosureEvidence(error_status=500, error_sample_complete=False), status=500)
    assert short["error_information_disclosure"].status == "not_verified"
    complete = results_for(DisclosureEvidence(error_status=500, error_sample_complete=True), status=500)
    assert complete["error_information_disclosure"].status == "passed"


def test_public_security_file_status_and_content_type_rules():
    assert PUBLIC_SECURITY_PATHS == ("/.well-known/security.txt", "/security.txt", "/robots.txt")
    missing = DisclosureEvidence(public_file_results=(
        (404, "security", "not_found", "unknown"),
        (410, "security", "not_found", "unknown"),
        (200, "robots", "present", "text/plain"),
    ))
    result = results_for(missing)["public_security_files"]
    assert (result.status, result.severity) == ("warning", "low")
    assert "robots.txt" in result.explanation
    present = DisclosureEvidence(public_file_results=(
        (404, "security", "not_found", "unknown"),
        (200, "security", "present", "text/plain"),
        (200, "robots", "present", "text/plain"),
    ))
    assert results_for(present)["public_security_files"].status == "passed"
    unexpected = DisclosureEvidence(public_file_results=((403, "security", "unknown", "text/html"),))
    assert results_for(unexpected)["public_security_files"].status == "not_verified"


class _HeaderBag:
    def __init__(self, values):
        self.values = values

    def keys(self):
        return self.values.keys()

    def getlist(self, name):
        return list(self.values.get(name, ()))


class _RawBody:
    def __init__(self, body):
        self.body = body
        self.read = 0
        self.offset = 0

    def stream(self, amt, decode_content):
        assert decode_content is False
        assert 0 < amt <= 4096
        while self.offset < len(self.body):
            chunk = self.body[self.offset:self.offset + amt]
            self.read += len(chunk)
            self.offset += len(chunk)
            yield chunk


def test_bounded_reader_never_reads_more_than_4_or_16_kib():
    body = b"A" * 20000
    for limit in (4096, 16384):
        raw = _RawBody(body)
        response = SimpleNamespace(
            headers={"Content-Encoding": "identity", "Content-Length": str(len(body))},
            raw=raw,
        )
        sample, complete = scanner._read_bounded_identity_sample(response, limit)
        assert len(sample) == limit
        assert raw.read == limit
        assert complete is False


def test_bounded_reader_refuses_compressed_content_without_decompression():
    raw = _RawBody(b"compressed-content")
    response = SimpleNamespace(
        headers={"Content-Encoding": "gzip"},
        raw=raw,
    )
    sample, complete = scanner._read_bounded_identity_sample(response, 4096)
    assert sample == b"" and complete is False
    assert raw.read == 0


def test_probe_pins_ip_uses_verified_tls_bounded_time_and_closes_resources(monkeypatch):
    raw = _RawBody(b"SAFE")
    response = SimpleNamespace(
        status_code=200,
        headers={"Content-Type": "text/plain", "Content-Encoding": "identity", "Content-Length": "4"},
        raw=SimpleNamespace(headers=_HeaderBag({
            "Content-Type": ["text/plain"], "Content-Encoding": ["identity"], "Content-Length": ["4"],
        }), stream=raw.stream),
        closed=False,
    )
    response.close = lambda: setattr(response, "closed", True)

    class FakeSession:
        def __init__(self):
            self.trust_env = True
            self.mounted = {}
            self.call = None
            self.closed = False

        def mount(self, prefix, adapter):
            self.mounted[prefix] = adapter

        def get(self, url, **kwargs):
            self.call = (url, kwargs)
            return response

        def close(self):
            self.closed = True

    fake_session = FakeSession()
    monkeypatch.setattr(scanner.requests, "Session", lambda: fake_session)
    target = (urlparse("https://site.invalid/a"), "site.invalid", ["93.184.216.34"])
    result = scanner._safe_disclosure_get(target, "/.env", deadline=time.monotonic() + 5)
    assert result["sample"] == b"SAFE"
    assert result["attempted"] is True
    url, kwargs = fake_session.call
    assert url == "https://93.184.216.34:443/.env"
    assert kwargs["headers"]["Host"] == "site.invalid"
    assert kwargs["headers"]["Range"] == "bytes=0-4095"
    assert kwargs["headers"]["Accept-Encoding"] == "identity"
    assert "Cookie" not in kwargs["headers"] and "Authorization" not in kwargs["headers"]
    assert kwargs["verify"] is True and kwargs["allow_redirects"] is False and kwargs["stream"] is True
    assert kwargs["timeout"].connect_timeout <= 2 and kwargs["timeout"].read_timeout <= 2
    assert fake_session.trust_env is False
    assert fake_session.mounted["https://"].hostname == "site.invalid"
    assert response.closed and fake_session.closed


def test_probe_does_not_read_redirect_body_and_skips_when_deadline_expired(monkeypatch):
    raw = _RawBody(b"must not read")
    response = SimpleNamespace(
        status_code=302, headers={"Content-Type": "text/plain"},
        raw=SimpleNamespace(headers=_HeaderBag({"Content-Type": ["text/plain"]}), stream=raw.stream),
        closed=False,
    )
    response.close = lambda: setattr(response, "closed", True)

    class FakeSession:
        trust_env = True
        def mount(self, *_args): pass
        def get(self, *_args, **_kwargs): return response
        def close(self): self.closed = True

    session = FakeSession()
    session.closed = False
    created = []
    monkeypatch.setattr(scanner.requests, "Session", lambda: (created.append(session) or session))
    target = (urlparse("https://site.invalid/"), "site.invalid", ["93.184.216.34"])
    redirect = scanner._safe_disclosure_get(target, "/.env")
    assert redirect["status"] == 302
    assert raw.read == 0
    assert response.closed and session.closed
    expired = scanner._safe_disclosure_get(target, "/.env", deadline=time.monotonic() - 1)
    assert expired["attempted"] is False and expired["error"] == "timeout"
    assert len(created) == 1


def test_probe_timeout_is_sanitized_and_closes_session(monkeypatch, caplog):
    class FakeSession:
        def __init__(self):
            self.closed = False
        def mount(self, *_args): pass
        def get(self, *_args, **_kwargs):
            raise scanner.requests.exceptions.Timeout("RAW_RESPONSE_SECRET")
        def close(self): self.closed = True

    session = FakeSession()
    monkeypatch.setattr(scanner.requests, "Session", lambda: session)
    target = (urlparse("https://site.invalid/"), "site.invalid", ["93.184.216.34"])
    result = scanner._safe_disclosure_get(target, "/.env")
    assert result["error"] == "timeout"
    assert result["attempted"] is True
    assert session.closed
    assert "RAW_RESPONSE_SECRET" not in caplog.text


def test_disclosure_collector_stays_within_exact_thirteen_path_budget(monkeypatch):
    seen = []
    bodies = {
        "/app.js": (200, b"//# sourceMappingURL=app.js.map\n", "application/javascript"),
        "/app.js.map": (200, b'{"version":3,"sources":["secret.ts"],"mappings":"AAAA"}', "application/json"),
    }

    def fake_probe(_target, path, **kwargs):
        seen.append((path, kwargs["limit"]))
        status, body, media = bodies.get(path, (404, b"", "unknown"))
        return {"status": status, "sample": body, "complete": True,
                "media_type": media, "attempted": True, "error": None}

    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://site.invalid/a/index.html"), "site.invalid", ["93.184.216.34"])
    capture = {
        "sample": b'<script src="/app.js"></script>', "sample_complete": True,
        "media_type": "text/html", "header_available": True,
        "server_header_names": (), "server_info_types": (),
    }
    evidence = scanner._collect_disclosure_evidence(target, 200, capture)
    assert len(seen) == evidence.request_count == 13
    assert seen[:6] == [(path, 4096) for path in SENSITIVE_PATHS]
    assert seen[6:8] == [("/app.js", 4096), ("/app.js.map", 4096)]
    assert seen[8:10] == [(path, 4096) for path in DIRECTORY_PATHS]
    assert seen[10:] == [(path, 4096) for path in PUBLIC_SECURITY_PATHS]
    assert evidence.source_map_state == "confirmed"
    assert "secret.ts" not in repr(evidence)
    assert capture == {}


def test_external_or_malformed_source_map_reference_is_never_requested(monkeypatch):
    seen = []

    def fake_probe(_target, path, **_kwargs):
        seen.append(path)
        return {"status": 200, "sample": b"//# sourceMappingURL=https://outside.invalid/app.map",
                "complete": True, "media_type": "text/javascript", "attempted": True}

    monkeypatch.setattr(scanner, "_safe_disclosure_get", fake_probe)
    target = (urlparse("https://site.invalid/index.html"), "site.invalid", ["93.184.216.34"])
    evidence = scanner._collect_disclosure_evidence(target, 200, {
        "sample": b'<script src="/app.js"></script>', "sample_complete": True,
        "media_type": "text/html", "header_available": True,
        "server_header_names": (), "server_info_types": (),
    })
    assert seen[6] == "/app.js"
    assert all("outside.invalid" not in path for path in seen)
    assert evidence.source_map_state == "reference_only"


def test_disclosure_evidence_rejects_over_budget_or_raw_classification():
    with pytest.raises(ValueError):
        DisclosureEvidence(request_count=14)
    with pytest.raises(ValueError):
        DisclosureEvidence(server_info_types=("SECRET SERVER VALUE",))


def test_server_and_location_raw_values_are_filtered_from_generic_evidence():
    server_secret = "SERVER_VERSION_PRIVATE_18"
    location_secret = "QUERY_SECRET_PRIVATE_29"
    context = CheckContext(
        safe_target_url="https://site.invalid",
        http_status=302,
        response_headers={
            "Server": f"Apache/{server_secret}",
            "Location": f"https://outside.invalid/?token={location_secret}",
            "Content-Type": "text/html",
        },
        disclosure_evidence=DisclosureEvidence(
            server_headers_available=True,
            server_header_names=("Server",),
            server_info_types=("technology", "version"),
        ),
    )
    evidence = EvidenceCollection.from_context(context)
    assert "server" not in context.response_headers
    assert "location" not in context.response_headers
    assert evidence.values_for_header("Server") == ()
    assert evidence.values_for_header("Location") == ()
    assert server_secret not in repr(context) and location_secret not in repr(context)
    assert server_secret not in repr(evidence) and location_secret not in repr(evidence)
