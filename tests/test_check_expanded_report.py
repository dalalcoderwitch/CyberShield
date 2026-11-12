from importlib import import_module

import pytest


report_module = import_module("security_scanner.report")

TARGET_URL = "https://example.com"

WEEK3_RESPONSE_CHECK_IDS = {
    "header_referrer_policy",
    "header_permissions_policy",
    "cookie_secure",
    "cookie_httponly",
    "cookie_samesite",
    "cors_misconfiguration",
    "open_redirect",
    "sensitive_file_exposure",
    "source_maps_exposure",
    "directory_listing",
    "server_information_disclosure",
    "error_information_disclosure",
    "public_security_files",
}

FOUNDATIONAL_CHECK_IDS = {
    "https_connection",
    "header_hsts",
    "header_csp",
    "header_x_content_type_options",
    "header_x_frame_options",
}

TLS_REDIRECT_CHECK_IDS = {
    "tls_certificate_expiry",
    "tls_certificate_chain",
    "tls_protocol_config",
    "http_to_https_redirect",
    "redirect_destination_safety",
}

WEEK3_EXPANDED_CHECK_IDS = TLS_REDIRECT_CHECK_IDS | WEEK3_RESPONSE_CHECK_IDS

DNS_WEEK4_CHECK_IDS = {"dns_dmarc", "dns_spf", "dnssec"}

EXPECTED_REPORT_CHECK_IDS = (
    FOUNDATIONAL_CHECK_IDS
    | TLS_REDIRECT_CHECK_IDS
    | WEEK3_RESPONSE_CHECK_IDS
    | DNS_WEEK4_CHECK_IDS
    | {"cache_security", "subdomain_takeover_indicators", "xss_passive_indicators", "sqli_passive_indicators"}
)


def install_mock_response(monkeypatch, result):
    calls = []

    def fake_safe_get_response(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    monkeypatch.setattr(
        report_module,
        "_safe_get_response",
        fake_safe_get_response,
    )
    return calls


def test_default_report_keeps_five_findings(monkeypatch):
    headers = {
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=()",
        "Cache-Control": "no-store",
    }
    calls = install_mock_response(
        monkeypatch,
        (200, headers, None),
    )

    report = report_module.scan_target(TARGET_URL)

    assert len(calls) == 1
    assert len(report["findings"]) == 5
    assert not (
        WEEK3_RESPONSE_CHECK_IDS
        & {item["check_id"] for item in report["findings"]}
    )


def test_expanded_report_contains_30_findings_from_one_response(monkeypatch):
    headers = {
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=()",
        "Cache-Control": "no-store",
    }
    calls = install_mock_response(
        monkeypatch,
        (200, headers, None),
    )

    report = report_module.scan_target(
        TARGET_URL,
        include_expanded_checks=True,
    )

    findings = report["findings"]
    check_ids = [item["check_id"] for item in findings]

    assert len(calls) == 1
    assert len(findings) == 30
    assert len(set(check_ids)) == 30
    assert set(check_ids) == EXPECTED_REPORT_CHECK_IDS
    assert check_ids.count("cache_security") == 1
    assert next(item for item in findings if item["check_id"] == "cache_security")["status"] == "passed"
    assert {"tls_certificate_expiry", "tls_certificate_chain", "tls_protocol_config", "http_to_https_redirect", "redirect_destination_safety"} <= set(check_ids)
    assert report["summary"]["total"] == 30


def test_expanded_findings_are_not_verified_without_response(monkeypatch):
    install_mock_response(
        monkeypatch,
        (None, {}, "timeout"),
    )

    report = report_module.scan_target(
        TARGET_URL,
        include_expanded_checks=True,
    )

    expanded_findings = [
        item
        for item in report["findings"]
        if item["check_id"] in WEEK3_EXPANDED_CHECK_IDS
    ]

    assert len(report["findings"]) == 30
    assert len(expanded_findings) == 18
    assert all(
        item["status"] == "not_verified"
        for item in expanded_findings
    )


def test_expanded_report_does_not_expose_raw_header_values(monkeypatch):
    secret = "PRIVATE_HEADER_VALUE_MUST_NOT_LEAK"
    headers = {
        "Referrer-Policy": secret,
        "Permissions-Policy": secret,
        "Cache-Control": f'no-store, extension="{secret}"',
    }
    install_mock_response(
        monkeypatch,
        (200, headers, None),
    )

    report = report_module.scan_target(
        TARGET_URL,
        include_expanded_checks=True,
    )

    assert secret not in repr(report["findings"])


def test_expanded_option_rejects_non_boolean_before_http(monkeypatch):
    calls = install_mock_response(
        monkeypatch,
        (200, {}, None),
    )

    with pytest.raises(TypeError):
        report_module.scan_target(
            TARGET_URL,
            include_expanded_checks="yes",
        )

    assert calls == []


@pytest.mark.parametrize("response, expected", [
    ((200, {"Cache-Control": "no-store"}, None), "passed"),
    ((200, {}, None), "not_verified"),
    ((200, {"Cache-Control": "public, max-age=3600"}, None), "not_verified"),
    ((200, {"Cache-Control": "no-store=invalid"}, None), "not_verified"),
    ((None, {}, "timeout"), "not_verified"),
])
def test_cache_report_uses_existing_response_once(monkeypatch, response, expected):
    calls = install_mock_response(monkeypatch, response)
    report = report_module.scan_target(TARGET_URL, include_expanded_checks=True)
    cache = [item for item in report["findings"] if item["check_id"] == "cache_security"]
    assert len(calls) == len(cache) == 1
    assert cache[0]["status"] == expected
    assert len(report["findings"]) == report["summary"]["total"] == 30
    for status in ("passed", "warning", "not_verified", "error", "skipped"):
        assert report["summary"][status] == sum(
            item["status"] == status for item in report["findings"]
        )


def test_cache_failure_is_isolated_in_expanded_report(monkeypatch, caplog):
    from security_scanner.checks.cache_checks import CacheSecurityEvaluator

    secret = "CACHE_EXCEPTION_SECRET"
    calls = install_mock_response(monkeypatch, (200, {"Cache-Control": "no-store"}, None))
    baseline = report_module.scan_target(TARGET_URL, include_expanded_checks=True)
    calls.clear()

    def fail(self, evidence):
        raise RuntimeError(secret)

    monkeypatch.setattr(CacheSecurityEvaluator, "_evaluate", fail)
    report = report_module.scan_target(TARGET_URL, include_expanded_checks=True)
    findings = {item["check_id"]: item for item in report["findings"]}
    assert len(calls) == 1
    assert len(findings) == len(report["findings"]) == 30
    assert report["status"] == "completed"
    assert findings["cache_security"]["status"] == "error"
    assert findings["https_connection"]["status"] == "passed"
    assert secret not in repr(report) + caplog.text
    assert report["summary"]["error"] == 1
    assert [item for item in baseline["findings"] if item["check_id"] != "cache_security"] == [
        item for item in report["findings"] if item["check_id"] != "cache_security"
    ]


@pytest.mark.parametrize("mode, expected", [
    ("matching", "not_verified"),
    ("wrong_owner", "not_verified"),
    ("missing_signature", "not_verified"),
    ("resolver_exception", "error"),
])
def test_dnssec_mocked_messages_reach_report_without_claiming_validation(monkeypatch, caplog, mode, expected):
    from types import SimpleNamespace
    from urllib.parse import urlsplit
    import dns.flags
    import dns.message
    import dns.rrset
    import security_scanner.checks.dnssec_checks as dnssec
    from security_scanner.checks.result import CheckResult

    resolver_calls = []
    http_calls = []
    exception_secret = "PRIVATE_RESOLVER_EXCEPTION_973"
    key_text, signature_text = "QUJDRA==", "RUZHSA=="

    def resolve(name, kind, **kwargs):
        resolver_calls.append((name, kind, kwargs))
        if mode == "resolver_exception":
            raise RuntimeError(exception_secret)
        message = dns.message.make_response(dns.message.make_query(name, kind))
        if kind == "SOA":
            rrset = dns.rrset.from_text(
                "example.com.", 60, "IN", "SOA",
                "ns.example.com. hostmaster.example.com. 1 60 60 60 60",
            )
            message.authority.append(rrset)
            return SimpleNamespace(rrset=None, response=message)
        owner = "other.example.net." if mode == "wrong_owner" else "example.com."
        rrset = dns.rrset.from_text(owner, 60, "IN", "DNSKEY", f"257 3 8 {key_text}")
        message.flags |= dns.flags.AD
        message.answer.append(rrset)
        if mode != "missing_signature":
            message.answer.append(dns.rrset.from_text(
                owner, 60, "IN", "RRSIG",
                f"DNSKEY 8 2 60 20300101000000 20200101000000 12345 example.com. {signature_text}",
            ))
        return SimpleNamespace(rrset=rrset, response=message)

    monkeypatch.setattr(dnssec.dns.resolver, "Resolver", lambda **kwargs: SimpleNamespace(
        use_edns=lambda **kwargs: None, resolve=resolve,
    ))
    def fake_http(url, **kwargs):
        http_calls.append(url)
        kwargs["validated_target_capture"]["target"] = (
            urlsplit(url), "www.example.com", ["93.184.216.34"],
        )
        return 200, {"Cache-Control": "no-store", "Set-Cookie": "PRIVATE_COOKIE_973"}, None

    monkeypatch.setattr(report_module, "_safe_get_response", fake_http)
    monkeypatch.setattr(report_module, "_safe_cors_preflight", lambda *args, **kwargs: None)
    monkeypatch.setattr(report_module, "_safe_http_redirect_probe", lambda *args, **kwargs: "connection")
    monkeypatch.setattr(report_module, "_collect_disclosure_evidence", lambda *args, **kwargs: None)

    def other_dns_result(check_id):
        return CheckResult(
            check_id=check_id, title="Mocked DNS check", status="not_verified",
            severity="info", confidence="low", evidence="No network operation.",
            explanation="Test only.", recommendation="Test only.", limitations=("Test only.",),
        )
    monkeypatch.setattr(report_module, "evaluate_spf_domain", lambda *args, **kwargs: other_dns_result("dns_spf"))
    monkeypatch.setattr(report_module, "evaluate_dmarc_domain", lambda *args, **kwargs: other_dns_result("dns_dmarc"))

    report = report_module.scan_target("https://www.example.com/", include_expanded_checks=True)
    findings = [item for item in report["findings"] if item["check_id"] == "dnssec"]
    assert len(findings) == 1
    assert findings[0]["status"] == expected
    assert findings[0]["severity"] == "info"
    assert findings[0]["confidence"] == "low"
    assert len(report["findings"]) == report["summary"]["total"] == 30
    assert http_calls == ["https://www.example.com/"]
    assert [(name, kind) for name, kind, _ in resolver_calls] == (
        [("www.example.com.", "SOA")] if mode == "resolver_exception" else
        [("www.example.com.", "SOA"), ("example.com.", "DNSKEY")]
    )
    assert all(kwargs["search"] is False and kwargs["lifetime"] <= 2 for _, _, kwargs in resolver_calls)
    if expected == "not_verified":
        assert any("cryptographic" in item for item in findings[0]["limitations"])
        assert any("AD is a resolver assertion" in item for item in findings[0]["limitations"])
    if mode == "matching":
        assert "1 DNSKEY" in findings[0]["evidence"]
        assert "1 matching RRSIG" in findings[0]["evidence"]
        assert "no configured trust" in findings[0]["explanation"]
    if mode == "missing_signature":
        assert "The resolver set AD" in findings[0]["evidence"]
    assert all(value not in repr(report) + caplog.text for value in (
        key_text, signature_text, exception_secret, "PRIVATE_COOKIE_973", "other.example.net",
    ))
    assert all(item["status"] != "passed" for item in findings)


def test_takeover_unresolved_hostname_gets_dns_only_diagnostic(monkeypatch, caplog):
    from types import SimpleNamespace
    import dns.message
    import dns.name
    import dns.rcode
    import dns.resolver
    import dns.rrset
    import security_scanner.scanner as scanner
    import security_scanner.checks.takeover_checks as takeover

    original_calls, diagnostic_calls = [], []
    def unresolved(hostname, deadline=None):
        original_calls.append(hostname)
        return None, "dns_error"
    def resolve(name, kind, **kwargs):
        diagnostic_calls.append((name, kind, kwargs))
        question = dns.message.make_query(name, kind)
        message = dns.message.make_response(question)
        message.set_rcode(dns.rcode.NXDOMAIN)
        message.answer.append(dns.rrset.from_text(
            name, 60, "IN", "CNAME", "private-cname-resource-819.service.example.",
        ))
        qname = dns.name.from_text(name)
        raise dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: message})
    monkeypatch.setattr(scanner, "_resolve_dns_with_status", unresolved)
    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **kwargs: SimpleNamespace(resolve=resolve))
    monkeypatch.setattr(scanner.requests, "Session", lambda: pytest.fail("HTTP/provider connection attempted"))
    for operation in ("_safe_cors_preflight", "_safe_http_redirect_probe", "_collect_disclosure_evidence"):
        monkeypatch.setattr(report_module, operation, lambda *args, **kwargs: pytest.fail("HTTP probe attempted for unresolved target"))

    report = report_module.scan_target("https://scan.example.com/private?secret=PRIVATE_URL_819", include_expanded_checks=True)
    results = {item["check_id"]: item for item in report["findings"]}
    assert report["http_status"] is None
    assert len(results) == len(report["findings"]) == report["summary"]["total"] == 30
    result = results["subdomain_takeover_indicators"]
    assert (result["status"], result["severity"], result["confidence"]) == ("warning", "low", "low")
    assert results["dnssec"]["status"] == "not_verified"
    assert results["dns_spf"]["status"] == "not_verified"
    assert original_calls == ["scan.example.com"]
    assert len(diagnostic_calls) == 1
    assert diagnostic_calls[0][:2] == ("scan.example.com.", "A")
    assert diagnostic_calls[0][2]["search"] is False
    assert all(secret not in repr(report) + caplog.text for secret in (
        "private-cname-resource-819", "PRIVATE_URL_819",
    ))


@pytest.mark.parametrize("url, addresses, resolution_error", [
    ("https://localhost/", None, "dns_error"),
    ("https://a.internal/", None, "dns_error"),
    ("https://bad..example/", None, "dns_error"),
    ("http://scan.example.com/", None, "dns_error"),
    ("https://scan.example.com:8443/", None, "dns_error"),
    ("https://user:pass@scan.example.com/", None, "dns_error"),
    ("https://127.0.0.1/", "private", None),
    ("https://scan.example.com/", "private", None),
    ("https://scan.example.com/", "mixed", None),
    ("https://scan.example.com/", "malformed", None),
    ("https://scan.example.com/", "private", "dns_error"),
    ("https://scan.example.com/", None, "dns_timeout"),
])
def test_takeover_rejected_or_inconsistent_targets_never_gain_dns_eligibility(monkeypatch, url, addresses, resolution_error):
    import socket
    import security_scanner.scanner as scanner
    import security_scanner.checks.takeover_checks as takeover

    private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 443))
    public = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
    answers = {"private": [private], "mixed": [public, private], "malformed": [()]}.get(addresses)
    monkeypatch.setattr(scanner, "_resolve_dns_with_status", lambda *args, **kwargs: (answers, resolution_error))
    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **kwargs: pytest.fail("Rejected hostname entered diagnostic DNS path"))
    monkeypatch.setattr(scanner.requests, "Session", lambda: pytest.fail("HTTP connection attempted"))
    report = report_module.scan_target(url, include_expanded_checks=True)
    result = next(item for item in report["findings"] if item["check_id"] == "subdomain_takeover_indicators")
    assert result["status"] == "not_verified"
    assert report["http_status"] is None


def test_takeover_valid_target_adds_one_dns_query_and_no_http_requests(monkeypatch):
    from types import SimpleNamespace
    import socket
    import dns.message
    import dns.rrset
    import security_scanner.scanner as scanner
    import security_scanner.checks.takeover_checks as takeover

    dns_calls, http_calls = [], []
    monkeypatch.setattr(scanner, "_resolve_dns_with_status", lambda *args, **kwargs: (
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))], None,
    ))
    def resolve(name, kind, **kwargs):
        dns_calls.append((name, kind))
        response = dns.message.make_response(dns.message.make_query(name, kind))
        response.answer.append(dns.rrset.from_text(name, 60, "IN", "A", "93.184.216.34"))
        return SimpleNamespace(response=response)
    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **kwargs: SimpleNamespace(resolve=resolve))
    class Session:
        def mount(self, *args):
            pass
        def get(self, url, **kwargs):
            http_calls.append(url)
            return SimpleNamespace(status_code=200, headers={}, close=lambda: None)
        def close(self):
            pass
    monkeypatch.setattr(scanner.requests, "Session", Session)
    for operation in ("_safe_cors_preflight", "_safe_http_redirect_probe", "_collect_disclosure_evidence"):
        monkeypatch.setattr(report_module, operation, lambda *args, **kwargs: None)
    # Existing DNS checks are stubbed; the new collector runs end-to-end.
    from security_scanner.checks.result import CheckResult
    def unchanged_dns(check_id):
        return CheckResult(check_id=check_id, title="Fixture", status="not_verified", severity="info",
                           confidence="low", evidence="Fixture", explanation="Fixture",
                           recommendation="Fixture", limitations=("Fixture",))
    for function, check_id in (("evaluate_spf_domain", "dns_spf"), ("evaluate_dmarc_domain", "dns_dmarc"), ("evaluate_dnssec_domain", "dnssec")):
        monkeypatch.setattr(report_module, function, lambda *args, _id=check_id, **kwargs: unchanged_dns(_id))
    report = report_module.scan_target("https://scan.example.com/", include_expanded_checks=True)
    assert http_calls == ["https://93.184.216.34:443/"]
    assert dns_calls == [("scan.example.com.", "A")]
    result = next(item for item in report["findings"] if item["check_id"] == "subdomain_takeover_indicators")
    assert result["status"] == "not_verified"


def test_takeover_evaluator_failure_is_isolated_and_sanitized(monkeypatch, caplog):
    calls = install_mock_response(monkeypatch, (None, {}, "dns_error"))
    def fail(*args, **kwargs):
        raise RuntimeError("PRIVATE_TAKEOVER_EXCEPTION_819")
    monkeypatch.setattr(report_module, "evaluate_takeover_domain", fail)
    report = report_module.scan_target(TARGET_URL, include_expanded_checks=True)
    findings = {item["check_id"]: item for item in report["findings"]}
    assert len(calls) == 1
    assert len(findings) == len(report["findings"]) == 30
    assert findings["subdomain_takeover_indicators"]["status"] == "error"
    assert findings["cache_security"]["status"] == "not_verified"
    assert "PRIVATE_TAKEOVER_EXCEPTION_819" not in repr(report) + caplog.text


def test_default_report_never_runs_takeover_diagnostic(monkeypatch):
    install_mock_response(monkeypatch, (200, {}, None))
    monkeypatch.setattr(report_module, "evaluate_takeover_domain", lambda *args, **kwargs: pytest.fail("Default report ran expanded DNS check"))
    assert len(report_module.scan_target(TARGET_URL)["findings"]) == 5


@pytest.mark.parametrize("rule,ids", [
    ("cookie_defense_gaps", ("cookie_secure", "cookie_httponly")),
    ("public_diagnostics", ("server_information_disclosure", "error_information_disclosure")),
])
def test_correlation_rules_are_stable_private_and_context_only(rule, ids):
    import json
    from security_scanner.checks.correlation import correlate_findings
    findings = [{"check_id": id_, "status": "warning", "severity": "medium", "confidence": "high",
                 "evidence": "SECRET", "unexpected": "cookie=secret"} for id_ in ids]
    result = correlate_findings(findings)
    assert result == correlate_findings(list(reversed(findings)))
    assert len(result) == 1
    assert result[0]["correlation_id"] == rule
    assert result[0]["contributing_check_ids"] == list(ids)
    assert result[0]["severity"] == result[0]["confidence"] == "low"
    assert "SECRET" not in json.dumps(result)
    assert "cookie=secret" not in json.dumps(result)
    assert findings[0]["severity"] == "medium"
    assert correlate_findings(findings + [findings[0]]) == []
    for status in ("passed", "not_verified", "skipped", "error", None):
        assert correlate_findings([dict(findings[0], status=status), findings[1]]) == []
    assert correlate_findings(findings[:1]) == []
    assert correlate_findings([dict(findings[0], severity=[]), findings[1]]) == []


def test_correlation_partial_input_and_shared_observation_are_not_risks():
    from security_scanner.checks.correlation import safe_correlate_findings
    for malformed in (None, {}, [None, {}, {"check_id": []}], "bad"):
        assert safe_correlate_findings(malformed) == []
    findings = [{"check_id": id_, "status": "warning", "severity": "low", "confidence": "low"}
                for id_ in ("sqli_passive_indicators", "error_information_disclosure", "header_csp", "xss_passive_indicators")]
    assert safe_correlate_findings(findings) == []


def test_correlation_failure_does_not_break_report(monkeypatch):
    from security_scanner.checks import correlation
    def fail(findings):
        raise RuntimeError("SECRET")
    monkeypatch.setattr(correlation, "correlate_findings", fail)
    install_mock_response(monkeypatch, (200, {}, None))
    report = report_module.scan_target(TARGET_URL, include_expanded_checks=True)
    assert report["correlations"] == []
    assert report["summary"]["total"] == len(report["findings"]) == 30
    assert "SECRET" not in str(report)
    default = report_module.scan_target(TARGET_URL)
    assert len(default["findings"]) == 5
    assert "correlations" not in default


def test_passive_sql_report_reuses_original_sanitized_evidence(monkeypatch):
    from urllib.parse import urlparse
    from security_scanner.checks.disclosure_evidence import DisclosureEvidence, classify_error_sample
    calls = []
    def response(url, **kwargs):
        calls.append(url)
        kwargs["validated_target_capture"]["target"] = (urlparse(url), "example.com", ["8.8.8.8"])
        return 500, {"Content-Security-Policy": "script-src * SECRET"}, None
    monkeypatch.setattr(report_module, "_safe_get_response", response)
    monkeypatch.setattr(report_module, "_safe_cors_preflight", lambda *a, **k: "timeout")
    monkeypatch.setattr(report_module, "_safe_http_redirect_probe", lambda *a, **k: "timeout")
    monkeypatch.setattr(report_module, "_collect_disclosure_evidence", lambda *a, **k:
        DisclosureEvidence(error_status=500, error_sample_complete=True, error_patterns=classify_error_sample(b"SQLSTATE[42000]: syntax error SECRET db password")))
    # No diagnostic network operations: collector boundary is mocked independently.
    monkeypatch.setattr(report_module, "evaluate_spf_domain", lambda *a, **k: (_ for _ in ()).throw(ValueError()))
    monkeypatch.setattr(report_module, "evaluate_dmarc_domain", lambda *a, **k: (_ for _ in ()).throw(ValueError()))
    monkeypatch.setattr(report_module, "evaluate_dnssec_domain", lambda *a, **k: (_ for _ in ()).throw(ValueError()))
    monkeypatch.setattr(report_module, "evaluate_takeover_domain", lambda *a, **k: (_ for _ in ()).throw(ValueError()))
    report = report_module.scan_target(TARGET_URL, include_expanded_checks=True)
    results = {r["check_id"]: r for r in report["findings"]}
    assert results["sqli_passive_indicators"]["status"] == "warning"
    assert results["xss_passive_indicators"]["status"] == "not_verified"
    assert len(calls) == 1
    assert len(results) == 30
    assert "SECRET" not in str(report)



def test_both_correlations_have_deterministic_order_and_json_roundtrip():
    import json
    from security_scanner.checks.correlation import safe_correlate_findings
    findings = [{"check_id": id_, "status": "warning", "severity": "low", "confidence": "low"}
        for id_ in ("error_information_disclosure", "cookie_httponly", "server_information_disclosure", "cookie_secure")]
    result = safe_correlate_findings(findings)
    assert [r["correlation_id"] for r in result] == ["cookie_defense_gaps", "public_diagnostics"]
    assert result == safe_correlate_findings(list(reversed(findings)))
    assert result == json.loads(json.dumps(result))
    assert len({r["correlation_id"] for r in result}) == 2
