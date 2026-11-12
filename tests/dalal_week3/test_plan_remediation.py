"""Plan acceptance regressions: bounded passive evidence and risk context."""

import json

import pytest

from security_scanner.checks.disclosure_evidence import DisclosureEvidence
from security_scanner.checks.evidence import EvidenceCollection
from security_scanner.checks.passive_evidence import collect_passive_xss_sample
from security_scanner.checks.response_runner import evaluate_passive_evidence


def xss_result(sample, *, status=200, media="text/html", complete=True):
    html = collect_passive_xss_sample(sample, status=status, media_type=media, complete=complete)
    evidence = EvidenceCollection(http_status=status, disclosure_evidence=DisclosureEvidence(passive_xss=html))
    return html, evaluate_passive_evidence(evidence)[0]


@pytest.mark.parametrize("script", [
    b'document.body.innerHTML = location.hash;',
    b'document.getElementById("output").innerHTML = window.location.search;',
    b'function render() { document.body.innerHTML = location.search; }',
    b'document /* comment */ .body.innerHTML=location.hash;',
])
def test_xss_direct_static_pattern_is_only_low_confidence_review(script):
    html, result = xss_result(b"<html><script>" + script + b"</script></html>")
    assert html.state == "direct_url_html_sink"
    assert (result.status, result.severity, result.confidence) == ("warning", "low", "low")
    assert "exploitability were not established" in result.explanation


@pytest.mark.parametrize("sample", [
    b"<html><p>ordinary HTML</p></html>",
    b"<script>console.log(location.hash);</script>",
    b'<script>document.body.innerHTML = "constant";</script>',
    b"<script>document.body.textContent = location.search;</script>",
    b"<script>// document.body.innerHTML=location.hash;\nconsole.log(1);</script>",
    b'<script>const example = "document.body.innerHTML=location.hash;";</script>',
    b"<script>/* document.body.innerHTML=location.hash; */</script>",
    b'<script type="application/json">document.body.innerHTML=location.hash;</script>',
    b'<script src="/asset.js">document.body.innerHTML=location.hash;</script>',
    b'<template><script>document.body.innerHTML=location.hash;</script></template>',
    b'<noscript><script>document.body.innerHTML=location.hash;</script></noscript>',
    b'<script>document.body.innerHTML=location.hash + "extra";</script>',
    b'<script>obj.document.body.innerHTML=location.hash;</script>',
    b'<script>document.body.innerHTML=trusted(location.hash);</script>',
    b'<button onclick="console.log(1)">ordinary handler</button>',
])
def test_xss_ordinary_scripts_comments_and_unrelated_sources_never_warn(sample):
    _, result = xss_result(sample)
    assert result.status == "not_verified"


@pytest.mark.parametrize("options", [
    {"complete": False}, {"status": 206}, {"status": None}, {"status": 500},
    {"media": "application/json"}, {"media": "text/plain"},
])
def test_xss_unavailable_or_incomplete_original_sample_is_inconclusive(options):
    _, result = xss_result(b"<script>document.body.innerHTML=location.hash;</script>", **options)
    assert result.status == "not_verified"


@pytest.mark.parametrize("sample", [
    b"<script>document.body.innerHTML=location.hash;", b"\xff<script>bad</script>",
    b"\0<script>document.body.innerHTML=location.hash;</script>", b"x" * 16385,
    b"<script>const pattern = /document.body.innerHTML=location.hash/;</script>",
    b"<script>const template = `document.body.innerHTML=location.hash;`;</script>",
    b'<script>const broken = "unterminated;</script>',
    b'<script type="module" type="application/json">document.body.innerHTML=location.hash;</script>',
])
def test_xss_malformed_unsupported_and_oversized_samples_do_not_warn(sample):
    _, result = xss_result(sample)
    assert result.status == "not_verified"


def test_passive_samples_never_retain_secrets_or_perform_io(monkeypatch):
    import socket
    import requests
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("Unexpected DNS"))
    monkeypatch.setattr(requests, "Session", lambda *a, **k: pytest.fail("Unexpected HTTP"))
    html, result = xss_result(b'<script>const token="SECRET_TOKEN";document.body.innerHTML=location.hash;</script>')
    assert result.status == "warning"
    assert "SECRET_TOKEN" not in repr(html) + json.dumps(result.to_dict())


@pytest.mark.parametrize("complete", [False, None, True])
def test_sqli_requires_complete_original_error_sample(complete):
    result = evaluate_passive_evidence(EvidenceCollection(http_status=500,
        disclosure_evidence=DisclosureEvidence(error_status=500, error_sample_complete=complete,
                                               error_patterns=("sql_error",))))[1]
    assert result.status == ("warning" if complete is True else "not_verified")


@pytest.mark.parametrize("ad", [False, True])
@pytest.mark.parametrize("keys,signatures", [(0, 0), (1, 0), (1, 1)])
def test_dnssec_untrusted_ad_and_presence_never_establish_crypto_validation(ad, keys, signatures):
    from security_scanner.checks.dnssec_checks import DNSSECEvidence, DNSSECCheckEvaluator
    from security_scanner.checks.registry import create_default_registry
    result = DNSSECCheckEvaluator(create_default_registry().get("dnssec")).evaluate(
        DNSSECEvidence("available" if keys else "no_dnskey", zone_name="example.com", dnskey_count=keys,
                       rrsig_count=signatures, authenticated_data=ad))
    assert result.status == "not_verified"
    assert "DS/DNSKEY" in str(result.limitations)


@pytest.mark.parametrize("body", [
    b"SQL tutorial: SELECT name FROM users", b"mysql_query is a PHP function",
    b"PDOException is a class", b"ORA-12345 documentation example",
    b"syntax error at or near is a common message", b"SQLSTATE[42000] example: syntax error",
    b"SQLSTATE[invalid]: syntax error", b"HTTP 500: database unavailable",
    b"<pre>SQLSTATE[42000]: syntax error</pre>",
    b"<code>ERROR: syntax error at or near secret</code>",
    b"<!-- SQLSTATE[42000]: syntax error -->",
    b'<script>const example="SQLSTATE[42000]: syntax error";</script>',
])
def test_sql_tutorial_code_and_generic_error_mentions_are_not_error_signatures(body):
    from security_scanner.checks.disclosure_evidence import classify_error_sample
    assert "sql_error" not in classify_error_sample(body)


@pytest.mark.parametrize("body", [
    b"SQLSTATE[42000]: syntax error SECRET_QUERY",
    b"SQLSTATE[HY000] [1045] Access denied SECRET_PASSWORD",
    b"<div>SQLSTATE[42S02] table missing SECRET_TABLE</div>",
    b"ERROR: syntax error at or near SECRET_QUERY",
    b"ORA-00942: SECRET_TABLE does not exist",
    b"sqlite3.OperationalError: no such table SECRET_TABLE",
])
def test_sql_error_signature_categories_are_bounded_and_redacted(body):
    from security_scanner.checks.disclosure_evidence import classify_error_sample
    categories = classify_error_sample(body)
    assert "sql_error" in categories
    result = evaluate_passive_evidence(EvidenceCollection(http_status=500,
        disclosure_evidence=DisclosureEvidence(error_status=500, error_sample_complete=True,
                                               error_patterns=categories)))[1]
    assert result.status == "warning"
    assert "SECRET" not in json.dumps(result.to_dict())
    assert "sql_error" not in classify_error_sample(b" " * 4096 + body)


def cache_result(headers, *, status=200, available=None, cookies=()):
    from security_scanner.checks.response_runner import evaluate_cache_evidence
    return evaluate_cache_evidence(EvidenceCollection(http_status=status, _headers=headers,
        cookie_evidence_available=available, cookie_observations=cookies))[0]


@pytest.mark.parametrize("headers,expected", [
    ({"Cache-Control": "no-store"}, "passed"),
    ({"Cache-Control": "private, s-maxage=60"}, "not_verified"),
    ({"Cache-Control": "no-cache, max-age=30"}, "not_verified"),
    ({"Cache-Control": "public, max-age=30"}, "not_verified"),
    ({"Cache-Control": "no-store, no-store"}, "not_verified"),
    ({"Cache-Control": "no-store, private, public"}, "not_verified"),
    ({"Pragma": "no-cache", "Expires": "0"}, "not_verified"), ({}, "not_verified"),
])
def test_cache_context_preserves_approved_classifications(headers, expected):
    assert cache_result(headers).status == expected


@pytest.mark.parametrize("headers,category", [
    ({"Pragma": "no-cache"}, "response Pragma is not a reliable replacement"),
    ({"Expires": "0"}, "Expires was invalid"),
    ({"Expires": ("Wed, 01 Jan 2031 00:00:00 GMT",) * 2}, "Expires was invalid"),
    ({"Expires": "Wed, 01 Jan 2031 00:00:00 GMT"}, "no reliable response Date"),
    ({"Date": "Tue, 01 Jan 2030 00:00:00 GMT", "Expires": "Wed, 01 Jan 2031 00:00:00 GMT"}, "later than the response Date"),
    ({"Date": "Tue, 01 Jan 2030 00:00:00 GMT", "Expires": "Tue, 01 Jan 2030 00:00:00 GMT"}, "not later than the response Date"),
    ({"Cache-Control": "max-age=30", "Expires": "Wed, 01 Jan 2031 00:00:00 GMT"}, "takes precedence"),
    ({"Vary": "*"}, "wildcard prevents a matching reuse"),
    ({"Vary": "Accept-Encoding, Accept-Language"}, "cache-key selectors"),
    ({"Vary": "Cookie, Authorization"}, "authentication-related selector"),
    ({"Vary": "Cookie, cookie"}, "Repeated Vary selectors"),
    ({"Vary": "bad field"}, "Vary syntax is ambiguous"),
    ({"Vary": ""}, "Vary syntax is ambiguous"),
])
def test_cache_interprets_legacy_expiry_and_variant_context_without_leaks(headers, category):
    result = cache_result(headers)
    assert result.status == "not_verified"
    assert category in str(result.limitations)
    assert "2031" not in str(result.to_dict())
    assert "Accept-Language" not in str(result.to_dict())


@pytest.mark.parametrize("available,cookies,description", [
    (None, (), "could not be established"),
    (True, (), "No Set-Cookie was observed"),
    (True, ((True, True, "lax"),), "Set-Cookie presence was observed"),
])
def test_cache_cookie_presence_and_partial_response_are_not_sensitivity_proof(available, cookies, description):
    result = cache_result({"Cache-Control": "public", "Vary": "Cookie"}, status=206,
                          available=available, cookies=cookies)
    assert result.status == "not_verified"
    assert description in str(result.limitations)
    assert "response is partial" in str(result.limitations)


def test_cache_variants_no_store_and_privacy_without_requests(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "Session", lambda: pytest.fail("Cache initiated HTTP"))
    for vary in ("Accept-Encoding", "Cookie", "X-SECRET-SELECTOR", "*"):
        result = cache_result({"Cache-Control": "no-store", "Vary": vary, "Pragma": "SECRET"},
                              available=True, cookies=((False, False, "missing"),))
        assert result.status == "passed"
        assert "SECRET" not in str(result.to_dict())
    assert cache_result({}, status=None).status == "not_verified"


from security_scanner.checks.correlation import RULE_CATALOG, CORRELATION_RULES_VERSION


def warning(check_id):
    return {"check_id": check_id, "status": "warning", "severity": "medium", "confidence": "high",
            "evidence": "SECRET", "unexpected": "SECRET_QUERY"}


@pytest.mark.parametrize("rule", RULE_CATALOG, ids=lambda r: r.correlation_id)
def test_every_correlation_rule_positive_negative_versions_dedup_and_privacy(rule):
    from copy import deepcopy
    from security_scanner.checks.correlation import safe_correlate_findings
    findings = [warning(check_id) for check_id in rule.contributors]
    snapshot = deepcopy(findings)
    results = safe_correlate_findings(findings)
    assert len(results) == 1
    result = results[0]
    assert result["correlation_id"] == rule.correlation_id
    assert result["rules_version"] == CORRELATION_RULES_VERSION
    assert result["rule_version"] == rule.rule_version
    assert result["contributing_check_ids"] == list(rule.contributors)
    assert result["recommendation"] and result["limitations"]
    assert (result["severity"], result["confidence"]) == ("low", "low")
    assert "SECRET" not in json.dumps(results)
    assert results == json.loads(json.dumps(results)) == safe_correlate_findings(list(reversed(findings)))
    assert findings == snapshot
    assert safe_correlate_findings(findings + [findings[0]]) == []
    assert safe_correlate_findings(findings[:1]) == []
    for status in ("passed", "not_verified", "error", "skipped", None):
        assert safe_correlate_findings([dict(findings[0], status=status), findings[1]]) == []
    assert safe_correlate_findings([dict(findings[0], confidence=[]), findings[1]]) == []
    assert safe_correlate_findings(findings + [dict(findings[0], status="passed")]) == []


def test_correlation_unsupported_domains_and_input_bounds():
    from security_scanner.checks.correlation import safe_correlate_findings
    for values in (None, {}, [], [None, {}], [warning("cookie_secure")]):
        assert safe_correlate_findings(values) == []
    for pair in (("sqli_passive_indicators", "error_information_disclosure"),
                 ("dnssec", "subdomain_takeover_indicators"),
                 ("cache_security", "xss_passive_indicators"),
                 ("header_csp", "open_redirect"),
                 ("tls_certificate_chain", "tls_certificate_expiry")):
        assert safe_correlate_findings([warning(check_id) for check_id in pair]) == []
    assert safe_correlate_findings([warning("cookie_secure")] * 101) == []


def test_one_correlation_rule_failure_preserves_other_rules(monkeypatch):
    from security_scanner.checks import correlation
    original = correlation._evaluate_rule
    def fail_one(rule, *args):
        if rule.correlation_id == "cookie_defense_gaps":
            raise ValueError("SECRET")
        return original(rule, *args)
    monkeypatch.setattr(correlation, "_evaluate_rule", fail_one)
    findings = [warning(check_id) for check_id in
                ("cookie_secure", "cookie_httponly", "server_information_disclosure", "error_information_disclosure")]
    results = correlation.safe_correlate_findings(findings)
    assert [r["correlation_id"] for r in results] == ["public_diagnostics"]
    assert "SECRET" not in str(results)


def test_static_xss_parser_failure_and_response_mismatch_stay_inconclusive(monkeypatch, caplog):
    import security_scanner.checks.passive_evidence as passive
    def fail(*args):
        raise ValueError("SECRET_PARSER_BODY")
    monkeypatch.setattr(passive, "_tokens", fail)
    html, result = xss_result(b"<script>document.body.innerHTML=location.hash;</script>")
    assert html.state == "inconclusive" and result.status == "not_verified"
    assert "SECRET_PARSER_BODY" not in caplog.text + str(result.to_dict())
    html = passive.PassiveXSSEvidence(200, "direct_url_html_sink")
    result = evaluate_passive_evidence(EvidenceCollection(http_status=201,
        disclosure_evidence=DisclosureEvidence(passive_xss=html)))[0]
    assert result.status == "not_verified"


def test_passive_xss_evidence_rejects_unsupported_state_and_partial_claim():
    from security_scanner.checks.passive_evidence import PassiveXSSEvidence
    for status, state in ((206, "direct_url_html_sink"), (None, "no_indicator"), (200, "SECRET")):
        with pytest.raises(ValueError):
            PassiveXSSEvidence(status, state)
    with pytest.raises(TypeError):
        DisclosureEvidence(passive_xss="RAW_BODY")


def test_expanded_version_and_counts_preserve_default_contract(monkeypatch):
    import security_scanner.report as report
    from security_scanner.checks.registry import create_default_registry
    calls = []
    def original(*args, **kwargs):
        calls.append(1)
        return 200, {"Cache-Control": "no-store", "Vary": "Cookie"}, None
    monkeypatch.setattr(report, "_safe_get_response", original)
    default = report.scan_target("https://example.com/path?SECRET")
    expanded = report.scan_target("https://example.com/path?SECRET", include_expanded_checks=True)
    assert len(calls) == 2
    assert set(default) == {"scan_id", "status", "target_url", "scanned_at", "engine_version",
                            "http_status", "summary", "findings", "limitations", "notice"}
    assert expanded["correlation_rules_version"] == CORRELATION_RULES_VERSION
    assert len(default["findings"]) == default["summary"]["total"] == 5
    assert len(expanded["findings"]) == expanded["summary"]["total"] == 30
    assert {r["check_id"] for r in expanded["findings"]} == {d.check_id for d in create_default_registry()}
    assert len({r["check_id"] for r in expanded["findings"]}) == 30
    for status in ("passed", "warning", "not_verified", "error", "skipped"):
        assert expanded["summary"][status] == sum(r["status"] == status for r in expanded["findings"])
    assert "SECRET" not in json.dumps(expanded)
    assert json.loads(json.dumps(expanded)) == expanded


@pytest.mark.parametrize("state", ["not_applicable", "invalid_target", "dns_capacity", "timeout", "dns_error", "oversized_response", "no_record"])
def test_dmarc_operational_messages_are_meaningful_and_redacted(state):
    from security_scanner.checks.dns_checks import DMARCEvidence, DMARCCheckEvaluator
    from security_scanner.checks.registry import create_default_registry
    result = DMARCCheckEvaluator(create_default_registry().get("dns_dmarc")).evaluate(DMARCEvidence(state))
    assert "???" not in str(result.to_dict())
    assert "DMARC" in result.title


@pytest.mark.parametrize("record", ["v=DMARC1; p=none", "v=DMARC1; p=reject", "v=DMARC1; p=invalid"])
def test_dmarc_policy_messages_describe_scope_without_corrupt_text(record):
    from security_scanner.checks.dns_checks import DMARCEvidence, DMARCCheckEvaluator
    from security_scanner.checks.registry import create_default_registry
    result = DMARCCheckEvaluator(create_default_registry().get("dns_dmarc")).evaluate(
        DMARCEvidence("available", records=(record,)))
    assert "???" not in str(result.to_dict())
    assert "DMARC" in result.title


@pytest.mark.parametrize("version", ["unknown", "TLSv1.4", "SECRET_VERSION"])
def test_unclassified_tls_versions_do_not_invent_legacy_verdicts(version):
    from security_scanner.checks.tls_checks import TLSMetadataEvaluator
    from security_scanner.checks.registry import create_default_registry
    result = TLSMetadataEvaluator(create_default_registry().get("tls_protocol_config")).evaluate(
        EvidenceCollection(http_status=200, tls_verified=True,
                           tls_metadata={"version": version, "cipher": "TLS_AES_128_GCM_SHA256"}))
    assert (result.status, result.severity) == ("not_verified", "info")
    assert version not in str(result.to_dict())


@pytest.mark.parametrize("group", ["_TLS_EVALUATORS", "_BLOCKED_REDIRECT_EVALUATORS"])
def test_tls_and_redirect_evaluator_failures_are_isolated(group, monkeypatch, caplog):
    from security_scanner.checks import response_runner as runner
    original = getattr(runner, group)
    class FailOne:
        def __init__(self, definition):
            self.definition = definition
        def evaluate(self, evidence):
            raise RuntimeError("SECRET_TLS_EVALUATOR")
    monkeypatch.setattr(runner, group, ((original[0][0], FailOne), *original[1:]))
    results = runner.evaluate_week3_evidence(EvidenceCollection(http_status=200))
    assert len(results) == 18
    by_id = {r.check_id: r for r in results}
    assert by_id[original[0][0]].status == "error"
    assert sum(r.status == "error" for r in results) == 1
    assert "SECRET_TLS_EVALUATOR" not in caplog.text + str([r.to_dict() for r in results])
