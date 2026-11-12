"""Offline provider attribution and demonstrated final regression cases."""

import json
from types import SimpleNamespace

import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset
import pytest

from security_scanner.checks.provider_catalog import (
    PROVIDER_CATALOG, PROVIDER_CATALOG_VERSION, ProviderObservation,
    classify_cname_providers,
)
from security_scanner.checks.takeover_checks import (
    TakeoverEvidence, _interpret_response, collect_takeover_evidence,
    evaluate_takeover_evidence,
)


def response(links=(), *, code="NXDOMAIN", address=None):
    message = dns.message.make_response(dns.message.make_query("scan.example.com.", "A"))
    message.set_rcode(dns.rcode.from_text(code))
    for owner, destination in links:
        message.answer.append(dns.rrset.from_text(owner, 60, "IN", "CNAME", destination))
    if address is not None:
        message.answer.append(dns.rrset.from_text(links[-1][1], 60, "IN", "A", address))
    return message


@pytest.mark.parametrize("destination,provider", [
    ("resource.github.io", "github_pages"),
    ("RESOURCE.GITHUB.IO.", "github_pages"),
    ("resource.azurewebsites.net", "azure_app_service"),
    ("resource-hash.westus.azurewebsites.net", "azure_app_service"),
])
def test_catalog_only_recognizes_documented_domain_association(destination, provider):
    result = classify_cname_providers([destination])
    assert result == ProviderObservation("recognized", provider)
    assert destination.lower().rstrip(".") not in repr(result)


@pytest.mark.parametrize("destination", [
    "github.io", "azurewebsites.net", "notgithub.io", "notazurewebsites.net",
    "resource.github.io.attacker.example", "resource.azurewebsites.net.attacker.example",
    "github.io-attacker.example", "azurewebsites.net-attacker.example", "other.service.example",
    "resource.githu\u0432.io", "127.0.0.1", "private.internal", "bad..github.io",
])
def test_catalog_suffix_boundaries_and_misleading_names_never_recognize(destination):
    result = classify_cname_providers([destination])
    assert result.state in {"unrecognized", "inconclusive"}
    assert result.provider_id is None


def test_catalog_bounds_conflicts_and_no_input_names_retained():
    assert classify_cname_providers([]) == ProviderObservation()
    assert classify_cname_providers(["app.github.io"] * 101).state == "inconclusive"
    assert classify_cname_providers("app.github.io").state == "inconclusive"
    assert classify_cname_providers([None]).state == "inconclusive"
    conflict = classify_cname_providers(["SECRET.github.io", "PRIVATE.azurewebsites.net"])
    assert conflict == ProviderObservation("conflicting")
    assert "SECRET" not in repr(conflict) and "PRIVATE" not in repr(conflict)
    assert len({item.provider_id for item in PROVIDER_CATALOG}) == len(PROVIDER_CATALOG)
    assert all(item.documentation_url.startswith("https://") for item in PROVIDER_CATALOG)


@pytest.mark.parametrize("code,address,expected", [
    ("NXDOMAIN", None, "warning"), ("NOERROR", None, "not_verified"),
    ("NOERROR", "8.8.8.8", "not_verified"),
])
def test_provider_recognition_cannot_upgrade_dns_observation(code, address, expected):
    message = response((("scan.example.com.", "SECRET-RESOURCE.github.io."),), code=code, address=address)
    evidence = _interpret_response(message, "scan.example.com")
    assert evidence.provider == ProviderObservation("recognized", "github_pages")
    result = evaluate_takeover_evidence(evidence)
    assert result.status == expected
    assert result.confidence == "low"
    assert result.severity == ("low" if expected == "warning" else "info")
    assert "GitHub Pages" in result.evidence
    assert "resource error evidence is not collected" in str(result.limitations)
    assert PROVIDER_CATALOG_VERSION in str(result.limitations)
    assert "SECRET-RESOURCE" not in repr(evidence) + json.dumps(result.to_dict())
    assert "github.io" not in result.evidence


def test_multihop_provider_conflict_does_not_claim_specific_provider_or_abandonment():
    evidence = _interpret_response(response((
        ("scan.example.com.", "SECRET.github.io."),
        ("SECRET.github.io.", "PRIVATE.azurewebsites.net."),
    )), "scan.example.com")
    assert evidence.cname_count == 2
    assert evidence.provider == ProviderObservation("conflicting")
    result = evaluate_takeover_evidence(evidence)
    # Existing independently observed dangling-DNS warning is retained. Provider
    # attribution/resource error/claimability do NOT become verified conclusions.
    assert result.status == "warning"
    assert "single provider association is not verified" in result.evidence
    assert "GitHub Pages" not in result.evidence and "Azure App Service" not in result.evidence
    assert "SECRET" not in str(result.to_dict())


def test_multihop_single_provider_and_missing_provider_evidence():
    known = _interpret_response(response((
        ("scan.example.com.", "alias.example."), ("alias.example.", "app.github.io."),
    )), "scan.example.com")
    assert known.provider.provider_id == "github_pages"
    unknown = _interpret_response(response((("scan.example.com.", "missing.example."),)), "scan.example.com")
    assert unknown.provider.state == "unrecognized"
    assert evaluate_takeover_evidence(unknown).status == "warning"
    absent = _interpret_response(response(), "scan.example.com")
    assert absent.provider.state == "unobserved"
    assert evaluate_takeover_evidence(absent).status == "not_verified"


@pytest.mark.parametrize("mutation", ["unrelated", "cycle", "duplicate", "private", "reserved", "wrong_question"])
def test_invalid_chain_cannot_leave_provider_attribution(mutation):
    links = [("scan.example.com.", "app.github.io.")]
    if mutation == "unrelated":
        links.append(("unrelated.example.", "app.azurewebsites.net."))
    elif mutation == "cycle":
        links.append(("app.github.io.", "scan.example.com."))
    elif mutation == "duplicate":
        links.append(links[0])
    address = "10.0.0.1" if mutation == "private" else "192.0.2.1" if mutation == "reserved" else None
    message = response(links, code="NOERROR" if address else "NXDOMAIN", address=address)
    if mutation == "wrong_question":
        message.question = dns.message.make_query("unrelated.example.", "A").question
    evidence = _interpret_response(message, "scan.example.com")
    assert evidence.query_state == "inconclusive"
    assert evidence.provider == ProviderObservation()
    assert evaluate_takeover_evidence(evidence).status == "not_verified"


@pytest.mark.parametrize("state,count", [("ineligible", 0), ("dangling", 0), ("resolved", 0)])
def test_provider_evidence_requires_a_valid_attributed_chain(state, count):
    with pytest.raises(ValueError):
        TakeoverEvidence(state, count, ProviderObservation("recognized", "github_pages"))
    with pytest.raises(ValueError):
        ProviderObservation("recognized", "SECRET_PROVIDER")


def test_provider_collector_one_dns_operation_and_no_http_or_claims(monkeypatch):
    import requests
    from security_scanner.checks import takeover_checks as takeover
    calls = []
    def resolve(name, kind, **kwargs):
        calls.append((name, kind, kwargs))
        qname = dns.name.from_text(name)
        raise dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: response(
            (("scan.example.com.", "SECRET.github.io."),))})
    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **k: SimpleNamespace(resolve=resolve))
    monkeypatch.setattr(requests, "Session", lambda *a, **k: pytest.fail("Provider HTTP or claim attempted"))
    evidence = collect_takeover_evidence("scan.example.com")
    assert evidence.provider.provider_id == "github_pages"
    assert len(calls) == 1 and calls[0][:2] == ("scan.example.com.", "A")
    assert calls[0][2] == {"lifetime": 2.0, "search": False, "raise_on_no_answer": False}


def test_provider_result_reaches_30_check_report_without_http_for_unresolved_target(monkeypatch):
    import requests
    import security_scanner.report as report
    import security_scanner.scanner as scanner
    from security_scanner.checks import takeover_checks as takeover
    calls = []
    monkeypatch.setattr(scanner, "_resolve_dns_with_status", lambda *a, **k: (None, "dns_error"))
    monkeypatch.setattr(requests, "Session", lambda *a, **k: pytest.fail("DNS-only target authorized HTTP"))
    def resolve(name, kind, **kwargs):
        calls.append((name, kind))
        qname = dns.name.from_text(name)
        raise dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: response(
            (("scan.example.com.", "PRIVATE.azurewebsites.net."),))})
    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **k: SimpleNamespace(resolve=resolve))
    result = report.scan_target("https://scan.example.com/private?SECRET", include_expanded_checks=True)
    assert calls == [("scan.example.com.", "A")]
    assert len(result["findings"]) == result["summary"]["total"] == 30
    assert len({item["check_id"] for item in result["findings"]}) == 30
    finding = next(item for item in result["findings"] if item["check_id"] == "subdomain_takeover_indicators")
    assert finding["status"] == "warning" and "Azure App Service" in finding["evidence"]
    assert "PRIVATE" not in json.dumps(result) and "SECRET" not in json.dumps(result)
    assert result["correlation_rules_version"] == "2.0.0"


@pytest.mark.parametrize("sample", [
    b"<template></noscript><script>document.body.innerHTML=location.hash;</script></template>",
    b"<noscript></template><script>document.body.innerHTML=location.hash;</script></noscript>",
    b"<template><template></noscript></template><script>document.body.innerHTML=location.hash;</script></template>",
])
def test_mismatched_inert_closing_tags_cannot_create_xss_indicator(sample):
    from security_scanner.checks.passive_evidence import collect_passive_xss_sample
    evidence = collect_passive_xss_sample(sample, status=200, media_type="text/html", complete=True)
    assert evidence.state == "inconclusive"
