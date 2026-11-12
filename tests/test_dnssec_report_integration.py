from urllib.parse import urlsplit

import pytest

import security_scanner.checks.dnssec_checks as dnssec_checks
import security_scanner.report as report_module
from security_scanner.checks.result import CheckResult


def _result(check_id, status="passed", severity="info"):
    return CheckResult(
        check_id=check_id,
        title=f"Test result: {check_id}",
        status=status,
        severity=severity,
        confidence="high",
        evidence="Synthetic evidence only.",
        explanation="Synthetic explanation.",
        recommendation="No action required in this test.",
        limitations=("Test only.",),
    )


def _install_successful_expanded_response(monkeypatch):
    def fake_response(url, **kwargs):
        capture = kwargs.get("validated_target_capture")
        if capture is not None:
            capture["target"] = (
                urlsplit(url),
                "example.com",
                ["93.184.216.34"],
            )
        return 200, {}, None

    monkeypatch.setattr(
        report_module, "_safe_get_response", fake_response
    )
    monkeypatch.setattr(
        report_module,
        "_safe_cors_preflight",
        lambda target, deadline=None, capture=None: None,
    )
    monkeypatch.setattr(
        report_module,
        "_collect_disclosure_evidence",
        lambda target, original_status, original_capture,
        deadline=None: None,
    )
    monkeypatch.setattr(
        report_module,
        "_safe_http_redirect_probe",
        lambda target, deadline=None, capture=None: None,
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_shared_week3_checks",
        lambda context: (),
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_spf_domain",
        lambda domain, deadline=None: _result("dns_spf"),
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_dmarc_domain",
        lambda domain, deadline=None: _result("dns_dmarc"),
    )


def test_dnssec_is_added_once_using_validated_hostname(monkeypatch):
    _install_successful_expanded_response(monkeypatch)

    calls = []

    def fake_dnssec(domain, deadline=None):
        calls.append((domain, deadline))
        return _result("dnssec", "not_verified", "info")

    monkeypatch.setattr(
        report_module,
        "evaluate_dnssec_domain",
        fake_dnssec,
    )

    report = report_module.scan_target(
        "https://example.com/",
        deadline=123.0,
        include_expanded_checks=True,
    )

    findings = [
        item for item in report["findings"]
        if item["check_id"] == "dnssec"
    ]

    assert calls == [("example.com", 123.0)]
    assert len(findings) == 1
    assert findings[0]["status"] == "not_verified"
    assert report["summary"]["total"] == len(report["findings"])


def test_dnssec_does_not_query_without_validated_target(monkeypatch):
    monkeypatch.setattr(
        report_module,
        "_safe_get_response",
        lambda url, **kwargs: (None, {}, "dns_error"),
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_week3_evidence",
        lambda evidence: (),
    )

    def unexpected_resolver(**kwargs):
        pytest.fail("DNS query attempted without a validated target")

    monkeypatch.setattr(
        dnssec_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    report = report_module.scan_target(
        "https://example.com/",
        include_expanded_checks=True,
    )

    findings = {
        item["check_id"]: item
        for item in report["findings"]
    }

    assert findings["dnssec"]["status"] == "not_verified"


def test_dnssec_failure_does_not_abort_other_findings(monkeypatch):
    _install_successful_expanded_response(monkeypatch)

    other_result = _result("header_referrer_policy")

    monkeypatch.setattr(
        report_module,
        "evaluate_shared_week3_checks",
        lambda context: (other_result,),
    )

    def failed_dnssec(domain, deadline=None):
        raise RuntimeError("synthetic internal failure")

    monkeypatch.setattr(
        report_module,
        "evaluate_dnssec_domain",
        failed_dnssec,
    )

    report = report_module.scan_target(
        "https://example.com/",
        include_expanded_checks=True,
    )

    findings = {
        item["check_id"]: item
        for item in report["findings"]
    }

    assert findings["header_referrer_policy"]["status"] == "passed"
    assert findings["dns_spf"]["status"] == "passed"
    assert findings["dns_dmarc"]["status"] == "passed"
    assert findings["dnssec"]["status"] == "error"
    assert len(findings) == len(report["findings"])


def test_basic_report_does_not_run_dnssec(monkeypatch):
    calls = []

    monkeypatch.setattr(
        report_module,
        "_safe_get_response",
        lambda url: (200, {}, None),
    )
    monkeypatch.setattr(
        report_module,
        "evaluate_dnssec_domain",
        lambda domain, deadline=None: calls.append(domain),
    )

    report = report_module.scan_target("https://example.com/")

    assert len(report["findings"]) == 5
    assert calls == []
