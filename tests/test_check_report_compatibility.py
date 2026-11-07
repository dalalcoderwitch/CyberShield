import security_scanner.report as report_module

from security_scanner.checks import (
    CheckContext,
    evaluate_shared_response_prototypes,
)


def make_prototype_findings():
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Cache-Control": "no-store",
        },
    )

    results = evaluate_shared_response_prototypes(context)
    return [result.to_dict() for result in results]


def test_expanded_findings_match_existing_report_factory():
    findings = make_prototype_findings()

    assert len(findings) == 3

    for finding in findings:
        converted = report_module._make_finding(**finding)

        assert converted == finding
        assert len(converted) == 9
        assert isinstance(converted["evidence"], str)
        assert isinstance(converted["limitations"], list)


def test_legacy_and_expanded_findings_can_be_summarized_together(
    monkeypatch,
):
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "Cache-Control": "no-store",
    }

    monkeypatch.setattr(
        report_module,
        "_safe_get_response",
        lambda *args, **kwargs: (200, headers, None),
    )

    legacy_report = report_module.scan_target(
        "https://example.com"
    )

    assert len(legacy_report["findings"]) == 5

    expanded_findings = make_prototype_findings()

    combined = (
        legacy_report["findings"] + expanded_findings
    )

    summary = report_module._summarize(combined)

    assert summary["total"] == 8

    statuses = (
        "passed",
        "warning",
        "not_verified",
        "error",
        "skipped",
    )

    assert sum(summary[item] for item in statuses) == 8

    ids = [item["check_id"] for item in combined]
    assert len(ids) == len(set(ids))

    # The actual legacy report remains unchanged.
    assert len(legacy_report["findings"]) == 5
