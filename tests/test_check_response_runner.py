import pytest

from security_scanner.checks import (
    CheckContext,
    EvidenceCollection,
    evaluate_shared_response_prototypes,
)
from security_scanner.checks.response_runner import evaluate_week3_evidence


def test_response_runner_evaluates_three_checks_from_one_response():
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

    assert len(results) == 3
    assert tuple(result.check_id for result in results) == (
        "header_referrer_policy",
        "header_permissions_policy",
        "cache_security",
    )

    assert tuple(result.status for result in results) == (
        "passed",
        "warning",
        "passed",
    )


def test_response_runner_returns_not_verified_without_http_response():
    context = CheckContext(
        safe_target_url="https://example.com",
        connection_error="timeout",
    )

    results = evaluate_shared_response_prototypes(context)

    assert len(results) == 3
    assert all(
        result.status == "not_verified"
        for result in results
    )


def test_response_runner_returns_immutable_result_collection():
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={"Cache-Control": "no-store"},
    )

    results = evaluate_shared_response_prototypes(context)

    assert isinstance(results, tuple)


def test_response_runner_rejects_invalid_context():
    with pytest.raises(TypeError, match="CheckContext"):
        evaluate_shared_response_prototypes(object())


def test_response_runner_preserves_report_result_schema():
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={"Cache-Control": "no-store"},
    )

    results = evaluate_shared_response_prototypes(context)

    expected_fields = {
        "check_id",
        "title",
        "status",
        "severity",
        "confidence",
        "evidence",
        "explanation",
        "recommendation",
        "limitations",
    }

    for result in results:
        assert set(result.to_dict()) == expected_fields


def test_response_runner_reuses_one_shared_evidence_snapshot(monkeypatch):
    import security_scanner.checks.response_runner as runner

    from security_scanner.checks.result import CheckResult

    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={"Cache-Control": "no-store"},
    )

    shared_evidence = EvidenceCollection(http_status=200)
    context_calls = []
    evaluated_evidence = []

    def fake_from_context(cls, supplied_context):
        context_calls.append(supplied_context)
        return shared_evidence

    monkeypatch.setattr(
        runner.EvidenceCollection,
        "from_context",
        classmethod(fake_from_context),
    )

    def fake_evaluate(self, evidence):
        evaluated_evidence.append(evidence)
        return CheckResult(
            check_id=self.definition.check_id,
            title=self.definition.title,
            status="passed",
            severity="info",
            confidence="high",
            evidence="Synthetic test evidence.",
            explanation="Synthetic test explanation.",
            recommendation="No action required.",
            limitations=["Test only."],
        )

    for evaluator_type in (
        runner.ReferrerPolicyEvaluator,
        runner.PermissionsPolicyEvaluator,
        runner.CacheSecurityEvaluator,
    ):
        monkeypatch.setattr(
            evaluator_type,
            "evaluate",
            fake_evaluate,
        )

    results = runner.evaluate_shared_response_prototypes(context)

    assert context_calls == [context]
    assert len(evaluated_evidence) == 3
    assert all(
        item is shared_evidence
        for item in evaluated_evidence
    )
    assert len(results) == 3


def test_response_runner_accepts_precollected_evidence():
    from security_scanner.checks.response_runner import (
        evaluate_response_evidence_prototypes,
    )

    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Cache-Control": "no-store"},
    )

    results = evaluate_response_evidence_prototypes(evidence)

    assert len(results) == 3
    assert all(result.status in {"passed", "warning"} for result in results)


def test_response_runner_rejects_invalid_evidence():
    from security_scanner.checks.response_runner import (
        evaluate_response_evidence_prototypes,
    )

    with pytest.raises(TypeError, match="EvidenceCollection"):
        evaluate_response_evidence_prototypes(object())


def test_week3_runner_excludes_week4_cache_check():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Cache-Control": "no-store",
        },
    )

    results = evaluate_week3_evidence(evidence)
    check_ids = [result.check_id for result in results]

    assert len(check_ids) == 18
    assert len(check_ids) == len(set(check_ids))
    assert "header_referrer_policy" in check_ids
    assert "header_permissions_policy" in check_ids
    assert "cache_security" not in check_ids
