import pytest

from security_scanner.checks import (
    CHECK_INPUT_CONTRACTS,
    CacheSecurityEvaluator,
    CheckContext,
    EvidenceCollection,
    PermissionsPolicyEvaluator,
    ReferrerPolicyEvaluator,
    create_default_registry,
)


def test_existing_response_flows_through_all_three_evaluators():
    registry = create_default_registry()

    context = CheckContext(
        safe_target_url="https://example.com",
        deadline=120.0,
        http_status=200,
        response_headers={
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "Cache-Control": "no-store",
        },
    )

    assert context.has_http_response

    evidence = EvidenceCollection.from_context(context)

    evaluators = {
        "header_referrer_policy": ReferrerPolicyEvaluator,
        "header_permissions_policy": PermissionsPolicyEvaluator,
        "cache_security": CacheSecurityEvaluator,
    }

    expected_statuses = {
        "header_referrer_policy": "passed",
        "header_permissions_policy": "warning",
        "cache_security": "passed",
    }

    results = {}

    for check_id, evaluator_type in evaluators.items():
        evaluator = evaluator_type(registry.get(check_id))
        results[check_id] = evaluator.evaluate(evidence)

    assert {
        check_id: result.status
        for check_id, result in results.items()
    } == expected_statuses

    for check_id, result in results.items():
        assert result.check_id == check_id

        finding = result.to_dict()

        assert isinstance(finding["evidence"], str)
        assert isinstance(finding["limitations"], list)
        assert set(finding) == {
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


def test_response_evaluators_use_shared_http_response_contract():
    check_ids = (
        "header_referrer_policy",
        "header_permissions_policy",
        "cache_security",
    )

    for check_id in check_ids:
        contract = CHECK_INPUT_CONTRACTS[check_id]

        assert contract.collection_modes == (
            "shared_http_response",
        )
        assert not contract.requires_additional_network_operation


def test_pipeline_does_not_expose_raw_cookie_values():
    secret = "session=private-test-secret"

    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={
            "Referrer-Policy": "same-origin",
            "Cache-Control": "no-store",
            "Set-Cookie": secret,
        },
    )

    evidence = EvidenceCollection.from_context(context)

    registry = create_default_registry()

    evaluators = (
        ReferrerPolicyEvaluator(
            registry.get("header_referrer_policy")
        ),
        CacheSecurityEvaluator(
            registry.get("cache_security")
        ),
    )

    results = [
        evaluator.evaluate(evidence)
        for evaluator in evaluators
    ]

    assert secret not in repr(context)
    assert secret not in repr(evidence)
    assert secret not in repr(results)

    assert all(
        secret not in result.to_dict()["evidence"]
        for result in results
    )


def test_pipeline_preserves_http_response_status():
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={
            "Cache-Control": "no-store",
        },
    )

    evidence = EvidenceCollection.from_context(context)

    assert evidence.http_status == context.http_status
    assert context.has_http_response


def test_failed_connection_does_not_create_response_evidence():
    context = CheckContext(
        safe_target_url="https://example.com",
        connection_error="timeout",
    )

    evidence = EvidenceCollection.from_context(context)

    assert not context.has_http_response
    assert evidence.http_status is None
    assert evidence.header_names == ()


@pytest.mark.parametrize(
    ("check_id", "evaluator_type"),
    [
        ("header_referrer_policy", ReferrerPolicyEvaluator),
        ("header_permissions_policy", PermissionsPolicyEvaluator),
        ("cache_security", CacheSecurityEvaluator),
    ],
)
def test_failed_http_context_produces_not_verified_findings(
    check_id,
    evaluator_type,
):
    context = CheckContext(
        safe_target_url="https://example.com",
        connection_error="timeout",
    )

    evidence = EvidenceCollection.from_context(context)
    registry = create_default_registry()
    evaluator = evaluator_type(registry.get(check_id))

    result = evaluator.evaluate(evidence)

    assert result.status == "not_verified"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert "HTTP" in result.evidence
