import security_scanner.checks as checks


def test_all_check_architecture_components_are_public():
    expected_exports = {
        "CheckDefinition",
        "CheckContext",
        "CheckInputContract",
        "CHECK_INPUT_CONTRACTS",
        "get_check_input_contract",
        "CheckEvaluator",
        "ReferrerPolicyEvaluator",
        "PermissionsPolicyEvaluator",
        "CacheSecurityEvaluator",
        "EvidenceCollection",
        "CheckResult",
        "CheckRegistry",
        "CHECK_DEFINITIONS",
        "FOUNDATIONAL_CHECK_DEFINITIONS",
        "EXPANDED_CHECK_DEFINITIONS",
        "create_default_registry",
    }

    assert expected_exports.issubset(set(checks.__all__))

    for name in expected_exports:
        assert hasattr(checks, name)


def test_public_components_can_be_imported_directly():
    from security_scanner.checks import (
        CheckContext,
        CHECK_INPUT_CONTRACTS,
        CheckInputContract,
        get_check_input_contract,
        CheckDefinition,
        CheckEvaluator,
        ReferrerPolicyEvaluator,
        PermissionsPolicyEvaluator,
        CacheSecurityEvaluator,
        CheckRegistry,
        CheckResult,
        EvidenceCollection,
    )

    assert CheckDefinition is checks.CheckDefinition
    assert CheckContext is checks.CheckContext
    assert CheckEvaluator is checks.CheckEvaluator
    assert ReferrerPolicyEvaluator is checks.ReferrerPolicyEvaluator
    assert PermissionsPolicyEvaluator is checks.PermissionsPolicyEvaluator
    assert CacheSecurityEvaluator is checks.CacheSecurityEvaluator
    assert CheckRegistry is checks.CheckRegistry
    assert CheckResult is checks.CheckResult
    assert EvidenceCollection is checks.EvidenceCollection


def test_response_runner_is_exported_from_public_package():
    import security_scanner.checks as checks

    from security_scanner.checks import (
        evaluate_shared_response_prototypes,
    )
    from security_scanner.checks.response_runner import (
        evaluate_shared_response_prototypes as internal_runner,
    )

    assert "evaluate_shared_response_prototypes" in checks.__all__
    assert evaluate_shared_response_prototypes is internal_runner
