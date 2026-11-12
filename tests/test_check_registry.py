from dataclasses import FrozenInstanceError

import pytest

from security_scanner.checks import (
    CheckDefinition,
    CheckRegistry,
    create_default_registry,
)


EXPECTED_CATEGORY_COUNTS = {
    "tls": 6,
    "headers": 6,
    "cookies": 3,
    "access": 2,
    "disclosure": 6,
    "dns": 4,
    "cache": 1,
    "passive": 2,
}


def test_default_registry_contains_30_unique_checks():
    registry = create_default_registry()

    assert len(registry) == 30

    ids = [item.check_id for item in registry]
    assert len(ids) == len(set(ids))


EXPECTED_IMPLEMENTED_EXPANDED_IDS = {
    "cookie_httponly",
    "cookie_samesite",
    "cookie_secure",
    "cors_misconfiguration",
    "directory_listing",
    "dns_dmarc",
    "dns_spf",
    "dnssec",
    "error_information_disclosure",
    "header_permissions_policy",
    "header_referrer_policy",
    "http_to_https_redirect",
    "open_redirect",
    "public_security_files",
    "redirect_destination_safety",
    "sensitive_file_exposure",
    "server_information_disclosure",
    "source_maps_exposure",
    "tls_certificate_chain",
    "tls_certificate_expiry",
    "tls_protocol_config",
}

EXPECTED_WEEK4_PLANNED_IDS = {
    "cache_security",
    "sqli_passive_indicators",
    "subdomain_takeover_indicators",
    "xss_passive_indicators",
}


def test_default_registry_has_correct_phases_and_statuses():
    registry = create_default_registry()

    foundational = registry.by_phase("foundational")
    expanded = registry.by_phase("expanded")

    assert len(foundational) == 5
    assert len(expanded) == 25

    assert all(
        item.implementation_status == "implemented"
        for item in foundational
    )

    expanded_implemented = {
        item.check_id for item in expanded
        if item.implementation_status == "implemented"
    }
    expanded_planned = {
        item.check_id for item in expanded
        if item.implementation_status == "planned"
    }

    assert expanded_implemented == EXPECTED_IMPLEMENTED_EXPANDED_IDS
    assert expanded_planned == EXPECTED_WEEK4_PLANNED_IDS
    assert len(expanded_implemented) == 21
    assert len(expanded_planned) == 4


def test_expanded_check_definition_accepts_both_lifecycle_statuses():
    for status in ("implemented", "planned"):
        definition = CheckDefinition(
            f"custom_{status}",
            "Custom check",
            "passive",
            "expanded",
            status,
        )
        assert definition.implementation_status == status


def test_foundational_check_definition_rejects_planned_status():
    with pytest.raises(ValueError, match="Foundational checks must be marked"):
        CheckDefinition(
            "custom_foundational",
            "Custom foundational check",
            "passive",
            "foundational",
            "planned",
        )


def test_check_definition_rejects_unsupported_implementation_status():
    with pytest.raises(ValueError, match="Unsupported implementation_status"):
        CheckDefinition(
            "custom_invalid_status",
            "Custom check",
            "passive",
            "expanded",
            "unknown",
        )


@pytest.mark.parametrize(
    ("category", "expected_count"),
    EXPECTED_CATEGORY_COUNTS.items(),
)
def test_default_registry_has_correct_category_counts(
    category,
    expected_count,
):
    registry = create_default_registry()

    assert len(registry.by_category(category)) == expected_count


def test_registry_lookup_returns_definition_or_none():
    registry = create_default_registry()

    definition = registry.get("https_connection")

    assert definition is not None
    assert definition.check_id == "https_connection"
    assert registry.get("unknown_check") is None


def test_registry_rejects_duplicate_check_ids():
    definition = CheckDefinition(
        "custom_check",
        "Custom check",
        "passive",
        "expanded",
        "planned",
    )
    registry = CheckRegistry([definition])

    with pytest.raises(ValueError, match="Duplicate check_id"):
        registry.register(definition)


def test_registry_rejects_non_definition_values():
    registry = CheckRegistry()

    with pytest.raises(TypeError):
        registry.register(object())


def test_registry_preserves_registration_order():
    first = CheckDefinition(
        "first_check",
        "First check",
        "passive",
        "expanded",
        "planned",
    )
    second = CheckDefinition(
        "second_check",
        "Second check",
        "cache",
        "expanded",
        "planned",
    )

    registry = CheckRegistry([first, second])

    assert registry.all() == (first, second)
    assert list(registry) == [first, second]


def test_default_registry_instances_are_independent():
    first = create_default_registry()
    second = create_default_registry()

    extra = CheckDefinition(
        "local_test_check",
        "Local test check",
        "passive",
        "expanded",
        "planned",
    )

    first.register(extra)

    assert len(first) == 31
    assert len(second) == 30
    assert second.get("local_test_check") is None


def test_check_definition_is_immutable():
    definition = CheckDefinition(
        "immutable_check",
        "Immutable check",
        "passive",
        "expanded",
        "planned",
    )

    with pytest.raises(FrozenInstanceError):
        definition.title = "Changed title"


def test_check_definition_rejects_invalid_id():
    with pytest.raises(ValueError, match="Invalid check_id"):
        CheckDefinition(
            "Invalid-ID",
            "Invalid ID",
            "passive",
            "expanded",
            "planned",
        )


def test_check_definition_rejects_unsupported_category():
    with pytest.raises(ValueError, match="Unsupported category"):
        CheckDefinition(
            "bad_category_check",
            "Bad category",
            "unknown",
            "expanded",
            "planned",
        )
