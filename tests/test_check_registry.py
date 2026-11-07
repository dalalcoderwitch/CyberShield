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
    assert all(
        item.implementation_status == "planned"
        for item in expanded
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


def test_check_definition_rejects_phase_status_mismatch():
    with pytest.raises(ValueError, match="must remain planned"):
        CheckDefinition(
            "bad_status_check",
            "Bad status",
            "passive",
            "expanded",
            "implemented",
        )
