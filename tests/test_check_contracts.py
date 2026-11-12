import pytest

from security_scanner.checks import create_default_registry
from security_scanner.checks.contracts import (
    CHECK_INPUT_CONTRACTS,
    CheckInputContract,
    get_check_input_contract,
)


def test_input_contracts_cover_exactly_all_registered_checks():
    registry = create_default_registry()

    assert set(CHECK_INPUT_CONTRACTS) == {
        item.check_id for item in registry
    }
    assert len(CHECK_INPUT_CONTRACTS) == 30


def test_every_contract_has_required_inputs_and_collection_modes():
    for contract in CHECK_INPUT_CONTRACTS.values():
        assert contract.required_inputs
        assert contract.collection_modes
        assert all(
            isinstance(item, str) and item.strip()
            for item in contract.required_inputs
        )


def test_existing_response_checks_do_not_require_extra_network():
    registry = create_default_registry()

    existing_response_ids = {
        "https_connection",
        "header_hsts",
        "header_csp",
        "header_x_content_type_options",
        "header_x_frame_options",
        "header_referrer_policy",
        "header_permissions_policy",
        "cookie_secure",
        "cookie_httponly",
        "cookie_samesite",
        "server_information_disclosure",
        "cache_security",
    }

    for check_id in existing_response_ids:
        assert not (
            CHECK_INPUT_CONTRACTS[
                check_id
            ].requires_additional_network_operation
        )


def test_dns_checks_are_explicitly_marked_as_dns_operations():
    dns_ids = {
        "dns_spf",
        "dns_dmarc",
        "dnssec",
        "subdomain_takeover_indicators",
    }

    for check_id in dns_ids:
        contract = CHECK_INPUT_CONTRACTS[check_id]

        assert contract.collection_modes == ("dns_queries",)
        assert contract.requires_additional_network_operation


def test_takeover_contract_requires_dns_evidence_without_provider_probes():
    contract = CHECK_INPUT_CONTRACTS["subdomain_takeover_indicators"]
    assert contract.required_inputs == (
        "attributable_cname_chain", "terminal_dns_status", "query_state",
    )
    assert contract.collection_modes == ("dns_queries",)


def test_http_probe_checks_are_explicitly_marked():
    probe_ids = {
        "http_to_https_redirect",
        "redirect_destination_safety",
        "cors_misconfiguration",
        "sensitive_file_exposure",
        "source_maps_exposure",
        "directory_listing",
        "public_security_files",
    }

    for check_id in probe_ids:
        contract = CHECK_INPUT_CONTRACTS[check_id]

        assert "bounded_http_probe" in contract.collection_modes
        assert contract.requires_additional_network_operation


def test_passive_checks_reuse_sanitized_shared_response():
    passive_ids = {
        "xss_passive_indicators",
        "sqli_passive_indicators",
    }

    for check_id in passive_ids:
        contract = CHECK_INPUT_CONTRACTS[check_id]

        assert contract.collection_modes == ("shared_http_response",)
        assert not contract.requires_additional_network_operation


def test_contract_lookup_returns_none_for_unknown_id():
    assert get_check_input_contract("unknown_check") is None


def test_contract_mapping_is_immutable():
    with pytest.raises(TypeError):
        CHECK_INPUT_CONTRACTS["new_check"] = object()


def test_input_contract_is_immutable():
    contract = get_check_input_contract("header_hsts")

    with pytest.raises(AttributeError):
        contract.check_id = "changed"


def test_contract_rejects_unknown_collection_mode():
    with pytest.raises(ValueError, match="Unsupported collection modes"):
        CheckInputContract(
            check_id="custom_check",
            required_inputs=("response_headers",),
            collection_modes=("unsafe_network_access",),
        )


def test_contract_rejects_duplicate_required_inputs():
    with pytest.raises(ValueError, match="Duplicate required inputs"):
        CheckInputContract(
            check_id="custom_check",
            required_inputs=("headers", "headers"),
            collection_modes=("shared_http_response",),
        )


def test_open_redirect_uses_original_shared_response_without_probe():
    contract = CHECK_INPUT_CONTRACTS["open_redirect"]

    assert contract.required_inputs == (
        "http_status",
        "redirect_location_values",
        "redirect_evidence_available",
        "redirect_request_url",
    )
    assert contract.collection_modes == ("shared_http_response",)
    assert not contract.requires_additional_network_operation
