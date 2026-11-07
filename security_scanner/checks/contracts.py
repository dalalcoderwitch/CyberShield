"""Input requirements and collection modes for security checks."""

from dataclasses import dataclass
from types import MappingProxyType
import re


_CHECK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

_ALLOWED_COLLECTION_MODES = frozenset(
    {
        "shared_http_response",
        "tls_handshake_metadata",
        "dns_queries",
        "bounded_http_probe",
        "bounded_response_body",
    }
)

_ADDITIONAL_NETWORK_MODES = frozenset(
    {
        "dns_queries",
        "bounded_http_probe",
    }
)


@dataclass(frozen=True)
class CheckInputContract:
    """Describe the data required by one check.

    This is metadata only. It does not perform DNS queries,
    HTTP requests, TLS inspection, or response-body reads.
    """

    check_id: str
    required_inputs: tuple[str, ...]
    collection_modes: tuple[str, ...]

    def __post_init__(self):
        if (
            not isinstance(self.check_id, str)
            or not _CHECK_ID_PATTERN.fullmatch(self.check_id)
        ):
            raise ValueError("Invalid check_id")

        if not isinstance(self.required_inputs, (list, tuple)):
            raise TypeError("required_inputs must be a list or tuple")

        if not isinstance(self.collection_modes, (list, tuple)):
            raise TypeError("collection_modes must be a list or tuple")

        required = tuple(self.required_inputs)
        modes = tuple(self.collection_modes)

        if not required or not all(
            isinstance(item, str) and item.strip()
            for item in required
        ):
            raise ValueError(
                "required_inputs must contain non-empty strings"
            )

        if len(required) != len(set(required)):
            raise ValueError("Duplicate required inputs")

        if not modes or not all(
            isinstance(mode, str) for mode in modes
        ):
            raise ValueError(
                "collection_modes must contain non-empty strings"
            )

        if len(modes) != len(set(modes)):
            raise ValueError("Duplicate collection modes")

        unsupported = set(modes) - _ALLOWED_COLLECTION_MODES
        if unsupported:
            raise ValueError(
                f"Unsupported collection modes: {sorted(unsupported)}"
            )

        object.__setattr__(self, "required_inputs", required)
        object.__setattr__(self, "collection_modes", modes)

    @property
    def requires_additional_network_operation(self) -> bool:
        """Whether a DNS query or additional HTTP probe is required."""
        return bool(
            set(self.collection_modes) & _ADDITIONAL_NETWORK_MODES
        )


def _contract(check_id, required_inputs, *collection_modes):
    return CheckInputContract(
        check_id=check_id,
        required_inputs=tuple(required_inputs),
        collection_modes=tuple(collection_modes),
    )


_CONTRACT_ITEMS = (
    # Foundational checks: existing connection and response.
    _contract(
        "https_connection",
        ("connection_outcome", "http_status", "tls_validation_result"),
        "shared_http_response",
    ),
    _contract(
        "header_hsts",
        ("strict_transport_security",),
        "shared_http_response",
    ),
    _contract(
        "header_csp",
        ("content_security_policy",),
        "shared_http_response",
    ),
    _contract(
        "header_x_content_type_options",
        ("x_content_type_options",),
        "shared_http_response",
    ),
    _contract(
        "header_x_frame_options",
        ("x_frame_options",),
        "shared_http_response",
    ),

    # TLS.
    _contract(
        "tls_certificate_expiry",
        ("certificate_not_before", "certificate_not_after"),
        "tls_handshake_metadata",
    ),
    _contract(
        "tls_certificate_chain",
        ("peer_certificate", "certificate_chain"),
        "tls_handshake_metadata",
    ),
    _contract(
        "tls_protocol_config",
        ("negotiated_tls_version", "cipher_suite"),
        "tls_handshake_metadata",
    ),
    _contract(
        "http_to_https_redirect",
        ("http_redirect_status", "location_header"),
        "bounded_http_probe",
    ),
    _contract(
        "redirect_destination_safety",
        ("redirect_location", "destination_policy_result"),
        "bounded_http_probe",
    ),

    # Additional headers.
    _contract(
        "header_referrer_policy",
        ("referrer_policy",),
        "shared_http_response",
    ),
    _contract(
        "header_permissions_policy",
        ("permissions_policy",),
        "shared_http_response",
    ),

    # Cookies.
    _contract(
        "cookie_secure",
        ("set_cookie_attributes",),
        "shared_http_response",
    ),
    _contract(
        "cookie_httponly",
        ("set_cookie_attributes",),
        "shared_http_response",
    ),
    _contract(
        "cookie_samesite",
        ("set_cookie_attributes",),
        "shared_http_response",
    ),

    # Access.
    _contract(
        "cors_misconfiguration",
        ("cors_preflight_headers", "cors_origin_response_headers"),
        "bounded_http_probe",
    ),
    _contract(
        "open_redirect",
        ("controlled_redirect_probe", "redirect_location"),
        "bounded_http_probe",
    ),

    # Disclosure.
    _contract(
        "sensitive_file_exposure",
        ("allowlisted_path_status", "content_type"),
        "bounded_http_probe",
    ),
    _contract(
        "source_maps_exposure",
        ("bounded_html_sample", "source_map_reference", "asset_response"),
        "bounded_response_body",
        "bounded_http_probe",
    ),
    _contract(
        "directory_listing",
        ("allowlisted_directory_status", "bounded_response_sample"),
        "bounded_http_probe",
    ),
    _contract(
        "server_information_disclosure",
        ("server_headers",),
        "shared_http_response",
    ),
    _contract(
        "error_information_disclosure",
        ("bounded_error_response_sample",),
        "bounded_response_body",
    ),
    _contract(
        "public_security_files",
        ("allowlisted_security_file_status", "content_type"),
        "bounded_http_probe",
    ),

    # DNS.
    _contract(
        "dns_spf",
        ("spf_txt_records",),
        "dns_queries",
    ),
    _contract(
        "dns_dmarc",
        ("dmarc_txt_records",),
        "dns_queries",
    ),
    _contract(
        "dnssec",
        ("dnssec_validation_status",),
        "dns_queries",
    ),
    _contract(
        "subdomain_takeover_indicators",
        ("cname_records", "provider_fingerprints"),
        "dns_queries",
    ),

    # Cache.
    _contract(
        "cache_security",
        ("cache_control", "pragma", "expires"),
        "shared_http_response",
    ),

    # Passive indicators.
    _contract(
        "xss_passive_indicators",
        ("bounded_response_body_sample",),
        "bounded_response_body",
    ),
    _contract(
        "sqli_passive_indicators",
        ("bounded_response_body_sample",),
        "bounded_response_body",
    ),
)


CHECK_INPUT_CONTRACTS = MappingProxyType(
    {
        item.check_id: item
        for item in _CONTRACT_ITEMS
    }
)


def get_check_input_contract(check_id):
    """Return the input contract or None for an unknown check."""
    return CHECK_INPUT_CONTRACTS.get(check_id)
