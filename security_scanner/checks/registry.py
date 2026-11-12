"""Registry and catalog for CyberShield security checks.

The registry stores metadata only. It does not execute checks.
Existing scanner behavior remains unchanged.
"""

from .base import CheckDefinition


class CheckRegistry:
    """Stores check definitions and prevents duplicate check IDs."""

    def __init__(self, definitions=()):
        self._definitions = {}

        for definition in definitions:
            self.register(definition)

    def register(self, definition):
        if not isinstance(definition, CheckDefinition):
            raise TypeError("definition must be a CheckDefinition")

        if definition.check_id in self._definitions:
            raise ValueError(
                f"Duplicate check_id: {definition.check_id}"
            )

        self._definitions[definition.check_id] = definition
        return definition

    def get(self, check_id):
        """Return a definition, or None when the ID is unknown."""
        return self._definitions.get(check_id)

    def all(self):
        """Return all definitions in registration order."""
        return tuple(self._definitions.values())

    def by_category(self, category):
        """Return definitions belonging to one category."""
        return tuple(
            definition
            for definition in self._definitions.values()
            if definition.category == category
        )

    def by_phase(self, phase):
        """Return foundational or expanded definitions."""
        return tuple(
            definition
            for definition in self._definitions.values()
            if definition.phase == phase
        )

    def __len__(self):
        return len(self._definitions)

    def __iter__(self):
        return iter(self.all())


FOUNDATIONAL_CHECK_DEFINITIONS = (
    CheckDefinition(
        "https_connection",
        "HTTPS connection",
        "tls",
        "foundational",
        "implemented",
    ),
    CheckDefinition(
        "header_hsts",
        "HTTP Strict Transport Security",
        "headers",
        "foundational",
        "implemented",
    ),
    CheckDefinition(
        "header_csp",
        "Content Security Policy",
        "headers",
        "foundational",
        "implemented",
    ),
    CheckDefinition(
        "header_x_content_type_options",
        "X-Content-Type-Options",
        "headers",
        "foundational",
        "implemented",
    ),
    CheckDefinition(
        "header_x_frame_options",
        "X-Frame-Options",
        "headers",
        "foundational",
        "implemented",
    ),
)


EXPANDED_CHECK_DEFINITIONS = (
    CheckDefinition(
        "tls_certificate_expiry",
        "TLS certificate expiry",
        "tls",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "tls_certificate_chain",
        "TLS certificate chain",
        "tls",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "tls_protocol_config",
        "TLS protocol configuration",
        "tls",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "http_to_https_redirect",
        "HTTP to HTTPS redirect",
        "tls",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "redirect_destination_safety",
        "Redirect destination safety",
        "tls",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "header_referrer_policy",
        "Referrer-Policy header",
        "headers",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "header_permissions_policy",
        "Permissions-Policy header",
        "headers",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "cookie_secure",
        "Cookie Secure attribute",
        "cookies",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "cookie_httponly",
        "Cookie HttpOnly attribute",
        "cookies",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "cookie_samesite",
        "Cookie SameSite attribute",
        "cookies",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "cors_misconfiguration",
        "CORS misconfiguration indicators",
        "access",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "open_redirect",
        "Open redirect indicators",
        "access",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "sensitive_file_exposure",
        "Sensitive file exposure",
        "disclosure",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "source_maps_exposure",
        "Source maps exposure",
        "disclosure",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "directory_listing",
        "Directory listing exposure",
        "disclosure",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "server_information_disclosure",
        "Server information disclosure",
        "disclosure",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "error_information_disclosure",
        "Error information disclosure",
        "disclosure",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "public_security_files",
        "Public security files",
        "disclosure",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "dns_spf",
        "DNS SPF record",
        "dns",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "dns_dmarc",
        "DNS DMARC record",
        "dns",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "dnssec",
        "DNSSEC indicators",
        "dns",
        "expanded",
        "implemented",
    ),
    CheckDefinition(
        "subdomain_takeover_indicators",
        "Subdomain takeover indicators",
        "dns",
        "expanded",
        "planned",
    ),
    CheckDefinition(
        "cache_security",
        "Cache security headers",
        "cache",
        "expanded",
        "planned",
    ),
    CheckDefinition(
        "xss_passive_indicators",
        "Passive XSS indicators",
        "passive",
        "expanded",
        "planned",
    ),
    CheckDefinition(
        "sqli_passive_indicators",
        "Passive SQL injection indicators",
        "passive",
        "expanded",
        "planned",
    ),
)


CHECK_DEFINITIONS = (
    FOUNDATIONAL_CHECK_DEFINITIONS + EXPANDED_CHECK_DEFINITIONS
)


def create_default_registry():
    """Build a fresh registry containing implemented and planned catalog entries."""
    return CheckRegistry(CHECK_DEFINITIONS)
