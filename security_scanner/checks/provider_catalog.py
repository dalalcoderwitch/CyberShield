"""Offline provider-domain associations, NOT unconfigured-resource fingerprints.

Sources establish documented hosting domains, never abandonment/claimability.
Only destinations in the attributed CNAME chain are examined by the caller.
No DNS/HTTP/provider requests, resource IDs or observed hostnames are retained.
"""

from dataclasses import dataclass

from .dns_checks import _normalize_domain


PROVIDER_CATALOG_VERSION = "1.0.0"


@dataclass(frozen=True)
class ProviderDefinition:
    provider_id: str
    label: str
    suffix: str
    documentation_url: str
    reviewed_on: str = "2026-11-12"


# Deliberately small; not a vulnerability/claimability database. No wildcards,
# error-page signatures, management endpoints or network refresh mechanism.
PROVIDER_CATALOG = (
    ProviderDefinition(
        "github_pages", "GitHub Pages", "github.io",
        "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site",
    ),
    ProviderDefinition(
        "azure_app_service", "Azure App Service", "azurewebsites.net",
        "https://learn.microsoft.com/en-us/azure/app-service/overview-custom-domains",
    ),
)


@dataclass(frozen=True)
class ProviderObservation:
    """Fixed classifications only; no supplied names or provider-resource data."""
    state: str = "unobserved"
    provider_id: str | None = None

    def __post_init__(self):
        if self.state not in {"unobserved", "unrecognized", "recognized", "conflicting", "inconclusive"}:
            raise ValueError("Unsupported provider classification")
        if self.state == "recognized":
            if self.provider_id not in tuple(item.provider_id for item in PROVIDER_CATALOG):
                raise ValueError("Unsupported catalog provider")
        elif self.provider_id is not None:
            raise ValueError("Only an unambiguous catalog match may identify a provider")


def classify_cname_providers(destinations):
    """Classify an already attributed chain with strict DNS label boundaries.

    A catalog suffix itself is not a resource hostname. A match at any hop is
    only an association in that chain, not verified current service ownership.
    Multiple recognized providers suppress a specific provider attribution.
    """
    if not isinstance(destinations, (tuple, list)) or len(destinations) > 100:
        return ProviderObservation("inconclusive")
    if not destinations:
        return ProviderObservation()
    recognized = set()
    for destination in destinations:
        normalized = _normalize_domain(destination)
        if normalized is None:
            return ProviderObservation("inconclusive")
        for provider in PROVIDER_CATALOG:
            if normalized.endswith("." + provider.suffix):
                recognized.add(provider.provider_id)
    if len(recognized) > 1:
        return ProviderObservation("conflicting")
    if recognized:
        return ProviderObservation("recognized", next(iter(recognized)))
    return ProviderObservation("unrecognized")


def describe_provider_observation(observation):
    """Render fixed catalog text only; input values never reach the report."""
    if observation.state == "recognized":
        provider = next(item for item in PROVIDER_CATALOG if item.provider_id == observation.provider_id)
        return f"A documented {provider.label} domain was observed in the attributed CNAME chain."
    if observation.state == "conflicting":
        return "Different catalog provider domains occurred in the chain; a single provider association is not verified."
    if observation.state == "unrecognized":
        return "No domain association in this small provider catalog was observed; other providers may exist."
    return "Provider-domain association was not established from the available CNAME evidence."
