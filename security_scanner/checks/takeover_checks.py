"""Bounded passive dangling-DNS indicators for one explicitly eligible name.

One logical A resolution through the configured resolver; no enumeration,
per-hop queries, HTTP, provider probes or resource-claim attempts. A recursive
resolver may itself retry or follow aliases. NXDOMAIN is an unverified resolver
observation, not proof that a third-party resource can be registered.
"""

from dataclasses import dataclass, field
import ipaddress
import math
import time

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from .dns_checks import _normalize_domain, _DNS_TXT_LOOKUP_SLOTS, _DNS_TXT_TIMEOUT_SECONDS
from .result import CheckResult
from .provider_catalog import (
    PROVIDER_CATALOG_VERSION, ProviderObservation,
    classify_cname_providers, describe_provider_observation,
)


# Reuse the existing DNS evidence count bound, applied after message parsing.
_MAX_RECORDS = 100
_STATES = frozenset({
    "ineligible", "ip_target", "timeout", "dns_capacity", "dns_error",
    "inconclusive", "dangling", "no_cname", "resolved", "nodata",
})


@dataclass(frozen=True)
class TakeoverEvidence:
    """Sanitized observations: never retain raw names, records or exceptions."""

    query_state: str
    cname_count: int = 0
    provider: ProviderObservation = field(default_factory=ProviderObservation)

    def __post_init__(self):
        if self.query_state not in _STATES:
            raise ValueError("Unsupported takeover evidence state")
        if type(self.cname_count) is not int or not 0 <= self.cname_count <= _MAX_RECORDS:
            raise ValueError("Invalid CNAME count")
        if self.query_state == "dangling" and self.cname_count == 0:
            raise ValueError("Dangling evidence requires an attributable CNAME chain")
        if self.query_state not in {"dangling", "resolved", "nodata"} and self.cname_count:
            raise ValueError("This state cannot retain a CNAME count")
        if not isinstance(self.provider, ProviderObservation):
            raise TypeError("Expected sanitized provider observation")
        if self.provider.state != "unobserved" and (
            not self.cname_count or self.query_state not in {"dangling", "resolved", "nodata"}
        ):
            raise ValueError("Provider classification requires an attributable CNAME chain")


def _owner(name):
    try:
        return _normalize_domain(name.to_text())
    except Exception:
        return None


def _interpret_response(message, hostname):
    """Attribute a single response chain; never resolve discovered names."""
    unknown = TakeoverEvidence("inconclusive")
    if not isinstance(message, dns.message.Message):
        return unknown
    if not message.flags & dns.flags.QR or message.flags & dns.flags.TC:
        return unknown
    if len(message.question) != 1:
        return unknown
    question = message.question[0]
    if (
        _owner(question.name) != hostname
        or question.rdtype != dns.rdatatype.A
        or question.rdclass != dns.rdataclass.IN
    ):
        return unknown
    code = message.rcode()
    if code not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return unknown
    if len(message.answer) > _MAX_RECORDS:
        return unknown

    links, address_owners = {}, []
    count = 0
    for rrset in message.answer:
        count += len(rrset)
        if count > _MAX_RECORDS or rrset.rdclass != dns.rdataclass.IN:
            return unknown
        if rrset.rdtype == dns.rdatatype.CNAME:
            owner = _owner(rrset.name)
            if owner is None or len(rrset) != 1 or owner in links:
                return unknown
            destination = _owner(next(iter(rrset)).target)
            if destination is None:
                return unknown
            links[owner] = destination
        elif rrset.rdtype == dns.rdatatype.A:
            owner = _owner(rrset.name)
            if owner is None or not len(rrset) or owner in address_owners:
                return unknown
            # Reuse destination policy for observations, without connecting.
            from ..scanner import _is_allowed_ip
            if not all(_is_allowed_ip(ipaddress.ip_address(item.address)) for item in rrset):
                return unknown
            address_owners.append(owner)
        elif rrset.rdtype != dns.rdatatype.RRSIG:
            # DNAME/synthesized or otherwise unsupported chains stay inconclusive.
            return unknown

    terminal, visited, destinations = hostname, set(), []
    while terminal in links:
        if terminal in visited:
            return unknown
        visited.add(terminal)
        terminal = links[terminal]
        destinations.append(terminal)
    if len(visited) != len(links) or terminal in visited:
        return unknown
    if any(owner != terminal for owner in address_owners):
        return unknown
    provider = classify_cname_providers(destinations)
    if code == dns.rcode.NXDOMAIN:
        if address_owners:
            return unknown
        return TakeoverEvidence("dangling", len(visited), provider) if visited else TakeoverEvidence("no_cname")
    if address_owners:
        return TakeoverEvidence("resolved", len(visited), provider)
    return TakeoverEvidence("nodata", len(visited), provider)


def collect_takeover_evidence(hostname, deadline=None):
    """Caller supplies only a DNS-diagnostic eligible name, never an HTTP URL."""
    normalized = _normalize_domain(hostname)
    if normalized is None:
        try:
            if isinstance(hostname, str):
                ipaddress.ip_address(hostname.rstrip("."))
                return TakeoverEvidence("ip_target")
        except ValueError:
            pass
        return TakeoverEvidence("ineligible")
    timeout = _DNS_TXT_TIMEOUT_SECONDS
    if deadline is not None:
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
            return TakeoverEvidence("inconclusive")
        timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            return TakeoverEvidence("timeout")
    if not _DNS_TXT_LOOKUP_SLOTS.acquire(blocking=False):
        return TakeoverEvidence("dns_capacity")
    try:
        resolver = dns.resolver.Resolver(configure=True)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return TakeoverEvidence("timeout")
            timeout = min(timeout, remaining)
        try:
            answer = resolver.resolve(
                normalized + ".", "A", lifetime=timeout,
                search=False, raise_on_no_answer=False,
            )
            message = answer.response
        except dns.resolver.NXDOMAIN as error:
            # Attribute the negative answer to this exact query, not a suffix
            # search, unrelated exception response or fabricated terminal name.
            responses = error.responses()
            requested = dns.name.from_text(normalized + ".")
            if len(responses) != 1 or requested not in responses:
                return TakeoverEvidence("inconclusive")
            message = responses[requested]
        except dns.resolver.NoAnswer:
            return TakeoverEvidence("inconclusive")
        if deadline is not None and time.monotonic() >= deadline:
            return TakeoverEvidence("timeout")
        return _interpret_response(message, normalized)
    except dns.exception.Timeout:
        return TakeoverEvidence("timeout")
    except dns.exception.DNSException:
        return TakeoverEvidence("dns_error")
    except Exception:
        return TakeoverEvidence("inconclusive")
    finally:
        _DNS_TXT_LOOKUP_SLOTS.release()


def evaluate_takeover_evidence(evidence):
    if not isinstance(evidence, TakeoverEvidence):
        raise TypeError("Expected TakeoverEvidence")
    state = evidence.query_state
    status, severity = "not_verified", "info"
    observation = "DNS observations are insufficient to establish a dangling CNAME."
    if state == "dangling":
        status, severity = "warning", "low"
        observation = (
            f"An attributable chain of {evidence.cname_count} CNAME record(s) "
            "terminates in a resolver NXDOMAIN response: potential dangling-DNS indicator only."
        )
    elif state in {"ip_target", "dns_capacity"}:
        status = "skipped"
        observation = "IP target is not applicable." if state == "ip_target" else "DNS capacity was unavailable."
    elif state in {"timeout", "dns_error"}:
        status = "error"
        observation = "DNS resolution timed out." if state == "timeout" else "DNS resolution failed."
    elif state == "resolved":
        observation = "Address records were observed; this does not establish service ownership or takeover safety."
    elif state == "nodata":
        observation = "No terminal A records were observed; NODATA is not NXDOMAIN."
    elif state == "no_cname":
        observation = "NXDOMAIN was observed without an attributable CNAME chain; no dangling-CNAME conclusion follows."
    observation += " " + describe_provider_observation(evidence.provider)
    return CheckResult(
        check_id="subdomain_takeover_indicators", title="Passive subdomain takeover indicators",
        status=status, severity=severity, confidence="low", evidence=observation,
        explanation="This is a passive DNS observation, never proven takeover or confirmed resource availability.",
        recommendation="Review the configured DNS alias and service ownership with the domain administrator.",
        limitations=(
            "Only the exact supplied hostname was examined; no subdomain enumeration or provider probes.",
            "At most one logical A resolution; recursive retries/alias processing may involve multiple DNS packets.",
            "Resolver assertions and negative caches are not independently authenticated or rechecked.",
            "No resource registration, claiming, HTTP checks or cryptographic verification was performed.",
            "No provider-name match alone proves abandonment; raw DNS names and exception details are omitted.",
            "CNAME/record processing is capped at 100 records after parsing; unknown chains remain inconclusive.",
            "Only resolver/parser-returned records are inspected; data already normalized or discarded by them is unavailable.",
            f"Offline provider-domain catalog version {PROVIDER_CATALOG_VERSION}; recognized domains do not prove service ownership or abandonment.",
            "Provider-specific resource error evidence is not collected or verified; resource configuration and claimability remain not_verified.",
        ),
    )


def evaluate_takeover_domain(hostname, deadline=None):
    return evaluate_takeover_evidence(collect_takeover_evidence(hostname, deadline=deadline))
