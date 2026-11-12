"""Passive DNSSEC indicator collection, not cryptographic validation.

Observe SOA, zone-owned DNSKEY and matching DNSKEY-covering RRSIG records
through the system-configured recursive resolver. DO requests records and AD
is an untrusted observation; neither establishes a verified chain of trust.
Counts are bounded after parsing; these are not wire-size limits. SOA-based
zone discovery can remain inconclusive for aliases and negative responses.
"""

from dataclasses import dataclass
import ipaddress
import time

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver

from .base import CheckDefinition
from .dns_checks import (
    _DNS_TXT_LOOKUP_SLOTS,
    _DNS_TXT_TIMEOUT_SECONDS,
    _normalize_domain,
)
from .result import CheckResult


_MAX_DNSSEC_RECORDS = 100

_ALLOWED_DNSSEC_STATES = frozenset({
    "available",
    "no_zone_apex",
    "no_dnskey",
    "timeout",
    "dns_error",
    "dns_capacity",
    "invalid_target",
    "not_applicable",
    "oversized_response",
    "inconsistent_response",
})


@dataclass(frozen=True)
class DNSSECEvidence:
    """Bounded DNSSEC indicators without retaining raw key material."""

    query_state: str
    dnskey_count: int = 0
    rrsig_count: int = 0
    authenticated_data: bool = False
    zone_name: str | None = None

    def __post_init__(self):
        if self.query_state not in _ALLOWED_DNSSEC_STATES:
            raise ValueError("Unsupported DNSSEC query state")

        for name in ("dnskey_count", "rrsig_count"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > _MAX_DNSSEC_RECORDS
            ):
                raise ValueError("Invalid DNSSEC record count")

        if not isinstance(self.authenticated_data, bool):
            raise TypeError("authenticated_data must be boolean")

        if self.zone_name is not None:
            normalized_zone = _normalize_domain(self.zone_name)
            if normalized_zone != self.zone_name:
                raise ValueError("Invalid DNSSEC zone name")

        if self.query_state == "available" and self.dnskey_count == 0:
            raise ValueError("Available evidence requires DNSKEY records")

        if self.query_state != "available":
            if self.dnskey_count or self.rrsig_count:
                raise ValueError("Non-available evidence cannot contain records")

        if (
            self.query_state not in ("available", "no_dnskey")
            and (self.authenticated_data or self.zone_name is not None)
        ):
            raise ValueError("This state cannot contain DNSSEC response evidence")


def _rrset_owner(rrset):
    """Normalize an observed owner without inventing one for missing data."""
    owner = getattr(rrset, "name", None)
    try:
        owner_text = owner if isinstance(owner, str) else owner.to_text()
        return _normalize_domain(owner_text)
    except Exception:
        return None


def _find_zone_apex(soa_answer, normalized_domain):
    """Accept one consistent ancestor SOA owner, never pick among zones."""

    response = getattr(soa_answer, "response", None)
    if response is None:
        return None

    candidates = []

    answer_rrset = getattr(soa_answer, "rrset", None)
    if answer_rrset is not None:
        candidates.append(answer_rrset)

    for section_name in ("answer", "authority"):
        candidates.extend(
            getattr(response, section_name, ()) or ()
        )

    zones = set()
    for rrset in candidates:
        if getattr(rrset, "rdtype", None) != dns.rdatatype.SOA:
            continue

        zone_name = _rrset_owner(rrset)
        if zone_name is None or len(rrset) != 1:
            return None

        if (
            normalized_domain == zone_name
            or normalized_domain.endswith("." + zone_name)
        ):
            zones.add(zone_name)
        else:
            return None

    return next(iter(zones)) if len(zones) == 1 else None


def collect_dnssec_evidence(domain, deadline=None):
    """Discover the enclosing zone from SOA, then query its DNSKEY RRset."""

    normalized_domain = _normalize_domain(domain)

    if normalized_domain is None:
        if isinstance(domain, str):
            try:
                ipaddress.ip_address(domain.rstrip("."))
                return DNSSECEvidence("not_applicable")
            except ValueError:
                pass
        return DNSSECEvidence("invalid_target")

    if deadline is not None:
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
        ):
            return DNSSECEvidence("invalid_target")

        if deadline - time.monotonic() <= 0:
            return DNSSECEvidence("timeout")

    def remaining_timeout():
        timeout = _DNS_TXT_TIMEOUT_SECONDS
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            timeout = min(timeout, remaining)
        return timeout

    if not _DNS_TXT_LOOKUP_SLOTS.acquire(blocking=False):
        return DNSSECEvidence("dns_capacity")

    zone_name = None

    try:
        resolver = dns.resolver.Resolver(configure=True)

        # Request DNSSEC records in both the SOA and DNSKEY responses.
        resolver.use_edns(
            edns=0,
            ednsflags=dns.flags.DO,
        )

        soa_timeout = remaining_timeout()
        if soa_timeout is None:
            return DNSSECEvidence("timeout")

        soa_answer = resolver.resolve(
            normalized_domain + ".",
            "SOA",
            lifetime=soa_timeout,
            search=False,
            raise_on_no_answer=False,
        )

        zone_name = _find_zone_apex(soa_answer, normalized_domain)
        if zone_name is None:
            return DNSSECEvidence("no_zone_apex")

        dnskey_timeout = remaining_timeout()
        if dnskey_timeout is None:
            return DNSSECEvidence("timeout")

        answer = resolver.resolve(
            zone_name + ".",
            "DNSKEY",
            lifetime=dnskey_timeout,
            search=False,
            raise_on_no_answer=False,
        )

        response = getattr(answer, "response", None)
        if response is None:
            return DNSSECEvidence("inconsistent_response")

        response_flags = getattr(response, "flags", None)
        answer_section = getattr(response, "answer", None)
        if (
            isinstance(response_flags, bool)
            or not isinstance(response_flags, int)
            or not 0 <= response_flags <= 65535
            or not isinstance(answer_section, (list, tuple))
        ):
            return DNSSECEvidence("inconsistent_response")
        authenticated_data = bool(response_flags & dns.flags.AD)

        rrset = getattr(answer, "rrset", None)
        if rrset is None:
            return DNSSECEvidence(
                "no_dnskey",
                authenticated_data=authenticated_data,
                zone_name=zone_name,
            )

        if (
            getattr(rrset, "rdtype", None) != dns.rdatatype.DNSKEY
            or _rrset_owner(rrset) != zone_name
            or len(rrset) == 0
        ):
            return DNSSECEvidence("inconsistent_response")

        dnskey_count = len(rrset)
        rrsig_count = 0

        for response_rrset in answer_section:
            record_type = getattr(response_rrset, "rdtype", None)
            if record_type == dns.rdatatype.DNSKEY and response_rrset is not rrset:
                # A second DNSKEY RRset is ambiguous, even at the same owner.
                return DNSSECEvidence("inconsistent_response")
            if record_type == dns.rdatatype.RRSIG:
                if (
                    _rrset_owner(response_rrset) != zone_name
                    or getattr(response_rrset, "covers", None) != dns.rdatatype.DNSKEY
                    or len(response_rrset) == 0
                ):
                    return DNSSECEvidence("inconsistent_response")
                rrsig_count += len(response_rrset)

        if (
            dnskey_count > _MAX_DNSSEC_RECORDS
            or rrsig_count > _MAX_DNSSEC_RECORDS
        ):
            return DNSSECEvidence("oversized_response")

        return DNSSECEvidence(
            "available",
            dnskey_count=dnskey_count,
            rrsig_count=rrsig_count,
            authenticated_data=authenticated_data,
            zone_name=zone_name,
        )

    except (
        dns.resolver.LifetimeTimeout,
        dns.exception.Timeout,
    ):
        return DNSSECEvidence("timeout")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        if zone_name is None:
            return DNSSECEvidence("no_zone_apex")
        return DNSSECEvidence(
            "no_dnskey",
            zone_name=zone_name,
        )
    except dns.exception.DNSException:
        return DNSSECEvidence("dns_error")
    except Exception:
        # Do not expose resolver details or raw exception text.
        return DNSSECEvidence("dns_error")
    finally:
        _DNS_TXT_LOOKUP_SLOTS.release()


class DNSSECCheckEvaluator:
    """Evaluate DNSSEC indicators without performing network access."""

    def __init__(self, definition: CheckDefinition):
        if not isinstance(definition, CheckDefinition):
            raise TypeError("definition must be a CheckDefinition")
        if definition.check_id != "dnssec":
            raise ValueError("DNSSEC evaluator requires the dnssec definition")
        self.definition = definition

    def _result(
        self,
        status,
        severity,
        confidence,
        evidence,
        explanation,
        recommendation,
        limitations=(),
    ):
        return CheckResult(
            check_id=self.definition.check_id,
            title="DNSSEC indicators",
            status=status,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            explanation=explanation,
            recommendation=recommendation,
            limitations=tuple(limitations) + (
                "Passive observations only: DNSKEY/RRSIG presence does not "
                "mean cryptographic signatures or a DS/DNSKEY trust chain were verified.",
                "AD is a resolver assertion, not trusted verification by CyberShield; "
                "there is no configured trust relationship or secure channel.",
                "SOA-based zone discovery can be inconclusive for aliases or negative "
                "answers. Missing records do not prove DNSSEC is disabled.",
                "Record-count limits apply after parsing; DNS requests use the "
                "system-configured resolver and the remaining query lifetime.",
            ),
        )

    def evaluate(self, evidence: DNSSECEvidence):
        if not isinstance(evidence, DNSSECEvidence):
            raise TypeError("evidence must be DNSSECEvidence")

        state = evidence.query_state

        if state == "inconsistent_response":
            return self._result(
                "not_verified", "info", "low",
                "DNSSEC response ownership, record type, or RRset contents were inconsistent.",
                "The observations could not be reliably attributed to the SOA-derived "
                "zone. No DNSSEC security conclusion was inferred.",
                "Review the zone's DNS response and resolver behavior, then retry.",
            )

        if state == "no_zone_apex":
            return self._result(
                "not_verified", "info", "low",
                "No single consistent ancestor SOA owner was available to identify the zone apex.",
                "The DNSSEC check could not reliably identify which zone "
                "owns the target name. No conclusion about DNSSEC deployment "
                "was inferred.",
                "Check the target's DNS delegation and SOA response, then retry.",
                (
                    "The check does not perform an independent DNS tree walk "
                    "or parent DS-chain validation.",
                ),
            )

        if state == "not_applicable":
            return self._result(
                "skipped", "info", "high",
                "The target is an IP address.",
                "DNSSEC is evaluated for DNS names, not IP literals.",
                "Use a valid hostname for this check.",
            )

        if state == "invalid_target":
            return self._result(
                "not_verified", "info", "low",
                "No valid hostname was available for the DNSSEC query.",
                "No DNSSEC conclusion can be drawn from an invalid target.",
                "Check the target hostname and retry.",
            )

        if state == "dns_capacity":
            return self._result(
                "skipped", "info", "low",
                "No shared DNS lookup capacity was available.",
                "The DNSSEC query was skipped rather than queued.",
                "Retry the scan later.",
            )

        if state in ("timeout", "dns_error"):
            message = (
                "The DNSSEC query timed out."
                if state == "timeout"
                else "The DNS resolver did not return usable DNSSEC evidence."
            )
            return self._result(
                "error", "info", "low",
                message,
                "No security conclusion was inferred from the failed query.",
                "Check DNS availability and retry the scan.",
            )

        if state == "oversized_response":
            return self._result(
                "not_verified", "info", "low",
                "The DNSSEC response exceeded configured record limits.",
                "The response was not fully evaluated.",
                "Review the DNS response and retry the scan.",
            )

        if state == "no_dnskey":
            ad_note = (
                " The resolver set the AD flag on this response."
                if evidence.authenticated_data
                else ""
            )
            return self._result(
                "not_verified", "info", "low",
                f"No DNSKEY RRset was returned for zone apex "
                f"{evidence.zone_name or 'identified by SOA'}."
                + ad_note,
                "The identified zone did not return a DNSKEY RRset. "
                "This check does not independently validate the parent "
                "delegation or determine the DS-chain status.",
                "Review the DNSSEC configuration and delegation for the identified zone.",
                (
                    "The zone apex was inferred from an ancestor SOA response. "
                    "The parent DS chain is not independently validated.",
                ),
            )

        if evidence.rrsig_count == 0:
            return self._result(
                "not_verified", "info", "low",
                f"Observed {evidence.dnskey_count} DNSKEY record(s), "
                "but no matching DNSKEY RRSIG was observed. "
                + ("The resolver set AD." if evidence.authenticated_data else "The resolver did not set AD."),
                "The available response does not establish an authenticated "
                "DNSKEY RRset.",
                "Verify DNSSEC signing and resolver support.",
            )

        if not evidence.authenticated_data:
            return self._result(
                "not_verified", "info", "low",
                f"Observed {evidence.dnskey_count} DNSKEY record(s) and "
                f"{evidence.rrsig_count} matching RRSIG record(s), "
                "but the resolver did not set AD.",
                "The records are indicators only; their trust chain was "
                "not verified by this check.",
                "Use a trusted validating resolver and verify the zone chain.",
            )

        return self._result(
            "not_verified", "info", "low",
            f"Observed {evidence.dnskey_count} DNSKEY record(s), "
            f"{evidence.rrsig_count} matching RRSIG record(s), "
            "and the resolver set the AD flag.",
            "The recursive resolver claims that the DNSKEY response is "
            "authenticated, but CyberShield has no configured trust "
            "relationship or secure channel for relying on that assertion.",
            "Repeat the check through a trusted validating resolver over "
            "a secure channel, or add an explicitly trusted resolver "
            "configuration before treating AD as verified evidence.",
            (
                "RFC 4035 does not permit reliance on AD unless the "
                "response came over a secure channel or the resolver "
                "was explicitly configured as trusted.",
                "This check does not independently validate DS/DNSKEY "
                "delegation or cryptographic signatures.",
                "The zone apex was inferred from an SOA response; "
                "the parent DS delegation and full trust chain are not "
                "independently validated.",
            ),
        )


def evaluate_dnssec_domain(domain, deadline=None):
    """Collect and evaluate DNSSEC indicators for a validated target."""

    from .registry import create_default_registry

    evidence = collect_dnssec_evidence(domain, deadline=deadline)
    definition = create_default_registry().get("dnssec")
    return DNSSECCheckEvaluator(definition).evaluate(evidence)
