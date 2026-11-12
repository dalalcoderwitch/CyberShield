"""Versioned, deterministic context for independent observed warnings.

Input: list/tuple of finding dictionaries. Only check_id, status, severity and
confidence are read; no raw evidence is copied or interpreted. Missing,
malformed, duplicate or contradictory contributors suppress that rule.
Output: JSON dictionaries; original findings and summary are never mutated.
"""

from dataclasses import dataclass


CORRELATION_RULES_VERSION = "2.0.0"


@dataclass(frozen=True)
class CorrelationRule:
    correlation_id: str
    contributors: tuple[str, ...]
    explanation: str
    recommendation: str
    limitations: tuple[str, ...]
    rule_version: str = "1"


# The first two IDs and their order are retained for existing consumers.
# All rules require independent warning results, never missing evidence.
RULE_CATALOG = (
    CorrelationRule("cookie_defense_gaps", ("cookie_secure", "cookie_httponly"),
        "Cookie transport and script-access defenses both have observed gaps; review session-cookie protection together.",
        "Review Secure and HttpOnly on the observed cookies according to each cookie's purpose.",
        ("Gaps may concern different non-session cookies; cookie sensitivity, theft and exploit chains are not established.",)),
    CorrelationRule("public_diagnostics", ("server_information_disclosure", "error_information_disclosure"),
        "Technology disclosure and public error details can jointly help reconnaissance; review public diagnostics together.",
        "Reduce unnecessary technology details and use generic public error pages with private server-side logs.",
        ("No additional vulnerability is inferred from the disclosed details; reachability beyond the sampled response is unknown.",)),
    CorrelationRule("tls_maintenance_gaps", ("tls_certificate_expiry", "tls_protocol_config"),
        "An observed certificate-date warning and a separate negotiated TLS configuration warning both need maintenance.",
        "Review certificate renewal and the negotiated protocol/cipher policy independently.",
        ("Only a verified handshake's metadata is considered; rejected handshakes provide no positive TLS evidence.",
         "No exhaustive protocol enumeration or certificate-chain failure is inferred.")),
    CorrelationRule("transport_policy_gaps", ("header_hsts", "http_to_https_redirect"),
        "The observed HSTS and HTTP-upgrade policies both need review as separate transport controls.",
        "Review HSTS deployment and the HTTP root upgrade response without automatically following its destination.",
        ("Missing HSTS does not prove redirect exploitation or intercepted traffic.",
         "The HTTP root probe and original HTTPS path may have different behavior.")),
    CorrelationRule("public_resource_exposure", ("sensitive_file_exposure", "directory_listing"),
        "Sensitive-content signatures and a directory-index marker were observed in separate fixed-path probes.",
        "Restrict public sensitive resources and disable unnecessary directory indexes; review each original finding.",
        ("The index is not proven to reference the sensitive file; no filenames or content are reproduced.",)),
    CorrelationRule("email_policy_review", ("dns_spf", "dns_dmarc"),
        "Separate SPF and DMARC policy observations both require mail-configuration review.",
        "Review authorized senders and DMARC policy/alignment with the mail administrator before changing enforcement.",
        ("The queried hostname may not be a sending domain; no message delivery, DKIM or successful spoofing was tested.",
         "SPF policy includes and inherited DMARC policies are not inferred by this rule.")),
    CorrelationRule("dom_cookie_review", ("xss_passive_indicators", "cookie_httponly"),
        "A static URL-to-HTML assignment indicator and a separate script-accessible cookie observation warrant joint review.",
        "Review the static assignment and each cookie's HttpOnly requirement without assuming a working attack chain.",
        ("Static code may be unreachable or shadowed; the cookie may be intentionally script-readable and non-sensitive.",
         "No execution, cookie access, authentication state or exploit chain was demonstrated.")),
)


def _evaluate_rule(rule, by_id, duplicates):
    if any(check_id in duplicates for check_id in rule.contributors):
        return None
    selected = [by_id.get(check_id, {}) for check_id in rule.contributors]
    if not all(item.get("status") == "warning"
               and item.get("severity") in ("low", "medium", "high")
               and item.get("confidence") in ("low", "medium", "high") for item in selected):
        return None
    return {
        "correlation_id": rule.correlation_id,
        "contributing_check_ids": list(rule.contributors),
        "severity": "low", "confidence": "low",
        "explanation": rule.explanation, "recommendation": rule.recommendation,
        "rules_version": CORRELATION_RULES_VERSION, "rule_version": rule.rule_version,
        "limitations": ["Context for existing observations only; not an additional vulnerability or summary count.",
                        *rule.limitations],
    }


def correlate_findings(findings):
    """Whitelisted, bounded input contract with per-rule failure isolation."""
    if not isinstance(findings, (list, tuple)) or len(findings) > 100:
        return []
    by_id, duplicates = {}, set()
    allowed_ids = {check_id for rule in RULE_CATALOG for check_id in rule.contributors}
    for item in findings:
        if not isinstance(item, dict):
            continue
        check_id = item.get("check_id")
        if not isinstance(check_id, str) or check_id not in allowed_ids:
            continue
        if check_id in by_id:
            duplicates.add(check_id)
        by_id[check_id] = item
    results = []
    for rule in RULE_CATALOG:
        try:
            result = _evaluate_rule(rule, by_id, duplicates)
            if result is not None:
                results.append(result)
        except Exception:
            # A rule failure is not a finding and cannot suppress other rules.
            continue
    return results


def safe_correlate_findings(findings):
    """Optional analysis failure cannot prevent the main report."""
    try:
        return correlate_findings(findings)
    except Exception:
        return []
