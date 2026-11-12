"""Deterministic risk context; never modifies or counts base findings."""

# Each rule uses independent observed weaknesses. SQL/error overlap is excluded.
_RULES = (
    ("cookie_defense_gaps", ("cookie_secure", "cookie_httponly"),
     "Cookie transport and script-access defenses both have observed gaps; review session-cookie protection together."),
    ("public_diagnostics", ("server_information_disclosure", "error_information_disclosure"),
     "Technology disclosure and public error details can jointly help reconnaissance; review public diagnostics together."),
)


def correlate_findings(findings):
    """Whitelist output; ignore partial, ambiguous, malformed and non-warning input."""
    if not isinstance(findings, (list, tuple)):
        return []
    by_id = {}
    duplicates = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        check_id = item.get("check_id")
        if not isinstance(check_id, str):
            continue
        if check_id in by_id:
            duplicates.add(check_id)
        by_id[check_id] = item
    results = []
    for rule_id, contributors, explanation in _RULES:
        if any(check_id in duplicates for check_id in contributors):
            continue
        selected = [by_id.get(check_id, {}) for check_id in contributors]
        if not all(item.get("status") == "warning"
                   and item.get("severity") in ("low", "medium", "high")
                   and item.get("confidence") in ("low", "medium", "high") for item in selected):
            continue
        results.append({
            "correlation_id": rule_id, "contributing_check_ids": list(contributors),
            "severity": "low", "confidence": "low", "explanation": explanation,
            "limitations": ["Context for existing observations only; not an additional vulnerability or summary count.",
                            "Contributors may concern different cookies or response paths; no exploit chain is established."],
        })
    return results


def safe_correlate_findings(findings):
    """Optional analysis failure cannot prevent the main report."""
    try:
        return correlate_findings(findings)
    except Exception:
        return []
