"""Passive observations only. No payloads, requests, or exploitability claims."""

from .evaluator import CheckEvaluator
from .result import CheckResult


class PassiveIndicatorEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        sql = self.definition.check_id == "sqli_passive_indicators"
        observed = False
        if sql:
            disclosure = evidence.disclosure_evidence
            observed = (evidence.http_status is not None and disclosure is not None
                        and disclosure.error_status == evidence.http_status
                        and "sql_error" in disclosure.error_patterns)
            description = (
                "A database-error signature category was observed in the original error response."
                if observed else "No sufficient database-error evidence was available."
            )
            explanation = "A database error may disclose implementation details; it does not prove SQL injection."
            recommendation = "Use generic public error pages, review server logs privately, and use parameterized queries."
        else:
            csp = evidence.values_for_header("content-security-policy")
            description = (
                "A CSP configuration was observed; its protection and application behavior remain unverified."
                if evidence.http_status is not None and csp else
                "No sufficient passive evidence establishes XSS; missing CSP alone is not an XSS finding."
            )
            explanation = "Headers alone cannot establish script injection or prove that XSS is impossible."
            recommendation = "Review context-aware output encoding and CSP with an authorized application assessment."
        return CheckResult(
            check_id=self.definition.check_id, title=self.definition.title,
            status="warning" if observed else "not_verified",
            severity="low" if observed else "info", confidence="low",
            evidence=description, explanation=explanation, recommendation=recommendation,
            limitations=(
                "Passive indicators only; no confirmed exploitable vulnerability or absence of vulnerability.",
                "No payloads, JavaScript execution, forms, crawling, parameter changes or extra requests.",
                "Only existing bounded observations are used; raw content and matched values are omitted.",
            ),
        )
