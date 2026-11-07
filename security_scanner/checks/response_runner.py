"""Standalone runner for pre-integration response evaluators.

This module does not modify scan_target, generate reports,
or perform additional network requests.
"""

import logging

from .cache_checks import CacheSecurityEvaluator
from .cookie_checks import CookieAttributeEvaluator
from .access_checks import CORSConfigurationEvaluator, OpenRedirectEvaluator
from .disclosure_checks import DisclosureEvaluator
from .context import CheckContext
from .evidence import EvidenceCollection
from .result import CheckResult
from .header_checks import (
    PermissionsPolicyEvaluator,
    ReferrerPolicyEvaluator,
)
from .registry import create_default_registry
from .tls_checks import TLSMetadataEvaluator, RedirectPolicyEvaluator


_LOGGER = logging.getLogger(__name__)


_RESPONSE_EVALUATORS = (
    ("header_referrer_policy", ReferrerPolicyEvaluator),
    ("header_permissions_policy", PermissionsPolicyEvaluator),
    ("cache_security", CacheSecurityEvaluator),
)

_TLS_EVALUATORS = tuple((check_id, TLSMetadataEvaluator) for check_id in (
    "tls_certificate_expiry", "tls_certificate_chain", "tls_protocol_config"
))
_BLOCKED_REDIRECT_EVALUATORS = tuple((check_id, RedirectPolicyEvaluator) for check_id in (
    "http_to_https_redirect", "redirect_destination_safety"
))
_COOKIE_EVALUATORS = tuple((check_id, CookieAttributeEvaluator) for check_id in (
    "cookie_secure", "cookie_httponly", "cookie_samesite"
))
_ACCESS_EVALUATORS = (
    ("cors_misconfiguration", CORSConfigurationEvaluator),
    ("open_redirect", OpenRedirectEvaluator),
)
_DISCLOSURE_EVALUATORS = tuple((check_id, DisclosureEvaluator) for check_id in (
    "sensitive_file_exposure", "source_maps_exposure", "directory_listing",
    "server_information_disclosure", "error_information_disclosure",
    "public_security_files",
))


def evaluate_response_evidence_prototypes(
    evidence: EvidenceCollection,
):
    """Evaluate prepared checks using an existing evidence snapshot."""
    if not isinstance(evidence, EvidenceCollection):
        raise TypeError("evidence must be an EvidenceCollection")

    registry = create_default_registry()
    results = []

    for check_id, evaluator_type in _RESPONSE_EVALUATORS:
        definition = registry.get(check_id)

        if definition is None:
            raise RuntimeError(
                f"Missing check definition: {check_id}"
            )

        try:
            evaluator = evaluator_type(definition)
            result = evaluator.evaluate(evidence)
        except Exception as error:
            # Keep internal exception details out of the report and logs.
            _LOGGER.error(
                "Evaluator failed: check_id=%s exception_type=%s",
                check_id,
                type(error).__name__,
            )
            result = CheckResult(
                check_id=check_id,
                title=definition.title,
                status="error",
                severity="info",
                confidence="low",
                evidence="\u062a\u0639\u0630\u0631 \u0625\u0643\u0645\u0627\u0644 \u062a\u0642\u064a\u064a\u0645 \u0627\u0644\u0623\u062f\u0644\u0629 \u0644\u0647\u0630\u0627 \u0627\u0644\u0641\u062d\u0635.",
                explanation=(
                    "\u062d\u062f\u062b \u062e\u0637\u0623 \u062f\u0627\u062e\u0644\u064a \u0623\u062b\u0646\u0627\u0621 \u062a\u0642\u064a\u064a\u0645 \u0627\u0644\u0623\u062f\u0644\u0629\u061b "
                    "\u0644\u0645 \u064a\u062a\u0645 \u0627\u0633\u062a\u0646\u062a\u0627\u062c \u0646\u062a\u064a\u062c\u0629 \u0623\u0645\u0646\u064a\u0629."
                ),
                recommendation=(
                    "\u0623\u0639\u064a\u062f\u064a \u0627\u0644\u0641\u062d\u0635 \u0628\u0639\u062f \u0645\u0631\u0627\u062c\u0639\u0629 \u0633\u0628\u0628 \u062a\u0639\u0630\u0631 \u062a\u0642\u064a\u064a\u0645 \u0627\u0644\u0623\u062f\u0644\u0629."
                ),
                limitations=(
                    "\u0644\u0645 \u064a\u062a\u0645 \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0647\u0630\u0627 \u0627\u0644\u0641\u062d\u0635 \u0628\u0633\u0628\u0628 \u062e\u0637\u0623 \u0623\u062b\u0646\u0627\u0621 \u0627\u0644\u062a\u0642\u064a\u064a\u0645.",
                ),
            )
        results.append(result)

    return tuple(results)


def evaluate_week3_evidence(evidence: EvidenceCollection):
    """Evaluate shared response, TLS, redirect and cookie evidence checks."""
    if not isinstance(evidence, EvidenceCollection):
        raise TypeError("evidence must be an EvidenceCollection")
    registry = create_default_registry()
    results = list(evaluate_response_evidence_prototypes(evidence))
    for check_id, evaluator_type in _TLS_EVALUATORS + _BLOCKED_REDIRECT_EVALUATORS:
        definition = registry.get(check_id)
        results.append(evaluator_type(definition).evaluate(evidence))
    for check_id, evaluator_type in _COOKIE_EVALUATORS:
        definition = registry.get(check_id)
        try:
            results.append(evaluator_type(definition).evaluate(evidence))
        except Exception as error:
            _LOGGER.error(
                "Evaluator failed: check_id=%s exception_type=%s",
                check_id,
                type(error).__name__,
            )
            results.append(CheckResult(
                check_id=check_id,
                title=definition.title,
                status="error",
                severity="info",
                confidence="low",
                evidence="تعذر تقييم خصائص ملفات Cookie دون الاحتفاظ بقيمها.",
                explanation="حدث خطأ داخلي أثناء تقييم دليل Cookie المنقح.",
                recommendation="راجع التنفيذ ثم أعد الفحص.",
                limitations=("لم تُسجل قيم Cookie أو تفاصيل الاستثناء.",),
            ))
    for check_id, evaluator_type in _ACCESS_EVALUATORS:
        definition = registry.get(check_id)
        try:
            results.append(evaluator_type(definition).evaluate(evidence))
        except Exception as error:
            _LOGGER.error("Evaluator failed: check_id=%s exception_type=%s", check_id, type(error).__name__)
            results.append(CheckResult(
                check_id=check_id, title=definition.title, status="error",
                severity="info", confidence="low",
                evidence="تعذر إكمال تقييم دليل الوصول.",
                explanation="حدث خطأ داخلي أثناء تحليل الدليل؛ لم يُستنتج حكم أمني.",
                recommendation="راجع التنفيذ الداخلي ثم أعد الفحص.",
                limitations=("لم تُسجل قيم ترويسات أو بيانات وجهة التحويل.",),
            ))
    for check_id, evaluator_type in _DISCLOSURE_EVALUATORS:
        definition = registry.get(check_id)
        try:
            results.append(evaluator_type(definition).evaluate(evidence))
        except Exception as error:
            _LOGGER.error("Evaluator failed: check_id=%s exception_type=%s", check_id, type(error).__name__)
            results.append(CheckResult(
                check_id=check_id, title=definition.title, status="error",
                severity="info", confidence="low",
                evidence="تعذر إكمال تقييم دليل Disclosure المصنف.",
                explanation="حدث خطأ داخلي أثناء تقييم الأنماط؛ لم يُستنتج حكم أمني.",
                recommendation="راجع التنفيذ الداخلي ثم أعد الفحص.",
                limitations=("لم يُحتفظ بأجسام الاستجابة أو قيمها الخام.",),
            ))
    return tuple(results)


def evaluate_shared_week3_checks(context: CheckContext):
    if not isinstance(context, CheckContext):
        raise TypeError("context must be a CheckContext")
    return evaluate_week3_evidence(EvidenceCollection.from_context(context))


def evaluate_shared_response_prototypes(
    context: CheckContext,
):
    """Collect evidence once, then evaluate all response prototypes."""
    if not isinstance(context, CheckContext):
        raise TypeError("context must be a CheckContext")

    evidence = EvidenceCollection.from_context(context)

    return evaluate_response_evidence_prototypes(evidence)
