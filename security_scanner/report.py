from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, urljoin
from uuid import uuid4

from .scanner import _safe_get_response, _safe_http_redirect_probe, _safe_cors_preflight, _resolve_redirect_location_addresses, _collect_disclosure_evidence, check_security_headers

from .checks.correlation import safe_correlate_findings
from .checks.context import CheckContext
from .checks.evidence import EvidenceCollection
from .checks.response_runner import (
    evaluate_week3_evidence,
    evaluate_cache_evidence,
    evaluate_passive_evidence,
    evaluate_shared_week3_checks,
)
from .checks.dns_checks import evaluate_dmarc_domain, evaluate_spf_domain
from .checks.dnssec_checks import evaluate_dnssec_domain
from .checks.takeover_checks import evaluate_takeover_domain
from .checks.result import CheckResult


ENGINE_VERSION = "1.0.0"

HEADER_CHECKS = [
    {
        "key": "HSTS",
        "check_id": "header_hsts",
        "title": "حماية النقل عبر HTTPS (HSTS)",
        "header": "Strict-Transport-Security",
        "severity": "medium",
        "recommendation": (
            "أضيفي ترويسة Strict-Transport-Security "
            "بإعداد max-age مناسب، وراجعي الخيارات الإضافية "
            "قبل تفعيلها."
        ),
    },
    {
        "key": "CSP",
        "check_id": "header_csp",
        "title": "سياسة أمن المحتوى (CSP)",
        "header": "Content-Security-Policy",
        "severity": "medium",
        "recommendation": (
            "أضيفي سياسة Content-Security-Policy مناسبة، "
            "وراجعي مصادر الموارد والتعليمات المسموح بها."
        ),
    },
    {
        "key": "X-Content-Type-Options",
        "check_id": "header_x_content_type_options",
        "title": "منع تخمين نوع المحتوى",
        "header": "X-Content-Type-Options",
        "severity": "low",
        "recommendation": (
            "أضيفي X-Content-Type-Options بالقيمة nosniff."
        ),
    },
    {
        "key": "X-Frame-Options",
        "check_id": "header_x_frame_options",
        "title": "الحماية من تضمين الصفحة داخل إطار",
        "header": "X-Frame-Options",
        "severity": "medium",
        "recommendation": (
            "اضبطي X-Frame-Options على DENY أو SAMEORIGIN "
            "بحسب احتياج الموقع، وراجعي frame-ancestors "
            "ضمن CSP."
        ),
    },
]

REPORT_LIMITATIONS = [
    "هذا الفحص أولي ولا يمثل اختبار اختراق شاملًا.",
    "لا يتبع الماسح التحويلات تلقائيًا؛ تُفحص الاستجابة الأولى فقط.",
    "وجود ترويسة لا يثبت أن إعدادها آمن أو مناسب بالكامل.",
    "النتائج تخص الاستجابة التي تم فحصها وقد تختلف باختلاف المسار أو الخادم.",
    "يُعرض أصل HTTPS فقط؛ تُحذف بيانات الاعتماد والمسار والاستعلام والجزء fragment من رابط الهدف.",
]

REPORT_NOTICE = (
    "هذا التقرير تقييم أولي محدود، ولا يضمن أمان الموقع بالكامل."
)


def _safe_report_target_url(target_url: str) -> str:
    """
    تجهيز أصل رابط آمن للعرض في التقرير.

    يُحتفظ بمخطط HTTPS واسم المضيف فقط.
    تُحذف بيانات المستخدم والمسار والاستعلام والجزء fragment.
    إذا كان الرابط غير صالح أو غير مدعوم، لا نعيد قيمته الأصلية.
    """
    if not isinstance(target_url, str) or not target_url:
        return ""

    if any(
        ord(char) < 32 or ord(char) == 127
        for char in target_url
    ):
        return "[invalid target URL]"

    try:
        parsed = urlsplit(target_url)
        port = parsed.port
    except ValueError:
        return "[invalid target URL]"

    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        return "[invalid target URL]"

    try:
        hostname = (
            parsed.hostname.encode("idna")
            .decode("ascii")
            .lower()
            .rstrip(".")
        )
    except UnicodeError:
        return "[invalid target URL]"

    if not hostname:
        return "[invalid target URL]"

    # وضع الأقواس حول IPv6 عند تكوين عنوان العرض.
    if ":" in hostname:
        safe_netloc = f"[{hostname}]"
    else:
        safe_netloc = hostname

    # لا نعرض المسار أو query أو fragment.
    return urlunsplit(
        (
            "https",
            safe_netloc,
            "",
            "",
            "",
        )
    )



def _make_finding(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    confidence: str,
    evidence: str,
    explanation: str,
    recommendation: str,
    limitations: list[str],
) -> dict:
    """إنشاء نتيجة موحدة لفحص واحد."""

    return {
        "check_id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "explanation": explanation,
        "recommendation": recommendation,
        "limitations": limitations,
    }


def _summarize(findings: list[dict]) -> dict:
    """حساب عدد النتائج لكل حالة."""

    statuses = (
        "passed",
        "warning",
        "not_verified",
        "error",
        "skipped",
    )

    summary = {status: 0 for status in statuses}

    for finding in findings:
        result_status = finding["status"]

        if result_status in summary:
            summary[result_status] += 1

    summary["total"] = len(findings)

    return summary


def scan_target(
    target_url: str,
    resolved_target=None,
    deadline: float | None = None,
    include_expanded_checks: bool = False,
) -> dict:
    """
    تنفيذ الفحوصات المحددة وإرجاع تقرير منظم.

    لا يعني اكتمال إنشاء التقرير أن جميع الفحوصات نجحت.
    """
    if type(include_expanded_checks) is not bool:
        raise TypeError("include_expanded_checks must be a bool")

    scanned_at = datetime.now(timezone.utc).isoformat()
    scan_id = str(uuid4())

    safe_target_url = _safe_report_target_url(target_url)
    tls_metadata = {}
    redirect_dns = {}
    validated_target = {}
    http_probe = {}
    cookie_evidence = {}
    access_evidence = {}
    cors_evidence = {}
    disclosure_capture = {}
    disclosure_evidence = None

    # يجب أن يبقى فحص الهدف داخل الماسح فعالًا،
    # حتى لو استُدعيت هذه الدالة مباشرةً خارج Flask.
    if deadline is None:
        if resolved_target is None:
            if include_expanded_checks:
                status_code, headers, error = _safe_get_response(
                    target_url,
                    tls_metadata=tls_metadata,
                    validated_target_capture=validated_target,
                    cookie_evidence_capture=cookie_evidence,
                    access_evidence_capture=access_evidence,
                    disclosure_evidence_capture=disclosure_capture,
                )
            else:
                status_code, headers, error = _safe_get_response(target_url)
        else:
            if include_expanded_checks:
                status_code, headers, error = _safe_get_response(
                    target_url,
                    resolved_target=resolved_target,
                    tls_metadata=tls_metadata,
                    validated_target_capture=validated_target,
                    cookie_evidence_capture=cookie_evidence,
                    access_evidence_capture=access_evidence,
                    disclosure_evidence_capture=disclosure_capture,
                )
            else:
                status_code, headers, error = _safe_get_response(target_url, resolved_target=resolved_target)
    elif resolved_target is None:
        if include_expanded_checks:
            status_code, headers, error = _safe_get_response(
                target_url,
                deadline=deadline,
                tls_metadata=tls_metadata,
                validated_target_capture=validated_target,
                cookie_evidence_capture=cookie_evidence,
                access_evidence_capture=access_evidence,
                disclosure_evidence_capture=disclosure_capture,
            )
        else:
            status_code, headers, error = _safe_get_response(target_url, deadline=deadline)
    else:
        if include_expanded_checks:
            status_code, headers, error = _safe_get_response(
                target_url,
                resolved_target=resolved_target,
                deadline=deadline,
                tls_metadata=tls_metadata,
                validated_target_capture=validated_target,
                cookie_evidence_capture=cookie_evidence,
                access_evidence_capture=access_evidence,
                disclosure_evidence_capture=disclosure_capture,
            )
        else:
            status_code, headers, error = _safe_get_response(target_url, resolved_target=resolved_target, deadline=deadline)
    findings = []

    # فحص HTTPS وTLS.
    if error is None:
        findings.append(
            _make_finding(
                check_id="https_connection",
                title="اتصال HTTPS والتحقق من شهادة TLS",
                status="passed",
                severity="info",
                confidence="high",
                evidence=(
                    "تم الاتصال والتحقق من TLS. "
                    f"رمز استجابة HTTP: {status_code}."
                ),
                explanation=(
                    "نجح الاتصال عبر HTTPS في هذا الطلب. "
                    "هذا لا يثبت سلامة الموقع بالكامل."
                ),
                recommendation=(
                    "حافظي على صلاحية شهادة TLS "
                    "واستمرار التحقق منها."
                ),
                limitations=[
                    "النتيجة تخص الاتصال والاستجابة اللذين تم فحصهما."
                ],
            )
        )
    else:
        https_severity = "medium"
        https_confidence = "high"
        recommendation = (
            "\u062a\u062d\u0642\u0642\u064a \u0645\u0646 \u0635\u0644\u0627\u062d\u064a\u0629 \u0627\u0644\u0631\u0627\u0628\u0637 \u0648\u0625\u0645\u0643\u0627\u0646\u064a\u0629 \u0627\u0644\u0648\u0635\u0648\u0644 \u0648\u0635\u062d\u0629 \u0625\u0639\u062f\u0627\u062f TLS\u060c \u062b\u0645 \u0623\u0639\u064a\u062f\u064a \u0627\u0644\u0641\u062d\u0635."
        )

        if error == "invalid":
            https_status = "warning"
            explanation = (
                "\u0627\u0644\u0631\u0627\u0628\u0637 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d \u0623\u0648 \u0644\u0627 \u064a\u0637\u0627\u0628\u0642 \u0642\u064a\u0648\u062f \u0627\u0644\u0641\u062d\u0635."
            )

        elif error == "not_allowed":
            https_status = "warning"
            explanation = (
                "\u0627\u0644\u0631\u0627\u0628\u0637 \u0635\u062d\u064a\u062d \u0645\u0646 \u0646\u0627\u062d\u064a\u0629 \u0627\u0644\u0635\u064a\u0627\u063a\u0629\u060c \u0644\u0643\u0646 \u0627\u0644\u0647\u062f\u0641 \u0645\u062d\u0638\u0648\u0631 \u0648\u0641\u0642 \u0633\u064a\u0627\u0633\u0629 \u0627\u0644\u062d\u0645\u0627\u064a\u0629."
            )
            recommendation = (
                "\u0627\u0633\u062a\u062e\u062f\u0645\u064a \u0647\u062f\u0641\u064b\u0627 \u0639\u0627\u0645\u064b\u0627 \u0648\u0645\u0633\u0645\u0648\u062d\u064b\u0627\u060c \u0648\u062a\u0623\u0643\u062f\u064a \u0645\u0646 \u0623\u0646\u0647 \u0644\u0627 \u064a\u0634\u064a\u0631 \u0625\u0644\u0649 \u0639\u0646\u0648\u0627\u0646 \u062f\u0627\u062e\u0644\u064a \u0623\u0648 \u0645\u062d\u0638\u0648\u0631."
            )

        elif error == "tls":
            https_status = "warning"
            explanation = (
                "\u062a\u0639\u0630\u0631 \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0634\u0647\u0627\u062f\u0629 TLS\u061b \u0644\u0645 \u064a\u064f\u0639\u062a\u0628\u0631 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0646\u0627\u062c\u062d\u064b\u0627."
            )

        elif error == "timeout":
            https_status = "error"
            explanation = (
                "\u0627\u0646\u062a\u0647\u062a \u0627\u0644\u0645\u0647\u0644\u0629 \u0627\u0644\u0632\u0645\u0646\u064a\u0629 \u0627\u0644\u0645\u0633\u0645\u0648\u062d\u0629 \u0642\u0628\u0644 \u0627\u0643\u062a\u0645\u0627\u0644 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0623\u0648 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629."
            )

        elif error == "dns_timeout":
            https_status = "error"
            https_severity = "info"
            explanation = (
                "\u0627\u0646\u062a\u0647\u062a \u0645\u0647\u0644\u0629 \u0627\u0646\u062a\u0638\u0627\u0631 DNS \u0642\u0628\u0644 \u0627\u0644\u062d\u0635\u0648\u0644 \u0639\u0644\u0649 \u0646\u062a\u064a\u062c\u0629\u061b \u0644\u0627 \u064a\u0639\u0646\u064a \u0630\u0644\u0643 \u0623\u0646 \u0627\u0644\u0631\u0627\u0628\u0637 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d."
            )
            recommendation = (
                "\u062a\u062d\u0642\u0642\u064a \u0645\u0646 \u0633\u0631\u0639\u0629 \u0627\u0633\u062a\u062c\u0627\u0628\u0629 DNS \u0648\u0625\u0645\u0643\u0627\u0646\u064a\u0629 \u0627\u0644\u0648\u0635\u0648\u0644 \u0625\u0644\u0649 \u062e\u0627\u062f\u0645 \u0627\u0644\u0623\u0633\u0645\u0627\u0621\u060c \u062b\u0645 \u0623\u0639\u064a\u062f\u064a \u0627\u0644\u0641\u062d\u0635."
            )

        elif error == "dns_error":
            https_status = "error"
            https_severity = "info"
            explanation = (
                "\u062a\u0639\u0630\u0631 \u062d\u0644 \u0627\u0633\u0645 \u0627\u0644\u0646\u0637\u0627\u0642 \u0639\u0628\u0631 DNS\u061b \u0644\u0627 \u064a\u0645\u0643\u0646 \u0627\u0644\u062c\u0632\u0645 \u0628\u0623\u0646 \u0627\u0644\u0647\u062f\u0641 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d."
            )
            recommendation = (
                "\u062a\u062d\u0642\u0642\u064a \u0645\u0646 \u0633\u062c\u0644 DNS \u0648\u0625\u0645\u0643\u0627\u0646\u064a\u0629 \u0627\u0644\u0648\u0635\u0648\u0644 \u0625\u0644\u0649 \u062e\u0627\u062f\u0645 \u0627\u0644\u0623\u0633\u0645\u0627\u0621\u060c \u062b\u0645 \u0623\u0639\u064a\u062f\u064a \u0627\u0644\u0641\u062d\u0635."
            )

        elif error == "dns_capacity":
            https_status = "skipped"
            https_severity = "info"
            https_confidence = "low"
            explanation = (
                "\u0644\u0645 \u062a\u062a\u0648\u0641\u0631 \u0633\u0639\u0629 DNS \u0644\u0628\u062f\u0621 \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u0647\u062f\u0641\u061b \u0644\u0645 \u064a\u062a\u0645 \u062a\u0646\u0641\u064a\u0630 \u0641\u062d\u0635 \u0627\u0644\u0627\u062a\u0635\u0627\u0644."
            )
            recommendation = (
                "\u0623\u0639\u064a\u062f\u064a \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629 \u0644\u0627\u062d\u0642\u064b\u0627 \u0628\u0639\u062f \u062a\u0648\u0641\u0631 \u0633\u0639\u0629 \u0644\u0641\u062d\u0648\u0635\u0627\u062a DNS."
            )

        else:
            https_status = "error"
            explanation = (
                "\u062a\u0639\u0630\u0631 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0628\u0627\u0644\u0645\u0648\u0642\u0639."
            )

        findings.append(
            _make_finding(
                check_id="https_connection",
                title="\u0627\u062a\u0635\u0627\u0644 HTTPS \u0648\u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0634\u0647\u0627\u062f\u0629 TLS",
                status=https_status,
                severity=https_severity,
                confidence=https_confidence,
                evidence=(
                    "\u0644\u0645 \u064a\u0643\u062a\u0645\u0644 \u0627\u0644\u0641\u062d\u0635. "
                    f"\u0646\u0648\u0639 \u0627\u0644\u0646\u062a\u064a\u062c\u0629: {error}."
                ),
                explanation=explanation,
                recommendation=recommendation,
                limitations=[
                    "\u0644\u0645 \u064a\u062a\u0645 \u0627\u0644\u062d\u0635\u0648\u0644 \u0639\u0644\u0649 \u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0635\u0627\u0644\u062d\u0629 \u0644\u0641\u062d\u0635 \u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0627\u062a."
                ],
            )
        )

    if error is None:
        header_results = check_security_headers(headers)

        security_header_names = {
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
        }

        normalized_headers = {}

        for key, value in headers.items():
            normalized_key = str(key).lower()

            if normalized_key not in security_header_names:
                continue

            normalized_value = str(value)

            if normalized_key in normalized_headers:
                normalized_headers[normalized_key] += ", " + normalized_value
            else:
                normalized_headers[normalized_key] = normalized_value

        for item in HEADER_CHECKS:
            header_name = item["header"]
            result = header_results[item["key"]]

            header_value = normalized_headers.get(
                header_name.lower()
            )

            header_is_present = bool(
                header_value is not None and header_value.strip()
            )

            if header_is_present:
                evidence = (
                    f"\u062a\u0645 \u0627\u0644\u0639\u062b\u0648\u0631 "
                    f"\u0639\u0644\u0649 \u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 {header_name}. "
                    "\u0644\u0645 \u062a\u064f\u062f\u0631\u062c "
                    "\u0627\u0644\u0642\u064a\u0645\u0629 \u0627\u0644\u062e\u0627\u0645 "
                    "\u0641\u064a \u0627\u0644\u062a\u0642\u0631\u064a\u0631 "
                    "\u0644\u062a\u062c\u0646\u0628 \u0643\u0634\u0641 "
                    "\u0628\u064a\u0627\u0646\u0627\u062a \u0642\u062f "
                    "\u062a\u0643\u0648\u0646 \u062d\u0633\u0627\u0633\u0629."
                )
            else:
                evidence = (
                    f"\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 {header_name} "
                    "\u063a\u064a\u0631 \u0645\u0648\u062c\u0648\u062f\u0629 "
                    "\u0623\u0648 \u0641\u0627\u0631\u063a\u0629."
                )

            if item["key"] == "CSP":
                confidence = "medium"
                severity = item["severity"]
            elif result["status"] == "passed":
                confidence = "high"
                severity = "info"
            else:
                confidence = "high"
                severity = item["severity"]
            explanation = result["message"]


            if item["key"] == "HSTS" and header_value:
                explanation += (
                    " هذا فحص أولي لقيمة max-age فقط."
                )

            findings.append(
                _make_finding(
                    check_id=item["check_id"],
                    title=item["title"],
                    status=result["status"],
                    severity=severity,
                    confidence=confidence,
                    evidence=evidence,
                    explanation=explanation,
                    recommendation=item["recommendation"],
                    limitations=[
                        "تم تقييم ترويسة الاستجابة الأولى فقط.",
                        "وجود الترويسة لا يثبت فعالية إعدادها بالكامل.",
                    ],
                )
            )

    else:
        # لا نعتبر الترويسات ناجحة أو مفقودة عند تعذر فحصها.
        for item in HEADER_CHECKS:
            findings.append(
                _make_finding(
                    check_id=item["check_id"],
                    title=item["title"],
                    status="not_verified",
                    severity="info",
                    confidence="low",
                    evidence=(
                        "لم تُسترجع استجابة HTTP قابلة للفحص."
                    ),
                    explanation=(
                        "تعذر التحقق من هذه الترويسة؛ "
                        "لا يمكن اعتبارها موجودة أو مفقودة."
                    ),
                    recommendation=item["recommendation"],
                    limitations=[
                        "الفحص غير مكتمل بسبب تعذر الاتصال أو رفض الرابط."
                    ],
                )
            )

    if include_expanded_checks:
        target = validated_target.get("target")
        if target is not None:
            if error is None:
                cors_error = _safe_cors_preflight(target, deadline=deadline, capture=cors_evidence)
                if cors_error is not None:
                    cors_evidence["error"] = cors_error
                try:
                    disclosure_evidence = _collect_disclosure_evidence(
                        target, status_code, disclosure_capture, deadline=deadline
                    )
                except Exception:
                    disclosure_capture.clear()
            http_probe_error = _safe_http_redirect_probe(target, deadline=deadline, capture=http_probe)
            if http_probe_error is not None:
                http_probe["error"] = http_probe_error
        if http_probe.get("status") in (301, 302, 303, 307, 308) and http_probe.get("location"):
            try:
                destination = urljoin(http_probe["request_url"], http_probe["location"])
            except (TypeError, ValueError):
                destination = None
            if destination is not None:
                http_probe["destination"] = destination
                answers = _resolve_redirect_location_addresses(destination, deadline=deadline)
                if answers is not None:
                    redirect_dns["addresses"] = answers
        if error is None:
            expanded_results = evaluate_shared_week3_checks(
                CheckContext(
                    safe_target_url=safe_target_url,
                    deadline=deadline,
                    http_status=status_code,
                    response_headers=headers,
                    tls_metadata=tls_metadata,
                    tls_verified=(error is None),
                    redirect_dns_answers=redirect_dns.get("addresses", ()),
                    http_probe_status=http_probe.get("status"),
                    http_probe_error=http_probe.get("error"),
                    http_probe_location=http_probe.get("location"),
                    http_probe_request_url=http_probe.get("request_url"),
                    redirect_destination_url=http_probe.get("destination"),
                    cookie_evidence_available=cookie_evidence.get("available"),
                    cookie_observations=cookie_evidence.get("observations", ()),
                    cors_probe_status=cors_evidence.get("status"),
                    cors_probe_error=cors_evidence.get("error"),
                    cors_probe_available=cors_evidence.get("available"),
                    cors_headers=cors_evidence.get("headers", {}),
                    redirect_location_values=access_evidence.get("location_values", ()),
                    redirect_evidence_available=access_evidence.get("available"),
                    redirect_request_url=target_url if access_evidence.get("available") else None,
                    disclosure_evidence=disclosure_evidence,
                )
            )
        else:
            expanded_results = evaluate_week3_evidence(
                EvidenceCollection(http_status=None, tls_verified=False,
                    redirect_dns_answers=redirect_dns.get("addresses", ()),
                    http_probe_status=http_probe.get("status"),
                    http_probe_error=http_probe.get("error"),
                    http_probe_location=http_probe.get("location"),
                    http_probe_request_url=http_probe.get("request_url"),
                    redirect_destination_url=http_probe.get("destination"),
                    cookie_evidence_available=cookie_evidence.get("available"),
                    cookie_observations=cookie_evidence.get("observations", ()),
                    cors_probe_status=cors_evidence.get("status"),
                    cors_probe_error=cors_evidence.get("error"),
                    cors_probe_available=cors_evidence.get("available"),
                    cors_headers=cors_evidence.get("headers", {}),
                    redirect_location_values=access_evidence.get("location_values", ()),
                    redirect_evidence_available=access_evidence.get("available"),
                    redirect_request_url=target_url if access_evidence.get("available") else None,
                    disclosure_evidence=disclosure_evidence)
            )

        # Cache reuses the original response; no collection or network operation.
        expanded_results = tuple(expanded_results) + evaluate_cache_evidence(
            EvidenceCollection(
                http_status=status_code if error is None else None,
                _headers=headers if error is None else {},
            )
        )

        expanded_results += evaluate_passive_evidence(EvidenceCollection(
            http_status=status_code if error is None else None,
            _headers=headers if error is None else {},
            disclosure_evidence=disclosure_evidence if error is None else None,
        ))

        # SPF uses only the hostname captured after target validation.
        spf_domain = (
            target[1]
            if isinstance(target, (tuple, list)) and len(target) >= 2
            else None
        )

        try:
            spf_result = evaluate_spf_domain(
                spf_domain,
                deadline=deadline,
            )
        except Exception:
            # A failure in one check must not abort the complete report.
            spf_result = CheckResult(
                check_id="dns_spf",
                title="\u0633\u064a\u0627\u0633\u0629 SPF \u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0628\u0631\u064a\u062f \u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a",
                status="error",
                severity="info",
                confidence="low",
                evidence="\u062a\u0639\u0630\u0631 \u0625\u0643\u0645\u0627\u0644 \u062a\u0642\u064a\u064a\u0645 \u0633\u062c\u0644 SPF.",
                explanation="\u062d\u062f\u062b \u062e\u0637\u0623 \u0623\u062b\u0646\u0627\u0621 \u062c\u0645\u0639 \u0623\u0648 \u062a\u062d\u0644\u064a\u0644 \u062f\u0644\u064a\u0644 SPF\u061b \u0644\u0645 \u064a\u062a\u0645 \u0627\u0633\u062a\u0646\u062a\u0627\u062c \u0646\u062a\u064a\u062c\u0629 \u0623\u0645\u0646\u064a\u0629.",
                recommendation="\u0631\u0627\u062c\u0639\u064a \u062e\u062f\u0645\u0629 DNS \u0648\u0627\u0644\u062a\u0646\u0641\u064a\u0630 \u0627\u0644\u062f\u0627\u062e\u0644\u064a \u062b\u0645 \u0623\u0639\u064a\u062f\u064a \u0627\u0644\u0641\u062d\u0635.",
                limitations=("\u0644\u0645 \u064a\u062a\u0645 \u0639\u0631\u0636 \u0642\u064a\u0645 DNS \u0627\u0644\u062e\u0627\u0645 \u0623\u0648 \u062a\u0641\u0627\u0635\u064a\u0644 \u0627\u0644\u0627\u0633\u062a\u062b\u0646\u0627\u0621.",),
            )

        expanded_results = tuple(expanded_results) + (spf_result,)
        try:
            dmarc_result = evaluate_dmarc_domain(
                spf_domain,
                deadline=deadline,
            )
        except Exception:
            # A DMARC failure must not affect SPF or other findings.
            dmarc_result = CheckResult(
                check_id="dns_dmarc",
                title="DMARC policy",
                status="error",
                severity="info",
                confidence="low",
                evidence="DMARC evaluation could not be completed.",
                explanation=(
                    "An internal error occurred while collecting or "
                    "evaluating DMARC evidence; no security conclusion "
                    "was inferred."
                ),
                recommendation=(
                    "Review DNS availability and internal error logs, "
                    "then retry the scan."
                ),
                limitations=(
                    "Raw DNS TXT records and exception details are not "
                    "included in the report.",
                ),
            )

        expanded_results = tuple(expanded_results) + (dmarc_result,)

        try:
            dnssec_result = evaluate_dnssec_domain(
                spf_domain,
                deadline=deadline,
            )
        except Exception:
            # DNSSEC failure must not affect other report findings.
            dnssec_result = CheckResult(
                check_id="dnssec",
                title="DNSSEC indicators",
                status="error",
                severity="info",
                confidence="low",
                evidence="DNSSEC evaluation could not be completed.",
                explanation=(
                    "An internal error occurred while collecting or "
                    "evaluating DNSSEC indicators; no security conclusion "
                    "was inferred."
                ),
                recommendation=(
                    "Review DNS availability and internal error logs, "
                    "then retry the scan."
                ),
                limitations=(
                    "Raw DNS records, key material, and exception details "
                    "are not included in the report.",
                ),
            )

        expanded_results = tuple(expanded_results) + (dnssec_result,)

        try:
            # DNS-only metadata never becomes a validated HTTP target, and is
            # intentionally NOT passed to SPF, DMARC, DNSSEC or HTTP probes.
            takeover_result = evaluate_takeover_domain(
                validated_target.get("takeover_hostname"), deadline=deadline,
            )
        except Exception:
            takeover_result = CheckResult(
                check_id="subdomain_takeover_indicators",
                title="Passive subdomain takeover indicators",
                status="error", severity="info", confidence="low",
                evidence="Passive DNS indicator evaluation could not be completed.",
                explanation="An internal error occurred; no takeover conclusion was inferred.",
                recommendation="Review the internal implementation and retry.",
                limitations=("Raw DNS records and resolver exception details are omitted.",),
            )
        expanded_results = tuple(expanded_results) + (takeover_result,)

        findings.extend(
            result.to_dict() for result in expanded_results
        )

    return {
        "scan_id": scan_id,
        "status": "completed",
        "target_url": safe_target_url,
        "scanned_at": scanned_at,
        "engine_version": ENGINE_VERSION,
        "http_status": status_code,
        "summary": _summarize(findings),
        "findings": findings,
        "limitations": REPORT_LIMITATIONS,
        "notice": REPORT_NOTICE,
        **({"correlations": safe_correlate_findings(findings)} if include_expanded_checks else {}),
    }
