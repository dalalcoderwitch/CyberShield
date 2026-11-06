from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from .scanner import _safe_get_response, check_security_headers


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
) -> dict:
    """
    تنفيذ الفحوصات المحددة وإرجاع تقرير منظم.

    لا يعني اكتمال إنشاء التقرير أن جميع الفحوصات نجحت.
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    scan_id = str(uuid4())

    safe_target_url = _safe_report_target_url(target_url)

    # يجب أن يبقى فحص الهدف داخل الماسح فعالًا،
    # حتى لو استُدعيت هذه الدالة مباشرةً خارج Flask.
    if deadline is None:
        if resolved_target is None:
            status_code, headers, error = _safe_get_response(target_url)
        else:
            status_code, headers, error = _safe_get_response(
                target_url,
                resolved_target=resolved_target,
            )
    elif resolved_target is None:
        status_code, headers, error = _safe_get_response(
            target_url,
            deadline=deadline,
        )
    else:
        status_code, headers, error = _safe_get_response(
            target_url,
            resolved_target=resolved_target,
            deadline=deadline,
        )
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
    }
