from datetime import datetime, timezone
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
]

REPORT_NOTICE = (
    "هذا التقرير تقييم أولي محدود، ولا يضمن أمان الموقع بالكامل."
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


def scan_target(target_url: str) -> dict:
    """
    تنفيذ الفحوصات المحددة وإرجاع تقرير منظم.

    لا يعني اكتمال إنشاء التقرير أن جميع الفحوصات نجحت.
    """

    scanned_at = datetime.now(timezone.utc).isoformat()
    scan_id = str(uuid4())

    safe_target_url = target_url if isinstance(target_url, str) else ""

    status_code, headers, error = _safe_get_response(safe_target_url)

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
        if error == "invalid":
            https_status = "warning"
            explanation = (
                "الرابط غير صالح أو لا يطابق قيود الفحص."
            )
        elif error == "tls":
            https_status = "warning"
            explanation = (
                "تعذر التحقق من شهادة TLS؛ "
                "لم يُعتبر الاتصال ناجحًا."
            )
        else:
            https_status = "error"
            explanation = "تعذر الاتصال بالموقع."

        findings.append(
            _make_finding(
                check_id="https_connection",
                title="اتصال HTTPS والتحقق من شهادة TLS",
                status=https_status,
                severity="medium",
                confidence="high",
                evidence=f"لم يكتمل الفحص. نوع النتيجة: {error}.",
                explanation=explanation,
                recommendation=(
                    "تحققي من صلاحية الرابط وإمكانية الوصول "
                    "وصحة إعداد TLS، ثم أعيدي الفحص."
                ),
                limitations=[
                    "لم يتم الحصول على استجابة صالحة لفحص الترويسات."
                ],
            )
        )

    # فحص الترويسات عند توفر استجابة.
    if error is None:
        header_results = check_security_headers(headers)

        normalized_headers = {
            str(key).lower(): str(value)
            for key, value in headers.items()
        }

        for item in HEADER_CHECKS:
            header_name = item["header"]
            result = header_results[item["key"]]

            header_value = normalized_headers.get(
                header_name.lower()
            )

            if result["status"] == "passed":
                evidence = (
                    f"تم العثور على الترويسة {header_name}."
                )

                if header_value is not None:
                    evidence += (
                        f" القيمة المرصودة: "
                        f"{header_value[:200]}"
                    )

                confidence = "high"
                severity = "info"
            else:
                evidence = (
                    f"الترويسة {header_name} مفقودة "
                    "أو أن قيمتها غير مقبولة في هذا الفحص."
                )

                confidence = "high"
                severity = item["severity"]

            explanation = result["message"]

            if item["key"] == "CSP" and header_value:
                explanation += (
                    " فحص وجود الترويسة لا يقيّم جودة "
                    "السياسة أو مدى فعاليتها."
                )

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