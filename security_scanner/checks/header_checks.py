"""Evidence-only evaluators for additional security headers."""

from .evaluator import CheckEvaluator
from .result import CheckResult


_KNOWN_POLICIES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)

_RESTRICTIVE_POLICIES = frozenset(
    {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)


class ReferrerPolicyEvaluator(CheckEvaluator):
    """Evaluate the recognized Referrer-Policy value conservatively."""

    def _evaluate(self, evidence):
        if evidence.http_status is None:
            return self._not_verified_result(
                title="سياسة الإحالة (Referrer-Policy)",
                recommendation=(
                    "أعيدي الفحص بعد الحصول على استجابة HTTP قابلة للتقييم."
                ),
            )

        values = evidence.values_for_header("Referrer-Policy")

        tokens = [
            token.strip().lower()
            for value in values
            for token in value.split(",")
            if token.strip()
        ]

        effective = next(
            (
                token
                for token in reversed(tokens)
                if token in _KNOWN_POLICIES
            ),
            None,
        )

        limitations = (
            "تم تقييم ترويسة الاستجابة فقط.",
            "لم يتم تقييم سياسات HTML أو سمات العناصر أو إعدادات الطلبات الفردية.",
            "التقييم أولي ولا يثبت سلوك جميع المتصفحات.",
        )

        recommendation = (
            "راجعي سياسة الإحالة واختاري سياسة تقيّد مشاركة معلومات الصفحة "
            "بما يناسب التطبيق."
        )

        if effective is None:
            return CheckResult(
                check_id=self.definition.check_id,
                title="سياسة الإحالة (Referrer-Policy)",
                status="warning",
                severity="low",
                confidence="high",
                evidence=(
                    "ترويسة Referrer-Policy غير موجودة أو لا تحتوي "
                    "على قيمة معروفة."
                ),
                explanation=(
                    "لم يتم العثور على سياسة إحالة معروفة يمكن تقييمها."
                ),
                recommendation=recommendation,
                limitations=limitations,
            )

        if effective in _RESTRICTIVE_POLICIES:
            return CheckResult(
                check_id=self.definition.check_id,
                title="سياسة الإحالة (Referrer-Policy)",
                status="passed",
                severity="info",
                confidence="high",
                evidence=(
                    "تم العثور على قيمة معروفة ذات قيود مناسبة "
                    "في ترويسة Referrer-Policy."
                ),
                explanation=(
                    "القيمة المعروفة المختارة تقلل مشاركة معلومات "
                    "الإحالة وفق قواعد السياسة."
                ),
                recommendation=(
                    "حافظي على السياسة وراجعي ملاءمتها لاحتياجات التطبيق."
                ),
                limitations=limitations,
            )

        severity = "medium" if effective == "unsafe-url" else "low"

        return CheckResult(
            check_id=self.definition.check_id,
            title="سياسة الإحالة (Referrer-Policy)",
            status="warning",
            severity=severity,
            confidence="high",
            evidence=(
                "تم العثور على سياسة إحالة معروفة، لكن مستوى تقييدها "
                "يحتاج إلى مراجعة."
            ),
            explanation=(
                "القيمة المختارة قد تسمح بمشاركة معلومات إحالة أكثر "
                "مما يلزم في بعض الطلبات."
            ),
            recommendation=recommendation,
            limitations=limitations,
        )


class PermissionsPolicyEvaluator(CheckEvaluator):
    """Detect the Permissions-Policy header without claiming policy quality."""

    def _evaluate(self, evidence):
        if evidence.http_status is None:
            return self._not_verified_result(
                title="سياسة صلاحيات المتصفح (Permissions-Policy)",
                recommendation=(
                    "أعيدي الفحص بعد الحصول على استجابة HTTP قابلة للتقييم."
                ),
            )

        values = evidence.values_for_header("Permissions-Policy")
        present = any(value.strip() for value in values)

        if present:
            evidence_text = (
                "تم العثور على ترويسة Permissions-Policy. "
                "لم تُعرض قيمتها الخام."
            )
            explanation = (
                "تم رصد وجود الترويسة فقط؛ لم يتم تقييم التوجيهات "
                "وقوائم السماح أو التأثير الفعلي للسياسة."
            )
            severity = "info"
        else:
            evidence_text = "ترويسة Permissions-Policy غير موجودة."
            explanation = (
                "لم يتم العثور على ترويسة تحدد قيود ميزات المتصفح "
                "في الاستجابة المفحوصة."
            )
            severity = "low"

        return CheckResult(
            check_id=self.definition.check_id,
            title="سياسة صلاحيات المتصفح (Permissions-Policy)",
            status="warning",
            severity=severity,
            confidence="high",
            evidence=evidence_text,
            explanation=explanation,
            recommendation=(
                "راجعي ميزات المتصفح المستخدمة، وقيّدي الميزات الحساسة "
                "إلى المصادر المطلوبة فقط."
            ),
            limitations=(
                "الفحص يتحقق من وجود الترويسة فقط.",
                "لم يتم تحليل التوجيهات أو قوائم السماح أو القيم الافتراضية.",
                "لم يتم تقييم تأثير السياسة على الإطارات المضمنة.",
            ),
        )
