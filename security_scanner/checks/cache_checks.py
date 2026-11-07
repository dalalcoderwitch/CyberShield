"""Evidence-only evaluator for HTTP cache directives."""

from .evaluator import CheckEvaluator
from .result import CheckResult


def _cache_directives(values):
    """Extract directive names while respecting quoted comma characters."""
    directives = set()

    for value in values:
        parts = []
        current = []
        quoted = False
        escaped = False

        for character in value:
            if escaped:
                current.append(character)
                escaped = False
                continue

            if character == "\\" and quoted:
                current.append(character)
                escaped = True
                continue

            if character == '"':
                quoted = not quoted
                current.append(character)
                continue

            if character == "," and not quoted:
                parts.append("".join(current))
                current = []
                continue

            current.append(character)

        parts.append("".join(current))

        for part in parts:
            name = part.partition("=")[0].strip().lower()
            if name:
                directives.add(name)

    return directives


class CacheSecurityEvaluator(CheckEvaluator):
    """Evaluate cache directives without inferring response sensitivity."""

    def _evaluate(self, evidence):
        if evidence.http_status is None:
            return self._not_verified_result(
                title="أمان التخزين المؤقت (Cache Security)",
                recommendation=(
                    "أعيدي الفحص بعد الحصول على استجابة HTTP قابلة للتقييم."
                ),
            )

        cache_values = evidence.values_for_header("Cache-Control")
        directives = _cache_directives(cache_values)

        limitations = (
            "التقييم يعتمد على ترويسات الاستجابة فقط.",
            "لم يتم تحديد ما إذا كان محتوى الاستجابة حساسًا أو شخصيًا.",
            "لا يقيّم الفحص ذاكرة Cache API أو التخزين الذي تديره التطبيقات.",
            "وجود no-store لا يثبت أن جميع طبقات التخزين تتبع التعليمات.",
        )

        recommendation = (
            "اضبطي سياسة التخزين وفق حساسية المحتوى، واستخدمي no-store "
            "للاستجابات الحساسة التي يجب عدم تخزينها."
        )

        if not cache_values or not directives:
            legacy_headers = (
                evidence.values_for_header("Pragma")
                or evidence.values_for_header("Expires")
            )

            evidence_text = (
                "ترويسة Cache-Control غير موجودة أو لا تحتوي "
                "على توجيهات قابلة للتقييم."
            )

            if legacy_headers:
                evidence_text += (
                    " توجد ترويسات تخزين قديمة، لكنها لا تُعامل "
                    "كبديل مكافئ في هذا الفحص."
                )

            return CheckResult(
                check_id=self.definition.check_id,
                title="أمان التخزين المؤقت (Cache Security)",
                status="warning",
                severity="low",
                confidence="high",
                evidence=evidence_text,
                explanation=(
                    "لم يتم العثور على توجيهات Cache-Control واضحة "
                    "يمكن الاستناد إليها في هذا التقييم."
                ),
                recommendation=recommendation,
                limitations=limitations,
            )

        if "no-store" in directives:
            if "must-understand" in directives:
                return CheckResult(
                    check_id=self.definition.check_id,
                    title="\u0623\u0645\u0627\u0646 \u0627\u0644\u062a\u062e\u0632\u064a\u0646 \u0627\u0644\u0645\u0624\u0642\u062a (Cache Security)",
                    status="warning",
                    severity="low",
                    confidence="high",
                    evidence=(
                        "\u062a\u0645 \u0627\u0644\u0639\u062b\u0648\u0631 \u0639\u0644\u0649 \u062a\u0648\u062c\u064a\u0647\u0627\u062a \u062a\u062e\u0632\u064a\u0646 \u062a\u062a\u0637\u0644\u0628 "
                        "\u062f\u0639\u0645\u0627\u064b \u062e\u0627\u0635\u0627\u064b \u0645\u0646 \u0627\u0644\u0645\u062e\u0627\u0632\u0646 \u0627\u0644\u0645\u0624\u0642\u062a\u0629\u061b "
                        "\u0644\u0645 \u062a\u064f\u062f\u0631\u062c \u0627\u0644\u0642\u064a\u0645 \u0627\u0644\u062e\u0627\u0645."
                    ),
                    explanation=(
                        "\u0642\u062f \u064a\u0633\u0645\u062d must-understand \u0644\u0628\u0639\u0636 \u0627\u0644\u0645\u062e\u0627\u0632\u0646 \u0627\u0644\u0645\u062a\u0648\u0627\u0641\u0642\u0629 "
                        "\u0628\u062a\u062c\u0627\u0647\u0644 no-store \u0625\u0630\u0627 \u0641\u0647\u0645\u062a \u0645\u062a\u0637\u0644\u0628\u0627\u062a \u0631\u0645\u0632 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 "
                        "\u0648\u0637\u0628\u0642\u062a\u0647\u0627\u061b \u0648\u0644\u0627 \u064a\u0645\u0643\u0646 \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0630\u0644\u0643 \u0645\u0646 \u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 \u0648\u062d\u062f\u0647\u0627."
                    ),
                    recommendation=(
                        "\u062a\u062d\u0642\u0642\u064a \u0645\u0646 \u062a\u0648\u0627\u0641\u0642 \u0627\u0644\u0645\u062e\u0627\u0632\u0646 \u0627\u0644\u0648\u0633\u064a\u0637\u0629 \u0645\u0639 must-understand "
                        "\u0648\u0645\u062a\u0637\u0644\u0628\u0627\u062a \u062a\u062e\u0632\u064a\u0646 \u0631\u0645\u0632 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629."
                    ),
                    limitations=limitations,
                )

            return CheckResult(
                check_id=self.definition.check_id,
                title="أمان التخزين المؤقت (Cache Security)",
                status="passed",
                severity="info",
                confidence="high",
                evidence=(
                    "تم العثور على توجيه no-store في Cache-Control."
                ),
                explanation=(
                    "تطلب الاستجابة من مخازن HTTP المتوافقة عدم تخزينها. "
                    "هذا نجاح محدود على مستوى الترويسة فقط."
                ),
                recommendation=(
                    "حافظي على هذا التوجيه للاستجابات الحساسة، "
                    "وتحققي بشكل مستقل من طبقات التخزين الأخرى."
                ),
                limitations=limitations,
            )

        if "public" in directives or "s-maxage" in directives:
            explanation = (
                "تسمح التوجيهات المكتشفة بالتخزين في مخازن مشتركة "
                "أو تحدد صلاحية لها؛ لا يمكن تقييم ملاءمتها دون معرفة "
                "حساسية المحتوى."
            )
            severity = "medium"

        elif "private" in directives:
            explanation = (
                "تمنع private التخزين في المخازن المشتركة، "
                "لكنها لا تمنع التخزين في مخازن المستخدم الخاصة."
            )
            severity = "low"

        elif "no-cache" in directives:
            explanation = (
                "no-cache لا يمنع تخزين الاستجابة؛ بل يطلب إعادة "
                "التحقق قبل إعادة استخدامها."
            )
            severity = "low"

        else:
            explanation = (
                "تم العثور على توجيهات تخزين مؤقت، لكن لا يوجد "
                "دليل كافٍ على منع تخزين الاستجابة."
            )
            severity = "low"

        return CheckResult(
            check_id=self.definition.check_id,
            title="أمان التخزين المؤقت (Cache Security)",
            status="warning",
            severity=severity,
            confidence="high",
            evidence=(
                "تم العثور على توجيهات Cache-Control، "
                "ولم يتم تضمين قيمها الخام."
            ),
            explanation=explanation,
            recommendation=recommendation,
            limitations=limitations,
        )
