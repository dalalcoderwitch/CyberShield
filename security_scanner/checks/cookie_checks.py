"""Aggregated cookie-attribute evaluators using sanitized evidence only."""

from .evaluator import CheckEvaluator
from .result import CheckResult


_COOKIE_IDS = (
    "cookie_secure",
    "cookie_httponly",
    "cookie_samesite",
)


class CookieAttributeEvaluator(CheckEvaluator):
    """Evaluate one attribute across all observed cookies without identifiers."""

    def _evaluate(self, evidence):
        check_id = self.definition.check_id
        if check_id not in _COOKIE_IDS:
            raise ValueError("Unsupported cookie check")

        if evidence.cookie_evidence_available is not True:
            return self._result(
                "not_verified", "info", "low",
                "تعذر جمع حقول Set-Cookie المنفصلة أو التحقق من سلامة دليلها.",
                "لا تتوفر أدلة كافية لتقييم خصائص ملفات Cookie.",
                "أعيدي الفحص بعد توفر ترويسات خام متعددة القيم.",
                ("لم تُحفظ قيم أو أسماء Cookie في الأدلة.",),
            )

        observations = evidence.cookie_observations
        count = len(observations)
        if count == 0:
            return self._result(
                "skipped", "info", "high",
                "لم تُرصد ملفات Cookie في استجابة HTTPS المشتركة.",
                "لا توجد ملفات Cookie لتقييم هذه الخاصية.",
                "لا يلزم إجراء لهذا الفحص في هذه الاستجابة.",
                ("النتيجة تخص الاستجابة المفحوصة فقط.",),
            )

        if check_id == "cookie_secure":
            affected = [index for index, item in enumerate(observations, 1) if not item[0]]
            if affected:
                return self._result(
                    "warning", "medium", "high",
                    self._count_evidence(count, len(affected), affected, "Secure"),
                    "غابت سمة Secure عن بعض ملفات Cookie المرصودة؛ لا يثبت ذلك حدوث تسريب فعلي.",
                    "راجع إعداد Secure لكل ملف Cookie.",
                    ("لم تُسجل أسماء أو قيم Cookie.",),
                )
            return self._result(
                "passed", "info", "high",
                f"تم رصد {count} ملف Cookie، وجميعها تتضمن Secure.",
                "أظهرت حقول Set-Cookie المرصودة سمة Secure لكل الملفات.",
                "حافظ على إعداد Secure.",
                ("النتيجة تخص الملفات المرصودة في هذه الاستجابة فقط.",),
            )

        if check_id == "cookie_httponly":
            affected = [index for index, item in enumerate(observations, 1) if not item[1]]
            if affected:
                return self._result(
                    "warning", "medium", "high",
                    self._count_evidence(count, len(affected), affected, "HttpOnly"),
                    "غابت سمة HttpOnly عن بعض ملفات Cookie. تساعد هذه السمة على تقليل وصول JavaScript إلى Cookie، لكنها لا تمنع جميع مخاطر XSS.",
                    "راجع إعداد HttpOnly مع الاحتفاظ بضوابط XSS الأخرى.",
                    ("لم تُسجل أسماء أو قيم Cookie.",),
                )
            return self._result(
                "passed", "info", "high",
                f"تم رصد {count} ملف Cookie، وجميعها تتضمن HttpOnly.",
                "أظهرت حقول Set-Cookie المرصودة سمة HttpOnly لكل الملفات.",
                "حافظ على HttpOnly مع تطبيق ضوابط XSS المناسبة.",
                ("HttpOnly لا يمنع جميع مخاطر XSS.",),
            )

        ambiguous = [index for index, item in enumerate(observations, 1) if item[2] == "ambiguous"]
        if ambiguous:
            unresolved = len(ambiguous)
            resolved = count - unresolved
            return self._result(
                "not_verified", "info", "medium",
                f"تعذر حسم SameSite لعدد {unresolved} من أصل {count} ملفات Cookie؛ حُسمت الخاصية لعدد {resolved}.",
                "تعارضت أو تعذر تحليل قيم SameSite لبعض ملفات Cookie.",
                "أعد التقييم بعد توفير قيمة SameSite واحدة قابلة للتحليل لكل ملف.",
                (f"الأرقام غير المحسومة: {self._indices(ambiguous)}.",
                 "لا تُعرض أسماء أو قيم Cookie."),
            )

        missing = [index for index, item in enumerate(observations, 1) if item[2] == "missing"]
        invalid = [index for index, item in enumerate(observations, 1) if item[2] == "invalid"]
        none_without_secure = [
            index for index, item in enumerate(observations, 1)
            if item[2] == "none" and not item[0]
        ]
        affected = sorted(set(missing + invalid + none_without_secure))
        if affected:
            if none_without_secure:
                severity = "medium"
                explanation = "تستخدم بعض ملفات Cookie SameSite=None دون Secure، بينما قد تكون خصائص أخرى مفقودة أو غير معروفة."
            else:
                severity = "low"
                explanation = "بعض ملفات Cookie تفتقد SameSite أو تحمل قيمة غير معروفة/غير صالحة."
            return self._result(
                "warning", severity, "high",
                self._count_evidence(count, len(affected), affected, "SameSite"),
                explanation,
                "حدد SameSite صراحةً، واستخدم Secure مع None.",
                ("SameSite=None يسمح بالاستخدام عبر المواقع؛ وجوده وحده لا يثبت وجود ثغرة.",
                 "لم تُسجل أسماء أو قيم Cookie."),
            )

        none_values = sum(item[2] == "none" for item in observations)
        if none_values:
            explanation = (
                f"تتضمن {none_values} من ملفات Cookie المرصودة SameSite=None مع Secure؛ "
                "وهذا يسمح بالاستخدام عبر المواقع ولا يعني وحده وجود ثغرة."
            )
        else:
            explanation = "تتضمن جميع ملفات Cookie المرصودة SameSite=Strict أو SameSite=Lax."
        return self._result(
            "passed", "info", "high",
            f"تم رصد {count} ملف Cookie، وكانت قيم SameSite مقبولة وفق السياسة.",
            explanation,
            "حافظ على قيم SameSite المناسبة لحاجة كل ملف.",
            ("لم تُسجل أسماء أو قيم Cookie.",),
        )

    def _count_evidence(self, total, affected_count, indices, attribute):
        return (
            f"تم رصد {total} ملف Cookie؛ تأثرت {affected_count} بغياب أو مشكلة "
            f"في {attribute} (الأرقام: {self._indices(indices)})."
        )

    @staticmethod
    def _indices(indices):
        return ", ".join(str(index) for index in indices)

    def _result(self, status, severity, confidence, evidence, explanation, recommendation, limitations):
        return CheckResult(
            self.definition.check_id,
            self.definition.title,
            status,
            severity,
            confidence,
            evidence,
            explanation,
            recommendation,
            tuple(limitations),
        )
