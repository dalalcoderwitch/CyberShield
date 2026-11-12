"""Evidence-only evaluator for HTTP cache directives."""

import re

from .evaluator import CheckEvaluator
from .result import CheckResult


_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_NO_ARGUMENT = {"no-store", "public", "must-revalidate", "proxy-revalidate",
                "must-understand", "no-transform", "immutable"}
_SECONDS = {"max-age", "s-maxage", "stale-while-revalidate", "stale-if-error"}


def _cache_directives(values):
    """Parse response directives; return names and sanitized ambiguity reason.

    RFC 9111 sections 4.2.1 and 5.2: accept quoted arguments, preserve
    duplicate detection across field lines, and never repair malformed input
    into a positive security conclusion. Empty list members are ignored.
    """
    directives = {}
    for value in values:
        parts, current = [], []
        quoted = escaped = False
        for character in value:
            if (ord(character) < 32 and character != "\t") or ord(character) == 127:
                return directives, "malformed"
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
            if character == "," and not quoted:
                parts.append("".join(current))
                current = []
            else:
                current.append(character)
        if quoted or escaped:
            return directives, "malformed"
        parts.append("".join(current))
        for part in parts:
            part = part.strip(" \t")
            if not part:
                continue
            name, separator, argument = part.partition("=")
            name = name.strip(" \t").lower()
            argument = argument.strip(" \t")
            if not _TOKEN.fullmatch(name):
                return directives, "malformed"
            decoded = None
            if separator:
                if argument.startswith('"') and argument.endswith('"'):
                    interior = argument[1:-1]
                    if not re.fullmatch(r'(?:[^"\\]|\\.)*', interior):
                        return directives, "malformed"
                    decoded = re.sub(r'\\(.)', r'\1', interior)
                elif _TOKEN.fullmatch(argument):
                    decoded = argument
                else:
                    return directives, "malformed"
            if name in _NO_ARGUMENT and separator:
                return directives, "malformed"
            if name in _SECONDS and (
                decoded is None or not decoded.isascii() or not decoded.isdecimal()
            ):
                return directives, "malformed"
            if name in {"private", "no-cache"} and separator:
                # Accept token or quoted field-name arguments (RFC 9111 5.2).
                if not decoded or not all(
                    _TOKEN.fullmatch(field.strip(" \t")) for field in decoded.split(",")
                ):
                    return directives, "malformed"
            if name in directives:
                return directives, "duplicate"
            directives[name] = decoded
    if "public" in directives and "private" in directives:
        return directives, "conflicting"
    return directives, None


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
        directives, ambiguity = _cache_directives(cache_values)

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

        if ambiguity:
            return CheckResult(
                check_id=self.definition.check_id,
                title="أمان التخزين المؤقت (Cache Security)",
                status="not_verified", severity="info", confidence="low",
                evidence="توجيهات Cache-Control مشوهة أو مكررة أو متعارضة؛ لم تُدرج القيم الخام.",
                explanation="لا تكفي هذه الأدلة لتأكيد سياسة منع التخزين، ولا تثبت وجود ثغرة.",
                recommendation="راجعي صيغة التوجيهات وأزيلي التكرار والتعارض ثم أعيدي الفحص.",
                limitations=limitations,
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
                status="not_verified",
                severity="info",
                confidence="low",
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
                    status="not_verified",
                    severity="info",
                    confidence="low",
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

        if "private" in directives and directives["private"] is None:
            # RFC 9111 5.2.2.7: unqualified private applies to the entire
            # response, regardless of shared-cache freshness information.
            explanation = (
                "تمنع private العامة تخزين الاستجابة كلها في المخازن المشتركة، "
                "لكنها لا تمنع التخزين في مخازن المستخدم الخاصة."
            )
            if "s-maxage" in directives:
                explanation += (
                    " يحدد s-maxage مدة الصلاحية للمخازن المشتركة، "
                    "ولا يلغي منع التخزين الذي تفرضه private العامة."
                )
            if directives.get("no-cache") is not None:
                explanation += (
                    " أما no-cache المخصصة لحقول معينة فتسمح بإعادة الاستخدام "
                    "بعد استبعاد تلك الحقول أو نجاح إعادة التحقق؛ "
                    "ولا تحصر أثر private العامة في تلك الحقول. "
                    "لم تُعرض أسماء الحقول."
                )

        elif any(directives.get(name) is not None for name in ("private", "no-cache")):
            explanation = (
                "توجد تعليمات private أو no-cache مخصصة لحقول معينة؛ "
                "لا تعمم هذه التعليمات على الاستجابة كلها، ولم تُعرض أسماء الحقول."
            )

        elif "public" in directives or "s-maxage" in directives:
            explanation = (
                "تسمح التوجيهات المكتشفة بالتخزين في مخازن مشتركة "
                "أو تحدد صلاحية لها؛ لا يمكن تقييم ملاءمتها دون معرفة "
                "حساسية المحتوى."
            )

        elif "no-cache" in directives:
            explanation = (
                "no-cache لا يمنع تخزين الاستجابة؛ بل يطلب إعادة "
                "التحقق قبل إعادة استخدامها."
            )

        else:
            explanation = (
                "تم العثور على توجيهات تخزين مؤقت، لكن لا يوجد "
                "دليل كافٍ على منع تخزين الاستجابة."
            )

        return CheckResult(
            check_id=self.definition.check_id,
            title="أمان التخزين المؤقت (Cache Security)",
            status="not_verified",
            severity="info",
            confidence="low",
            evidence=(
                "تم العثور على توجيهات Cache-Control، "
                "ولم يتم تضمين قيمها الخام."
            ),
            explanation=explanation + " لم تُحدد حساسية المحتوى؛ غياب no-store وحده لا يثبت وجود ثغرة.",
            recommendation=recommendation,
            limitations=limitations,
        )
