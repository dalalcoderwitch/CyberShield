"""Evidence-only evaluators for additional security headers."""

import re

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




# Structured Fields parsing for the Permissions-Policy HTTP dictionary.
_SF_KEY_PATTERN = re.compile(r"[a-z*][a-z0-9_.*-]*\Z")
_SF_TOKEN_PATTERN = re.compile(
    r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*\Z"
)
_SF_INTEGER_PATTERN = re.compile(r"-?[0-9]{1,15}\Z")
_SF_DECIMAL_PATTERN = re.compile(r"-?[0-9]{1,12}\.[0-9]{1,3}\Z")

_SCHEME_PART = r"[A-Za-z][A-Za-z0-9+.-]*"
_HOST_LABEL = r"[A-Za-z0-9-]+"
_HOST_PART = (
    r"(?:\*|"
    rf"\*\.{_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?|"
    rf"{_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?)"
)
_PATH_CHAR = r"(?:[A-Za-z0-9._~!$&'()*+=:@/-]|%[0-9A-Fa-f]{2})"

_SCHEME_SOURCE_PATTERN = re.compile(rf"{_SCHEME_PART}:\Z", re.IGNORECASE)
_HOST_SOURCE_PATTERN = re.compile(
    rf"(?:{_SCHEME_PART}://)?{_HOST_PART}"
    rf"(?::(?:[0-9]+|\*))?(?:/{_PATH_CHAR}*)?\Z",
    re.IGNORECASE,
)


def _is_permissions_source_expression(value):
    if not isinstance(value, str) or not value or not value.isascii():
        return False

    return bool(
        _SCHEME_SOURCE_PATTERN.fullmatch(value)
        or _HOST_SOURCE_PATTERN.fullmatch(value)
    )


def _skip_sf_ows(value, index):
    while index < len(value) and value[index] in " \t":
        index += 1
    return index


def _read_sf_key(value, index):
    start = index

    while index < len(value) and value[index] in (
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789_.*-"
    ):
        index += 1

    key = value[start:index]

    if not _SF_KEY_PATTERN.fullmatch(key):
        raise ValueError("Invalid Structured Field key")

    return key, index


def _read_sf_string(value, index):
    if index >= len(value) or value[index] != '"':
        raise ValueError("Expected Structured Field string")

    index += 1
    result = []

    while index < len(value):
        char = value[index]
        code = ord(char)

        if char == '"':
            return "".join(result), index + 1

        if char == "\\":
            index += 1
            if index >= len(value) or value[index] not in ('"', "\\"):
                raise ValueError("Invalid Structured Field string escape")
            result.append(value[index])
            index += 1
            continue

        if code < 0x20 or code > 0x7E:
            raise ValueError("Invalid Structured Field string character")

        result.append(char)
        index += 1

    raise ValueError("Unterminated Structured Field string")


def _read_sf_bare_item(value, index):
    if index >= len(value):
        raise ValueError("Missing Structured Field item")

    if value[index] == '"':
        item, index = _read_sf_string(value, index)
        return "string", item, index

    if value[index] == ":":
        end = value.find(":", index + 1)
        if end < 0:
            raise ValueError("Invalid Structured Field byte sequence")

        encoded = value[index + 1:end]
        if (
            not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", encoded)
            or len(encoded) % 4 != 0
        ):
            raise ValueError("Invalid Structured Field byte sequence")

        return "bytes", encoded, end + 1

    start = index
    while (
        index < len(value)
        and value[index] not in " \t,;)=("
    ):
        index += 1

    item = value[start:index]

    if not item:
        raise ValueError("Empty Structured Field item")

    if item in ("?0", "?1"):
        return "boolean", item, index

    if _SF_INTEGER_PATTERN.fullmatch(item):
        return "integer", item, index

    if _SF_DECIMAL_PATTERN.fullmatch(item):
        return "decimal", item, index

    if _SF_TOKEN_PATTERN.fullmatch(item):
        return "token", item, index

    raise ValueError("Invalid Structured Field item")


def _read_sf_parameters(value, index):
    parameters = {}

    while index < len(value) and value[index] == ";":
        index += 1

        while index < len(value) and value[index] == " ":
            index += 1

        name, index = _read_sf_key(value, index)

        parameter = ("boolean", "?1")

        if index < len(value) and value[index] == "=":
            index += 1
            item_kind, item_value, index = _read_sf_bare_item(value, index)
            parameter = (item_kind, item_value)

        # Structured Fields parameters are maps: the last duplicate wins.
        parameters[name] = parameter

    return index, parameters


def _read_sf_inner_list(value, index):
    if index >= len(value) or value[index] != "(":
        raise ValueError("Expected Structured Field inner list")

    index += 1
    items = []

    while index < len(value) and value[index] == " ":
        index += 1

    if index < len(value) and value[index] == ")":
        return items, index + 1

    while True:
        item_kind, item_value, index = _read_sf_bare_item(value, index)

        # Item parameters are parsed for syntax, but do not change the
        # Permissions-Policy allowlist item itself.
        index, _ = _read_sf_parameters(value, index)
        items.append((item_kind, item_value))

        if index >= len(value):
            raise ValueError("Unterminated Structured Field inner list")

        if value[index] == ")":
            return items, index + 1

        if value[index] != " ":
            raise ValueError("Invalid Structured Field inner-list separator")

        while index < len(value) and value[index] == " ":
            index += 1

        if index < len(value) and value[index] == ")":
            return items, index + 1


def _permissions_member_semantics(item_kind, item_value):
    member = {
        "wildcard": False,
        "explicit_sources": False,
        "ignored_members": 0,
    }

    def process_item(kind, value):
        if kind == "token" and value == "*":
            member["wildcard"] = True
        elif kind == "token" and value == "self":
            return
        elif kind == "string":
            if _is_permissions_source_expression(value):
                member["explicit_sources"] = True
            else:
                member["ignored_members"] += 1
        else:
            # Unsupported items in an Inner List are ignored by the
            # Permissions-Policy processing algorithm.
            member["ignored_members"] += 1

    if item_kind == "inner_list":
        for inner_kind, inner_value in item_value:
            process_item(inner_kind, inner_value)
    else:
        process_item(item_kind, item_value)

    return member


def _parse_permissions_policy_dictionary(values):
    if not isinstance(values, (tuple, list)):
        raise ValueError("Invalid Permissions-Policy evidence")

    if not all(isinstance(item, str) for item in values):
        raise ValueError("Invalid Permissions-Policy field values")

    # Multiple field lines of a Dictionary are combined using commas.
    serialized = ", ".join(values)

    if len(serialized) > 16384:
        raise ValueError("Permissions-Policy exceeds parser limit")

    index = _skip_sf_ows(serialized, 0)
    members = {}

    while index < len(serialized):
        key, index = _read_sf_key(serialized, index)

        if index < len(serialized) and serialized[index] == "=":
            index += 1

            if index < len(serialized) and serialized[index] == "(":
                item_kind = "inner_list"
                item_value, index = _read_sf_inner_list(serialized, index)
            else:
                item_kind, item_value, index = _read_sf_bare_item(
                    serialized, index
                )
        else:
            # A bare Dictionary member has the Structured Fields value true.
            item_kind, item_value = "boolean", "?1"

        index, parameters = _read_sf_parameters(serialized, index)

        member = _permissions_member_semantics(item_kind, item_value)

        report_to = parameters.get("report-to")
        member["invalid_report_to"] = (
            report_to is not None and report_to[0] != "token"
        )

        # Duplicate Dictionary keys use the last complete member.
        members[key] = member

        index = _skip_sf_ows(serialized, index)

        if index >= len(serialized):
            break

        if serialized[index] != ",":
            raise ValueError("Invalid Permissions-Policy dictionary separator")

        index += 1
        index = _skip_sf_ows(serialized, index)

        if index >= len(serialized):
            raise ValueError("Trailing Permissions-Policy dictionary separator")

    return {
        "directive_count": len(members),
        "wildcard": any(item["wildcard"] for item in members.values()),
        "explicit_sources": any(
            item["explicit_sources"] for item in members.values()
        ),
        "ignored_members": sum(
            item["ignored_members"] for item in members.values()
        ),
        "invalid_report_to_count": sum(
            item["invalid_report_to"] for item in members.values()
        ),
    }


class PermissionsPolicyEvaluator(CheckEvaluator):
    """Conservatively inspect the HTTP Structured Fields dictionary."""

    def _evaluate(self, evidence):
        title = (
            "\u0633\u064a\u0627\u0633\u0629 "
            "\u0635\u0644\u0627\u062d\u064a\u0627\u062a "
            "\u0627\u0644\u0645\u062a\u0635\u0641\u062d "
            "(Permissions-Policy)"
        )

        if evidence.http_status is None:
            return self._not_verified_result(
                title=title,
                recommendation=(
                    "\u0623\u0639\u064a\u062f\u064a "
                    "\u0627\u0644\u0641\u062d\u0635 "
                    "\u0628\u0639\u062f \u062a\u0648\u0641\u0631 "
                    "\u0627\u0633\u062a\u062c\u0627\u0628\u0629 HTTP."
                ),
            )

        values = evidence.values_for_header("Permissions-Policy")

        if not values:
            return self._result(
                title,
                "low",
                "\u062a\u0631\u0648\u064a\u0633\u0629 Permissions-Policy "
                "\u063a\u064a\u0631 \u0645\u0648\u062c\u0648\u062f\u0629.",
                "\u0644\u0645 \u064a\u062a\u0645 "
                "\u0627\u0644\u0639\u062b\u0648\u0631 "
                "\u0639\u0644\u0649 \u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 "
                "\u0641\u064a \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629.",
            )

        try:
            parsed = _parse_permissions_policy_dictionary(values)
        except (TypeError, ValueError):
            return self._result(
                title,
                "medium",
                "\u062a\u0631\u0648\u064a\u0633\u0629 Permissions-Policy "
                "\u0645\u0648\u062c\u0648\u062f\u0629 \u0644\u0643\u0646 "
                "\u0635\u064a\u0627\u063a\u0629 \u0627\u0644\u0642\u0627\u0645\u0648\u0633 "
                "\u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629 "
                "\u0623\u0648 \u0645\u0644\u062a\u0628\u0633\u0629.",
                "\u062a\u0639\u0630\u0631 "
                "\u062a\u062d\u0644\u064a\u0644 \u0628\u0646\u064a\u0629 "
                "\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 "
                "\u0628\u0627\u0639\u062a\u0628\u0627\u0631\u0647\u0627 "
                "Structured Fields Dictionary.",
            )

        if parsed["ignored_members"]:
            return self._result(
                title,
                "medium",
                "\u062a\u062d\u062a\u0648\u064a "
                "\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 "
                "\u0639\u0644\u0649 \u062a\u0648\u062c\u064a\u0647\u0627\u062a "
                "\u0644\u0645 \u062a\u064f\u0642\u0628\u0644 "
                "\u0648\u0641\u0642 \u0623\u0646\u0648\u0627\u0639 "
                "\u0627\u0644\u0642\u064a\u0645 \u0627\u0644\u0645\u0633\u0645\u0648\u062d "
                "\u0628\u0647\u0627.",
                "\u0642\u062f \u064a\u062a\u062c\u0627\u0647\u0644 "
                "\u0627\u0644\u0645\u062a\u0635\u0641\u062d "
                "\u0628\u0639\u0636 \u0627\u0644\u0623\u0639\u0636\u0627\u0621 "
                "\u063a\u064a\u0631 \u0627\u0644\u0645\u062a\u0648\u0627\u0641\u0642\u0629 "
                "\u0645\u0639 \u0623\u0646\u0648\u0627\u0639 "
                "\u0642\u064a\u0645 Permissions-Policy.",
            )

        if parsed["directive_count"] == 0:
            return self._result(
                title,
                "low",
                "\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 "
                "\u0645\u0648\u062c\u0648\u062f\u0629 "
                "\u0644\u0643\u0646\u0647\u0627 "
                "\u0644\u0627 \u062a\u062d\u062a\u0648\u064a "
                "\u0639\u0644\u0649 \u062a\u0648\u062c\u064a\u0647\u0627\u062a.",
                "\u0627\u0644\u0642\u0627\u0645\u0648\u0633 "
                "\u0641\u0627\u0631\u063a \u0648\u0644\u0645 "
                "\u062a\u064f\u0631\u0635\u062f "
                "\u0623\u0639\u0636\u0627\u0621 \u0633\u064a\u0627\u0633\u0629.",
            )

        if parsed["wildcard"]:
            return self._result(
                title,
                "low",
                "\u062a\u0645 \u0627\u0644\u0639\u062b\u0648\u0631 "
                "\u0639\u0644\u0649 \u0635\u0644\u0627\u062d\u064a\u0629 "
                "\u0648\u0627\u0633\u0639\u0629 "
                "\u0628\u0627\u0633\u062a\u062e\u062f\u0627\u0645 "
                "\u0627\u0644\u0646\u062c\u0645\u0629\u061b "
                "\u0631\u0627\u062c\u0639\u064a "
                "\u0645\u0627 \u0625\u0630\u0627 "
                "\u0643\u0627\u0646 \u0627\u0644\u0633\u0645\u0627\u062d "
                "\u0644\u062c\u0645\u064a\u0639 "
                "\u0627\u0644\u0645\u0635\u0627\u062f\u0631 "
                "\u0645\u0637\u0644\u0648\u0628\u0627\u064b.",
                "\u0648\u062c\u0648\u062f "
                "\u0627\u0644\u0646\u062c\u0645\u0629 "
                "\u064a\u0634\u064a\u0631 "
                "\u0625\u0644\u0649 \u0642\u0627\u0626\u0645\u0629 "
                "\u0633\u0645\u0627\u062d \u0639\u0627\u0645\u0629 "
                "\u0644\u0644\u0645\u0635\u0627\u062f\u0631\u061b "
                "\u0648\u0644\u064a\u0633 "
                "\u0625\u062b\u0628\u0627\u062a\u0627\u064b "
                "\u0642\u0627\u0637\u0639\u0627\u064b "
                "\u0644\u062b\u063a\u0631\u0629.",
            )

        if parsed["explicit_sources"]:
            explanation = (
                "\u062a\u0645 \u062a\u062d\u0644\u064a\u0644 "
                "\u0628\u0646\u064a\u0629 \u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 "
                "\u0645\u0639 \u0648\u062c\u0648\u062f "
                "\u0645\u0635\u0627\u062f\u0631 \u0645\u062d\u062f\u062f\u0629\u061b "
                "\u0644\u0645 \u062a\u062a\u0645 "
                "\u0645\u0642\u0627\u0631\u0646\u0629 "
                "\u0647\u0630\u0647 \u0627\u0644\u0645\u0635\u0627\u062f\u0631 "
                "\u0628\u0623\u0635\u0644 \u0627\u0644\u0647\u062f\u0641."
            )
        else:
            explanation = (
                "\u062a\u0645 \u062a\u062d\u0644\u064a\u0644 "
                "\u0628\u0646\u064a\u0629 \u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629. "
                "\u0644\u0645 \u062a\u064f\u0631\u0635\u062f "
                "\u0639\u0644\u0627\u0645\u0629 \u0627\u0644\u0633\u0645\u0627\u062d "
                "\u0644\u062c\u0645\u064a\u0639 "
                "\u0627\u0644\u0645\u0635\u0627\u062f\u0631."
            )

        return self._result(
            title,
            "info",
            "\u062a\u0645 \u062a\u062d\u0644\u064a\u0644 "
            "\u0628\u0646\u064a\u0629 \u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 "
            "\u062f\u0648\u0646 \u0627\u0644\u0627\u062d\u062a\u0641\u0627\u0638 "
            "\u0628\u0642\u064a\u0645\u0647\u0627 \u0627\u0644\u062e\u0627\u0645.",
            explanation,
        )

    def _result(self, title, severity, evidence, explanation):
        return CheckResult(
            check_id=self.definition.check_id,
            title=title,
            status="warning",
            severity=severity,
            confidence="high",
            evidence=evidence,
            explanation=explanation,
            recommendation=(
                "\u062a\u062d\u0642\u0642\u064a "
                "\u0645\u0646 \u0635\u064a\u0627\u063a\u0629 "
                "Structured Fields \u0648\u0642\u064a\u0645 "
                "\u0627\u0644\u062a\u0648\u062c\u064a\u0647\u0627\u062a\u060c "
                "\u0648\u0644\u0627 \u062a\u0639\u062a\u0645\u062f\u064a "
                "\u0639\u0644\u0649 \u0648\u062c\u0648\u062f "
                "\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 \u0648\u062d\u062f\u0647."
            ),
            limitations=(
                "\u0644\u0645 \u064a\u062a\u0645 "
                "\u062a\u062d\u0644\u064a\u0644 "
                "\u0642\u0627\u0626\u0645\u0629 "
                "\u0645\u064a\u0632\u0627\u062a "
                "\u0627\u0644\u0645\u062a\u0635\u0641\u062d "
                "\u0627\u0644\u0645\u062f\u0639\u0648\u0645\u0629.",
                "\u0644\u0645 \u064a\u062a\u0645 "
                "\u0627\u0644\u062a\u062d\u0642\u0642 "
                "\u0645\u0646 \u0635\u062d\u0629 "
                "\u0645\u0635\u0627\u062f\u0631 "
                "\u0627\u0644\u0623\u0635\u0648\u0644 "
                "\u0623\u0648 \u0645\u0637\u0627\u0628\u0642\u062a\u0647\u0627 "
                "\u0644\u0623\u0635\u0644 \u0627\u0644\u0647\u062f\u0641.",
                "\u0644\u0645 \u064a\u062a\u0645 "
                "\u062a\u0642\u064a\u064a\u0645 "
                "\u0627\u0644\u0642\u064a\u0645 "
                "\u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a\u0629 "
                "\u0623\u0648 \u0633\u064a\u0627\u0633\u0629 "
                "\u0627\u0644\u0625\u0637\u0627\u0631\u0627\u062a "
                "\u0627\u0644\u0645\u0636\u0645\u0646\u0629 "
                "\u0623\u0648 \u0633\u0644\u0648\u0643 \u0627\u0644\u0645\u062a\u0635\u0641\u062d.",
            ),
        )
