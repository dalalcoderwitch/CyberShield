"""Bounded DNS SPF evidence collection and passive policy analysis."""

from dataclasses import dataclass, field
import ipaddress
import re
import time
from threading import BoundedSemaphore

import dns.exception
import dns.resolver

from .base import CheckDefinition
from .result import CheckResult


_DNS_TXT_TIMEOUT_SECONDS = 2.0
_DNS_TXT_MAX_CONCURRENT_LOOKUPS = 4
_DNS_TXT_LOOKUP_SLOTS = BoundedSemaphore(_DNS_TXT_MAX_CONCURRENT_LOOKUPS)
_MAX_TXT_RECORDS = 100
_MAX_TXT_RECORD_BYTES = 4096

_ALLOWED_QUERY_STATES = frozenset({
    "available",
    "no_spf",
    "timeout",
    "dns_error",
    "dns_capacity",
    "invalid_target",
    "not_applicable",
    "oversized_response",
})


@dataclass(frozen=True)
class SPFEvidence:
    """DNS observations retained only for the SPF evaluator."""

    query_state: str
    records: tuple[str, ...] = field(default_factory=tuple, repr=False)

    def __post_init__(self):
        if self.query_state not in _ALLOWED_QUERY_STATES:
            raise ValueError("Unsupported SPF query state")
        if not isinstance(self.records, (tuple, list)):
            raise TypeError("SPF records must be a sequence")
        if not all(isinstance(item, str) for item in self.records):
            raise TypeError("SPF records must contain strings")
        if self.query_state != "available" and self.records:
            raise ValueError("Only available evidence may contain records")
        if len(self.records) > _MAX_TXT_RECORDS:
            raise ValueError("Too many SPF records")
        object.__setattr__(self, "records", tuple(self.records))


def _normalize_domain(domain):
    """Accept only a bounded DNS hostname, never an IP literal."""
    if not isinstance(domain, str) or not domain:
        return None

    candidate = domain.rstrip(".")
    if not candidate or len(candidate) > 253:
        return None

    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass

    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    labels = normalized.split(".")
    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    if not labels or any(
        len(label) > 63 or not label_pattern.fullmatch(label)
        for label in labels
    ):
        return None

    if normalized == "localhost" or normalized.endswith(
        (".localhost", ".local", ".internal", ".home.arpa")
    ):
        return None

    return normalized


def collect_spf_evidence(domain, deadline=None):
    """Collect one bounded TXT answer; do not follow SPF mechanisms."""
    normalized_domain = _normalize_domain(domain)
    if normalized_domain is None:
        if isinstance(domain, str):
            try:
                ipaddress.ip_address(domain.rstrip("."))
                return SPFEvidence("not_applicable")
            except ValueError:
                pass
        return SPFEvidence("invalid_target")

    timeout = _DNS_TXT_TIMEOUT_SECONDS
    if deadline is not None:
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
        ):
            return SPFEvidence("invalid_target")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return SPFEvidence("timeout")
        timeout = min(timeout, remaining)

    if not _DNS_TXT_LOOKUP_SLOTS.acquire(blocking=False):
        return SPFEvidence("dns_capacity")

    try:
        resolver = dns.resolver.Resolver(configure=True)
        answer = resolver.resolve(
            normalized_domain + ".",
            "TXT",
            lifetime=timeout,
            search=False,
            raise_on_no_answer=False,
        )

        rrset = answer.rrset
        if rrset is None:
            return SPFEvidence("no_spf")

        if len(rrset) > _MAX_TXT_RECORDS:
            return SPFEvidence("oversized_response")

        spf_records = []

        for item in rrset:
            chunks = getattr(item, "strings", None)
            if not isinstance(chunks, (tuple, list)):
                return SPFEvidence("dns_error")

            try:
                raw_value = b"".join(chunks)
            except (TypeError, ValueError):
                return SPFEvidence("dns_error")

            if len(raw_value) > _MAX_TXT_RECORD_BYTES:
                return SPFEvidence("oversized_response")

            value = raw_value.decode("utf-8", errors="replace")

            # Other TXT uses (verification tokens, etc.) are not SPF.
            if (
                value[:6].lower() == "v=spf1"
                and (len(value) == 6 or value[6].isspace())
            ):
                spf_records.append(value)

        if not spf_records:
            return SPFEvidence("no_spf")

        return SPFEvidence("available", tuple(spf_records))

    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return SPFEvidence("timeout")
    except dns.resolver.NoAnswer:
        return SPFEvidence("no_spf")
    except dns.exception.DNSException:
        return SPFEvidence("dns_error")
    except Exception:
        # Do not expose resolver details or raw exception text.
        return SPFEvidence("dns_error")
    finally:
        _DNS_TXT_LOOKUP_SLOTS.release()


def _valid_domain_spec(value):
    """Conservatively validate a non-empty SPF domain-spec token."""
    return (
        bool(value)
        and len(value) <= 253
        and not any(ord(char) <= 32 or ord(char) == 127 for char in value)
    )


def _valid_cidr_length(value, maximum):
    """Validate RFC-style CIDR decimal notation and its range."""
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        return False
    return int(value) <= maximum


def _valid_dual_cidr(value):
    """Validate optional IPv4 and IPv6 CIDR lengths for a/mx."""
    if value == "":
        return True

    match = re.fullmatch(
        r"(?:/(0|[1-9][0-9]?))?(?://(0|[1-9][0-9]{0,2}))?",
        value,
    )
    if match is None:
        return False

    ipv4_length, ipv6_length = match.groups()

    if ipv4_length is None and ipv6_length is None:
        return False

    if ipv4_length is not None and int(ipv4_length) > 32:
        return False

    if ipv6_length is not None and int(ipv6_length) > 128:
        return False

    return True


def _valid_a_mx_suffix(suffix):
    """Validate optional domain-spec and dual CIDR for a/mx."""
    if not suffix:
        return True

    if suffix.startswith(":"):
        value = suffix[1:]
        if "/" not in value:
            return _valid_domain_spec(value)

        domain_spec, _separator, remainder = value.partition("/")
        cidr = "/" + remainder

        return (
            _valid_domain_spec(domain_spec)
            and _valid_dual_cidr(cidr)
        )

    return suffix.startswith("/") and _valid_dual_cidr(suffix)


def _parse_spf_record(record):
    """Validate supported SPF syntax without DNS expansion."""
    if (
        not isinstance(record, str)
        or not record
        or len(record) > _MAX_TXT_RECORD_BYTES
        or any(char in record for char in ("\r", "\n", "\x00"))
    ):
        return False, None

    if (
        record[:6].lower() != "v=spf1"
        or (len(record) > 6 and not record[6].isspace())
    ):
        return False, None

    tokens = record.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        return False, None

    all_qualifier = None
    seen_known_modifiers = set()

    for token in tokens[1:]:
        if "=" in token and token[0] not in "+-~?":
            name, _separator, value = token.partition("=")

            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", name):
                return False, None

            normalized_name = name.lower()

            if normalized_name in ("redirect", "exp"):
                if normalized_name in seen_known_modifiers:
                    return False, None

                if not _valid_domain_spec(value):
                    return False, None

                seen_known_modifiers.add(normalized_name)

            # Unknown modifiers are ignored, including repeated ones.
            continue

        qualifier = "+"
        term = token

        if term[0] in "+-~?":
            qualifier = term[0]
            term = term[1:]

        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)(.*)", term)
        if match is None:
            return False, None

        mechanism = match.group(1).lower()
        suffix = match.group(2)

        if mechanism == "all":
            if suffix:
                return False, None
            if all_qualifier is None:
                all_qualifier = qualifier
            continue

        if mechanism in ("ip4", "ip6"):
            if not suffix.startswith(":"):
                return False, None

            network_value = suffix[1:]
            address, separator, prefix = network_value.partition("/")

            if separator:
                maximum = 32 if mechanism == "ip4" else 128
                if not _valid_cidr_length(prefix, maximum):
                    return False, None

            try:
                network = ipaddress.ip_network(network_value, strict=False)
            except ValueError:
                return False, None

            if mechanism == "ip4" and network.version != 4:
                return False, None

            if mechanism == "ip6" and network.version != 6:
                return False, None

            continue

        if mechanism in ("include", "exists"):
            if not suffix.startswith(":"):
                return False, None
            if not _valid_domain_spec(suffix[1:]):
                return False, None
            continue

        if mechanism in ("a", "mx"):
            if not _valid_a_mx_suffix(suffix):
                return False, None
            continue

        if mechanism == "ptr":
            if suffix and (
                not suffix.startswith(":")
                or not _valid_domain_spec(suffix[1:])
            ):
                return False, None
            continue

        return False, None

    return True, all_qualifier


class SPFCheckEvaluator:
    """Interpret collected SPF evidence without performing network access."""

    def __init__(self, definition: CheckDefinition):
        if not isinstance(definition, CheckDefinition):
            raise TypeError("definition must be a CheckDefinition")
        if definition.check_id != "dns_spf":
            raise ValueError("SPF evaluator requires the dns_spf definition")
        self.definition = definition

    def _result(
        self,
        status,
        severity,
        confidence,
        evidence,
        explanation,
        recommendation,
        limitations=(),
    ):
        return CheckResult(
            check_id=self.definition.check_id,
            title="سياسة SPF لنطاق البريد الإلكتروني",
            status=status,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            explanation=explanation,
            recommendation=recommendation,
            limitations=tuple(limitations),
        )

    def evaluate(self, evidence: SPFEvidence):
        if not isinstance(evidence, SPFEvidence):
            raise TypeError("evidence must be SPFEvidence")

        state = evidence.query_state

        if state == "not_applicable":
            return self._result(
                "skipped", "info", "high",
                "الهدف عنوان IP وليس اسم نطاق.",
                "فحص SPF مخصص لأسماء النطاقات وليس لعناوين IP المباشرة.",
                "استخدمي اسم النطاق عند الحاجة إلى فحص سياسة SPF.",
            )

        if state == "invalid_target":
            return self._result(
                "not_verified", "info", "low",
                "لم يتوفر اسم نطاق صالح لاستعلام SPF.",
                "لم يُنفذ استعلام DNS لأن اسم النطاق غير صالح أو غير متاح.",
                "تحققي من اسم النطاق ثم أعيدي الفحص.",
            )

        if state == "dns_capacity":
            return self._result(
                "skipped", "info", "low",
                "لم تتوفر سعة تنفيذ لاستعلام SPF.",
                "تم تجاوز استعلام SPF بدلاً من الانتظار خارج حدود السعة.",
                "أعيدي الفحص لاحقاً.",
            )

        if state in ("timeout", "dns_error"):
            message = (
                "انتهت مهلة استعلام TXT."
                if state == "timeout"
                else "تعذر الحصول على إجابة DNS قابلة للتقييم."
            )
            return self._result(
                "error", "info", "high",
                message,
                "لم تتوفر أدلة DNS كافية لتحديد سياسة SPF.",
                "تحققي من خدمة DNS ثم أعيدي الفحص.",
            )

        if state == "oversized_response":
            return self._result(
                "not_verified", "info", "low",
                "تجاوزت إجابة TXT حدود القراءة المسموح بها.",
                "لم تُحلل إجابة DNS كبيرة أو تتجاوز الحدود المحددة.",
                "راجعي حجم سجلات TXT وإعدادات النطاق.",
            )

        if state == "no_spf":
            return self._result(
                "warning", "low", "high",
                "لم يُعثر على سجل TXT يبدأ بإصدار SPF1.",
                "لم يتم العثور على سجل SPF في إجابة TXT المتاحة.",
                "انشري سجل SPF مناسباً لخدمات إرسال البريد المعتمدة لديك.",
            )

        if len(evidence.records) > 1:
            return self._result(
                "warning", "high", "high",
                "عُثر على أكثر من سجل SPF مستقل للنطاق.",
                "وجود سجلات SPF متعددة يجعل اختيار سياسة واحدة غير صالح وفق قواعد SPF.",
                "ادمجي سياسة الإرسال في سجل SPF واحد واحذفي السجلات المتعارضة.",
            )

        valid, all_qualifier = _parse_spf_record(evidence.records[0])

        if not valid:
            return self._result(
                "warning", "medium", "high",
                "عُثر على سجل SPF لكن بنيته تحتوي على صيغة غير مدعومة أو غير صالحة.",
                "تعذر اعتماد السجل كسياسة SPF سليمة وفق التحليل النحوي المحدود.",
                "راجعي صيغة سجل SPF وآلياتها ومعدّلاتها وفق RFC 7208.",
            )

        limitations = (
            "هذا الفحص يحلل سجل SPF المنشور فقط ولا يختبر رسالة بريد فعلية.",
            "لم يتم توسيع include أو redirect ولم تُنفذ استعلامات SPF متداخلة.",
            "لا يثبت هذا التحليل وحده صحة جميع مصادر إرسال البريد أو نتيجة SPF الفعلية.",
        )

        if all_qualifier == "-":
            return self._result(
                "passed", "info", "high",
                "يتضمن السجل سياسة -all الصريحة.",
                "تم العثور على آلية all بمعامل Fail الصريح. هذا مؤشر على سياسة أكثر تقييداً، وليس تحققاً كاملاً من مصادر الإرسال.",
                "حافظي على تحديث مصادر الإرسال المصرح بها قبل الإبقاء على سياسة الرفض.",
                limitations,
            )

        if all_qualifier == "~":
            return self._result(
                "warning", "medium", "high",
                "تنتهي السياسة بآلية ~all (SoftFail).",
                "تسمح السياسة بوضع علامة SoftFail على المصادر غير المطابقة بدلاً من إعلان الرفض الصريح.",
                "راجعي مصادر الإرسال، ثم قيّمي الانتقال إلى -all عند التأكد من اكتمالها.",
                limitations,
            )

        if all_qualifier == "?":
            return self._result(
                "warning", "low", "high",
                "تنتهي السياسة بآلية ?all (Neutral).",
                "لا تقدم السياسة حكماً تقييدياً واضحاً للمصادر غير المطابقة.",
                "راجعي سياسة الإرسال وحددي المعامل النهائي الملائم.",
                limitations,
            )

        if all_qualifier == "+":
            return self._result(
                "warning", "high", "high",
                "تتضمن السياسة +all أو all دون معامل.",
                "تسمح هذه الآلية بمطابقة جميع المصادر، مما يجعل سياسة SPF واسعة جداً.",
                "راجعي سجل SPF وأزيلي السماح العام بعد التحقق من مصادر الإرسال المعتمدة.",
                limitations,
            )

        return self._result(
            "warning", "low", "high",
            "لم يُعثر على آلية all صريحة في سجل SPF.",
            "السجل موجود، لكن التحليل لم يجد سياسة all نهائية واضحة.",
            "راجعي نهاية السجل وحددي سياسة صريحة تتناسب مع مصادر الإرسال.",
            limitations,
        )


def evaluate_spf_domain(domain, deadline=None):
    """Collect and evaluate one SPF record for an already validated target."""
    from .registry import create_default_registry

    evidence = collect_spf_evidence(domain, deadline=deadline)
    definition = create_default_registry().get("dns_spf")
    return SPFCheckEvaluator(definition).evaluate(evidence)

# ---------------------------------------------------------------------------
# DMARC: bounded TXT collection and passive policy analysis
# ---------------------------------------------------------------------------

_DMARC_QUERY_STATES = frozenset({
    "available",
    "no_record",
    "timeout",
    "dns_error",
    "dns_capacity",
    "invalid_target",
    "not_applicable",
    "oversized_response",
})


@dataclass(frozen=True)
class DMARCEvidence:
    """Bounded DMARC observations; raw DNS data is hidden from repr."""

    query_state: str
    records: tuple[str, ...] = field(default_factory=tuple, repr=False)

    def __post_init__(self):
        if self.query_state not in _DMARC_QUERY_STATES:
            raise ValueError("Unsupported DMARC query state")

        if not isinstance(self.records, (tuple, list)):
            raise TypeError("DMARC records must be a sequence")

        if not all(isinstance(item, str) for item in self.records):
            raise TypeError("DMARC records must contain strings")

        if self.query_state == "available" and not self.records:
            raise ValueError("Available DMARC evidence requires records")

        if self.query_state != "available" and self.records:
            raise ValueError("Only available evidence may contain records")

        if len(self.records) > _MAX_TXT_RECORDS:
            raise ValueError("Too many DMARC records")

        if any(
            len(item.encode("utf-8")) > _MAX_TXT_RECORD_BYTES
            for item in self.records
        ):
            raise ValueError("DMARC record exceeds the configured limit")

        object.__setattr__(self, "records", tuple(self.records))


def collect_dmarc_evidence(domain, deadline=None):
    """Collect only DMARC TXT records from the validated domain's _dmarc name."""

    normalized_domain = _normalize_domain(domain)

    if normalized_domain is None:
        if isinstance(domain, str):
            try:
                ipaddress.ip_address(domain.rstrip("."))
                return DMARCEvidence("not_applicable")
            except ValueError:
                pass

        return DMARCEvidence("invalid_target")

    timeout = _DNS_TXT_TIMEOUT_SECONDS

    if deadline is not None:
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
        ):
            return DMARCEvidence("invalid_target")

        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return DMARCEvidence("timeout")

        timeout = min(timeout, remaining)

    # Never wait outside the shared bounded DNS capacity.
    if not _DNS_TXT_LOOKUP_SLOTS.acquire(blocking=False):
        return DMARCEvidence("dns_capacity")

    try:
        resolver = dns.resolver.Resolver(configure=True)

        answer = resolver.resolve(
            "_dmarc." + normalized_domain + ".",
            "TXT",
            lifetime=timeout,
            search=False,
            raise_on_no_answer=False,
        )

        rrset = answer.rrset

        if rrset is None:
            return DMARCEvidence("no_record")

        if len(rrset) > _MAX_TXT_RECORDS:
            return DMARCEvidence("oversized_response")

        dmarc_records = []

        for item in rrset:
            chunks = getattr(item, "strings", None)

            if not isinstance(chunks, (tuple, list)):
                return DMARCEvidence("dns_error")

            try:
                raw_value = b"".join(chunks)
            except (TypeError, ValueError):
                return DMARCEvidence("dns_error")

            if len(raw_value) > _MAX_TXT_RECORD_BYTES:
                return DMARCEvidence("oversized_response")

            value = raw_value.decode("utf-8", errors="replace").strip()

            # Ignore unrelated TXT records; do not expose their contents.
            if re.match(
                r"^v[ \t]*=[ \t]*DMARC1(?:[ \t]*;|[ \t]*$)",
                value,
            ):
                dmarc_records.append(value)

        if not dmarc_records:
            return DMARCEvidence("no_record")

        return DMARCEvidence("available", tuple(dmarc_records))

    except (
        dns.resolver.LifetimeTimeout,
        dns.exception.Timeout,
    ):
        return DMARCEvidence("timeout")

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
    ):
        return DMARCEvidence("no_record")

    except dns.exception.DNSException:
        return DMARCEvidence("dns_error")

    except Exception:
        # Do not expose resolver details or raw exception text.
        return DMARCEvidence("dns_error")

    finally:
        _DNS_TXT_LOOKUP_SLOTS.release()


def _valid_dmarc_uri_list(value):
    """Basic bounded syntax validation for comma-separated DMARC URIs."""

    if not isinstance(value, str) or not value:
        return False

    for entry in value.split(","):
        uri = entry.strip()

        if (
            not uri
            or any(ord(char) < 33 or ord(char) > 126 for char in uri)
            or not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:[^,\s]+$", uri)
        ):
            return False

    return True


def _parse_dmarc_record(record):
    """Parse DMARC Policy Records using the RFC 9989 tag definitions."""

    if (
        not isinstance(record, str)
        or not record
        or len(record.encode("utf-8")) > _MAX_TXT_RECORD_BYTES
        or any(ord(char) < 32 or ord(char) > 126 for char in record)
    ):
        return False, None

    segments = record.split(";")

    # The version tag must be first, with case-sensitive value DMARC1.
    if not segments or not re.fullmatch(
        r"v[ \t]*=[ \t]*DMARC1",
        segments[0].strip(),
    ):
        return False, None

    known_tags = {
        "adkim", "aspf", "fo", "np", "p",
        "psd", "rua", "ruf", "sp", "t",
    }

    tags = {}

    for segment in segments[1:]:
        segment = segment.strip()

        # A trailing separator is allowed.
        if not segment:
            continue

        if "=" not in segment:
            return False, None

        name, _separator, value = segment.partition("=")
        name = name.strip()
        value = value.strip()

        if not re.fullmatch(r"[A-Za-z]+", name):
            return False, None

        if not value:
            return False, None

        name = name.lower()

        # The version tag is only valid in the first position.
        if name == "v":
            return False, None

        # Only registered tags are interpreted. Unknown tags are ignored.
        if name not in known_tags:
            continue

        if name in tags:
            return False, None

        tags[name] = value

    # A missing p tag defaults to none under RFC 9989.
    policy = tags.get("p", "none")

    if policy not in ("none", "quarantine", "reject"):
        return False, None

    for name in ("sp", "np"):
        if name in tags and tags[name] not in (
            "none", "quarantine", "reject"
        ):
            return False, None

    adkim = tags.get("adkim", "r")
    aspf = tags.get("aspf", "r")

    if adkim not in ("r", "s") or aspf not in ("r", "s"):
        return False, None

    psd = tags.get("psd", "u")
    if psd not in ("y", "n", "u"):
        return False, None

    test_mode = tags.get("t", "n")
    if test_mode not in ("y", "n"):
        return False, None

    for name in ("rua", "ruf"):
        if name in tags and not _valid_dmarc_uri_list(tags[name]):
            return False, None

    # fo is ignored unless ruf is also present.
    if "ruf" in tags and "fo" in tags:
        fo_values = tags["fo"].split(":")
        allowed = {"0", "1", "d", "s"}

        if (
            not fo_values
            or any(value not in allowed for value in fo_values)
            or len(fo_values) != len(set(fo_values))
            or ("0" in fo_values and "1" in fo_values)
        ):
            return False, None

    return True, {
        "policy": policy,
        "subdomain_policy": tags.get("sp"),
        "non_existent_policy": tags.get("np"),
        "adkim": adkim,
        "aspf": aspf,
        "psd": psd,
        "test_mode": test_mode,
        "aggregate_reporting": bool(tags.get("rua")),
        "forensic_reporting": bool(tags.get("ruf")),
    }


class DMARCCheckEvaluator:
    """Interpret DMARC evidence without performing network access."""

    def __init__(self, definition: CheckDefinition):
        if not isinstance(definition, CheckDefinition):
            raise TypeError("definition must be a CheckDefinition")
        if definition.check_id != "dns_dmarc":
            raise ValueError("DMARC evaluator requires dns_dmarc")
        self.definition = definition

    def _result(
        self, status, severity, confidence,
        evidence, explanation, recommendation, limitations=(),
    ):
        return CheckResult(
            check_id=self.definition.check_id,
            title='DMARC policy for the queried domain',
            status=status,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            explanation=explanation,
            recommendation=recommendation,
            limitations=tuple(limitations),
        )

    @staticmethod
    def _effective_policy(policy, test_mode):
        # In test mode, RFC 9989 specifies one level less restrictive.
        if test_mode != "y":
            return policy
        if policy == "reject":
            return "quarantine"
        if policy == "quarantine":
            return "none"
        return "none"

    def evaluate(self, evidence: DMARCEvidence):
        if not isinstance(evidence, DMARCEvidence):
            raise TypeError("evidence must be DMARCEvidence")

        state = evidence.query_state

        if state == "not_applicable":
            return self._result(
                "skipped", "info", "high",
                'An IP target has no applicable DMARC domain policy.',
                'DMARC applies to domain names.',
                'Use an authorized domain name for this check.',
            )

        if state == "invalid_target":
            return self._result(
                "not_verified", "info", "low",
                'No eligible domain was available for DMARC.',
                'No DNS request was made for an invalid domain.',
                'Review the authorized target hostname.',
            )

        if state == "dns_capacity":
            return self._result(
                "skipped", "info", "low",
                'DMARC DNS capacity was unavailable.',
                'The bounded DNS concurrency limit prevented collection.',
                'Retry when capacity is available.',
            )

        if state in ("timeout", "dns_error"):
            message = (
                'The DMARC query timed out.'
                if state == "timeout"
                else 'The DMARC resolver operation failed.'
            )
            return self._result(
                "error", "info", "low",
                message,
                'No usable DNS evidence supports a DMARC policy conclusion.',
                'Review DNS availability and retry.',
            )

        if state == "oversized_response":
            return self._result(
                "not_verified", "info", "low",
                'The TXT response exceeded the supported evidence bounds.',
                'Oversized DNS evidence was not evaluated.',
                'Review the published TXT record size.',
            )

        limitations = (
            'Only the exact queried domain DMARC name was checked.',
            'No DNS Tree Walk, organizational-domain inference or PSD policy discovery was performed.',
            'No mail was sent and no receiving-server behavior was tested.',
            'SPF/DKIM alignment was not tested against a real message.',
            'Reporting URIs were not contacted or exposed.',
        )

        if state == "no_record":
            return self._result(
                "not_verified", "info", "low",
                'No direct DMARC policy record was observed.',
                'An inherited organizational or PSD policy may exist; this check does not perform DNS Tree Walk.',
                'Review direct and inherited DMARC policies with the mail administrator.',
                limitations,
            )

        if len(evidence.records) > 1:
            return self._result(
                "warning", "high", "high",
                'Multiple DMARC policy records were observed at the queried name.',
                'Multiple policy records make direct policy interpretation ambiguous.',
                'Publish one unambiguous policy record at this name.',
                limitations,
            )

        valid, parsed = _parse_dmarc_record(evidence.records[0])

        if not valid:
            return self._result(
                "warning", "medium", "high",
                'The observed DMARC record has unsupported or invalid policy syntax.',
                'The parser could not establish a valid supported policy record.',
                'Review the published DMARC record syntax and supported tags.',
                limitations,
            )

        policy = parsed["policy"]
        sp = parsed["subdomain_policy"]
        np = parsed["non_existent_policy"]
        test_mode = parsed["test_mode"]

        # The direct policy record applies p to the queried domain.
        # sp and np concern subdomains and are retained as evidence only.
        effective_p = self._effective_policy(policy, test_mode)

        evidence_summary = (
            f"p: {policy} (effective: {effective_p}); "
            f"sp: {sp or 'inherits p'}; np: {np or 'inherits sp/p'}; "
            f"t: {test_mode}; psd: {parsed['psd']}; "
            f"aspf: {parsed['aspf']}; adkim: {parsed['adkim']}; "
            f"aggregate reporting: {'present' if parsed['aggregate_reporting'] else 'not observed'}."
        )

        if effective_p == "none":
            return self._result(
                "warning", "medium", "high",
                evidence_summary,
                'The effective observed policy does not request message quarantine or rejection; this is not proof of successful spoofing.',
                'Review authorized sending sources and alignment before changing enforcement.',
                limitations,
            )

        return self._result(
            "passed", "info", "high",
            evidence_summary,
            'A direct DMARC record requests an enforcement policy; message authentication and receiving-server behavior remain unverified.',
            'Maintain the policy and verify authorized SPF/DKIM alignment with the mail administrator.',
            limitations,
        )


def evaluate_dmarc_domain(domain, deadline=None):
    """Collect and evaluate DMARC for an already validated target hostname."""

    from .registry import create_default_registry

    evidence = collect_dmarc_evidence(domain, deadline=deadline)
    definition = create_default_registry().get("dns_dmarc")
    return DMARCCheckEvaluator(definition).evaluate(evidence)
