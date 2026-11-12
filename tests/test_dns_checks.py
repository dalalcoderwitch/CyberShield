from types import SimpleNamespace

import dns.exception
import pytest

from security_scanner.checks import create_default_registry
from security_scanner.checks.dns_checks import (
    SPFEvidence,
    SPFCheckEvaluator,
    _normalize_domain,
    _parse_spf_record,
    collect_spf_evidence,
)


def make_txt(*chunks):
    return SimpleNamespace(strings=tuple(chunks))


class FakeResolver:
    def __init__(self, answer=None, error=None):
        self.answer = answer
        self.error = error
        self.calls = []

    def resolve(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return self.answer


def install_resolver(monkeypatch, fake_resolver):
    monkeypatch.setattr(
        "security_scanner.checks.dns_checks.dns.resolver.Resolver",
        lambda configure=True: fake_resolver,
    )


@pytest.fixture
def evaluator():
    definition = create_default_registry().get("dns_spf")
    return SPFCheckEvaluator(definition)


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", "example.com"),
        ("Sub.Example.com.", "sub.example.com"),
        ("localhost", None),
        ("127.0.0.1", None),
        ("bad..example.com", None),
        ("", None),
        ("a" * 64 + ".example.com", None),
    ],
)
def test_normalize_domain(domain, expected):
    assert _normalize_domain(domain) == expected


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1 ip4:192.0.2.0/24 -all", (True, "-")),
        ("v=spf1 include:_spf.example.com ~all", (True, "~")),
        ("v=spf1 +all", (True, "+")),
        ("v=spf1 -all", (True, "-")),
        ("v=spf1 ?all", (True, "?")),
        ("v=spf1", (True, None)),
        ("v=spf1 ip4:999.0.0.1 -all", (False, None)),
        ("v=spf1 unknownmechanism -all", (False, None)),
        ("v=spf1 ip6:192.0.2.1 -all", (False, None)),
        ("not-spf-record", (False, None)),
    ],
)
def test_parse_spf_record(record, expected):
    assert _parse_spf_record(record) == expected


def test_collect_spf_joins_txt_chunks_without_adding_spaces(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[
                make_txt(b"google-site-verification=example"),
                make_txt(
                    b"v=spf1 ip4:192.0.2.0/24",
                    b" -all",
                ),
            ]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = collect_spf_evidence("Example.com")

    assert evidence.query_state == "available"
    assert evidence.records == (
        "v=spf1 ip4:192.0.2.0/24 -all",
    )
    assert fake.calls[0][0] == ("example.com.", "TXT")
    assert fake.calls[0][1]["search"] is False
    assert fake.calls[0][1]["raise_on_no_answer"] is False
    assert fake.calls[0][1]["lifetime"] <= 2.0
    assert "v=spf1" not in repr(evidence)


def test_collect_spf_detects_multiple_independent_records(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[
                make_txt(b"v=spf1 -all"),
                make_txt(b"v=spf1 ~all"),
            ]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = collect_spf_evidence("example.com")

    assert evidence.query_state == "available"
    assert len(evidence.records) == 2


def test_collect_spf_ignores_unrelated_txt_records(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[
                make_txt(b"google-site-verification=abc"),
                make_txt(b"v=DKIM1; k=rsa; p=abc"),
            ]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = collect_spf_evidence("example.com")

    assert evidence.query_state == "no_spf"
    assert evidence.records == ()


def test_collect_spf_handles_empty_answer(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(rrset=None)
    )
    install_resolver(monkeypatch, fake)

    evidence = collect_spf_evidence("example.com")

    assert evidence.query_state == "no_spf"


def test_collect_spf_handles_dns_timeout(monkeypatch):
    fake = FakeResolver(error=dns.exception.Timeout())
    install_resolver(monkeypatch, fake)

    evidence = collect_spf_evidence("example.com")

    assert evidence.query_state == "timeout"


def test_collect_spf_handles_dns_failure(monkeypatch):
    fake = FakeResolver(
        error=dns.exception.DNSException("synthetic DNS failure")
    )
    install_resolver(monkeypatch, fake)

    evidence = collect_spf_evidence("example.com")

    assert evidence.query_state == "dns_error"


def test_collect_spf_rejects_invalid_domain_without_query(monkeypatch):
    def unexpected_resolver(**kwargs):
        raise AssertionError("DNS must not be queried")

    monkeypatch.setattr(
        "security_scanner.checks.dns_checks.dns.resolver.Resolver",
        unexpected_resolver,
    )

    evidence = collect_spf_evidence("localhost")

    assert evidence.query_state == "invalid_target"


def test_collect_spf_marks_ip_as_not_applicable():
    evidence = collect_spf_evidence("192.0.2.10")

    assert evidence.query_state == "not_applicable"


def test_collect_spf_respects_expired_deadline(monkeypatch):
    monkeypatch.setattr(
        "security_scanner.checks.dns_checks.time.monotonic",
        lambda: 100.0,
    )

    evidence = collect_spf_evidence(
        "example.com",
        deadline=100.0,
    )

    assert evidence.query_state == "timeout"


def test_collect_spf_skips_when_capacity_is_exhausted(monkeypatch):
    class BusySlots:
        def acquire(self, blocking=False):
            return False

    monkeypatch.setattr(
        "security_scanner.checks.dns_checks._DNS_TXT_LOOKUP_SLOTS",
        BusySlots(),
    )

    evidence = collect_spf_evidence("example.com")

    assert evidence.query_state == "dns_capacity"


def test_collect_spf_rejects_too_many_txt_records(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[make_txt(b"ordinary-record")] * 101
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = collect_spf_evidence("example.com")

    assert evidence.query_state == "oversized_response"


def test_collect_spf_rejects_oversized_txt_value(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[make_txt(b"x" * 4097)]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = collect_spf_evidence("example.com")

    assert evidence.query_state == "oversized_response"


@pytest.mark.parametrize(
    ("evidence", "expected_status", "expected_severity"),
    [
        (SPFEvidence("no_spf"), "warning", "low"),
        (SPFEvidence("timeout"), "error", "info"),
        (SPFEvidence("dns_error"), "error", "info"),
        (SPFEvidence("dns_capacity"), "skipped", "info"),
        (SPFEvidence("invalid_target"), "not_verified", "info"),
        (SPFEvidence("not_applicable"), "skipped", "info"),
        (
            SPFEvidence("available", ("v=spf1 -all",)),
            "passed",
            "info",
        ),
        (
            SPFEvidence("available", ("v=spf1 ~all",)),
            "warning",
            "medium",
        ),
        (
            SPFEvidence("available", ("v=spf1 +all",)),
            "warning",
            "high",
        ),
        (
            SPFEvidence(
                "available",
                ("v=spf1 -all", "v=spf1 ~all"),
            ),
            "warning",
            "high",
        ),
        (
            SPFEvidence(
                "available",
                ("v=spf1 ip4:999.0.0.1 -all",),
            ),
            "warning",
            "medium",
        ),
        (
            SPFEvidence("available", ("v=spf1",)),
            "warning",
            "low",
        ),
    ],
)
def test_spf_evaluator_classifies_expected_results(
    evaluator,
    evidence,
    expected_status,
    expected_severity,
):
    result = evaluator.evaluate(evidence)

    assert result.check_id == "dns_spf"
    assert result.status == expected_status
    assert result.severity == expected_severity
    assert result.confidence in {"low", "medium", "high"}


def test_spf_evaluator_does_not_disclose_raw_record(evaluator):
    secret_record = "v=spf1 include=private-example-token -all"

    result = evaluator.evaluate(
        SPFEvidence("available", (secret_record,))
    )

    serialized = repr(result.to_dict())
    assert secret_record not in serialized
    assert "private-example-token" not in serialized


def test_spf_evaluator_rejects_wrong_evidence_type(evaluator):
    with pytest.raises(TypeError, match="SPFEvidence"):
        evaluator.evaluate(object())

@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 a/33 -all",
        "v=spf1 mx//129 -all",
        "v=spf1 a:mail.example.com/999 -all",
        "v=spf1 mx:mail.example.com/24//129 -all",
        "v=spf1 redirect=one.example redirect=two.example",
        "v=spf1 exp=one.example exp=two.example",
        "v=spf1 =bad -all",
        "v=spf1 bad!name=value -all",
    ],
)
def test_parse_rejects_invalid_cidr_and_modifier_syntax(record):
    assert _parse_spf_record(record) == (False, None)


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1 a/32 -all", (True, "-")),
        ("v=spf1 mx//128 -all", (True, "-")),
        ("v=spf1 a:mail.example.com/32//128 -all", (True, "-")),
        ("v=spf1 mx:mail.example.com//128 -all", (True, "-")),
        ("v=spf1 a -all", (True, "-")),
        ("v=spf1 ptr:example.com -all", (True, "-")),
        ("v=spf1 custom=value -all", (True, "-")),
    ],
)
def test_parse_accepts_valid_cidr_and_modifier_forms(record, expected):
    assert _parse_spf_record(record) == expected





def test_parser_ignores_repeated_unknown_modifiers():
    assert _parse_spf_record(
        "v=spf1 custom=one custom=two -all"
    ) == (True, "-")


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 redirect=one.example REDIRECT=two.example",
        "v=spf1 exp=one.example Exp=two.example",
    ],
)
def test_parser_rejects_repeated_known_modifiers(record):
    assert _parse_spf_record(record) == (False, None)


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 ip4:192.0.2.1/024 -all",
        "v=spf1 ip4:192.0.2.1/33 -all",
        "v=spf1 ip6:2001:db8::1/0128 -all",
        "v=spf1 ip6:2001:db8::1/129 -all",
        "v=spf1 a/033 -all",
        "v=spf1 mx//0128 -all",
        "v=spf1 a/33 -all",
        "v=spf1 mx//129 -all",
    ],
)
def test_parser_rejects_invalid_cidr_prefixes(record):
    assert _parse_spf_record(record) == (False, None)


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 ip4:192.0.2.1/0 -all",
        "v=spf1 ip4:192.0.2.1/32 -all",
        "v=spf1 ip6:2001:db8::1/128 -all",
        "v=spf1 a/0 -all",
        "v=spf1 mx//128 -all",
        "v=spf1 a/24//64 -all",
        "v=spf1 mx:mail.example.com/24//128 -all",
    ],
)
def test_parser_accepts_valid_cidr_boundaries(record):
    assert _parse_spf_record(record) == (True, "-")
