from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

import security_scanner.checks.dns_checks as dns_checks
from security_scanner.checks import create_default_registry


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


def install_resolver(monkeypatch, fake):
    monkeypatch.setattr(
        dns_checks.dns.resolver,
        "Resolver",
        lambda configure=True: fake,
    )


@pytest.fixture
def evaluator():
    definition = create_default_registry().get("dns_dmarc")
    return dns_checks.DMARCCheckEvaluator(definition)


# ---------------------------------------------------------------------------
# Evidence validation
# ---------------------------------------------------------------------------

def test_dmarc_evidence_hides_raw_records_from_repr():
    record = "v=DMARC1; p=reject"
    evidence = dns_checks.DMARCEvidence("available", (record,))

    assert record not in repr(evidence)


def test_dmarc_evidence_rejects_available_state_without_records():
    with pytest.raises(ValueError):
        dns_checks.DMARCEvidence("available")


def test_dmarc_evidence_rejects_records_for_non_available_state():
    with pytest.raises(ValueError):
        dns_checks.DMARCEvidence("no_record", ("v=DMARC1; p=reject",))


def test_dmarc_evidence_rejects_unsupported_state():
    with pytest.raises(ValueError):
        dns_checks.DMARCEvidence("unknown")


def test_dmarc_evidence_rejects_non_string_record():
    with pytest.raises(TypeError):
        dns_checks.DMARCEvidence("available", (123,))


def test_dmarc_evidence_rejects_oversized_record():
    with pytest.raises(ValueError):
        dns_checks.DMARCEvidence(
            "available",
            ("x" * (dns_checks._MAX_TXT_RECORD_BYTES + 1),),
        )


# ---------------------------------------------------------------------------
# DMARC record parsing: RFC 9989 behavior
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("record", "expected_valid", "expected_policy"),
    [
        ("v=DMARC1; p=reject", True, "reject"),
        ("v=DMARC1; p=quarantine", True, "quarantine"),
        ("v=DMARC1; p=none", True, "none"),
        ("v=DMARC1", True, "none"),
        ("v=DMARC1; rua=mailto:reports@example.com", True, "none"),
        ("v=DMARC1; p=reject;", True, "reject"),
        ("v = DMARC1 ; p = reject", True, "reject"),
        ("v=DMARC1; p=reject; xnew=ignored", True, "reject"),
        ("v=DMARC1; p=reject; pct=0", True, "reject"),
        ("v=DMARC1; p=reject; ri=86400", True, "reject"),
        ("v=DMARC1; p=reject; rf=afrf", True, "reject"),
        ("v=DMARC1; p=reject; psd=y", True, "reject"),
        ("v=DMARC1; p=reject; t=n", True, "reject"),
        ("v=DMARC1; p=reject; t=y", True, "reject"),
        (
            "v=DMARC1; p=reject; sp=quarantine; np=reject",
            True,
            "reject",
        ),
        ("v=DMARC1; p=reject; adkim=s; aspf=s", True, "reject"),
        (
            "v=DMARC1; p=reject; rua=mailto:reports@example.com",
            True,
            "reject",
        ),
        (
            "v=DMARC1; p=reject; ruf=mailto:fail@example.com; fo=1",
            True,
            "reject",
        ),
        ("v=dmarc1; p=reject", False, None),
        ("p=reject; v=DMARC1", False, None),
        ("v=DMARC1; p=invalid", False, None),
        ("v=DMARC1; p=reject; p=none", False, None),
        ("v=DMARC1; x-new=invalid", False, None),
        ("v=DMARC1; t=maybe", False, None),
        ("v=DMARC1; psd=maybe", False, None),
        ("v=DMARC1; sp=invalid", False, None),
        ("v=DMARC1; np=invalid", False, None),
        ("v=DMARC1; adkim=invalid", False, None),
        ("v=DMARC1; aspf=invalid", False, None),
        ("v=DMARC1; rua=not-a-uri", False, None),
        ("v=DMARC1; ruf=not-a-uri", False, None),
        ("v=DMARC1; p=reject; fo=z; ruf=mailto:a@example.com", False, None),
        ("", False, None),
        ("not a DMARC record", False, None),
    ],
)
def test_parse_dmarc_record(record, expected_valid, expected_policy):
    valid, parsed = dns_checks._parse_dmarc_record(record)

    assert valid is expected_valid

    policy = parsed["policy"] if parsed else None
    assert policy == expected_policy


def test_parse_dmarc_ignores_invalid_fo_when_ruf_is_absent():
    valid, parsed = dns_checks._parse_dmarc_record(
        "v=DMARC1; p=reject; fo=not-a-valid-value"
    )

    assert valid is True
    assert parsed["policy"] == "reject"


def test_parse_dmarc_rejects_duplicate_version_tag():
    valid, parsed = dns_checks._parse_dmarc_record(
        "v=DMARC1; p=reject; v=DMARC1"
    )

    assert valid is False
    assert parsed is None


def test_parse_dmarc_returns_defaults_for_optional_tags():
    valid, parsed = dns_checks._parse_dmarc_record(
        "v=DMARC1; p=reject"
    )

    assert valid is True
    assert parsed["adkim"] == "r"
    assert parsed["aspf"] == "r"
    assert parsed["psd"] == "u"
    assert parsed["test_mode"] == "n"
    assert parsed["subdomain_policy"] is None
    assert parsed["non_existent_policy"] is None


def test_parse_dmarc_never_returns_reporting_addresses():
    valid, parsed = dns_checks._parse_dmarc_record(
        "v=DMARC1; p=reject; rua=mailto:private@example.com"
    )

    assert valid is True
    assert "private@example.com" not in repr(parsed)
    assert parsed["aggregate_reporting"] is True


# ---------------------------------------------------------------------------
# Bounded DNS collection
# ---------------------------------------------------------------------------

def test_collect_dmarc_uses_validated_domain_and_exact_owner_name(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[
                make_txt(b"google-site-verification=abc"),
                make_txt(
                    b"v=DMARC1; p=",
                    b"reject; rua=mailto:reports@example.com",
                ),
            ]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence(
        "Sub.Example.com."
    )

    assert evidence.query_state == "available"
    assert evidence.records == (
        "v=DMARC1; p=reject; rua=mailto:reports@example.com",
    )

    args, kwargs = fake.calls[0]

    assert args == ("_dmarc.sub.example.com.", "TXT")
    assert kwargs["search"] is False
    assert kwargs["raise_on_no_answer"] is False
    assert kwargs["lifetime"] <= dns_checks._DNS_TXT_TIMEOUT_SECONDS
    assert "reports@example.com" not in repr(evidence)


def test_collect_dmarc_ignores_unrelated_txt_records(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[
                make_txt(b"google-site-verification=abc"),
                make_txt(b"v=spf1 -all"),
                make_txt(b"v=DKIM1; k=rsa; p=abc"),
            ]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "no_record"
    assert evidence.records == ()


def test_collect_dmarc_handles_empty_rrset(monkeypatch):
    fake = FakeResolver(answer=SimpleNamespace(rrset=None))
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "no_record"


def test_collect_dmarc_handles_dns_timeout(monkeypatch):
    fake = FakeResolver(error=dns.exception.Timeout())
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "timeout"


def test_collect_dmarc_handles_dns_failure(monkeypatch):
    fake = FakeResolver(
        error=dns.exception.DNSException("synthetic DNS failure")
    )
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "dns_error"
    assert "synthetic DNS failure" not in repr(evidence)


def test_collect_dmarc_handles_nxdomain(monkeypatch):
    fake = FakeResolver(error=dns.resolver.NXDOMAIN())
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "no_record"


def test_collect_dmarc_rejects_invalid_domain_without_query(monkeypatch):
    def unexpected_resolver(**kwargs):
        pytest.fail("DNS query attempted for invalid domain")

    monkeypatch.setattr(
        dns_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dns_checks.collect_dmarc_evidence("bad..example.com")

    assert evidence.query_state == "invalid_target"


def test_collect_dmarc_marks_ip_as_not_applicable(monkeypatch):
    def unexpected_resolver(**kwargs):
        pytest.fail("DNS query attempted for IP address")

    monkeypatch.setattr(
        dns_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dns_checks.collect_dmarc_evidence("192.0.2.1")

    assert evidence.query_state == "not_applicable"


def test_collect_dmarc_rejects_expired_deadline_without_query(monkeypatch):
    monkeypatch.setattr(
        dns_checks.time,
        "monotonic",
        lambda: 100.0,
    )

    def unexpected_resolver(**kwargs):
        pytest.fail("DNS query attempted after deadline")

    monkeypatch.setattr(
        dns_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dns_checks.collect_dmarc_evidence(
        "example.com",
        deadline=99.0,
    )

    assert evidence.query_state == "timeout"


def test_collect_dmarc_rejects_invalid_deadline_without_query(monkeypatch):
    def unexpected_resolver(**kwargs):
        pytest.fail("DNS query attempted with invalid deadline")

    monkeypatch.setattr(
        dns_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dns_checks.collect_dmarc_evidence(
        "example.com",
        deadline=True,
    )

    assert evidence.query_state == "invalid_target"


def test_collect_dmarc_respects_concurrency_capacity(monkeypatch):
    class NoSlots:
        def acquire(self, blocking=False):
            return False

        def release(self):
            pytest.fail("Semaphore released without being acquired")

    monkeypatch.setattr(
        dns_checks,
        "_DNS_TXT_LOOKUP_SLOTS",
        NoSlots(),
    )

    def unexpected_resolver(**kwargs):
        pytest.fail("Resolver created without DNS capacity")

    monkeypatch.setattr(
        dns_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "dns_capacity"


def test_collect_dmarc_releases_capacity_after_resolver_failure(monkeypatch):
    class TrackingSlot:
        def __init__(self):
            self.acquires = 0
            self.releases = 0

        def acquire(self, blocking=False):
            self.acquires += 1
            return True

        def release(self):
            self.releases += 1

    slot = TrackingSlot()

    monkeypatch.setattr(
        dns_checks,
        "_DNS_TXT_LOOKUP_SLOTS",
        slot,
    )

    fake = FakeResolver(
        error=dns.exception.DNSException("synthetic failure")
    )
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "dns_error"
    assert slot.acquires == 1
    assert slot.releases == 1


def test_collect_dmarc_rejects_too_many_txt_records(monkeypatch):
    records = [
        make_txt(b"unrelated=" + str(index).encode())
        for index in range(dns_checks._MAX_TXT_RECORDS + 1)
    ]

    fake = FakeResolver(
        answer=SimpleNamespace(rrset=records)
    )
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "oversized_response"


def test_collect_dmarc_rejects_oversized_txt_record(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[
                make_txt(
                    b"v=DMARC1; p=reject; "
                    + b"x" * dns_checks._MAX_TXT_RECORD_BYTES
                )
            ]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "oversized_response"


def test_collect_dmarc_rejects_non_byte_txt_chunks(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[
                SimpleNamespace(strings=("not-bytes",))
            ]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "dns_error"


def test_collect_dmarc_does_not_match_lowercase_version(monkeypatch):
    fake = FakeResolver(
        answer=SimpleNamespace(
            rrset=[make_txt(b"v=dmarc1; p=reject")]
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = dns_checks.collect_dmarc_evidence("example.com")

    assert evidence.query_state == "no_record"


# ---------------------------------------------------------------------------
# Evaluator behavior
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("state", "expected_status"),
    [
        ("not_applicable", "skipped"),
        ("invalid_target", "not_verified"),
        ("dns_capacity", "skipped"),
        ("timeout", "error"),
        ("dns_error", "error"),
        ("oversized_response", "not_verified"),
        ("no_record", "not_verified"),
    ],
)
def test_dmarc_evaluator_maps_collection_states(
    evaluator, state, expected_status
):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(state)
    )

    assert result.status == expected_status
    assert result.check_id == "dns_dmarc"


def test_dmarc_evaluator_warns_for_monitoring_policy(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            ("v=DMARC1; p=none",),
        )
    )

    assert result.status == "warning"
    assert result.severity == "medium"


def test_dmarc_evaluator_passes_reject_policy(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            ("v=DMARC1; p=reject",),
        )
    )

    assert result.status == "passed"


def test_dmarc_evaluator_passes_quarantine_policy(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            ("v=DMARC1; p=quarantine",),
        )
    )

    assert result.status == "passed"


def test_dmarc_evaluator_warns_for_test_mode_quarantine(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            ("v=DMARC1; p=quarantine; t=y",),
        )
    )

    assert result.status == "warning"


def test_dmarc_evaluator_keeps_reject_test_mode_restrictive(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            ("v=DMARC1; p=reject; t=y",),
        )
    )

    assert result.status == "passed"


def test_dmarc_evaluator_ignores_subdomain_policy_for_target(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            ("v=DMARC1; p=reject; sp=none",),
        )
    )

    assert result.status == "passed"


def test_dmarc_evaluator_ignores_nonexistent_policy_for_target(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            ("v=DMARC1; p=reject; np=none",),
        )
    )

    assert result.status == "passed"


def test_dmarc_evaluator_warns_for_multiple_records(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            (
                "v=DMARC1; p=reject",
                "v=DMARC1; p=none",
            ),
        )
    )

    assert result.status == "warning"
    assert result.severity == "high"


def test_dmarc_evaluator_warns_for_invalid_record(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            ("v=DMARC1; p=invalid",),
        )
    )

    assert result.status == "warning"


def test_dmarc_evaluator_does_not_leak_reporting_addresses(evaluator):
    result = evaluator.evaluate(
        dns_checks.DMARCEvidence(
            "available",
            (
                "v=DMARC1; p=reject; "
                "rua=mailto:private-report@example.com",
            ),
        )
    )

    rendered = str(result.to_dict())

    assert "private-report@example.com" not in rendered
    assert result.status == "passed"


def test_dmarc_evaluator_rejects_wrong_evidence_type(evaluator):
    with pytest.raises(TypeError):
        evaluator.evaluate("not evidence")
