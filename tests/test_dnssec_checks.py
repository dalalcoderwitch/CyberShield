from types import SimpleNamespace

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver
import pytest

import security_scanner.checks.dnssec_checks as dnssec_checks
from security_scanner.checks import create_default_registry


class FakeRRset:
    def __init__(self, rdtype, count, covers=None, name="example.com."):
        self.rdtype = rdtype
        self.covers = covers
        self.count = count
        self.name = name

    def __len__(self):
        return self.count


class FakeResolver:
    def __init__(
        self,
        answer=None,
        error=None,
        zone_name="example.com.",
        soa_answer=None,
    ):
        self.answer = answer
        self.error = error
        self.zone_name = zone_name
        self.soa_answer = soa_answer
        self.edns_calls = []
        self.resolve_calls = []

    def use_edns(self, **kwargs):
        self.edns_calls.append(kwargs)

    def resolve(self, *args, **kwargs):
        self.resolve_calls.append((args, kwargs))

        if self.error is not None:
            raise self.error

        if len(args) > 1 and str(args[1]).upper() == "SOA":
            if self.soa_answer is not None:
                return self.soa_answer

            soa_rrset = FakeRRset(
                dns.rdatatype.SOA,
                1,
                name=self.zone_name,
            )
            queried_name = str(args[0]).rstrip(".").lower()
            zone_name = self.zone_name.rstrip(".").lower()

            # At the zone apex, SOA is the answer.
            # For a descendant name, model the usual NODATA response:
            # the enclosing zone SOA appears in the authority section.
            if queried_name == zone_name:
                answer_rrset = soa_rrset
                authority = []
            else:
                answer_rrset = None
                authority = [soa_rrset]

            return SimpleNamespace(
                rrset=answer_rrset,
                response=SimpleNamespace(
                    flags=0,
                    answer=[],
                    authority=authority,
                ),
            )

        return self.answer


def make_answer(
    dnskey_count=2,
    rrsig_count=1,
    authenticated_data=True,
    zone_name="example.com.",
):
    dnskey_rrset = (
        FakeRRset(
            dns.rdatatype.DNSKEY,
            dnskey_count,
            name=zone_name,
        )
        if dnskey_count is not None
        else None
    )

    answer_rrsets = []
    if rrsig_count:
        answer_rrsets.append(
            FakeRRset(
                dns.rdatatype.RRSIG,
                rrsig_count,
                covers=dns.rdatatype.DNSKEY,
                name=zone_name,
            )
        )

    flags = dns.flags.AD if authenticated_data else 0

    return SimpleNamespace(
        rrset=dnskey_rrset,
        response=SimpleNamespace(
            flags=flags,
            answer=answer_rrsets,
        ),
    )


def install_resolver(monkeypatch, fake):
    monkeypatch.setattr(
        dnssec_checks.dns.resolver,
        "Resolver",
        lambda configure=True: fake,
    )


@pytest.fixture
def evaluator():
    definition = create_default_registry().get("dnssec")
    return dnssec_checks.DNSSECCheckEvaluator(definition)


# ---------------------------------------------------------------------------
# Evidence validation
# ---------------------------------------------------------------------------

def test_dnssec_evidence_contains_only_bounded_indicators():
    evidence = dnssec_checks.DNSSECEvidence(
        "available",
        dnskey_count=2,
        rrsig_count=1,
        authenticated_data=True,
    )

    assert evidence.dnskey_count == 2
    assert evidence.rrsig_count == 1
    assert evidence.authenticated_data is True
    assert "private-key-material" not in repr(evidence)


def test_dnssec_evidence_rejects_unknown_state():
    with pytest.raises(ValueError):
        dnssec_checks.DNSSECEvidence("unknown")


def test_dnssec_evidence_requires_dnskey_for_available_state():
    with pytest.raises(ValueError):
        dnssec_checks.DNSSECEvidence("available")


@pytest.mark.parametrize("value", [-1, 101, True, 1.5])
def test_dnssec_evidence_rejects_invalid_record_counts(value):
    with pytest.raises(ValueError):
        dnssec_checks.DNSSECEvidence(
            "available",
            dnskey_count=value,
        )


def test_dnssec_evidence_rejects_records_for_non_available_state():
    with pytest.raises(ValueError):
        dnssec_checks.DNSSECEvidence(
            "timeout",
            dnskey_count=1,
        )


def test_dnssec_evidence_rejects_non_boolean_ad_flag():
    with pytest.raises(TypeError):
        dnssec_checks.DNSSECEvidence(
            "available",
            dnskey_count=1,
            authenticated_data=1,
        )


def test_dnssec_evidence_rejects_ad_for_timeout_state():
    with pytest.raises(ValueError):
        dnssec_checks.DNSSECEvidence(
            "timeout",
            authenticated_data=True,
        )


# ---------------------------------------------------------------------------
# Bounded DNS collection
# ---------------------------------------------------------------------------

def test_collect_dnssec_requests_dnskey_with_edns_do(monkeypatch):
    fake = FakeResolver(answer=make_answer())
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence(
        "Sub.Example.com."
    )

    assert evidence.query_state == "available"
    assert evidence.dnskey_count == 2
    assert evidence.rrsig_count == 1
    assert evidence.authenticated_data is True

    assert fake.edns_calls == [
        {
            "edns": 0,
            "ednsflags": dns.flags.DO,
        }
    ]

    assert [item[0] for item in fake.resolve_calls] == [
        ("sub.example.com.", "SOA"),
        ("example.com.", "DNSKEY"),
    ]
    assert all(
        kwargs["search"] is False
        and kwargs["raise_on_no_answer"] is False
        and kwargs["lifetime"] <= dnssec_checks._DNS_TXT_TIMEOUT_SECONDS
        for _args, kwargs in fake.resolve_calls
    )


def test_collect_dnssec_queries_zone_apex_for_subdomain(monkeypatch):
    fake = FakeResolver(
        answer=make_answer(zone_name="example.com."),
        zone_name="example.com.",
    )
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence("www.example.com")

    assert evidence.query_state == "available"
    assert evidence.zone_name == "example.com"
    assert [item[0] for item in fake.resolve_calls] == [
        ("www.example.com.", "SOA"),
        ("example.com.", "DNSKEY"),
    ]


def test_collect_dnssec_rejects_unrelated_soa_owner(monkeypatch):
    fake = FakeResolver(
        answer=make_answer(zone_name="unrelated.example.net."),
        zone_name="unrelated.example.net.",
    )
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence("www.example.com")

    assert evidence.query_state == "no_zone_apex"
    assert len(fake.resolve_calls) == 1


def test_collect_dnssec_does_not_retain_raw_key_material(monkeypatch):
    fake = FakeResolver(answer=make_answer())
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence("example.com")

    assert "DNSKEY-RDATA-SECRET" not in repr(evidence)
    assert not hasattr(evidence, "records")


def test_collect_dnssec_handles_no_dnskey_and_ad_flag(monkeypatch):
    fake = FakeResolver(
        answer=make_answer(
            dnskey_count=None,
            rrsig_count=0,
            authenticated_data=True,
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence("example.com")

    assert evidence.query_state == "no_dnskey"
    assert evidence.authenticated_data is True


def test_collect_dnssec_does_not_query_invalid_domain(monkeypatch):
    def unexpected_resolver(**kwargs):
        pytest.fail("DNSSEC query attempted for invalid domain")

    monkeypatch.setattr(
        dnssec_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dnssec_checks.collect_dnssec_evidence(
        "bad..example.com"
    )

    assert evidence.query_state == "invalid_target"


def test_collect_dnssec_marks_ip_as_not_applicable(monkeypatch):
    def unexpected_resolver(**kwargs):
        pytest.fail("DNSSEC query attempted for IP address")

    monkeypatch.setattr(
        dnssec_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dnssec_checks.collect_dnssec_evidence("192.0.2.1")

    assert evidence.query_state == "not_applicable"


def test_collect_dnssec_rejects_expired_deadline_without_query(monkeypatch):
    monkeypatch.setattr(
        dnssec_checks.time,
        "monotonic",
        lambda: 100.0,
    )

    def unexpected_resolver(**kwargs):
        pytest.fail("DNSSEC query attempted after deadline")

    monkeypatch.setattr(
        dnssec_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dnssec_checks.collect_dnssec_evidence(
        "example.com",
        deadline=99.0,
    )

    assert evidence.query_state == "timeout"


def test_collect_dnssec_rejects_invalid_deadline_without_query(monkeypatch):
    def unexpected_resolver(**kwargs):
        pytest.fail("DNSSEC query attempted with invalid deadline")

    monkeypatch.setattr(
        dnssec_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dnssec_checks.collect_dnssec_evidence(
        "example.com",
        deadline=True,
    )

    assert evidence.query_state == "invalid_target"


def test_collect_dnssec_respects_shared_capacity(monkeypatch):
    class NoSlots:
        def acquire(self, blocking=False):
            return False

        def release(self):
            pytest.fail("Semaphore released without being acquired")

    monkeypatch.setattr(
        dnssec_checks,
        "_DNS_TXT_LOOKUP_SLOTS",
        NoSlots(),
    )

    def unexpected_resolver(**kwargs):
        pytest.fail("Resolver created without DNS capacity")

    monkeypatch.setattr(
        dnssec_checks.dns.resolver,
        "Resolver",
        unexpected_resolver,
    )

    evidence = dnssec_checks.collect_dnssec_evidence("example.com")

    assert evidence.query_state == "dns_capacity"


def test_collect_dnssec_handles_timeout(monkeypatch):
    fake = FakeResolver(error=dns.exception.Timeout())
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence("example.com")

    assert evidence.query_state == "timeout"


def test_collect_dnssec_handles_dns_failure_without_leaking_details(
    monkeypatch,
):
    fake = FakeResolver(
        error=dns.exception.DNSException("synthetic private resolver detail")
    )
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence("example.com")

    assert evidence.query_state == "dns_error"
    assert "synthetic private resolver detail" not in repr(evidence)


def test_collect_dnssec_rejects_oversized_dnskey_rrset(monkeypatch):
    fake = FakeResolver(
        answer=make_answer(
            dnskey_count=dnssec_checks._MAX_DNSSEC_RECORDS + 1,
            rrsig_count=1,
        )
    )
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence("example.com")

    assert evidence.query_state == "oversized_response"


def test_collect_dnssec_releases_capacity_after_resolver_failure(
    monkeypatch,
):
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
        dnssec_checks,
        "_DNS_TXT_LOOKUP_SLOTS",
        slot,
    )

    fake = FakeResolver(
        error=dns.exception.DNSException("synthetic failure")
    )
    install_resolver(monkeypatch, fake)

    evidence = dnssec_checks.collect_dnssec_evidence("example.com")

    assert evidence.query_state == "dns_error"
    assert slot.acquires == 1
    assert slot.releases == 1


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
        ("no_zone_apex", "not_verified"),
        ("no_dnskey", "not_verified"),
    ],
)
def test_dnssec_evaluator_maps_collection_states(
    evaluator,
    state,
    expected_status,
):
    result = evaluator.evaluate(
        dnssec_checks.DNSSECEvidence(state)
    )

    assert result.check_id == "dnssec"
    assert result.status == expected_status


def test_dnssec_evaluator_does_not_pass_without_ad_flag(evaluator):
    result = evaluator.evaluate(
        dnssec_checks.DNSSECEvidence(
            "available",
            dnskey_count=2,
            rrsig_count=1,
            authenticated_data=False,
        )
    )

    assert result.status == "not_verified"
    assert result.severity == "info"


def test_dnssec_evaluator_does_not_pass_without_rrsig(evaluator):
    result = evaluator.evaluate(
        dnssec_checks.DNSSECEvidence(
            "available",
            dnskey_count=2,
            rrsig_count=0,
            authenticated_data=True,
        )
    )

    assert result.status == "not_verified"


def test_dnssec_evaluator_does_not_trust_ad_without_trusted_resolver(
    evaluator,
):
    result = evaluator.evaluate(
        dnssec_checks.DNSSECEvidence(
            "available",
            dnskey_count=2,
            rrsig_count=1,
            authenticated_data=True,
        )
    )

    assert result.status == "not_verified"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert "no configured trust" in result.explanation.lower()
    assert any(
        "secure channel" in item.lower()
        for item in result.limitations
    )


def test_dnssec_evaluator_explains_no_dnskey_is_not_proof_of_failure(
    evaluator,
):
    result = evaluator.evaluate(
        dnssec_checks.DNSSECEvidence("no_dnskey")
    )

    assert result.status == "not_verified"
    assert "does not independently validate" in result.explanation


def test_dnssec_evaluator_rejects_wrong_evidence_type(evaluator):
    with pytest.raises(TypeError):
        evaluator.evaluate("not evidence")
