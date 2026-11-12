from dataclasses import FrozenInstanceError

import pytest

from security_scanner.checks.context import CheckContext
from security_scanner.checks.evidence import EvidenceCollection
from security_scanner.checks.limits import (
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADER_COUNT,
)


def _dnssec_fixture_answers():
    """Real DNS message/RRset objects, with no external DNS operations."""
    from types import SimpleNamespace
    import dns.flags
    import dns.message
    import dns.rrset

    soa = dns.rrset.from_text(
        "example.com.", 60, "IN", "SOA",
        "ns.example.com. hostmaster.example.com. 1 60 60 60 60",
    )
    key = dns.rrset.from_text("example.com.", 60, "IN", "DNSKEY", "257 3 8 QUJDRA==")
    signature = dns.rrset.from_text(
        "example.com.", 60, "IN", "RRSIG",
        "DNSKEY 8 2 60 20300101000000 20200101000000 12345 example.com. RUZHSA==",
    )
    soa_message = dns.message.make_response(dns.message.make_query("example.com.", "SOA"))
    soa_message.answer.append(soa)
    key_message = dns.message.make_response(dns.message.make_query("example.com.", "DNSKEY"))
    key_message.flags |= dns.flags.AD
    key_message.answer.extend((key, signature))
    return (
        SimpleNamespace(rrset=soa, response=soa_message),
        SimpleNamespace(rrset=key, response=key_message),
    )


def _collect_dnssec_fixture(monkeypatch, soa_answer, key_answer):
    from types import SimpleNamespace
    import security_scanner.checks.dnssec_checks as dnssec
    from security_scanner.checks.registry import create_default_registry

    calls = []
    def resolve(name, kind, **kwargs):
        calls.append((name, kind))
        return soa_answer if kind == "SOA" else key_answer

    monkeypatch.setattr(dnssec.dns.resolver, "Resolver", lambda **kwargs: SimpleNamespace(
        use_edns=lambda **kwargs: None, resolve=resolve,
    ))
    evidence = dnssec.collect_dnssec_evidence("example.com")
    result = dnssec.DNSSECCheckEvaluator(
        create_default_registry().get("dnssec")
    ).evaluate(evidence)
    return evidence, result, calls


@pytest.mark.parametrize("owner", [None, "unrelated.example.net.", "child.example.com.", "."])
def test_dnssec_rejects_missing_or_mismatched_dnskey_owner(monkeypatch, owner):
    import dns.name

    soa, answer = _dnssec_fixture_answers()
    answer.rrset.name = dns.name.from_text(owner) if owner is not None else None
    evidence, result, calls = _collect_dnssec_fixture(monkeypatch, soa, answer)
    assert evidence.query_state == "inconsistent_response"
    assert evidence.dnskey_count == evidence.rrsig_count == 0
    assert (result.status, result.severity, result.confidence) == ("not_verified", "info", "low")
    assert calls == [("example.com.", "SOA"), ("example.com.", "DNSKEY")]


@pytest.mark.parametrize("owner, covered", [
    (None, "DNSKEY"), ("unrelated.example.net.", "DNSKEY"),
    ("example.com.", "A"), ("example.com.", "SOA"),
])
def test_dnssec_rejects_inconsistent_rrsig_owner_or_covered_type(monkeypatch, owner, covered):
    import dns.name
    import dns.rrset

    soa, answer = _dnssec_fixture_answers()
    signature = dns.rrset.from_text(
        "example.com.", 60, "IN", "RRSIG",
        f"{covered} 8 2 60 20300101000000 20200101000000 12345 example.com. RUZHSA==",
    )
    signature.name = dns.name.from_text(owner) if owner is not None else None
    # Include a valid signature too: inconsistent extra evidence must not be counted.
    answer.response.answer.append(signature)
    evidence, result, _ = _collect_dnssec_fixture(monkeypatch, soa, answer)
    assert evidence.query_state == "inconsistent_response"
    assert evidence.rrsig_count == 0
    assert result.status == "not_verified"


def test_dnssec_normalized_matching_owner_counts_only_observations(monkeypatch):
    import dns.name

    soa, answer = _dnssec_fixture_answers()
    answer.rrset.name = dns.name.from_text("EXAMPLE.COM.")
    evidence, result, calls = _collect_dnssec_fixture(monkeypatch, soa, answer)
    assert evidence.query_state == "available"
    assert evidence.zone_name == "example.com"
    assert evidence.dnskey_count == evidence.rrsig_count == 1
    assert evidence.authenticated_data is True
    assert result.status == "not_verified"
    assert len(calls) == 2
    assert "QUJDRA==" not in repr(evidence) + repr(result.to_dict())
    assert "RUZHSA==" not in repr(evidence) + repr(result.to_dict())
    assert any("cryptographic" in limitation for limitation in result.limitations)


def test_dnssec_rejects_ambiguous_soa_regions_without_second_query(monkeypatch):
    import dns.rrset

    soa, answer = _dnssec_fixture_answers()
    soa.response.authority.append(dns.rrset.from_text(
        "com.", 60, "IN", "SOA", "ns.com. hostmaster.com. 1 60 60 60 60",
    ))
    evidence, result, calls = _collect_dnssec_fixture(monkeypatch, soa, answer)
    assert evidence.query_state == "no_zone_apex"
    assert result.status == "not_verified"
    assert calls == [("example.com.", "SOA")]


def test_dnssec_rejects_multiple_dnskey_rrsets(monkeypatch):
    import dns.rrset

    soa, answer = _dnssec_fixture_answers()
    answer.response.answer.append(dns.rrset.from_text(
        "other.example.net.", 60, "IN", "DNSKEY", "257 3 8 QUJDRA==",
    ))
    evidence, result, _ = _collect_dnssec_fixture(monkeypatch, soa, answer)
    assert evidence.query_state == "inconsistent_response"
    assert result.status == "not_verified"


@pytest.mark.parametrize("missing", ["response", "answer_section", "flags"])
def test_dnssec_missing_response_metadata_is_not_verified(monkeypatch, missing):
    soa, answer = _dnssec_fixture_answers()
    if missing == "response":
        answer.response = None
    elif missing == "answer_section":
        answer.response.answer = None
    else:
        answer.response.flags = None
    evidence, result, _ = _collect_dnssec_fixture(monkeypatch, soa, answer)
    assert evidence.query_state == "inconsistent_response"
    assert result.status == "not_verified"


def _takeover_message(links=(), *, code="NXDOMAIN", addresses=()):
    import dns.message
    import dns.rcode
    import dns.rrset

    message = dns.message.make_response(dns.message.make_query("scan.example.com.", "A"))
    message.set_rcode(dns.rcode.from_text(code))
    for owner, target in links:
        message.answer.append(dns.rrset.from_text(owner, 60, "IN", "CNAME", target))
    for owner, address in addresses:
        message.answer.append(dns.rrset.from_text(owner, 60, "IN", "A", address))
    return message


def _takeover_collect(monkeypatch, message=None, error=None):
    from types import SimpleNamespace
    import security_scanner.checks.takeover_checks as takeover

    calls = []
    def resolve(name, kind, **kwargs):
        calls.append((name, kind, kwargs))
        if error is not None:
            raise error
        return SimpleNamespace(response=message)

    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **kwargs: SimpleNamespace(resolve=resolve))
    evidence = takeover.collect_takeover_evidence("scan.example.com")
    return evidence, takeover.evaluate_takeover_evidence(evidence), calls


@pytest.mark.parametrize("links", [
    (("scan.example.com.", "missing.service.example."),),
    (("alias.example.", "missing.service.example."), ("scan.example.com.", "alias.example.")),
])
def test_takeover_dangling_chain_is_low_confidence_warning_with_one_query(monkeypatch, links):
    import dns.name
    import dns.resolver

    message = _takeover_message(links)
    name = dns.name.from_text("scan.example.com.")
    error = dns.resolver.NXDOMAIN(qnames=[name], responses={name: message})
    evidence, result, calls = _takeover_collect(monkeypatch, error=error)
    assert evidence.query_state == "dangling"
    assert evidence.cname_count == len(links)
    assert (result.status, result.severity, result.confidence) == ("warning", "low", "low")
    assert "potential dangling-DNS indicator only" in result.evidence
    assert "never proven takeover" in result.explanation
    assert len(calls) == 1
    assert calls[0][:2] == ("scan.example.com.", "A")
    assert calls[0][2] == {"lifetime": 2.0, "search": False, "raise_on_no_answer": False}
    assert "missing.service.example" not in repr(evidence) + repr(result.to_dict())


@pytest.mark.parametrize("code, links, addresses, state", [
    ("NXDOMAIN", (), (), "no_cname"),
    ("NOERROR", (), (), "nodata"),
    ("NOERROR", (("scan.example.com.", "provider.example."),), (), "nodata"),
    ("NOERROR", (("scan.example.com.", "provider.example."),), (("provider.example.", "93.184.216.34"),), "resolved"),
    ("NOERROR", (), (("scan.example.com.", "93.184.216.34"),), "resolved"),
])
def test_takeover_no_cname_nodata_or_resolution_is_not_a_vulnerability(monkeypatch, code, links, addresses, state):
    evidence, result, calls = _takeover_collect(monkeypatch, _takeover_message(links, code=code, addresses=addresses))
    assert evidence.query_state == state
    assert (result.status, result.severity, result.confidence) == ("not_verified", "info", "low")
    assert len(calls) == 1


@pytest.mark.parametrize("links", [
    (("scan.example.com.", "scan.example.com."),),
    (("scan.example.com.", "alias.example."), ("alias.example.", "scan.example.com.")),
    (("other.example.", "missing.example."),),
    (("scan.example.com.", "a.example."), ("scan.example.com.", "b.example.")),
    (("scan.example.com.", "alias.example."), ("unrelated.example.", "missing.example.")),
    (("scan.example.com.", "localhost."),),
    (("scan.example.com.", "private.internal."),),
    (("scan.example.com.", "127.0.0.1."),),
])
def test_takeover_malformed_conflicting_or_unsafe_chain_is_inconclusive(monkeypatch, links):
    evidence, result, calls = _takeover_collect(monkeypatch, _takeover_message(links))
    assert evidence.query_state == "inconclusive"
    assert result.status == "not_verified"
    assert len(calls) == 1


@pytest.mark.parametrize("mutation", ["wrong_question", "wrong_type", "truncated", "too_many", "address_with_nxdomain", "private_address"])
def test_takeover_inconsistent_response_never_warns(monkeypatch, mutation):
    import dns.flags
    import dns.message
    import dns.rrset

    message = _takeover_message((("scan.example.com.", "missing.example."),))
    if mutation == "wrong_question":
        message.question = dns.message.make_query("unrelated.example.", "A").question
    elif mutation == "wrong_type":
        message.question = dns.message.make_query("scan.example.com.", "AAAA").question
    elif mutation == "truncated":
        message.flags |= dns.flags.TC
    elif mutation == "too_many":
        message.answer *= 101
    elif mutation == "address_with_nxdomain":
        message.answer.append(dns.rrset.from_text("missing.example.", 60, "IN", "A", "93.184.216.34"))
    else:
        message = _takeover_message(code="NOERROR", addresses=(("scan.example.com.", "10.0.0.1"),))
    evidence, result, calls = _takeover_collect(monkeypatch, message)
    assert evidence.query_state == "inconclusive"
    assert result.status == "not_verified"
    assert len(calls) == 1


@pytest.mark.parametrize("hostname", [None, "localhost", "a.internal", "bad..example", "127.0.0.1", "9.9.9.9", "::1"])
def test_takeover_ineligible_or_ip_names_do_not_query(monkeypatch, hostname):
    import security_scanner.checks.takeover_checks as takeover

    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **kwargs: pytest.fail("Unexpected DNS query"))
    result = takeover.evaluate_takeover_domain(hostname)
    assert result.status in {"not_verified", "skipped"}


@pytest.mark.parametrize("reason", ["timeout", "exception", "capacity", "deadline"])
def test_takeover_limits_and_errors_release_capacity_without_leaking(monkeypatch, reason):
    from types import SimpleNamespace
    import dns.exception
    import security_scanner.checks.takeover_checks as takeover

    acquired, released, calls = [], [], []
    def acquire(**kwargs):
        acquired.append(True)
        return reason != "capacity"
    def resolve(*args, **kwargs):
        calls.append(True)
        if reason == "timeout":
            raise dns.exception.Timeout()
        raise dns.exception.DNSException("PRIVATE_RESOLVER_MARKER_819")
    monkeypatch.setattr(takeover, "_DNS_TXT_LOOKUP_SLOTS", SimpleNamespace(acquire=acquire, release=lambda: released.append(True)))
    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **kwargs: SimpleNamespace(resolve=resolve))
    result = takeover.evaluate_takeover_domain("scan.example.com", deadline=0 if reason == "deadline" else None)
    assert result.status == ("skipped" if reason == "capacity" else "error")
    assert len(calls) == (1 if reason in {"timeout", "exception"} else 0)
    assert len(released) == (1 if reason in {"timeout", "exception"} else 0)
    assert "PRIVATE_RESOLVER_MARKER_819" not in repr(result.to_dict())


def test_takeover_resolution_rejection_clears_stale_diagnostic_eligibility(monkeypatch):
    import security_scanner.scanner as scanner

    capture = {"takeover_hostname": "old.example.com", "target": object()}
    monkeypatch.setattr(scanner.requests, "Session", lambda: pytest.fail("HTTP after rejection"))
    status, _, error = scanner._safe_get_response("https://localhost/", validated_target_capture=capture)
    assert status is None and error == "not_allowed"
    assert "takeover_hostname" not in capture
    assert "target" not in capture


def test_takeover_conflicting_targets_in_one_rrset_are_inconclusive(monkeypatch):
    import dns.name
    import dns.rdataclass
    import dns.rdatatype

    message = _takeover_message()
    # dnspython's normal builder replaces singleton CNAME data. Explicitly
    # model a malformed returned RRset rather than silently repairing it.
    class ConflictingRRset:
        rdclass = dns.rdataclass.IN
        rdtype = dns.rdatatype.CNAME
        name = dns.name.from_text("scan.example.com.")
        def __len__(self):
            return 2
    message.answer.append(ConflictingRRset())
    evidence, result, calls = _takeover_collect(monkeypatch, message)
    assert evidence.query_state == "inconclusive"
    assert result.status == "not_verified"
    assert len(calls) == 1


def test_takeover_expired_budget_during_resolver_setup_never_queries(monkeypatch):
    from types import SimpleNamespace
    import security_scanner.checks.takeover_checks as takeover

    clock = iter((10.0, 12.0))
    released = []
    monkeypatch.setattr(takeover.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(takeover, "_DNS_TXT_LOOKUP_SLOTS", SimpleNamespace(
        acquire=lambda **kwargs: True, release=lambda: released.append(True),
    ))
    monkeypatch.setattr(takeover.dns.resolver, "Resolver", lambda **kwargs: SimpleNamespace(
        resolve=lambda *args, **kwargs: pytest.fail("Expired diagnostic budget queried DNS"),
    ))
    result = takeover.evaluate_takeover_domain("scan.example.com", deadline=11.0)
    assert result.status == "error"
    assert "timed out" in result.evidence
    assert released == [True]


def test_evidence_collection_captures_response_metadata():
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000",
        },
    )

    evidence = EvidenceCollection.from_context(context)

    assert evidence.http_status == 200
    assert "content-type" in evidence.header_names
    assert evidence.values_for_header("Content-Type") == ("text/html",)


def test_header_lookup_is_case_insensitive():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Strict-Transport-Security": "max-age=31536000"},
    )

    assert evidence.values_for_header(
        "strict-transport-security"
    ) == ("max-age=31536000",)


def test_collection_preserves_separate_header_values():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={
            "X-Trace": ("first",),
            "x-trace": ("second",),
        },
    )

    assert evidence.values_for_header("X-TRACE") == (
        "first",
        "second",
    )


def test_raw_header_values_are_not_in_repr():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Set-Cookie": "session=secret-value"},
    )

    assert "secret-value" not in repr(evidence)
    assert "session=secret" not in repr(evidence)
    assert evidence.values_for_header("Set-Cookie") == ()


def test_cookie_evidence_retains_only_parsed_attributes():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Set-Cookie": "sensitive-name=sensitive-value; Secure"},
        cookie_evidence_available=True,
        cookie_observations=((True, False, "missing"),),
    )

    assert evidence.values_for_header("Set-Cookie") == ()
    assert evidence.cookie_observations == ((True, False, "missing"),)
    assert "sensitive-name" not in repr(evidence)
    assert "sensitive-value" not in repr(evidence)


def test_collection_headers_cannot_be_mutated():
    evidence = EvidenceCollection(
        http_status=200,
        _headers={"Content-Type": "text/html"},
    )

    with pytest.raises(TypeError):
        evidence._headers["content-type"] = ("changed",)


def test_collection_is_immutable():
    evidence = EvidenceCollection(http_status=200)

    with pytest.raises(FrozenInstanceError):
        evidence.http_status = 404


def test_collection_from_context_without_response_is_empty():
    context = CheckContext(
        safe_target_url="https://example.com",
        connection_error="timeout",
    )

    evidence = EvidenceCollection.from_context(context)

    assert evidence.http_status is None
    assert evidence.header_names == ()
    assert evidence.values_for_header("Content-Type") == ()


def test_collection_rejects_invalid_context():
    with pytest.raises(TypeError, match="must be a CheckContext"):
        EvidenceCollection.from_context(object())


def test_collection_rejects_invalid_http_status():
    with pytest.raises(ValueError, match="between 100 and 599"):
        EvidenceCollection(http_status=600)


def test_collection_rejects_invalid_header_values():
    with pytest.raises(TypeError, match="must be strings"):
        EvidenceCollection(
            http_status=200,
            _headers={"Content-Length": 123},
        )


def test_collection_rejects_empty_header_name():
    with pytest.raises(ValueError, match="non-empty strings"):
        EvidenceCollection(
            http_status=200,
            _headers={"": "value"},
        )


def test_header_lookup_rejects_empty_name():
    evidence = EvidenceCollection(http_status=200)

    with pytest.raises(ValueError, match="non-empty string"):
        evidence.values_for_header("")


def test_evidence_rejects_excessive_header_value_count():
    values = tuple("v" for _ in range(MAX_RESPONSE_HEADER_COUNT + 1))

    with pytest.raises(ValueError, match="maximum header count"):
        EvidenceCollection(
            http_status=200,
            _headers={"X-Trace": values},
        )


def test_evidence_accepts_exact_header_byte_limit():
    value = "x" * (MAX_RESPONSE_HEADER_BYTES - 5)

    evidence = EvidenceCollection(
        http_status=200,
        _headers={"X": value},
    )

    assert len(evidence.values_for_header("X")[0]) == len(value)


def test_evidence_rejects_excessive_header_bytes():
    value = "x" * (MAX_RESPONSE_HEADER_BYTES - 4)

    with pytest.raises(ValueError, match="maximum byte limit"):
        EvidenceCollection(
            http_status=200,
            _headers={"X": value},
        )


@pytest.mark.parametrize(
    ("http_status", "connection_error"),
    [
        (200, "timeout"),
        (None, None),
    ],
)
def test_failed_context_never_contributes_partial_response_evidence(
    http_status,
    connection_error,
):
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=http_status,
        connection_error=connection_error,
        response_headers={"Cache-Control": "no-store"},
    )

    assert context.has_http_response is False

    evidence = EvidenceCollection.from_context(context)

    assert evidence.http_status is None
    assert evidence.header_names == ()
    assert evidence.values_for_header("Cache-Control") == ()
