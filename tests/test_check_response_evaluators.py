import pytest

from security_scanner.checks import (
    CacheSecurityEvaluator,
    PermissionsPolicyEvaluator,
    ReferrerPolicyEvaluator,
    create_default_registry,
)
from security_scanner.checks.evidence import EvidenceCollection
from security_scanner.checks.context import CheckContext
from security_scanner.checks.response_runner import evaluate_week3_evidence
from security_scanner.scanner import _collect_set_cookie_observations
from security_scanner.checks.access_checks import CORSConfigurationEvaluator, OpenRedirectEvaluator
from types import SimpleNamespace


def make_evaluator(check_id, evaluator_type):
    definition = create_default_registry().get(check_id)
    return evaluator_type(definition)


def make_evidence(headers=None):
    return EvidenceCollection(
        http_status=200,
        _headers=headers or {},
    )


def test_referrer_policy_accepts_strict_policy():
    evaluator = make_evaluator(
        "header_referrer_policy",
        ReferrerPolicyEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence(
            {"Referrer-Policy": "strict-origin-when-cross-origin"}
        )
    )

    assert result.status == "passed"
    assert result.severity == "info"


def test_referrer_policy_uses_last_recognized_fallback():
    evaluator = make_evaluator(
        "header_referrer_policy",
        ReferrerPolicyEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence(
            {
                "Referrer-Policy": (
                    "no-referrer, strict-origin-when-cross-origin"
                )
            }
        )
    )

    assert result.status == "passed"


def test_referrer_policy_warns_for_unsafe_url():
    evaluator = make_evaluator(
        "header_referrer_policy",
        ReferrerPolicyEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Referrer-Policy": "unsafe-url"})
    )

    assert result.status == "warning"
    assert result.severity == "medium"


def test_referrer_policy_warns_for_unknown_value():
    evaluator = make_evaluator(
        "header_referrer_policy",
        ReferrerPolicyEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Referrer-Policy": "unknown-policy"})
    )

    assert result.status == "warning"


@pytest.mark.parametrize(
    ("values", "expected_status", "expected_severity"),
    [
        (("strict-origin", "unknown-policy"), "passed", "info"),
        (("no-referrer", "unsafe-url"), "warning", "medium"),
        (("", ",, invalid policy token"), "warning", "low"),
    ],
)
def test_referrer_policy_handles_multiple_and_invalid_field_values(
    values,
    expected_status,
    expected_severity,
):
    evaluator = make_evaluator(
        "header_referrer_policy",
        ReferrerPolicyEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Referrer-Policy": values})
    )

    assert result.status == expected_status
    assert result.severity == expected_severity
    assert all(not value or value not in result.evidence for value in values)


def test_referrer_policy_missing_header_warns():
    evaluator = make_evaluator(
        "header_referrer_policy",
        ReferrerPolicyEvaluator,
    )

    result = evaluator.evaluate(make_evidence())

    assert result.status == "warning"


def test_referrer_policy_does_not_echo_raw_value():
    evaluator = make_evaluator(
        "header_referrer_policy",
        ReferrerPolicyEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Referrer-Policy": "unsafe-url"})
    )

    assert "unsafe-url" not in result.evidence


def test_permissions_policy_presence_is_not_reported_as_passed():
    evaluator = make_evaluator(
        "header_permissions_policy",
        PermissionsPolicyEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence(
            {"Permissions-Policy": "camera=(), microphone=()"}
        )
    )

    assert result.status == "warning"
    assert result.severity == "info"
    assert "camera=()" not in result.evidence


def test_permissions_policy_missing_header_warns():
    evaluator = make_evaluator(
        "header_permissions_policy",
        PermissionsPolicyEvaluator,
    )

    result = evaluator.evaluate(make_evidence())

    assert result.status == "warning"
    assert result.severity == "low"


@pytest.mark.parametrize(
    "values",
    [
        ("not a policy ???",),
        ("future-feature=()",),
        ("camera=()", "microphone=()"),
    ],
)
def test_permissions_policy_presence_never_claims_parsing_or_validity(values):
    evaluator = make_evaluator(
        "header_permissions_policy",
        PermissionsPolicyEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Permissions-Policy": values})
    )

    assert result.status == "warning"
    assert result.severity == "info"
    assert "لم يتم تقييم التوجيهات" in result.explanation
    assert all(value not in result.evidence for value in values)


def test_cache_security_passes_for_no_store():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Cache-Control": "no-store"})
    )

    assert result.status == "passed"
    assert result.severity == "info"


def test_cache_security_no_store_takes_precedence_over_other_directives():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    for cache_control in (
        "public, no-store",
        "private, no-store",
        "s-maxage=60, no-store",
        "no-cache, no-store",
    ):
        result = evaluator.evaluate(
            make_evidence({"Cache-Control": cache_control})
        )

        assert result.status == "passed"
        assert result.severity == "info"


def test_cache_security_warns_when_must_understand_is_present():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence(
            {"Cache-Control": "no-store, must-understand"}
        )
    )

    assert result.status == "warning"
    assert result.severity == "low"
    assert "must-understand" not in result.evidence


def test_cache_security_warns_for_private():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Cache-Control": "private, max-age=300"})
    )

    assert result.status == "warning"


def test_cache_security_warns_for_no_cache():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Cache-Control": "no-cache"})
    )

    assert result.status == "warning"
    assert "لا يمنع تخزين" in result.explanation


def test_cache_security_warns_when_header_is_missing():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    result = evaluator.evaluate(make_evidence())

    assert result.status == "warning"


def test_pragma_no_cache_does_not_replace_cache_control():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence({"Pragma": "no-cache", "Expires": "0"})
    )

    assert result.status == "warning"
    assert "Cache-Control" in result.evidence


def test_cache_parser_does_not_treat_quoted_text_as_directive():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence(
            {"Cache-Control": 'extension="no-store"'}
        )
    )

    assert result.status == "warning"


def test_cache_security_does_not_echo_raw_directives():
    evaluator = make_evaluator(
        "cache_security",
        CacheSecurityEvaluator,
    )

    result = evaluator.evaluate(
        make_evidence(
            {"Cache-Control": "private, max-age=300"}
        )
    )

    assert "max-age=300" not in result.evidence


@pytest.mark.parametrize(
    ("check_id", "evaluator_type"),
    [
        ("header_referrer_policy", ReferrerPolicyEvaluator),
        ("header_permissions_policy", PermissionsPolicyEvaluator),
        ("cache_security", CacheSecurityEvaluator),
    ],
)
def test_response_evaluators_do_not_treat_missing_response_as_missing_headers(
    check_id,
    evaluator_type,
):
    evaluator = make_evaluator(check_id, evaluator_type)

    result = evaluator.evaluate(
        EvidenceCollection(http_status=None)
    )

    assert result.status == "not_verified"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert "HTTP" in result.evidence
    assert all(
        header_name not in result.evidence
        for header_name in (
            "Referrer-Policy",
            "Permissions-Policy",
            "Cache-Control",
        )
    )
    assert "not_verified" == result.to_dict()["status"]


def _cookie_results(observations=(), available=True):
    evidence = EvidenceCollection(
        http_status=200,
        cookie_evidence_available=available,
        cookie_observations=observations,
    )
    return {
        result.check_id: result
        for result in evaluate_week3_evidence(evidence)
    }


def test_cookie_checks_aggregate_observations_and_apply_attribute_rules():
    results = _cookie_results((
        (True, True, "strict"),
        (False, False, "none"),
    ))
    assert results["cookie_secure"].status == "warning"
    assert results["cookie_secure"].severity == "medium"
    assert "2" in results["cookie_secure"].evidence
    assert results["cookie_httponly"].status == "warning"
    assert "لا تمنع جميع مخاطر XSS" in results["cookie_httponly"].explanation
    assert results["cookie_samesite"].status == "warning"
    assert results["cookie_samesite"].severity == "medium"


def test_single_cookie_with_all_attributes_passes_all_three_checks():
    results = _cookie_results(((True, True, "strict"),))
    assert results["cookie_secure"].status == "passed"
    assert results["cookie_httponly"].status == "passed"
    assert results["cookie_samesite"].status == "passed"


@pytest.mark.parametrize("state", ("strict", "lax"))
def test_cookie_samesite_strict_and_lax_pass(state):
    assert _cookie_results(((True, True, state),))["cookie_samesite"].status == "passed"


def test_cookie_samesite_none_with_secure_passes_and_discloses_cross_site_semantics():
    result = _cookie_results(((True, True, "none"),))["cookie_samesite"]
    assert result.status == "passed"
    assert "يسمح بالاستخدام عبر المواقع" in result.explanation
    assert "لا يعني وحده وجود ثغرة" in result.explanation


@pytest.mark.parametrize(
    ("state", "status", "severity"),
    (("missing", "warning", "low"), ("invalid", "warning", "low"),
     ("ambiguous", "not_verified", "info")),
)
def test_cookie_samesite_missing_unknown_and_conflicting_states(state, status, severity):
    result = _cookie_results(((True, True, state),))["cookie_samesite"]
    assert (result.status, result.severity) == (status, severity)


@pytest.mark.parametrize("check_id", ("cookie_secure", "cookie_httponly", "cookie_samesite"))
def test_cookie_checks_skip_empty_collection_and_not_verify_unavailable(check_id):
    results = _cookie_results((), available=True)
    assert results[check_id].status == "skipped"
    assert _cookie_results((), available=False)[check_id].status == "not_verified"
    assert _cookie_results((), available=None)[check_id].status == "not_verified"


def test_cookie_evidence_never_retains_raw_set_cookie_values_or_names():
    name = "SENSITIVE_COOKIE_NAME_41"
    value = "SENSITIVE_COOKIE_VALUE_92"
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=200,
        response_headers={"Set-Cookie": f"{name}={value}; Secure; HttpOnly; SameSite=Lax"},
        cookie_evidence_available=True,
        cookie_observations=((True, True, "lax"),),
    )
    evidence = EvidenceCollection.from_context(context)
    assert "Set-Cookie" not in context.response_headers
    assert evidence.values_for_header("Set-Cookie") == ()
    assert name not in repr(context) and value not in repr(context)
    assert name not in repr(evidence) and value not in repr(evidence)


class _CookieRawHeaders:
    def __init__(self, values):
        self.values = values

    def keys(self):
        return self.values.keys()

    def getlist(self, name):
        return list(self.values.get(name, ()))


def test_cookie_raw_collector_preserves_fields_and_expires_commas_without_retaining_values():
    secret_values = ("FAKE_COOKIE_SECRET_1", "FAKE_COOKIE_SECRET_2")
    response = SimpleNamespace(raw=SimpleNamespace(headers=_CookieRawHeaders({
        "Set-Cookie": [
            f"first={secret_values[0]}; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure; HttpOnly; SameSite=None",
            f"second={secret_values[1]}; Expires=Thu, 22 Oct 2031 08:29:00 GMT; Secure; HttpOnly; SameSite=Lax",
        ],
        "Content-Type": ["text/html"],
    })))
    available, observations = _collect_set_cookie_observations(response)
    assert available is True
    assert observations == ((True, True, "none"), (True, True, "lax"))
    assert all(secret not in repr(observations) for secret in secret_values)


def test_cookie_raw_collector_marks_conflicting_samesite_attributes_ambiguous():
    response = SimpleNamespace(raw=SimpleNamespace(headers=_CookieRawHeaders({
        "Set-Cookie": ["id=private; SameSite=Strict; SameSite=Lax"],
    })))
    available, observations = _collect_set_cookie_observations(response)
    assert available is True
    assert observations == ((False, False, "ambiguous"),)


def test_cookie_raw_collector_reports_unavailable_without_multivalue_support_or_logging(caplog):
    assert _collect_set_cookie_observations(
        SimpleNamespace(raw=SimpleNamespace(headers=object()))
    ) == (False, ())
    secret = "FAKE_COOKIE_EXCEPTION_SECRET"

    class BrokenHeaders:
        def keys(self):
            return ("Set-Cookie",)

        def getlist(self, _name):
            raise RuntimeError(secret)

    response = SimpleNamespace(raw=SimpleNamespace(headers=BrokenHeaders()))
    assert _collect_set_cookie_observations(response) == (False, ())
    assert secret not in caplog.text


def test_cookie_raw_collector_applies_existing_header_count_and_byte_limits():
    from security_scanner.checks.limits import (
        MAX_RESPONSE_HEADER_BYTES,
        MAX_RESPONSE_HEADER_COUNT,
    )
    too_many = ["a=b"] * (MAX_RESPONSE_HEADER_COUNT + 1)
    response = SimpleNamespace(raw=SimpleNamespace(headers=_CookieRawHeaders({"Set-Cookie": too_many})))
    assert _collect_set_cookie_observations(response) == (False, ())
    oversized = "a=" + "v" * MAX_RESPONSE_HEADER_BYTES
    response = SimpleNamespace(raw=SimpleNamespace(headers=_CookieRawHeaders({"Set-Cookie": [oversized]})))
    assert _collect_set_cookie_observations(response) == (False, ())


def _access_result(check_id, **kwargs):
    evidence = EvidenceCollection(
        http_status=kwargs.pop("http_status", 200),
        cors_probe_status=kwargs.pop("cors_probe_status", 204),
        cors_probe_available=kwargs.pop("cors_probe_available", True),
        cors_probe_error=kwargs.pop("cors_probe_error", None),
        cors_headers=kwargs.pop("cors_headers", {}),
        redirect_location_values=kwargs.pop("redirect_location_values", ()),
        redirect_evidence_available=kwargs.pop("redirect_evidence_available", True),
        redirect_request_url=kwargs.pop("redirect_request_url", "https://example.com/a/b?token=hidden"),
    )
    evaluator_type = CORSConfigurationEvaluator if check_id == "cors_misconfiguration" else OpenRedirectEvaluator
    return make_evaluator(check_id, evaluator_type).evaluate(evidence)


def test_cors_wildcard_reports_potential_broad_policy_without_claiming_exploit():
    result = _access_result("cors_misconfiguration", cors_headers={
        "access-control-allow-origin": ("*",),
        "access-control-allow-methods": ("GET",),
        "access-control-allow-headers": ("x-cybershield-audit",),
    })
    assert (result.status, result.severity) == ("warning", "medium")
    assert "لا يثبت وحده استغلالاً" in result.explanation


def test_cors_accepts_test_origin_and_reports_vary_methods_and_headers():
    result = _access_result("cors_misconfiguration", cors_headers={
        "access-control-allow-origin": ("https://cybershield.invalid",),
        "access-control-allow-methods": ("POST, GET",),
        "access-control-allow-headers": ("x-other, X-CyberShield-Audit",),
        "vary": ("Accept-Encoding, Origin",),
    })
    assert result.status == "warning"
    assert "GET=allowed" in result.evidence
    assert "requested-header=allowed" in result.evidence
    assert "Vary-Origin=yes" in result.evidence


def test_cors_credentials_and_wildcard_do_not_claim_credentialed_access():
    result = _access_result("cors_misconfiguration", cors_headers={
        "access-control-allow-origin": ("*",),
        "access-control-allow-credentials": ("true",),
        "access-control-allow-methods": ("GET",),
        "access-control-allow-headers": ("x-cybershield-audit",),
    })
    assert result.status == "warning"
    assert "المتصفحات ترفض استخدام wildcard" in result.explanation
    assert "لا يثبت هذا الطلب نجاح وصول credentialed" in result.explanation


@pytest.mark.parametrize("headers", [
    {},
    {"access-control-allow-origin": ("https://other.invalid",)},
    {"access-control-allow-origin": ("https://cybershield.invalid",), "access-control-allow-methods": ("POST",), "access-control-allow-headers": ("x-cybershield-audit",)},
    {"access-control-allow-origin": ("https://cybershield.invalid",), "access-control-allow-methods": ("GET",), "access-control-allow-headers": ("x-other",)},
])
def test_cors_denied_or_incomplete_preflight_does_not_claim_broad_access(headers):
    assert _access_result("cors_misconfiguration", cors_headers=headers).status == "passed"


@pytest.mark.parametrize("headers", [
    {"access-control-allow-origin": ("*", "https://cybershield.invalid")},
    {"access-control-allow-origin": ("https://cybershield.invalid", "https://other.invalid")},
    {"access-control-allow-origin": ("https://cybershield.invalid, *",)},
    {"access-control-allow-origin": ("https://cybershield.invalid",), "access-control-allow-credentials": ("true", "false")},
])
def test_cors_conflicting_or_invalid_multiple_values_are_not_verified(headers):
    assert _access_result("cors_misconfiguration", cors_headers=headers).status == "not_verified"


def test_cors_does_not_echo_sensitive_or_unexpected_policy_values():
    secret = "CORS_POLICY_SECRET_771"
    result = _access_result("cors_misconfiguration", cors_headers={
        "access-control-allow-origin": (f"{secret}, *",),
    })
    assert result.status == "not_verified"
    assert secret not in repr(result)


@pytest.mark.parametrize("status,error,available", [
    (405, None, True), (None, "timeout", False), (None, "connection", False),
    (None, "internal", False), (204, None, False),
])
def test_cors_unsupported_timeout_and_unavailable_evidence_are_not_verified(status, error, available):
    result = _access_result("cors_misconfiguration", cors_probe_status=status,
                            cors_probe_error=error, cors_probe_available=available)
    assert result.status == "not_verified"


@pytest.mark.parametrize("location", ["../next", "/local/path", "?next=local", "#section"])
def test_open_redirect_relative_locations_resolve_to_same_origin(location):
    result = _access_result("open_redirect", http_status=302,
                            redirect_location_values=(location,))
    assert result.status == "passed"
    assert location not in result.evidence


@pytest.mark.parametrize("location", [
    "https://outside.invalid/path", "http://outside.invalid/path",
    "//outside.invalid/path", "//outside.invalid:8443/path",
])
def test_open_redirect_external_absolute_and_protocol_relative_are_potential_warning(location):
    result = _access_result("open_redirect", http_status=302,
                            redirect_location_values=(location,))
    assert (result.status, result.severity) == ("warning", "medium")
    assert "not" not in result.evidence.lower()
    assert "لم يتم اتباع التحويل" in result.limitations[0]
    assert "hidden" not in repr(result)


@pytest.mark.parametrize("location", ["javascript:alert(1)", "data:text/html,hi"])
def test_open_redirect_non_http_scheme_is_reported_without_following(location):
    result = _access_result("open_redirect", http_status=302,
                            redirect_location_values=(location,))
    assert result.status == "warning"
    assert "scheme خارج HTTP/HTTPS" in result.evidence


@pytest.mark.parametrize("location", ["http://[broken", "", "https://example.com:bad"])
def test_open_redirect_malformed_or_multiple_locations_are_not_verified(location):
    result = _access_result("open_redirect", http_status=302,
                            redirect_location_values=(location,))
    assert result.status == "not_verified"


def test_open_redirect_repeated_location_or_unavailable_raw_evidence_is_not_verified():
    repeated = _access_result("open_redirect", http_status=302,
                              redirect_location_values=("/local", "https://outside.invalid"))
    unavailable = _access_result("open_redirect", http_status=302,
                                 redirect_evidence_available=False)
    assert repeated.status == "not_verified"
    assert unavailable.status == "not_verified"


@pytest.mark.parametrize("location", ["https://bad host/path", r"\\outside.invalid\path"])
def test_open_redirect_malformed_host_or_backslash_is_not_verified(location):
    result = _access_result("open_redirect", http_status=302,
                            redirect_location_values=(location,))
    assert result.status == "not_verified"


def test_open_redirect_skips_non_redirect_response_and_marks_missing_location():
    assert _access_result("open_redirect", http_status=200).status == "skipped"
    assert _access_result("open_redirect", http_status=304,
                          redirect_location_values=("https://outside.invalid",)).status == "skipped"
    assert _access_result("open_redirect", http_status=302).status == "passed"
