# CyberShield — Backend Week 2 Integration Summary

**Owner:** Bilsan — Flask API / Backend integration  
**Review date:** 2026-11-16  
**Branch:** `main`  
**Scope:** Week 2 items from the approved Bilsan four-week plan

## 1. Outcome

The Week 2 Backend integration and API-boundary verification for the seven TLS, redirect, and response-header checks is implemented and covered by the Backend regression suite.

The existing Flask adapter already forwards `include_expanded_checks` to the report engine and returns its report without recalculating finding status, severity, confidence, or evidence. The review found no runtime defect requiring a change to `backend/app.py` or `backend/scanner.py`; the Backend work therefore focused on explicit integration tests and contract documentation rather than duplicating Dalal's check logic.

## 2. Week 2 findings verified at the API boundary

The seven planned Week 2 check IDs are:

| Group | Check ID |
|---|---|
| Certificate validity | `tls_certificate_expiry` |
| Certificate chain | `tls_certificate_chain` |
| Negotiated TLS | `tls_protocol_config` |
| HTTP upgrade | `http_to_https_redirect` |
| Redirect destination | `redirect_destination_safety` |
| Response header | `header_referrer_policy` |
| Response header | `header_permissions_policy` |

The API must preserve each engine finding's original `status`, `severity`, `confidence`, evidence, explanation, recommendation, and limitations. A single evaluator error must not remove the other findings or discard the report. Summary counters continue to count findings only.

## 3. Backend-owned regression coverage added

The following tests were added or extended in `tests/test_api.py`:

- `test_scan_api_preserves_week2_findings_and_partial_results`: verifies that the five foundational and seven Week 2 IDs survive the Flask response, all five statuses remain distinct, and a single error does not drop the other findings.
- `test_scan_api_returns_correlation_generated_by_real_report_engine`: exercises Flask and the real report engine, and asserts that all seven Week 2 IDs and their finding fields are present in the expanded response.
- `test_scan_api_preserves_tls_expiry_outcome_and_other_week2_checks`: covers valid, expired, malformed, and date-parser-error outcomes. It also covers a verified handshake with unavailable chain metadata and missing TLS version/cipher metadata.
- `test_scan_api_keeps_expanded_tls_checks_unverified_after_handshake_failure`: verifies that certificate, chain, and protocol findings remain `not_verified` after a failed handshake while the expanded report remains available.
- `test_scan_api_preserves_week2_redirect_outcomes_without_following_destination`: covers a valid HTTPS redirect, mixed public/private DNS answers, a credential-bearing Location, and a non-redirect response. It verifies that the destination is not followed as a second HTTPS request.
- `test_scan_api_preserves_week2_header_evaluator_results`: covers strict, missing, and unsafe/malformed Referrer-Policy and Permissions-Policy values through Flask and the real report engine.

The 12-finding API-boundary fixture verifies the Week 2 target of five foundational plus seven new findings. The current expanded report engine already contains additional later-week checks; in its real expanded-mode integration test the API receives 30 findings. Flask forwards the engine output unchanged rather than truncating it to 12 or reclassifying later-week findings.

## 4. Existing scanner-owner tests reviewed without modification

The following existing tests were reviewed as supporting evidence and were not edited:

- `tests/test_check_response_evaluators.py`: detailed Referrer-Policy, Permissions-Policy, HTTP-to-HTTPS redirect, and redirect-destination evaluator cases.
- `tests/test_report.py`: expanded TLS metadata and response-header evidence flowing into report findings and summary.
- `tests/test_scanner.py`: TLS certificate verification, expired-certificate rejection, pinned destination behavior, and redirect handling.

The Backend additions verify that the API boundary preserves the report-engine outcomes; they do not reimplement the security evaluators.

## 5. Verification

GitHub Actions run [#54](https://github.com/dalalcoderwitch/CyberShield/actions/runs/43885027429) completed successfully on 2026-11-16 with **1024 passed in 6.71s** at commit `5b58acfabd6888bdc999c8510ac69aa730e43bed`.

This is automated Backend CI evidence. The redirect and TLS API tests use controlled fixtures for external HTTP/DNS dependencies; they are not a claim of exhaustive public-network or production-deployment verification.

## 6. Ownership and scope boundaries

- No files under `security_scanner/` were modified. Dalal remains the owner of scanner collection, evaluator logic, and security rules.
- No files under `mobile/` were modified. Ahmad remains the owner of Flutter models, screens, and mobile test execution.
- No Flutter test or analyzer result is claimed here.
- The Backend did not add its own severity/confidence calculation, redirect-follow behavior, or DNS policy. It preserves the report engine's result contract.

## 7. Backend handoff

The Week 2 API contract and test-plan documentation are updated. The next team integration activity is to keep Flutter consuming the same report contract and to run the mobile verification under Ahmad's ownership. Any future changes to the scanner rules remain with Dalal; any future Flask behavior change must be accompanied by Backend regression tests.
