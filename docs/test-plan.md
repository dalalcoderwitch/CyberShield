# CyberShield — Test Plan

## 1. Purpose

This document defines the current testing strategy for CyberShield Project 1.

The purpose of testing is to verify the Flask API, report structure, scanner decision logic, and security restrictions.

The current test suite is a development baseline. Passing the tests does not certify that the scanner is completely secure and does not prove that a target website is secure.

## 2. Project Scope

The initial version checks the following five items:

1. https_connection
2. header_hsts
3. header_csp
4. header_x_content_type_options
5. header_x_frame_options

The application uses Flutter for the mobile interface, Flask for the API, Python Requests for HTTP communication, and pytest for automated testing.

No database, report history, login testing, password guessing, MFA verification, or session-management testing is included in Project 1.

The API endpoints are:

- GET /api/v1/health
- POST /api/v1/scan

A scan request uses the following JSON structure:

{"target_url": "https://example.com", "authorization_confirmed": true}

## 3. Security Requirements

The scanner must follow these requirements:

- Accept only supported HTTPS targets on port 443.
- Reject URLs containing embedded credentials.
- Reject loopback, private, link-local, and other non-global destination IP addresses.
- Reject DNS results if any returned address is not permitted.
- Validate DNS results before making an outbound request.
- Do not automatically follow redirects.
- Preserve TLS certificate and hostname verification.
- Apply connection and read timeouts.
- Avoid downloading unbounded response bodies.
- Disable implicit proxy configuration inherited from the environment unless explicitly designed and secured.
- Do not expose internal exception details through API responses.
- Do not log passwords, session tokens, or sensitive cookies.
- Treat an authorization confirmation as necessary but not sufficient to establish that a destination is safe to scan.

Security restrictions must be tested directly. A rejected destination must not trigger an HTTP request.

## 4. Finding Statuses

The report uses the following statuses:

- passed: The specific check has sufficient evidence to satisfy its defined condition.
- warning: The observed evidence indicates a condition that needs review.
- not_verified: There is insufficient evidence to determine the result.
- error: The check encountered an execution error.
- skipped: The check was not executed because a defined restriction or condition prevented it.

A missing header, failed connection, or insufficient response must never be reported as passed.

A report with status completed means that report generation finished. It does not mean every security check passed or that the target is secure.

### 4.1 Severity and Confidence

`severity` describes the potential security impact of an observation,
not whether the check executed successfully.

- `info`: informational or operational context; no weakness is established.
- `low`: a hardening observation with limited potential impact.
- `medium`: a security configuration observation whose impact depends on context.
- `high`: a potentially significant impact requiring clear evidence and defined criteria.

`high` is allowed by the result contract but is not currently assigned
by the five foundational checks.

`confidence` describes the strength of the evidence:

- `low`: limited evidence or insufficient basis for a strong conclusion.
- `medium`: direct evidence exists, but interpretation or coverage is limited.
- `high`: clear, direct evidence supports the specific condition tested.

Tests must treat severity, confidence, and status as independent fields.
A change in one field must not silently change the meaning of another.

## 5. Expected Report Structure

Each finding must include:

- check_id
- title
- status
- severity
- confidence
- evidence
- explanation
- recommendation
- limitations

The report must also include the target URL, scan timestamp, HTTP status when available, a summary of finding statuses, an engine version, and general limitations. Expanded mode additionally includes `correlations` (an array that may be empty) and `correlation_rules_version`; correlations are contextual metadata and are excluded from finding and summary counts. Base mode omits both fields.

The summary counts must agree with the statuses of the findings.

If the scanner cannot obtain a usable response, header checks must not be marked passed without evidence.

## 6. Automated Test Files

The automated test suite is organized into four files.

### 6.1 API Tests — tests/test_api.py

Representative API tests include:

1. test_health_endpoint
2. test_scan_rejects_invalid_json
3. test_scan_requires_authorization
4. test_scan_rejects_disallowed_target
5. test_scan_returns_report
6. test_scan_hides_internal_error

These tests cover the health endpoint, request validation, authorization confirmation, target restrictions, the successful report response, and the hiding of internal errors. Additional API regression coverage includes:

- `test_scan_maps_detailed_resolution_errors_to_api_responses`, parameterized across the six detailed resolver outcomes.
- `test_scan_passes_detailed_resolved_target_to_engine`, verifying that the same validated target is passed to the engine without a second DNS lookup.

The API test file also covers request-size and method errors, rate limiting, scan capacity, deadlines, CORS, and safe error handling. The test `test_scan_api_returns_correlation_generated_by_real_report_engine` exercises the Flask route and Backend adapter with the real report and correlation engine; only the external HTTP response and DNS evaluators are isolated with fixtures. It verifies that all seven Week 2 TLS, redirect, and header check IDs and their finding fields reach the API response, and that a correlation generated from actual cookie-check findings reaches the same response without being counted as a finding. The scanner test `test_all_correlation_items_match_the_versioned_json_contract` checks all seven rules against the exact nine-field JSON schema, field types, catalog version, and JSON round-trip serialization.

The Week 2 Backend integration regression `test_scan_api_preserves_week2_findings_and_partial_results` sends the five foundational and seven Week 2 IDs through the Flask route and checks that finding fields, all five statuses, and summary counts are preserved unchanged. Its controlled engine fixture sets one Week 2 result to `error` and verifies the remaining eleven findings remain in the response. Existing report/scanner tests separately exercise the underlying TLS, redirect, and header evaluators.

The parameterized API integration regression `test_scan_api_preserves_tls_expiry_outcome_and_other_week2_checks` exercises valid, expired, malformed, and date-parser-error outcomes through Flask and the real report engine. It also exercises a verified handshake with unavailable chain metadata and missing negotiated TLS version/cipher fields, checking that only the affected TLS check becomes `not_verified` while the remaining TLS findings and report summary are retained.

The API regression `test_scan_api_keeps_expanded_tls_checks_unverified_after_handshake_failure` verifies that a failed TLS handshake leaves certificate expiry, chain, and protocol checks as `not_verified`, while the expanded report, header outcomes, and summary are still returned.

The parameterized Flask/report integration regression `test_scan_api_preserves_week2_redirect_outcomes_without_following_destination` checks a valid HTTPS redirect, mixed public/private destination DNS answers, a credential-bearing Location, and a non-redirect response. It verifies the separate `http_to_https_redirect` and `redirect_destination_safety` outcomes, confirms no destination DNS lookup is attempted for malformed credential-bearing Location, and ensures the destination is not followed by a second HTTPS request.

The parameterized API regression `test_scan_api_preserves_week2_header_evaluator_results` runs the real report engine through Flask with strict, missing, and unsafe/malformed values for Referrer-Policy and Permissions-Policy. It checks status/severity preservation, summary consistency, and that raw header values are not echoed into report evidence.

### 6.2 Report Tests — tests/test_report.py

Representative report tests include:

1. test_scan_target_returns_complete_report
2. test_failed_connection_does_not_mark_headers_passed
3. test_report_summary_matches_finding_statuses

These tests cover the report schema, failure behavior, and consistency between findings and summary counts.

### 6.3 Scanner Tests — tests/test_scanner.py

Representative scanner tests include:

1. test_http_url_warns
2. test_missing_headers_warn
3. test_present_headers
4. test_invalid_header_values_warn
5. test_reject_unsafe_urls
6. test_reject_private_dns_address
7. test_accept_public_dns_address
8. test_reject_url_with_credentials
9. test_reject_unsupported_port
10. test_reject_mixed_public_and_private_dns_addresses
11. test_private_dns_address_never_triggers_http_request
12. test_redirect_is_not_followed
13. test_tls_error_does_not_pass_https
14. test_request_pins_validated_ip_and_preserves_tls_hostname

These tests cover URL restrictions, header evaluation, DNS filtering, redirect handling, TLS failure behavior, and the scanner's configured connection behavior.

### 6.4 Backend Network Integration Tests — tests/test_backend_network_integration.py

The Backend-owned integration file covers bounded response sampling and the
Flask-to-scanner network boundary without changing scanner implementation files:

- `test_bounded_identity_sample_handles_chunked_body_without_content_length`
- `test_bounded_identity_sample_never_exceeds_limit_for_large_chunks`
- `test_bounded_identity_sample_marks_truncated_content_length_incomplete`
- `test_response_and_session_are_closed_after_body_read_failure`
- `test_flask_expanded_scan_pins_dns_ip_and_verifies_tls_on_real_socket`

The Flask integration uses a controlled DNS fixture and a local TLS server. It
checks the pinned socket peer, SNI, certificate hostname validation, a mismatched
hostname, chunked response sampling capped at 16 KiB, and read-timeout behavior.
It is a controlled local integration test rather than a public-network test.

The existence of a test does not automatically establish that the underlying security property has been proven against a real network environment.

## 7. Mocked Tests and Real-Environment Tests

Mocked automated tests are useful for validating application logic without depending on external websites.

However, mocked responses cannot independently prove that a real connection:

- Uses only the validated IP address.
- Preserves the intended TLS Server Name Indication (SNI).
- Validates the certificate against the requested hostname.
- Resists DNS rebinding and time-of-check/time-of-use attacks.
- Rejects every unsafe redirect or destination change.

The test named test_request_pins_validated_ip_and_preserves_tls_hostname verifies the configured connection URL, adapter hostname, SNI parameter, and certificate hostname parameter.

The test named test_request_uses_pinned_ip_and_tls_hostname_through_http_stack follows Requests and urllib3 to the connection boundary, but deliberately intercepts before opening a network socket.

The test named test_real_tls_rejects_untrusted_self_signed_certificate performs local TLS handshakes and records the SNI values received by the local server. It verifies the expected values (localhost, wrong.example, and localhost) while checking certificate trust and hostname matching.

The Backend-owned test `test_flask_expanded_scan_pins_dns_ip_and_verifies_tls_on_real_socket`
extends this proof through the Flask route and report adapter. It uses a controlled
local DNS answer and a real local TLS socket, records the requested pinned address
and the connected peer, verifies the SNI value and certificate hostname, and checks
that a hostname mismatch does not produce a successful HTTPS finding. This is a
controlled integration test: it does not claim to validate public recursive DNS or
an external production network.

Together, these tests exercise the complete DNS-validation-to-pinned-socket-to-TLS path through Flask in a controlled local environment, including certificate hostname mismatch rejection. They do not establish behavior with public recursive DNS, DNS rebinding in production, every IPv4/IPv6 network path, or arbitrary external production networks.

Automated mocked regression tests also verify that a validated DNS result is reused without a second lookup, that prohibited IPv4 and IPv6 destinations are rejected while a public IPv6 address is accepted, and that redirects are not followed automatically. These tests do not constitute live-network verification.

A manual request to a public website is a smoke test only. It is not a substitute for automated regression tests or a controlled security test environment.

The current test suite must therefore be described as a development baseline, not a complete security assessment.

## 8. Remaining Verification Work

The following points are covered by the current automated suite:

- Local TLS tests reject an untrusted self-signed certificate and an expired certificate, and verify hostname mismatch behavior.
- A Flask-level controlled integration test follows validated DNS data through the pinned IP socket, observes the connected peer and SNI, verifies the matching certificate hostname, and rejects a mismatched hostname.
- The chunked-response integration sends a paced body without Content-Length; the scanner reads no more than 16 KiB, closes the response after reaching the cap, and does not expose the raw sample in the API report.
- A delayed local response withholds its first body byte beyond the scanner's two-second read timeout; the sample remains incomplete rather than being treated as full evidence.
- A truncated response with a declared Content-Length is treated as incomplete, and response/session cleanup is checked after the body read fails.
- Existing local TLS scanner tests reject responses with excessive header counts and an oversized header line. Existing tests also cover duplicate security headers, disallowed IPv4/IPv6 destinations, DNS failure/capacity, redirects, and deadline handling.

The following operational and deployment cases remain outside the proof provided by this test suite:

- Public recursive DNS and operating-system resolver behavior under production conditions.
- Full live-network verification across external IPv4 and IPv6 destinations, including DNS rebinding and time-of-check/time-of-use behavior.
- Multi-process/shared rate limiting and trusted reverse-proxy source identification; the current Flask rate limit is in-process.
- Deployed reverse-proxy request-body and response-header limits.
- Broader certificate-chain edge cases and real-world read/connect timeout behavior under varied network conditions.

These are deployment or broader security-validation items; they must not be represented as established merely because the automated suite passes.

### 8.1 Flutter integration review and Week 1 scope boundary — 2026-11-16

The current Flutter client is wired to the basic Flask scan contract:

- `mobile/lib/services/scan_api_service.dart` sends
  `POST /api/v1/scan` with `target_url`,
  `authorization_confirmed`, and requests the expanded response option.
- `ScanReport.fromJson()` reads the base report fields, summary, and findings;
  `ReportScreen` renders the report and its individual findings.
- Mobile tests cover request fields, API response parsing, invalid responses,
  timeouts, service errors, the authorized scan flow, and report rendering.
  These are primarily mocked/service-level tests, not a live deployed
  Flutter-to-Flask smoke test.

The absence of top-level correlation parsing and display is **not a Week 1
acceptance failure** under the approved four-week Bilsan plan. That plan places
the integration of Correlation output and coordination with its Flutter display
in Week 4 (29 November). The first-week acceptance criteria are the stable
Health/Scan API and JSON contract, authorization and target validation,
resource controls, and the basic scan journey reaching Flutter. Backend
correlation output is already exposed and covered by Backend/API tests as
preparatory integration, but its dedicated mobile model, UI, and widget tests
belong to the later correlation milestone.

No Flutter GitHub Actions workflow is currently configured, so this repository
does not provide CI evidence for `flutter test` or `flutter analyze`. The
mobile source and its tests were reviewed, but these Flutter commands have not
been reported as executed here. This is a mobile verification follow-up, not a
reason to keep Bilsan's Week 1 Backend/API scope open. A live deployed
Flutter-to-Flask smoke test also remains a separate integration validation.

**Week 1 Backend decision:** Bilsan's Week 1 scope is complete: the required
API behavior, validation and target restrictions, resource/response limits,
controlled DNS-to-pinned-IP-to-TLS integration evidence, basic Flutter API
contract path, automated Backend regression suite, Git review, and
documentation are present on `main`. This does not mean the four-week project
or the later correlation/mobile milestones are complete.

**Week 2 Backend decision — 2026-11-16:** Bilsan's Week 2 API-integration scope is
complete on `main`. The seven planned TLS, redirect, and response-header findings
are covered at the Flask/report boundary; single-check failures preserve the
remaining report, summary counts are checked, and redirect destinations are not
followed by the API. The latest implementation/integration suite result is 1024
passed (GitHub Actions run #54). The Backend changes are limited to
`tests/test_api.py`, `docs/api-contract.md`, `docs/test-plan.md`, and
`docs/backend-week-2-summary.md`. No `security_scanner/` or `mobile/` files were
changed. This closes Bilsan's Week 2 Backend work; scanner-owner sign-off and
Flutter-owned test execution remain with Dalal and Ahmad respectively, and live
public-network/deployment verification remains outside the automated test proof.

## 9. Test Execution

Run the complete automated suite from the project root using:

.\.venv\Scripts\python.exe -m pytest

List collected tests without executing them using:

.\.venv\Scripts\python.exe -m pytest --collect-only -q

The full suite was executed through GitHub Actions on 2026-11-16
at implementation and Week 2 integration commit `5b58acfabd6888bdc999c8510ac69aa730e43bed`.
GitHub Actions run [#54](https://github.com/dalalcoderwitch/CyberShield/actions/runs/43885027429)
completed successfully with `1024 passed in 6.71s`. This run includes
the Week 2 Flask pass-through and real report-engine assertions, valid,
expired, malformed, and evaluator-error certificate-date outcomes, a verified
handshake with unavailable chain metadata, missing negotiated TLS metadata,
handshake failure, four redirect policy scenarios, and three header policy
scenarios. This run includes
the Flask-to-report-engine correlation integration regression, the
seven-rule correlation JSON schema/serialization regression, exact
Flask request-body boundary tests, bounded chunked-response sampling,
a delayed-body read-timeout test, truncated-body handling, resource
cleanup after a body-read failure, and the controlled
Flask-to-real-local-TLS integration test. The controlled TLS integration
uses test DNS data and a local socket; it is not a live public-DNS or
external-network test. Re-run the workflow after subsequent code changes
and update this record with the newest run.

A test collection count alone does not indicate that the tests passed. Record the actual execution result separately.

## 10. Current Acceptance Criteria

- The latest recorded implementation and Week 2 integration run completed with 1024 passed in 6.71 seconds on commit `5b58acfabd6888bdc999c8510ac69aa730e43bed` (GitHub Actions run [#54](https://github.com/dalalcoderwitch/CyberShield/actions/runs/43885027429)); later code changes require a new successful run.
- The test count must be updated whenever tests are added or removed.
- All current automated tests pass.
- The test plan distinguishes mocked behavior from real network verification.
- Known scanner limitations are explicitly documented.
- Missing evidence is never treated as a successful check.
- Additional security cases remain tracked until they are tested and reviewed.
- The report summary matches the statuses of its findings.
- Rejected targets do not trigger outbound HTTP requests.

Passing the automated suite is not proof that every security requirement has been satisfied; controlled real-network and deployment verification remain separate requirements.

CyberShield Project 1 provides a limited preliminary assessment of selected HTTPS and HTTP security indicators. It is not a full penetration test, a security certification, or a guarantee that a website is secure.