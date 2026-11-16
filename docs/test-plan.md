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

The API test file also covers request-size and method errors, rate limiting, scan capacity, deadlines, CORS, and safe error handling. The test `test_scan_api_returns_correlation_generated_by_real_report_engine` exercises the Flask route and Backend adapter with the real report and correlation engine; only the external HTTP response and DNS evaluators are isolated with fixtures. It verifies that a correlation generated from actual cookie-check findings reaches the API response without being counted as a finding. The scanner test `test_all_correlation_items_match_the_versioned_json_contract` checks all seven rules against the exact nine-field JSON schema, field types, catalog version, and JSON round-trip serialization.

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

## 9. Test Execution

Run the complete automated suite from the project root using:

.\.venv\Scripts\python.exe -m pytest

List collected tests without executing them using:

.\.venv\Scripts\python.exe -m pytest --collect-only -q

The full suite was executed through GitHub Actions on 2026-11-16
at implementation commit `5c32b096324d5ba8010a6ef6298a7e7ffac62a24`.
GitHub Actions run [#30](https://github.com/dalalcoderwitch/CyberShield/actions/runs/43875434967)
completed successfully with `1009 passed in 6.02s`. This run includes
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

- The latest recorded implementation run completed with 1009 passed in 6.02 seconds on implementation commit `5c32b096324d5ba8010a6ef6298a7e7ffac62a24` (GitHub Actions run [#30](https://github.com/dalalcoderwitch/CyberShield/actions/runs/43875434967)); later code changes require a new successful run.
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