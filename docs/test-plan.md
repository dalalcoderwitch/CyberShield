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

The report must also include the target URL, scan timestamp, HTTP status when available, a summary of finding statuses, an engine version, and general limitations.

The summary counts must agree with the statuses of the findings.

If the scanner cannot obtain a usable response, header checks must not be marked passed without evidence.

## 6. Automated Test Files

The automated test suite is organized into three files.

### 6.1 API Tests — tests/test_api.py

Six tests are currently collected:

1. test_health_endpoint
2. test_scan_rejects_invalid_json
3. test_scan_requires_authorization
4. test_scan_rejects_disallowed_target
5. test_scan_returns_report
6. test_scan_hides_internal_error

These tests cover the health endpoint, request validation, authorization confirmation, target restrictions, the successful report response, and the hiding of internal errors.

### 6.2 Report Tests — tests/test_report.py

Three tests are currently collected:

1. test_scan_target_returns_complete_report
2. test_failed_connection_does_not_mark_headers_passed
3. test_report_summary_matches_finding_statuses

These tests cover the report schema, failure behavior, and consistency between findings and summary counts.

### 6.3 Scanner Tests — tests/test_scanner.py

Fourteen tests are currently collected:

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

These tests provide coverage of individual connection and TLS properties. They do not prove the complete scanner path from DNS validation through the pinned outbound connection, or establish behavior in every production network environment.

Automated mocked regression tests also verify that a validated DNS result is reused without a second lookup, that prohibited IPv4 and IPv6 destinations are rejected while a public IPv6 address is accepted, and that redirects are not followed automatically. These tests do not constitute live-network verification.

A manual request to a public website is a smoke test only. It is not a substitute for automated regression tests or a controlled security test environment.

The current test suite must therefore be described as a development baseline, not a complete security assessment.

## 8. Additional Tests Required

The following cases remain to be implemented or independently verified:

- Expired TLS certificates and additional certificate-validation edge cases.
- End-to-end controlled verification of the scanner's DNS-validation-to-pinned-connection flow, including the actual socket peer IP, received SNI, and hostname validation in one test. Existing tests cover parts of this flow separately or intercept before socket connection.
- Slow responses and responses with missing or misleading Content-Length headers.
- Chunked responses and response-size limits.
- Cleanup of response and session resources after failures.
- DNS failures, empty results, simulated DNS timeouts, and DNS-capacity exhaustion are covered by automated tests. Additional resolver exception variants and real operating-system DNS behavior remain outstanding.
- Duplicate or conflicting security headers.
- Automated API tests cover malformed JSON, invalid request fields, request-size limits, and unsupported HTTP methods; deployed proxy limits still require separate verification.
- Multi-process and shared rate-limit behavior, including trusted-proxy source identification. The current automated tests cover only the in-process limit.
- Real-network deadline behavior under slow DNS, connection, and read conditions. Current tests cover injected deadlines and simulated slow DNS.
- Confirmation that unexpected exceptions do not expose stack traces or sensitive details.
- Regression tests ensuring rejected targets never cause outbound requests.

These cases must remain marked as outstanding until they have been implemented, executed, and reviewed.

## 9. Test Execution

Run the complete automated suite from the project root using:

.\.venv\Scripts\python.exe -m pytest

List collected tests without executing them using:

.\.venv\Scripts\python.exe -m pytest --collect-only -q

The current baseline is 102 tests across the three test files. The latest full execution completed with 102 passed.

A test collection count alone does not indicate that the tests passed. Record the actual execution result separately.

## 10. Current Acceptance Criteria

- The current automated suite contains 102 tests; the latest full execution completed with 102 passed.
- The test count must be updated whenever tests are added or removed.
- All current automated tests pass.
- The test plan distinguishes mocked behavior from real network verification.
- Known scanner limitations are explicitly documented.
- Missing evidence is never treated as a successful check.
- Additional security cases remain tracked until they are tested and reviewed.
- The report summary matches the statuses of its findings.
- Rejected targets do not trigger outbound HTTP requests.

The 23-test baseline is not proof that every security requirement has been satisfied.

CyberShield Project 1 provides a limited preliminary assessment of selected HTTPS and HTTP security indicators. It is not a full penetration test, a security certification, or a guarantee that a website is secure.