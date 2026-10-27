# CyberShield — Test Plan

## 1. Purpose

This document defines the planned tests for the CyberShield
scanner and API.

Passing tests does not prove that the scanner is completely secure.

## 2. Automated Tests Already Available

The current test suite contains 23 tests across three files:

- `tests/test_scanner.py`
- `tests/test_report.py`
- `tests/test_api.py`

### Scanner tests

- Reject HTTP URLs.
- Reject localhost and loopback targets.
- Reject private DNS addresses.
- Reject DNS results containing both public and private addresses.
- Accept a mocked public DNS address.
- Reject URLs containing credentials.
- Reject unsupported ports.
- Avoid HTTP requests when DNS resolves to a private address.
- Verify that redirects are not followed automatically.
- Verify that a simulated TLS error does not produce a passed result.
- Check missing, present, and invalid security-header values.

### Report tests

- Verify the report structure and required finding identifiers.
- Verify that a failed connection does not mark unverified headers as passed.

### API tests

- Verify `GET /api/v1/health`.
- Reject invalid request data.
- Require explicit authorization confirmation.
- Reject disallowed targets.
- Verify successful report responses using mocked scan results.
- Avoid exposing internal exception details to API clients.

## 3. Manual Test Already Performed

A request to `https://example.com` returned HTTP 200
with no reported connection or TLS error.

The API also returned a report containing five findings.

A request targeting `https://127.0.0.1` was rejected
with HTTP 403 and error code `TARGET_NOT_ALLOWED`.

These are individual manual tests, not proof of complete SSRF protection.

## 4. Additional Tests Required

The following cases require further testing or review:

- DNS resolution failure.
- Connection timeout.
- TLS certificate verification failure using a controlled test server.
- Connection errors and incomplete responses.
- Redirect responses to internal or private destinations.
- DNS rebinding and changes in DNS results.
- IPv4 and IPv6 edge cases.
- Verification that the connected IP is the validated IP.
- Malformed URLs and unusual hostname formats.
- Request size, response-header size, and connection resource limits.
- Consistent API error responses for invalid and disallowed targets.

Mocked tests must be clearly distinguished from real network tests.

## 5. Security Testing Rules

- Do not test against targets without authorization.
- Keep TLS certificate verification enabled.
- Do not follow redirects without validating the destination.
- Reject loopback, private, link-local, and other disallowed addresses.
- Lack of evidence must never be reported as passed.
- Do not expose internal exception details or sensitive data.
- Do not claim that the scanner proves a website is fully secure.

## 6. Result Statuses

- `passed`: The specific check passed based on available evidence.
- `warning`: A finding needs review.
- `not_verified`: Available evidence is insufficient.
- `error`: The check failed to execute correctly.
- `skipped`: The check was deliberately not run because of a defined constraint.

## 7. Limitations

The existing tests include mocked network behavior.
The live request tested only one public website and one response.

Further security testing is required before considering
the scanner ready for production use.

## 8. Execution Command

Run the test suite from the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest
