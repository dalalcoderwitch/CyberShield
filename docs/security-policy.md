# CyberShield Security Policy

**Project:** CyberShield — Project 1
**Document version:** 1.1
**Status:** Development policy; implementation review required
**Scope:** Authorized website security assessment

## 1. Purpose

This document defines the security requirements for the CyberShield
scanner, Flask API, and their network interactions.

It distinguishes required security controls from controls that have
been implemented and tested.

A written policy or passing unit tests alone do not prove that the
application is secure.

The scanner must not be exposed as a public service until its target
policy, connection behavior, resource limits, and security tests
have been reviewed.

## 2. Authorized Scanning

- Scan only websites owned by the user or covered by explicit,
  appropriate authorization.
- Require the user to confirm authorization before submitting a scan.
- Treat authorization confirmation as an acknowledgement, not as
  a technical security control.
- Reject targets that violate the server-side target policy.
- Do not request, store, or transmit login credentials.
- Do not perform password guessing, login attempts, or exploit testing.
- Do not crawl websites or discover additional targets in Project 1.
- Limit the scanner to the five agreed checks.
- Do not describe a website as completely secure based on these checks.

## 3. URL Validation

The target URL must be validated by the server before a network request.

The current Project 1 policy is:

- Accept HTTPS URLs only.
- Allow only the default HTTPS port or explicit port 443.
- Reject user information embedded in URLs, including usernames
  and passwords.
- Reject malformed URLs, unsupported ports, control characters,
  and ambiguous URL forms.
- Reject localhost and disallowed internal hostnames.
- Normalize and validate hostnames before resolving them.
- Apply the same destination policy to IPv4 and IPv6.
- Reject a target if any resolved address is not permitted.
- Treat DNS failures, empty DNS results, and excessive DNS results
  as reasons to reject the target.

URL syntax validation alone does not establish that a target is safe.

## 4. Server-Side Request Forgery (SSRF) Protection

SSRF prevention is a critical requirement.

### 4.1 Disallowed destinations

The target policy must block, at minimum:

- IPv4 loopback addresses.
- IPv6 loopback addresses.
- Private IPv4 networks.
- IPv6 unique-local addresses.
- Link-local addresses.
- Unspecified and multicast addresses.
- Other non-global or special-purpose addresses prohibited
  by the project's network policy.
- Local and internal hostnames.
- Cloud metadata services and their known hostnames.
- Internal service endpoints that must not be reachable by the scanner.

Examples of addresses that must be rejected include:

- `127.0.0.1`
- `10.0.0.1`
- `172.16.0.1`
- `192.168.1.1`
- `169.254.169.254`
- `::1`
- `fc00::1`
- `fe80::1`

This list is illustrative, not exhaustive.

### 4.2 DNS validation and connection pinning

The scanner must validate DNS results before connecting.

It must also guarantee that the actual network connection uses an
address that passed the target policy.

A DNS lookup followed by an independent, unchecked lookup by the HTTP
client is insufficient because the address can change between
validation and connection.

The connection implementation must:

- Connect only to a validated destination IP.
- Preserve the original hostname for the HTTP Host header.
- Preserve appropriate TLS SNI and hostname certificate verification.
- Keep certificate verification enabled.
- Ensure retries and fallback connections cannot bypass target policy.

The implementation must be verified by tests that establish which
destination address the connection actually uses.

If this guarantee cannot be established, arbitrary user-supplied
targets must not be scanned by the deployed service.

### 4.3 Defense in depth

Application-level validation is not the only required defense.

Before deployment beyond controlled development, review network-level
restrictions that prevent the scanner from reaching sensitive internal
services and metadata endpoints.

## 5. HTTP and TLS Security

- Keep TLS certificate verification enabled.
- Never use `verify=False` in application scanning code.
- Use HTTPS only for target requests in the initial implementation.
- Use the approved HTTPS port.
- Do not automatically follow redirects.
- Do not send authentication credentials to target websites.
- Do not inherit unexpected proxy configuration from the environment.
- Do not retry a request through an unvalidated destination.
- Treat TLS verification failures as unsuccessful TLS checks.

A successful HTTPS connection means only that the specific connection
check passed. It does not prove that the website is free of
vulnerabilities.

## 6. Redirect Handling

The initial implementation must not follow redirects automatically.

A redirect response may be recorded, but it must not be treated as
permission to contact the destination.

If redirect checking is added in the future:

1. Parse the Location value safely.
2. Resolve relative destinations correctly.
3. Validate the destination URL independently.
4. Resolve and validate its destination addresses.
5. Ensure the connection uses a validated address.
6. Reject internal, private, link-local, and other disallowed targets.
7. Enforce a small maximum redirect count.
8. Detect redirect loops.
9. Keep TLS verification enabled for HTTPS destinations.

Every redirect destination must pass the policy before a new request.

## 7. Network and Resource Limits

### 7.1 Timeouts

The scanner configures an HTTP connection timeout of 3 seconds
and a read timeout of 5 seconds.

DNS resolution is performed in a bounded background worker with
a 2-second wait limit and a maximum of four concurrent lookups.

When the wait limit expires, the target is rejected. However, the
underlying getaddrinfo operation cannot be forcibly cancelled by
this timeout wrapper. A timed-out DNS operation may continue in
the background and retain a lookup slot until it finishes.

These settings do not guarantee a maximum duration for the entire
scan. The DNS timeout test currently uses a simulated slow lookup;
real operating-system DNS behavior still requires controlled
integration testing.

A total scan deadline and further resource controls must be
evaluated before deployment.

### 7.2 Response handling

The scanner needs response headers for the agreed checks; it does not
need to download an entire web page.

The implementation should:

- Avoid reading response bodies unless strictly necessary.
- Close responses and sessions reliably.
- Bound response resources, including headers and any data read.
- Avoid processing large or unnecessary response bodies.
- Handle malformed or incomplete responses safely.

The current implementation uses streaming and closes responses
without intentionally reading the response body. Explicit maximum
resource limits still require review and testing.

### 7.3 Request volume

Before deployment, define and enforce:

- A maximum number of concurrent scans.
- A request rate limit appropriate to the deployment.
- A maximum total duration for a scan.
- Appropriate connection resource limits.

These controls must not be described as implemented until they exist
in the application or its deployment environment and have been tested.

## 8. Reporting and Result Accuracy

Each finding must use the agreed result model:

- `check_id`
- `title`
- `status`
- `severity`
- `confidence`
- `evidence`
- `explanation`
- `recommendation`
- `limitations`

Allowed statuses:

- `passed`: The specific check passed according to its documented rule.
- `warning`: An observation requires review.
- `not_verified`: Evidence is insufficient to establish the result.
- `error`: The check failed during execution or processing.
- `skipped`: The check was intentionally not executed because of
  a defined constraint.

Severity values:

- `info`
- `low`
- `medium`
- `high`

Confidence values:

- `low`
- `medium`
- `high`

Rules:

- Missing evidence must never be reported as `passed`.
- An unsuccessful connection must not cause response headers to be
  reported as missing.
- Distinguish between a failed check and a check that could not be run.
- A present header does not prove its complete configuration is secure.
- Recommendations must be relevant to the evidence collected.
- Findings must describe only the response and checks actually examined.
- Explain limitations that materially affect the conclusion.
- Do not claim that CyberShield performs a complete penetration test.

## 9. Security Header Rules

The initial scanner checks:

1. `https_connection`
2. `header_hsts`
3. `header_csp`
4. `header_x_content_type_options`
5. `header_x_frame_options`

### HSTS

Check for the presence of Strict-Transport-Security and validate
the basic max-age rule documented by the scanner.

Do not assume every site requires identical optional directives.

### CSP

Check for the enforced Content-Security-Policy header.

Distinguish it from Content-Security-Policy-Report-Only.

The initial implementation must not claim that a policy is effective
or strong merely because a header is present.

### X-Content-Type-Options

Check for the expected `nosniff` value.

### X-Frame-Options

Check the supported `DENY` and `SAMEORIGIN` values.

Interpret missing headers as observations requiring context, not
as proof of a confirmed vulnerability.

A suitable Content Security Policy using frame-ancestors may affect
how framing protections should be assessed.

## 10. Error Handling and Logging

- Return structured API error responses.
- Do not expose stack traces, internal paths, secrets, or sensitive
  implementation details to API clients.
- Log only information needed for safe diagnosis.
- Avoid logging credentials, session tokens, or full URLs containing
  sensitive query parameters.
- Sanitize untrusted data before including it in log messages.
- Distinguish invalid targets, TLS failures, DNS failures, timeouts,
  and other connection errors where possible.
- Never turn an exception into a successful finding.
- Avoid storing scan reports unless a documented requirement exists.

The initial project does not require a database or scan history.

## 11. API Security

The Flask API must:

- Validate JSON request structure and field types.
- Require `target_url` and `authorization_confirmed`.
- Reject unsupported or malformed target URLs.
- Apply target policy before making a target request.
- Return a consistent error structure.
- Limit request body size.
- Avoid leaking internal exceptions in client responses.

The current API configures a request body size limit. Rate limiting,
concurrency limits, and the deployed network policy require separate
implementation or deployment controls.

The local development server is for development only and must not
be treated as a production deployment.

## 12. Privacy

- Do not request website account credentials.
- Do not store cookies, session tokens, or target authentication data.
- Do not persist scan history in Project 1.
- Do not collect more information than required for the assessment.
- Avoid exposing sensitive URL components in reports or logs.
- Return only the information required by the agreed report schema.

## 13. Required Security Tests

Security tests must include both mocked unit tests and controlled
integration tests where appropriate.

Required cases include:

- Reject HTTP and unsupported schemes.
- Reject credentials embedded in URLs.
- Reject unsupported ports.
- Reject localhost and loopback addresses.
- Reject private, link-local, and prohibited IPv6 addresses.
- Reject mixed DNS results containing permitted and prohibited IPs.
- Reject DNS resolution failures.
- Verify the actual connection uses a validated address.
- Verify TLS hostname and certificate validation.
- Verify that a TLS error cannot produce a passed result.
- Verify that redirects are not followed automatically.
- Verify that any future redirect destination is checked before access.
- Test timeouts and connection failures.
- Test malformed and incomplete responses.
- Verify responses and sessions are closed.
- Test limits on request size and response resources.
- Verify exceptions do not reveal internal details to API clients.
- Verify unavailable header checks are not falsely reported as passed.

Mocked tests prove the behavior of the mocked scenario; they do not
prove the real network connection is safe.

## 14. Current Implementation Status

The following items have been implemented or observed during development:

- HTTPS-only URL validation.
- Restriction to the default HTTPS port or port 443.
- Rejection of URLs containing credentials.
- DNS validation that rejects non-global resolved addresses.
- A request configured with TLS verification enabled.
- Automatic redirect handling disabled.

These implementation observations do not independently prove that
the actual network connection always uses the validated destination
IP or that every DNS rebinding scenario is prevented. These properties
remain subject to controlled integration testing and security review.
- Connection and read timeouts configured.
- Streaming responses that are closed without intentionally
  reading their bodies.
- Unit tests for target validation, selected SSRF cases, redirects,
  TLS error handling, reporting, and API behavior.
- A manual successful request to `https://example.com`.
- A manual API rejection of `https://127.0.0.1`.

The following items remain to be verified or implemented:

- Robust proof that the actual connected IP is the validated IP
  while preserving TLS hostname verification.
- Explicit handling of all prohibited metadata hostnames.
- Controlled integration tests for real TLS certificate failures.
- DNS failure, timeout, and additional IPv4/IPv6 edge cases.
- A total scan deadline.
- Explicit resource limits and tests appropriate to deployment.
- Concurrency and request rate limiting.
- A review of safe logging and sensitive URL handling.
- A complete security review of the connection implementation.

Passing the current test suite does not resolve these remaining items.

## 15. Development and Release Rules

- Keep the scanner in controlled development while critical network
  safety checks remain unverified.
- Do not expose arbitrary target scanning to the public internet
  before completing the required security review.
- Do not introduce extra scanning features outside Project 1 scope.
- Review security-sensitive changes before merging them.
- Run the automated test suite after relevant changes.
- Update this policy when security behavior changes.
- Coordinate API contract changes with the Flutter and Flask owners.
- Record known limitations rather than claiming unverified controls
  are complete.

## 16. References

OWASP Server Side Request Forgery Prevention Cheat Sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Requests API documentation:
https://requests.readthedocs.io/en/stable/api/

Requests Quickstart — redirects and timeouts:
https://requests.readthedocs.io/en/stable/user/quickstart/

## 17. Review Checklist

- [ ] Target policy reviewed.
- [ ] Actual destination IP behavior verified.
- [ ] TLS hostname and certificate validation verified.
- [ ] Redirect behavior verified.
- [ ] Resource limits reviewed.
- [ ] Logging and privacy reviewed.
- [ ] Required security tests reviewed.
- [ ] API error handling reviewed.
- [ ] Known gaps documented.
- [ ] Changes reviewed by the team before deployment.
