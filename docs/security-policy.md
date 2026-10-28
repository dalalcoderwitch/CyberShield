# CyberShield Security Policy

## 1. Purpose and Security Boundaries

CyberShield performs a limited, preliminary assessment of selected
HTTPS security indicators for a website that the user is authorized
to assess.

The initial scanner checks:

1. HTTPS connection and TLS certificate validation.
2. HTTP Strict Transport Security (HSTS).
3. Content Security Policy (CSP).
4. X-Content-Type-Options.
5. X-Frame-Options.

CyberShield is not a full penetration-testing platform, vulnerability
scanner, or guarantee that a website is secure.

A successful result for an individual check means only that the
specific condition tested by that check was observed. It must not
be presented as proof that the entire website is secure.

## 2. Authorized Use

The scanner must only be used against websites that the user owns
or has explicit permission to assess.

The application's authorization confirmation expresses the user's
claim that they have permission. It does not independently prove
ownership or authorization.

The scanner must not:

- Attempt to guess, discover, or reuse passwords.
- Perform repeated login attempts.
- Request or collect passwords, session tokens, or other login
  credentials.
- Attempt to exploit vulnerabilities or modify the target website.
- Perform destructive tests, denial-of-service tests, or unrestricted
  crawling.
- Access internal services or protected infrastructure through a
  user-supplied URL.
- Claim that a target is fully secure based on the limited checks.

Only the explicitly implemented checks are within the initial
project scope.

## 3. URL and Target Validation

Before making an HTTP request, the backend must validate the target.

The initial implementation applies the following restrictions:

- Only the HTTPS scheme is accepted.
- Only TCP port 443 is accepted.
- URLs containing username or password components are rejected.
- Localhost names and their subdomains are rejected.
- Invalid or unsupported hostnames are rejected.
- DNS results must contain supported IPv4 or IPv6 addresses.
- Targets are rejected if DNS resolution fails, produces no usable
  addresses, or returns more than the configured address limit.
- All returned addresses must pass the public-address policy.
- A target must not be requested when any resolved address violates
  that policy.

These checks help reduce server-side request forgery (SSRF) risk.
They do not replace network-level egress restrictions or deployment
security controls.

## 4. SSRF and Network Destination Protections

### 4.1 Restricted destinations

The scanner must not connect to loopback, private, link-local,
or other non-public IP addresses.

It must reject addresses associated with internal or special-purpose
destinations, including cloud metadata and internal services.

IPv4 and IPv6 addresses must be checked. IPv4-mapped IPv6 addresses
and relevant IPv6 transition or translation ranges must also be
considered so that an address cannot bypass the destination policy
by using an alternate representation.

The implementation uses Python IP address classification and
additional explicit network restrictions.

### 4.2 DNS resolution

The hostname is resolved before the HTTP connection is made.

The current implementation uses:

- A maximum DNS wait time of 2 seconds.
- A maximum of four concurrent DNS lookup slots.
- A maximum of 32 returned addresses for a target.

If the DNS lookup exceeds the wait limit, the target is rejected.
If the lookup fails or returns an unacceptable result, the scanner
must not continue with the HTTP request.

The timeout wrapper cannot forcibly cancel an operating-system
`getaddrinfo` operation. A DNS lookup that exceeds the wait limit
may continue in the background and hold its lookup slot until it
finishes.

Consequently, the DNS timeout limits how long the caller waits;
it does not guarantee that the underlying operating-system lookup
will stop after 2 seconds.

### 4.3 Connection pinning

After target validation, the scanner connects to a validated IP
address instead of resolving the original hostname again for the
HTTP connection.

The original hostname must still be used for the HTTP Host header
and TLS hostname verification, including Server Name Indication
(SNI) where applicable.

TLS certificate validation must remain enabled.

This approach helps prevent a second DNS resolution from directing
the actual connection to a different address after validation.
It does not eliminate every possible network-level SSRF risk.

### 4.4 Redirects

Automatic HTTP redirects are disabled.

The scanner must not follow a redirect to another hostname, IP
address, port, or internal destination without validating the new
destination under the same policy.

The initial implementation does not follow redirects. A redirect
response must not be treated as evidence that the destination
behind the redirect was checked.

## 5. HTTPS and TLS Requirements

The scanner must:

- Accept HTTPS URLs only.
- Keep TLS certificate verification enabled.
- Reject connections with invalid or untrusted certificates.
- Verify that the certificate hostname matches the original
  requested hostname.
- Preserve the original hostname for TLS verification when
  connecting to a validated IP address.
- Never retry a failed HTTPS connection using plain HTTP.
- Avoid disabling certificate verification to make a scan succeed.

A TLS failure must not be reported as a successful HTTPS check.

The presence of HTTPS alone does not prove that every aspect of
the target's TLS configuration is secure.

## 6. HTTP Request and Response Handling

The scanner uses Python Requests to make the HTTP request.

The current implementation applies:

- Connection timeout: 3 seconds.
- Read timeout: 5 seconds.
- Automatic redirects disabled.
- Streaming response handling.
- Explicit response closure.
- Explicit HTTP session closure.

The scanner examines the relevant response status and security
headers. It does not need to download or execute the target's
page content for the initial checks.

The response body is not intentionally consumed by the scanner.
Response and session resources must be closed after use, including
when an error occurs.

The connection and read timeouts do not guarantee a fixed maximum
duration for an entire scan. DNS processing and other operations
must also be considered when evaluating total execution time.

## 7. Resource Limits and Request Capacity

### 7.1 DNS and HTTP timeouts

DNS resolution has a 2-second caller wait limit and a maximum
of four concurrent lookup slots.

The HTTP request uses a 3-second connection timeout and a
5-second read timeout.

The DNS timeout test currently uses a simulated slow DNS lookup.
Controlled integration testing is still needed to characterize
real operating-system DNS behavior.

These individual timeout settings do not constitute a complete
end-to-end scan deadline.

### 7.2 Concurrent scans

The Flask API currently limits the number of active scans to
four per Python process.

The capacity limit is implemented with a bounded semaphore.
If all scan slots are occupied, a new scan request is rejected
without starting target resolution or scanning.

The API returns:

- HTTP status: `503`
- Error code: `SCAN_CAPACITY_EXCEEDED`

The client may retry later.

This is a per-process limit. If the service is deployed with
multiple worker processes or multiple application instances,
each process may have its own limit. The current semaphore
does not enforce a single shared limit across all processes
or instances.

### 7.3 Remaining resource controls

The following controls still require evaluation or separate
implementation before deployment:

- Request-rate limiting.
- A reliable end-to-end scan deadline.
- Capacity limits shared across multiple workers or instances,
  if applicable.
- Appropriate worker, connection, and operating-system limits.
- Network-level egress restrictions.
- Monitoring for repeated rejected requests or resource exhaustion.

The application must not be considered production-ready merely
because the per-process concurrency limit is implemented.

## 8. Error Handling and Logging

The API must return predictable JSON error responses and must not
expose internal stack traces, filesystem paths, secrets, or other
implementation details to clients.

Expected API error categories include:

- `400 INVALID_REQUEST`: request data is invalid.
- `403 AUTHORIZATION_REQUIRED`: authorization confirmation is
  missing or insufficient for the API's request rules.
- `403 TARGET_NOT_ALLOWED`: the target violates the destination
  policy or is otherwise not permitted.
- `413 REQUEST_TOO_LARGE`: the request exceeds the configured
  request-size limit.
- `503 SCAN_CAPACITY_EXCEEDED`: the active scan capacity is full.
- `500 INTERNAL_ERROR`: an unexpected server-side failure occurred.

The exact response body and status code must remain consistent
with the API contract.

Unexpected scan failures must not be logged with full exception
details if doing so could expose sensitive target information.
Logs must not contain passwords, session tokens, or other secrets.

Security-relevant failures should be recorded at an appropriate
level without unnecessarily exposing sensitive data.

## 9. Data Minimization and Privacy

The initial version does not use a database and does not persist
scan history.

The scanner must not collect authentication credentials or
intentionally retrieve a website's complete page content.

Report target URLs must be sanitized before being included in
the report. The current report sanitization removes URL credentials,
query strings, and fragments from the displayed target URL.

This report sanitization does not mean the query string is removed
from the outgoing HTTP request. The request may still send the
provided target path and query to the remote server.

Users should therefore avoid placing passwords, access tokens,
or other secrets in the URL.

URL paths may also contain sensitive information and should not
be treated as automatically safe to display or log.

Any future database, history, or centralized logging feature must
define access control, data minimization, retention, and deletion
requirements before implementation.

## 10. Finding Statuses and Reporting Rules

Each report finding must describe only what the corresponding
check actually established.

The supported finding statuses are:

- `passed`: the specific tested condition was observed.
- `warning`: the result indicates a condition that needs review.
- `not_verified`: there is insufficient evidence to establish the
  condition.
- `error`: the check could not be completed because of an error.
- `skipped`: the check was not run due to a defined constraint.

A failed connection or unavailable response must not cause every
security-header check to be marked as passed.

When there is insufficient evidence, the result must not be
converted into `passed`.

Findings should provide appropriate evidence, explanations,
recommendations, severity, confidence, and limitations where
applicable.

The report must clearly state that it represents a limited,
preliminary assessment.

## 11. Testing and Verification

Automated tests should cover at least:

- Request validation and malformed input.
- Missing authorization confirmation.
- Disallowed schemes and ports.
- URLs containing credentials.
- Localhost and prohibited IP addresses.
- IPv4, IPv6, and relevant special-purpose address cases.
- DNS failures, empty results, excessive results, and timeouts.
- Connection pinning and hostname verification.
- TLS certificate validation, including untrusted certificates.
- Redirect behavior.
- Security-header interpretation.
- Response and session cleanup.
- API error responses.
- Scan-capacity rejection and permit release.
- Report sanitization and finding statuses.

Tests using mocks verify the behavior represented by those mocks.
They do not independently prove the security of every real network
environment.

Local TLS tests provide useful regression coverage, but do not
replace controlled integration testing or a deployment security
review.

DNS timeout tests that simulate a slow lookup must not be treated
as proof that the operating system can forcibly cancel a real
DNS lookup.

## 12. Deployment Requirements and Limitations

The development server is intended for local use and binds to
`127.0.0.1` with debug mode disabled.

The development server must not be exposed directly as a
production service.

Before deployment, the team must review:

- Production-grade Flask hosting and server configuration.
- TLS termination and transport protection for the mobile-to-API
  connection.
- Authentication, authorization, and access controls appropriate
  to the deployment.
- Request-rate limiting.
- Total scan deadlines and resource exhaustion protections.
- Network-level egress filtering and isolation.
- Shared concurrency controls where multiple workers are used.
- Secret management and logging practices.
- Monitoring, alerting, and operational response.
- Tests in a controlled environment representative of deployment.

A local test suite passing does not demonstrate that the application
is ready for public deployment.

## 13. Security Policy Maintenance

Changes to URL validation, DNS handling, connection behavior,
TLS verification, timeouts, concurrency controls, error responses,
or report interpretation must be accompanied by appropriate
regression tests and documentation updates.

The API contract, security policy, implementation, and tests must
describe consistent behavior.

Any control that is documented as required but has not been
implemented or verified must be clearly identified as a limitation
or outstanding deployment task.