# CyberShield — API Contract

**Version:** Draft 1.2

**Scope:** Project 1 — Website Security Assessment

**Status:** Draft — pending implementation verification and team approval

## 1. Purpose

This document defines the API contract between the Flutter client,
the Flask API, and the scanner.

It specifies the request format, report structure, finding statuses,
API error responses, and security requirements.

Field names, field types, status meanings, and error codes must remain
consistent across the API implementation, automated tests, and Flutter
data models.

This contract must not be considered finalized until it has been checked
against the current implementation and reviewed by the team.

## 2. Local Development

Default development server:

`http://127.0.0.1:5000`

The API base URL must be configured for the environment in which the
mobile application runs.

For a standard Android emulator, the host computer's local development
server is commonly reachable through:

`http://10.0.2.2:5000`

The Flask development server is intended for local development only.
Production deployment requires a separately configured and secured
environment.

## 3. Health Endpoint

### Request

`GET /api/v1/health`

### Successful response

HTTP status: `200 OK`

```json
{
  "status": "ok",
  "service": "CyberShield API"
}
```

This endpoint confirms that the API responds.

It does not prove that every scanner dependency is ready or that a
scan will succeed.

## 4. Scan Endpoint

### Request

`POST /api/v1/scan`

Content type:

`application/json`

### Request body

```json
{
  "target_url": "https://example.com",
  "authorization_confirmed": true
}
```

### Request fields

| Field | Type | Required | Description |
|---|---|---|---|
| `target_url` | string | Yes | Requested target URL |
| `authorization_confirmed` | boolean | Yes | Confirms that the user states they have appropriate authorization |

The server must validate the request independently.

The authorization confirmation is not, by itself, a technical security
control and does not make an otherwise prohibited target safe.

The server must apply its target security policy before making an
outbound request. A disallowed target must be rejected before scanning
begins.

## 5. Successful Scan Response

When the request is accepted and a report is produced, the API returns
HTTP `200 OK`.

The response follows this structure:

```json
{
  "scan_id": "00000000-0000-4000-8000-000000000001",
  "status": "completed",
  "target_url": "https://example.com",
  "scanned_at": "2026-10-27T12:00:00Z",
  "engine_version": "1.0.0",
  "http_status": 200,
  "summary": {
    "total": 5,
    "passed": 1,
    "warning": 4,
    "not_verified": 0,
    "error": 0,
    "skipped": 0
  },
  "findings": [
    {
      "check_id": "https_connection",
      "title": "HTTPS connection and TLS verification",
      "status": "passed",
      "severity": "info",
      "confidence": "high",
      "evidence": "The HTTPS request completed with certificate verification enabled.",
      "explanation": "The connection was established for the response examined.",
      "recommendation": "Continue maintaining valid TLS configuration.",
      "limitations": [
        "This result does not establish that the entire website is secure."
      ]
    },
    {
      "check_id": "header_hsts",
      "title": "HTTP Strict Transport Security",
      "status": "warning",
      "severity": "medium",
      "confidence": "high",
      "evidence": "The expected HSTS condition was not satisfied.",
      "explanation": "The observed response requires review against the HSTS check rule.",
      "recommendation": "Review the Strict-Transport-Security header and its max-age directive.",
      "limitations": [
        "The result applies to the response examined."
      ]
    },
    {
      "check_id": "header_csp",
      "title": "Content Security Policy",
      "status": "warning",
      "severity": "medium",
      "confidence": "high",
      "evidence": "The enforced Content-Security-Policy header was not observed.",
      "explanation": "The response did not provide the expected header evidence.",
      "recommendation": "Review whether a suitable Content-Security-Policy header should be configured.",
      "limitations": [
        "Header presence alone does not establish policy quality."
      ]
    },
    {
      "check_id": "header_x_content_type_options",
      "title": "X-Content-Type-Options",
      "status": "warning",
      "severity": "low",
      "confidence": "high",
      "evidence": "The expected nosniff value was not observed.",
      "explanation": "The response did not satisfy the configured header check.",
      "recommendation": "Review the X-Content-Type-Options header and consider setting it to nosniff.",
      "limitations": [
        "The result applies to the response examined."
      ]
    },
    {
      "check_id": "header_x_frame_options",
      "title": "X-Frame-Options",
      "status": "warning",
      "severity": "medium",
      "confidence": "high",
      "evidence": "The expected DENY or SAMEORIGIN value was not observed.",
      "explanation": "The response did not satisfy the configured X-Frame-Options check.",
      "recommendation": "Review the framing policy and choose an appropriate protection.",
      "limitations": [
        "This check does not evaluate every possible framing protection."
      ]
    }
  ],
  "limitations": [
    "This is a preliminary assessment, not a full penetration test.",
    "Results apply to the response examined at the time of the scan."
  ],
  "notice": "This limited assessment does not guarantee complete website security."
}
```

The JSON above is an illustrative schema example. Its timestamps, evidence,
and finding results are not a fixed result for every target. The actual
report must reflect observed evidence.

A complete report contains five findings, one for each agreed check.

### Report field semantics

| Field | Meaning |
|---|---|
| `scan_id` | Identifier generated for the report |
| `status` | Report-generation status |
| `target_url` | Sanitized HTTPS origin only; credentials, path, query, and fragment are omitted |
| `scanned_at` | Scan timestamp in ISO 8601 format |
| `engine_version` | Scanner report version |
| `http_status` | Target response status code, or `null` if no response was obtained |
| `summary` | Counts of findings by status |
| `findings` | The five individual check results |
| `limitations` | Report-level limitations |
| `notice` | General assessment disclaimer |

The top-level status `completed` means that report generation finished.
It does not mean that all security checks passed.

The `summary.total` value must equal the number of findings.
Every status count must match the findings actually returned.

The illustrative report above has five findings: one `passed` and four
`warning`. Therefore, the summary counts add up to five.

## 6. Finding Schema

Every finding must contain the following fields:

| Field | Type | Description |
|---|---|---|
| `check_id` | string | Stable identifier of the check |
| `title` | string | Human-readable check title |
| `status` | string | Result status |
| `severity` | string | Severity classification |
| `confidence` | string | Confidence in the finding |
| `evidence` | string | Evidence observed |
| `explanation` | string | Interpretation of the result |
| `recommendation` | string | Recommended action based on the evidence |
| `limitations` | array of strings | Limitations of the finding |

### Allowed severity values

- `info`
- `low`
- `medium`
- `high`

### Allowed confidence values

- `low`
- `medium`
- `high`

The `limitations` field must be an array of strings in each finding
and at the report level.

Severity, confidence, and status represent different concepts and
must not be used interchangeably.

## 7. Stable Check Identifiers

Project 1 defines exactly five check identifiers:

| Identifier | Check |
|---|---|
| `https_connection` | HTTPS connection and TLS verification |
| `header_hsts` | Strict-Transport-Security |
| `header_csp` | Content-Security-Policy |
| `header_x_content_type_options` | X-Content-Type-Options |
| `header_x_frame_options` | X-Frame-Options |

Identifiers must remain consistent across scanner code, report
generation, automated tests, API documentation, and Flutter models.

## 8. Finding Statuses

| Status | Meaning |
|---|---|
| `passed` | The specific check satisfied its documented rule based on sufficient evidence |
| `warning` | An observation requires review |
| `not_verified` | Available evidence is insufficient to verify the check |
| `error` | The check encountered an execution or processing error |
| `skipped` | The check was deliberately not executed because of a defined constraint |

Missing evidence must never be reported as `passed`.

A connection failure must not cause response headers to be classified
as missing. When no usable response is obtained, those checks should
be `not_verified`, unless a different status is explicitly justified
by the agreed implementation contract.

## 9. API Error Response

API errors use this structure:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "بيانات الطلب غير صالحة."
  }
}
```

The example message is illustrative. Actual client-facing messages
must match the implementation, remain safe to display to users, and
avoid exposing internal exception details.

### Current documented error codes

| HTTP status | Error code | Meaning |
|---|---|---|
| `400` | `INVALID_REQUEST` | Request JSON or fields are invalid |
| `403` | `AUTHORIZATION_REQUIRED` | Authorization confirmation is false |
| `403` | `TARGET_NOT_ALLOWED` | The target is rejected by the target security policy |
| `405` | `METHOD_NOT_ALLOWED` | The HTTP method is not supported for this endpoint |
| `413` | `REQUEST_TOO_LARGE` | The request exceeds the configured size limit |
| `429` | `RATE_LIMIT_EXCEEDED` | The source IP exceeded the in-process scan rate limit or the source tracking table is full |
| `504` | `SCAN_TIMEOUT` | The configured scan budget expired at a checked stage |
| `500` | `INTERNAL_ERROR` | An unexpected server-side error occurred |
| `503` | `SCAN_CAPACITY_EXCEEDED` | The maximum number of concurrent scans has been reached |

A missing or non-boolean authorization_confirmed field is treated
as INVALID_REQUEST (400). A boolean false value is treated as
AUTHORIZATION_REQUIRED (403).

These codes and status mappings must be verified against the current
Flask implementation and API tests before this document is approved.

Internal exception details, stack traces, secrets, and sensitive
data must not be returned in client-facing responses.

## 10. HTTP Status Semantics

The API response status code is separate from the report's `http_status`
field.

- API `200`: a report was returned.
- API `400`: request data is invalid.
- API `403`: authorization confirmation or target policy prevents scanning.
- API `405`: the HTTP method is not supported for the requested endpoint.
- API `413`: the request body exceeds the configured size limit.
- API `429`: the source IP exceeded the in-process request rate limit; the request was rejected before target resolution and scanning.
- API `504`: the configured scan budget expired during a checked stage of the scan.
- API `500`: an unexpected server error occurred.
- API `503`: scan capacity is exhausted; the request was not started.

A scan can return API HTTP `200` even when one or more findings have
status `warning`, `not_verified`, or `error`, provided the API processed
the request and successfully returned a report.

A target rejected by the security policy must be rejected before the
scanner makes an outbound request.

Plain HTTP URLs are rejected by the server-side target policy before
the outbound scan request begins. The API returns HTTP 403 with error
code TARGET_NOT_ALLOWED. No scan report is generated for this request.

## 11. Current Check Behavior and Limitations

The scanner is intended to check:

- HTTPS connection and TLS certificate verification.
- HSTS presence and a positive `max-age`.
- Presence of the enforced Content-Security-Policy header.
- `X-Content-Type-Options: nosniff`.
- `X-Frame-Options: DENY` or `SAMEORIGIN`.

The CSP check does not deeply evaluate policy quality.

The header checks do not prove that the entire website is secure.

The scanner does not automatically follow redirects.
The report describes the response examined by the scanner.

## 12. Security Requirements

The scanner and API must:

- Keep TLS certificate verification enabled.
- Reject disallowed destinations before connecting.
- Avoid automatically following redirects to unchecked destinations.
- Ensure the actual connection uses a destination IP permitted by policy.
- Preserve TLS hostname verification when connecting to a validated IP.
- Use explicit connection and read timeouts.
- Enforce appropriate request and response resource limits.
- Avoid treating missing evidence as a successful result.
- Avoid exposing sensitive internal error information.
- Avoid claiming that a website is completely secure.

Passing mocked tests alone does not prove that the real network
connection satisfies all these requirements.

## 13. Known Implementation Review Items

The following items require implementation review or additional testing:

- Actual destination IP pinning and TLS hostname verification.
- DNS rebinding resistance.
- Controlled integration tests for certificate failures.
- DNS failures, timeouts, and IPv4/IPv6 edge cases.
- Explicit response-header size limits and real-network response-size behavior still require verification. The scanner uses streaming mode and closes responses without consuming response bodies.
- The initial 25-second monotonic scan budget and `504 SCAN_TIMEOUT` response; real-network verification and DNS limitations remain.
- Four concurrent scans per Python process and an in-memory per-source limit of five authorized scans per 60 seconds, returning `429 RATE_LIMIT_EXCEEDED`; these limits are not shared across multiple workers or instances.
- Safe logging and handling of sensitive URL components.
- Consistent handling of plain HTTP URLs.
- Verification that every documented API error mapping is implemented.

These items must not be described as fully implemented merely because
the current automated suite passes.

## 14. Team Approval Checklist

- [ ] Dalal reviews finding semantics and scanner output.
- [ ] Bailsan reviews Flask request validation and API error behavior.
- [ ] Ahmad reviews the response schema for Dart models and UI.
- [ ] The team agrees on report fields and field types.
- [ ] The team agrees on scan-level versus API-level failure behavior.
- [ ] API tests validate the approved contract.
- [ ] The approved version is recorded in Git.

This document remains a draft until the implementation has been checked
and the team has reviewed and approved the contract.