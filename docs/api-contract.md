# CyberShield — API Contract

**Version:** Draft 1.1
**Scope:** Project 1 — Website Security Assessment
**Status:** Implementation-aligned draft; team approval pending

## 1. Purpose

This document describes the current API request and response
contracts for the Flutter client, Flask API, and scanner.

It reflects the current implementation and identifies decisions
that still require review.

Changes to field names, field types, status meanings, or error
codes must be coordinated before the contract is finalized.

## 2. Local Development

Default development server:

`http://127.0.0.1:5000`

The base URL must be configured for the execution environment.
An Android emulator may need `http://10.0.2.2:5000` to reach a
development server running on the host computer.

The Flask development server is for local development only.
Production deployment requires an appropriately secured setup.

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
Production deployment requires an appropriately secured setup.

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


This endpoint confirms that the API responds.
It does not prove that every scanner dependency is ready.
4. Scan Endpoint
Request
POST /api/v1/scan

Content type:

application/json
Request body
{
  "target_url": "https://example.com",
  "authorization_confirmed": true
}


Fields
FieldTypeRequiredDescription
target_urlstringYesRequested target URL
authorization_confirmedbooleanYesUser confirms appropriate authorization

The server validates the request independently.
Authorization confirmation alone is not a technical security control.

The server must reject targets that do not pass its target policy.
Disallowed targets must be rejected before the scan begins.
5. Successful Scan Response
When the API accepts the request and produces a report, it returns
HTTP 200 OK.

The current report has this structure:
{
  "scan_id": "UUID",
  "status": "completed",
  "target_url": "https://example.com",
  "scanned_at": "ISO-8601 timestamp",
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
      "evidence": "Evidence observed for this check.",
      "explanation": "Explanation of the observed result.",
      "recommendation": "Recommended action based on the evidence.",
      "limitations": [
        "This result does not prove that the entire website is secure."
      ]
    }
  ],
  "limitations": [
    "This is a preliminary assessment, not a full penetration test.",
    "Results apply to the response examined at the time of the scan."
  ],
  "notice": "This limited assessment does not guarantee complete website security."
}


The JSON above illustrates the schema. Values are examples, not
a fixed result for every scan.

A complete report contains five findings, one for each agreed check.

scan_id is generated for the report.
scanned_at is a UTC timestamp.
engine_version identifies the scanner report version.
http_status is the status code received from the target, or null
when no target response was obtained.

The top-level report status completed means that report generation
finished. It does not mean that all checks passed.

The summary counts must match the actual findings.
The total field must equal the number of findings.
6. Finding Schema
Every finding must contain:
FieldTypeDescription
check_idstringStable check identifier
titlestringHuman-readable check title
statusstringResult status
severitystringFinding severity
confidencestringConfidence in the finding
evidencestringObserved evidence
explanationstringInterpretation of the result
recommendationstringRelevant recommended action
limitationsarray of stringsLimitations for this finding

Allowed severity values:
- info
- low
- medium
- high
Allowed confidence values:
- low
- medium
- high
limitations is an array of strings at both the finding level
and the report level.
7. Stable Check Identifiers
The Project 1 scanner uses exactly these five identifiers:
IdentifierCheck
https_connectionHTTPS connection and TLS verification
header_hstsStrict-Transport-Security
header_cspContent-Security-Policy
header_x_content_type_optionsX-Content-Type-Options
header_x_frame_optionsX-Frame-Options

Identifiers must remain consistent across scanner code, report
generation, automated tests, API documentation, and Flutter models.
8. Result Statuses
StatusMeaning
passedThe specific check passed its documented rule
warningAn observation requires review
not_verifiedAvailable evidence is insufficient to verify the check
errorThe check encountered an execution or processing error
skippedThe check was deliberately not executed because of a defined constraint

Missing evidence must never be reported as passed.

A connection failure must not cause response headers to be reported
as missing; those checks should be not_verified when no response
was obtained.

Status, severity, and confidence have different meanings and must
not be used interchangeably.
9. Current Error Response Format
API errors use this structure:
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Request data is invalid."
  }
}


The actual client-facing messages in the current implementation
are Arabic. Messages must remain safe to display to users.
Current error codes
HTTP statusCodeMeaning
400INVALID_REQUESTRequest JSON or fields are invalid
403AUTHORIZATION_REQUIREDAuthorization confirmation is false
403TARGET_NOT_ALLOWEDTarget is rejected by the target policy
413REQUEST_TOO_LARGERequest exceeds the configured size limit
500INTERNAL_ERRORUnexpected server-side error

Internal exception details, stack traces, secrets, and sensitive
data must not be returned in client-facing responses.
10. HTTP Status Semantics
The HTTP status code of the API response is separate from the
http_status field in the report.
- API 200: a report was returned.
- API 400: request data is invalid.
- API 403: authorization confirmation or target policy prevents scanning.
- API 413: request body exceeds the configured size limit.
- API 500: an unexpected server error occurred.
If a scan produces a report with a failed or unverified check,
the API may still return HTTP 200 because the request itself
was processed and a report was produced.

A disallowed target must be rejected before the scanner performs
a target request.
11. Current Check Behavior and Limitations
The scanner currently checks:
- HTTPS/TLS connection behavior.
- Basic HSTS presence and positive max-age.
- Presence of the enforced Content-Security-Policy header.
- X-Content-Type-Options: nosniff.
- X-Frame-Options: DENY or SAMEORIGIN.
The current CSP check does not deeply evaluate policy quality.
The current header checks do not prove that the full website is secure.

The scanner does not automatically follow redirects.
The report describes the response examined by the scanner.
12. Security Requirements
- Keep TLS certificate verification enabled.
- Reject disallowed destinations before connecting.
- Do not automatically follow redirects to unchecked destinations.
- Ensure the actual connection uses an IP address permitted by target policy.
- Preserve hostname verification when connecting to a validated IP.
- Use explicit connection and read timeouts.
- Limit request and response resources.
- Do not turn missing evidence into a passed result.
- Do not expose sensitive internal error information.
- Do not claim that a website is completely secure.
Passing mocked tests alone does not prove that the real network
connection satisfies all these requirements.
13. Known Implementation Review Items
The following items remain subject to additional verification:
- Actual destination IP pinning and TLS hostname validation.
- DNS rebinding resistance.
- Controlled integration tests for certificate failures.
- DNS failures, timeouts, and IPv4/IPv6 edge cases.
- Explicit resource limits and a total scan deadline.
- Concurrency and request rate controls.
- Safe logging and handling of sensitive URL components.
These items must not be described as fully implemented merely
because the current automated suite passes.
14. Team Approval Checklist
- [ ] Dalal reviews finding semantics and scanner output.
- [ ] Bailsan reviews Flask request validation and API error behavior.
- [ ] Ahmad reviews the response schema for Dart models and UI.
- [ ] The team agrees on report fields and field types.
- [ ] The team agrees on scan-level versus API-level failure behavior.
- [ ] API tests validate the approved contract.
- [ ] The approved version is recorded in Git.
This document remains a draft until the team has reviewed it.
