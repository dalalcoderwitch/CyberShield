# CyberShield — API Contract

**Version:** Draft 1.0
**Status:** Awaiting review by Dalal, Bailsan, and Ahmad
**Scope:** Project 1 — Website Security Assessment

## 1. Purpose

This document defines the proposed request and response formats
shared by the Flutter application, Flask API, and Python scanner.

The contract must be reviewed by the team before it is considered final.
Changes to field names, types, or status meanings must be coordinated.

## 2. Base URL

Local development server:

`http://127.0.0.1:5000`

The base URL must be configured according to the environment.
An Android emulator may require `http://10.0.2.2:5000` to reach
a development server running on the host computer.

Production deployment must use an appropriately secured HTTPS endpoint.

## 3. Health Endpoint

### Request

`GET /api/v1/health`

### Successful response — HTTP 200

```json
{
  "status": "ok",
  "service": "CyberShield API"
}
This endpoint confirms that the API process is responding.
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


Field definitions
FieldTypeRequiredMeaning
target_urlstringYesTarget URL requested for assessment
authorization_confirmedbooleanYesUser confirms appropriate authorization

The server must validate the request independently.
User confirmation alone is not a security control and does not make
a disallowed target acceptable.

Only targets permitted by the server-side target policy may be contacted.
5. Proposed Successful Scan Response
HTTP status: 200 OK

The following is the proposed target schema for team review.
Example values are illustrative and are not actual scan results.
{
  "scan_id": "8b3a2e8e-7b5d-4e7a-ae31-8a8c42b6d0f0",
  "status": "completed",
  "target_url": "https://example.com",
  "scanned_at": "2026-10-24T15:00:00Z",
  "engine_version": "1.0.0",
  "http_status": 200,
  "summary": {
    "total": 5,
    "passed": 3,
    "warning": 1,
    "not_verified": 1,
    "error": 0,
    "skipped": 0
  },
  "findings": [
    {
      "check_id": "https_connection",
      "title": "HTTPS connection and TLS certificate",
      "status": "passed",
      "severity": "info",
      "confidence": "high",
      "evidence": "The HTTPS request completed with certificate verification enabled.",
      "explanation": "The specific connection check passed.",
      "recommendation": "Maintain valid TLS configuration and certificate verification.",
      "limitations": [
        "This check does not prove that the entire website is secure."
      ]
    }
  ],
  "limitations": [
    "This is a preliminary assessment, not a full penetration test.",
    "Results apply to the response examined at the time of the scan."
  ],
  "notice": "A successful check does not guarantee complete website security."
}


6. Required Finding Fields
Every finding must contain the following fields:
FieldTypeMeaning
check_idstringStable identifier for the check
titlestringHuman-readable check name
statusstringResult status
severitystringImportance of the finding
confidencestringStrength of the evidence
evidencestringObserved evidence
explanationstringMeaning of the result
recommendationstringRelevant next action
limitationsarray of stringsLimitations for this finding

Severity values: info, low, medium, high.

Confidence values: low, medium, high.
7. Stable Check Identifiers
The following identifiers are used throughout Project 1:
Check IDPurpose
https_connectionHTTPS connection and TLS verification
header_hstsStrict-Transport-Security
header_cspContent-Security-Policy
header_x_content_type_optionsX-Content-Type-Options
header_x_frame_optionsX-Frame-Options

Check identifiers must not be changed without updating the scanner,
API contract, tests, and Flutter data models.
8. Result Statuses
StatusMeaning
passedThe specific check passed according to its documented rule
warningAn observation needs review
not_verifiedAvailable evidence is insufficient to verify the check
errorAn execution or processing error occurred
skippedThe check was deliberately not executed because of a defined constraint

Missing evidence must never be reported as passed.

A finding's status is independent from its severity and confidence.
9. Error Responses
Error responses use this shape:
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Request data is invalid."
  }
}


The message must be safe to show to the user.
Internal exception details, stack traces, secrets, and sensitive data
must not be returned to the client.
Proposed and current error codes
HTTP statusError codeMeaning
400INVALID_REQUESTRequest data is invalid
403AUTHORIZATION_REQUIREDAuthorization confirmation is missing or false
403TARGET_NOT_ALLOWEDTarget is rejected by the target policy
413REQUEST_TOO_LARGERequest exceeds the allowed size
500INTERNAL_ERRORUnexpected server-side error

If more specific network error responses are needed later, they must
be agreed upon without exposing sensitive implementation details.
10. HTTP Behavior
- 200: request completed and a report was returned.
- 400: malformed or invalid request.
- 403: request or target is not allowed.
- 413: request body is too large.
- 500: unexpected internal error.
The team must agree on how scan-level failures are represented:
as findings inside a completed report or as API-level errors.
A disallowed target must be rejected before the scan begins.
11. Security and Correctness Rules
- Keep TLS certificate verification enabled.
- Reject disallowed targets before connecting.
- Do not automatically follow redirects to unchecked destinations.
- Apply target policy to every destination that may be contacted.
- Use connection and read timeouts.
- Limit response resources.
- Never convert missing evidence or connection failure into passed.
- Do not claim that a website is fully secure.
- Do not expose internal errors to the client.
12. Differences Requiring Review
The currently implemented report and this proposed target schema
are not yet fully aligned.

The current report implementation does not include:
- scan_id
- top-level scan status
- engine_version
- top-level notice
The current per-finding limitations field is a string, while this
proposal defines it as an array of strings.

The current summary also includes total, in addition to the status
counters. This proposal retains total.

These differences must be reviewed before changing production code.
Dalal and Bailsan should agree on the backend contract, and Ahmad should
confirm that the proposed schema is suitable for the Flutter models.
13. Approval Checklist
- [ ] Dalal reviews the finding fields and status meanings.
- [ ] Bailsan reviews API paths, request validation, and error responses.
- [ ] Ahmad reviews the response format for Dart models and UI.
- [ ] The team agrees on the fields listed in Section 12.
- [ ] API tests validate the approved contract.
- [ ] The approved contract is committed to version control.
Until these items are agreed upon, this document remains a draft.
