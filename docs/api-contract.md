# CyberShield — API Contract

**Version:** 1.3

**Scope:** Project 1 — Website Security Assessment

**Status:** Backend contract baseline — implementation and API tests checked against `main` on 2026-11-16; Flutter adoption and end-to-end integration remain pending

## 1. Purpose

This document defines the API contract between the Flutter client,
the Flask API, and the scanner.

It specifies the request format, report structure, finding statuses,
API error responses, and security requirements.

Field names, field types, status meanings, and error codes must remain
consistent across the API implementation, automated tests, and Flutter
data models.

This document defines the current Backend response contract. Cross-client
adoption still requires the Flutter model and UI to implement the documented
expanded-report metadata, followed by an end-to-end integration check.

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
| `include_expanded_checks` | boolean | No | Requests the additional implemented checks; defaults to `false` when omitted |

The server must validate the request independently.

The optional `include_expanded_checks` field must be a boolean when supplied; a non-boolean value is rejected as `INVALID_REQUEST`. Omitted values default to `false`. The Flutter client currently requests expanded checks.

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

When `include_expanded_checks` is omitted or `false`, the base
report contains the five foundational findings. When it is `true`,
the scanner may return additional findings from the implemented
expanded checks. The actual number of findings depends on the selected
scan mode and the checks returned by the engine.

### Week 2 TLS, Redirect, and Header Findings

Expanded mode includes the following seven Week 2 findings in the same
`findings` array and with the same nine-field finding contract defined above:

| Group | Check ID |
|---|---|
| TLS certificate | `tls_certificate_expiry` |
| TLS certificate | `tls_certificate_chain` |
| TLS negotiation | `tls_protocol_config` |
| HTTP transport | `http_to_https_redirect` |
| Redirect validation | `redirect_destination_safety` |
| Response header | `header_referrer_policy` |
| Response header | `header_permissions_policy` |

These findings are returned by the report engine; Flask must pass their
`status`, `severity`, `confidence`, evidence, explanation, recommendation,
and limitations through without recalculating or reclassifying them. An
individual result of `error` or `not_verified` must remain attached to that
finding and must not cause the other findings or the report to be discarded.
The summary counts findings by their original statuses; these seven checks
are not separate from the `findings` array.

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
| `findings` | The individual check results returned by the selected scan mode |
| `correlations` | Expanded-mode contextual relationships between existing findings; omitted in base mode |
| `correlation_rules_version` | Expanded-mode correlation catalog version; omitted in base mode |
| `limitations` | Report-level limitations |
| `notice` | General assessment disclaimer |

The top-level status `completed` means that report generation finished.
It does not mean that all security checks passed.

The `summary.total` value must equal the number of findings.
Every status count must match the findings actually returned.

The illustrative report above has five findings: one `passed` and four
`warning`. Therefore, the summary counts add up to five.

### Expanded-report metadata

When `include_expanded_checks` is `true`, the report includes both
`correlations` and `correlation_rules_version`. When the option is omitted
or `false`, both fields are omitted. In expanded mode, `correlations` is
an array and may be empty when no correlation rule is satisfied; the
rules-version field is still present.

Each correlation is contextual information about existing findings. It
is not a new finding, does not prove an exploit chain, and must not be
added to `findings` or any `summary` counter. The API passes this metadata
through unchanged; the scanner owns correlation evaluation and versioning.

| Correlation field | Type | Meaning |
|---|---|---|
| `correlation_id` | string | Stable identifier of the correlation rule |
| `contributing_check_ids` | array of strings | Finding identifiers that contributed to this correlation |
| `severity` | string | Correlation context severity; currently emitted as `low` |
| `confidence` | string | Confidence in this context; currently emitted as `low` |
| `explanation` | string | Why the contributing observations are grouped |
| `recommendation` | string | Suggested review action |
| `rules_version` | string | Correlation catalog version used for this item |
| `rule_version` | string | Version of the individual rule |
| `limitations` | array of strings | Constraints on interpreting this context |

`correlation_rules_version` is a top-level string identifying the complete
correlation catalog version. It currently matches each correlation's
`rules_version` value (`2.0.0`). It is separate from `engine_version`.

Illustrative expanded-only fields:

```json
{
  "correlations": [
    {
      "correlation_id": "cookie_defense_gaps",
      "contributing_check_ids": ["cookie_secure", "cookie_httponly"],
      "severity": "low",
      "confidence": "low",
      "explanation": "Two independent cookie observations need joint review.",
      "recommendation": "Review the Secure and HttpOnly attributes.",
      "rules_version": "2.0.0",
      "rule_version": "1",
      "limitations": ["This context does not establish an exploit chain."]
    }
  ],
  "correlation_rules_version": "2.0.0"
}
```

This contract reflects the current scanner output and fixes the Flask
response behavior for version 1.3. Scanner rule changes remain owned by the
scanner module; Flutter must preserve these fields when parsing and
serializing expanded reports. Any incompatible schema change requires a
coordinated contract revision.

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

The Flutter model also has optional presentation fields named `impact`,
`remediation`, `relations`, and `priority`. These are not required finding
fields in the current `CheckResult` serializer and are not promoted to
required API fields by this proposal. Their scanner-owned meanings and
production emission conditions must be agreed before they are treated as
stable cross-client fields.

Severity, confidence, and status represent different concepts and
must not be used interchangeably.

## 7. Stable Check Identifiers

Project 1 defines five foundational check identifiers. Expanded scan\nmode may return additional identifiers implemented by the scanner:

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
| `502` | `DNS_RESOLUTION_FAILED` | DNS resolution failed or returned no usable addresses |
| `503` | `DNS_CAPACITY_EXCEEDED` | No DNS lookup slot was available |
| `504` | `DNS_TIMEOUT` | The DNS caller wait limit expired before resolution completed |
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
- API `502`: DNS resolution failed or returned no usable addresses.
- API `503`: scan capacity or DNS lookup capacity is exhausted.
- API `504`: the total scan deadline expired, or the DNS lookup wait limit expired (`DNS_TIMEOUT`).
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

## 14. Cross-client Rollout Checklist

- [ ] Dalal verifies that the documented correlation semantics match scanner output.
- [x] Backend request validation and API error behavior have been reviewed against the Flask implementation.
- [ ] Ahmad implements and verifies the response fields in the Dart model and report UI.
- [x] The Backend response shape is defined, including expanded-only correlation metadata.
- [x] API tests validate expanded metadata passthrough, empty correlations, and base-mode omission.
- [x] Backend contract version 1.3 is recorded in Git.
- [ ] The team completes an end-to-end scan test from Scanner through Flask to Flutter.

Version 1.3 is the Backend contract baseline. The remaining checklist items
track cross-client verification and adoption; they do not make the defined
Flask response behavior provisional.