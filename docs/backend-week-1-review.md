# Backend Week 1 Review — Bailsan

**Review date:** 2026-11-16  
**Branch:** `main`  
**Reviewed commit:** `bd7011f6b1480e3dd1763c37bd0000607baacd74`  
**Scope:** Flask API, backend adapter, API tests, API contract, and Flutter API compatibility review. No scanner-owner or Flutter-owned files were modified.

## 1. Executive result

The core Flask API work planned for Week 1 is present on `main`: request validation, authorization gating, detailed DNS outcome handling, validated-target reuse, structured report forwarding, scan deadlines, in-process rate limiting, concurrency limiting, and API regression coverage.

The current `main` head has a successful full-suite execution in GitHub Actions: **997 passed in 3.14s** on Python 3.14.10 / Ubuntu 26.04 ([run #6](https://github.com/dalalcoderwitch/CyberShield/actions/runs/43864268227)). This is an executed CI result, not test collection.

A local clone/test run was not possible in this execution environment because the container could not resolve `github.com`. The GitHub Actions run above did execute the suite against the exact reviewed `main` commit.

## 2. Backend implementation verified

- `GET /api/v1/health` and `POST /api/v1/scan` are implemented.
- JSON body must be an object. `target_url` must be a non-empty, trimmed string of at most 2048 characters. `authorization_confirmed` must be a Boolean. `include_expanded_checks` is optional, defaults to `false`, and must be a Boolean when supplied.
- Missing or invalid request fields return `400 INVALID_REQUEST`; explicit authorization denial returns `403 AUTHORIZATION_REQUIRED`.
- The Flask layer uses `resolve_target_with_status` and distinguishes the engine outcomes as follows:

| Resolver outcome | API response |
|---|---|
| `invalid`, `not_allowed` | `403 TARGET_NOT_ALLOWED` |
| `dns_error` | `502 DNS_RESOLUTION_FAILED` |
| `dns_timeout` | `504 DNS_TIMEOUT` |
| `dns_capacity` | `503 DNS_CAPACITY_EXCEEDED` |
| `timeout` | `504 SCAN_TIMEOUT` |

- The resolved target is passed to the backend adapter and report engine, avoiding a second DNS lookup for the scan's primary HTTPS request.
- The report is returned from the scanner integration layer without recalculating finding status, severity, or confidence in Flask.
- Request size is capped at 16 KiB; URL length is capped at 2048 characters.
- Scan controls currently include a 25-second monotonic deadline, four concurrent scans per Python process, and five scan requests per source per 60 seconds. The source tracking table is capped at 4096 entries and expired entries are cleaned.
- The semaphore is released in a `finally` block. API error responses avoid returning exception details; rate limiting uses `request.remote_addr` and does not trust `X-Forwarded-For` by default.
- The CORS development allowlist is restricted to localhost / 127.0.0.1 origins.

## 3. API and Flutter contract items requiring team alignment

- The Flutter API client currently sends `include_expanded_checks: true`; the Flask API validates and forwards this option.
- In expanded mode, the report engine adds top-level `correlations` and `correlation_rules_version`. The current API contract does not describe these optional fields, and the Flutter `ScanReport` model does not retain them. This should be agreed with Dalal and Ahmad before treating the expanded response schema as final. No Flutter files were changed.
- The API contract remains a draft pending team approval. This review verifies implementation behavior; it does not substitute for Dalal's and Ahmad's approval of shared report semantics and model compatibility.

## 4. Documentation follow-ups for their owners

- `docs/security-policy.md` §4.2 still says the Flask integration uses the backward-compatible resolver and that detailed DNS-to-API mapping remains future work. That statement conflicts with the current `backend/app.py` implementation and the API regression tests. The security-policy owner should update that section; it was not edited as part of this Backend-owned review.
- `docs/week-1-summary.md` still records the earlier 43-test baseline and initial implementation state. Its owner should refresh it against the current repository state; it was not edited here.
- `docs/test-plan.md` was updated to record the latest successful run on the current `main` head.
- `docs/api-contract.md` was corrected for escaped line breaks and now records that implementation checking is complete while team approval remains pending.

## 5. Remaining limitations / not yet proven

- Rate limiting and the scan semaphore are per Python process, not shared across multiple workers or instances.
- The DNS caller timeout does not forcibly cancel an operating-system `getaddrinfo` operation; a timed-out lookup may continue in its daemon worker until it finishes.
- The test plan still tracks end-to-end real-socket verification of DNS validation, pinned peer IP, SNI, and hostname verification as outstanding. Existing mocked and local TLS tests cover separate parts of that path.
- Response-size/header-size behavior and additional slow/chunked response cases remain outstanding in the test plan. Streaming and response closure reduce body consumption, but do not replace those verification cases.
- A successful CI run proves the automated tests passed in that runner; it does not certify production readiness or all real-network conditions.

## 6. Week 1 Backend acceptance

**Backend baseline:** implementation and API regression suite are present and the current `main` suite passes in CI.

**Still requiring coordination or separate verification:** shared response-contract approval (especially correlation metadata), security-policy documentation correction by its owner, and the explicitly listed real-network / response-size / multi-process limitations.

No scanner implementation or Flutter-owned file was changed during this review.
