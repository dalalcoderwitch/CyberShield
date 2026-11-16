# CyberShield — Backend Week 3 Day 1 Review

**Owner:** Bilsan — Flask API / Backend integration  
**Date:** 2026-11-17  
**Branch:** `main`  
**Baseline:** Week 2 close at `a422033e9b7966d16eb7a47c21893ddaefd7c75c`

## Scope reviewed

Tuesday's planned review covers the response integration interfaces, cookie-value redaction, response-body limits, response/session cleanup, the fixed Disclosure path allowlist, and preparation of Flask API integration tests. This review is read-only for `security_scanner/` and `mobile/`; no scanner-owner or Flutter-owned files are changed.

## Findings

1. **Flask/API adapter:** `POST /api/v1/scan` validates `include_expanded_checks` as a boolean and passes the option through `backend.scanner.scan_target`. The Backend adapter forwards it to the report engine and does not re-evaluate finding status, severity, confidence, or evidence. No Flask contract change is required for the Week 3 findings based on the current interface.
2. **Expanded report:** the report engine already emits the 11 Week 3 finding IDs in expanded mode. The combined expanded report target is 30 findings (five foundational, seven Week 2, and eleven Week 3 plus the later expanded checks already implemented by the engine); summary counts are derived from the returned findings.
3. **Cookie privacy:** the response collector parses each separate `Set-Cookie` field into only Secure/HttpOnly flags and a normalized SameSite state. It does not retain cookie names or values. If raw multi-value access or header bounds cannot be confirmed, cookie evidence is unavailable rather than guessed.
4. **Response bounds and cleanup:** the original response uses streaming and a bounded identity-encoded sample; Disclosure probes accept only 4 KiB or 16 KiB sample limits. The response and session are closed in `finally`. The Flask `MAX_CONTENT_LENGTH` limit applies to the incoming API request, not to the remote target's response body.
5. **Disclosure access policy:** Disclosure requests use fixed same-origin path lists for sensitive files, directory indicators, and public security files. The collector has a per-scan request budget of 13; it does not perform general crawling or unbounded directory enumeration. Each probe disables redirect following, pins the previously validated public IP, verifies TLS, applies timeouts, and reads only a bounded sample.
6. **Sanitized evidence:** Disclosure evidence retains result categories, approved header names/types, and bounded status metadata rather than raw response bodies or secret values. The Flask layer returns the report object without adding file contents or raw cookie values.

## Backend-owned test preparation

Updated `tests/test_api.py` in commit `c2e14f22d1f6ca394424c48f84ea1f158217a223` so the real Flask-to-report-engine integration test explicitly asserts:

- All 11 Week 3 check IDs are present in the expanded API response.
- Each Week 2 and Week 3 finding retains the required nine-field finding contract and an allowed status.
- All five summary status counters equal the statuses actually returned in `findings`.
- The combined expanded report still has a consistent total.

This adds API-boundary assertions only. It does not modify scanner evaluators, scanner evidence collection, Flutter models, screens, or tests owned by Dalal/Ahmad.

## Day 1 acceptance status

- [x] Review API and report-engine integration interfaces.
- [x] Review cookie redaction and response/resource boundaries.
- [x] Confirm the fixed Disclosure path lists and bounded request plan.
- [x] Prepare Backend-owned Flask integration assertions for all 11 Week 3 checks.
- [ ] Run the updated API integration test and full CI; record the actual result before declaring the day closed.

## Next step — Wednesday

Proceed only after Day 1 verification is complete. Wednesday's scope is limited to the API integration of `cookie_secure` and `cookie_httponly`, including multiple cookies, missing attributes/evidence, and explicit proof that cookie values do not appear in API responses or logs. Scanner rule implementation remains with Dalal.
