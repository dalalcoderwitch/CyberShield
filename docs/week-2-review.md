# CyberShield — Week 2 Security Review

## 1. Baseline
- Branch: feature/dalal-scanner
- Baseline tests: 43 passed
- Scope: Python scanner, security controls, API compatibility

## 2. Initial Risk Review

| Item | Current observation | Status |
|---|---|---|
| Total scan deadline | 25-second monotonic budget passed from Flask through DNS and HTTP; API returns 504 SCAN_TIMEOUT when exceeded at checked stages | Implemented with limitations; real-network verification remains |
| Network timeouts | Connect/read limits plus a shared 25-second scan deadline | Implemented; simulated timeout tests pass; real-network verification remains |
| DNS timeout | Caller wait limit: 2s; underlying lookup may continue | Limitation documented |
| Request rate limiting | Five scan requests per 60 seconds per source IP; excess requests return 429 RATE_LIMIT_EXCEEDED | Implemented in memory per Flask process; not shared across workers |
| SSRF protection | URL, DNS results, IP destination policy, IP pinning, and redirect handling have regression coverage | Automated regression tests expanded; real-network and deployment-level validation remain |
| Concurrent scan capacity | Four active scans per Python process | Implemented; multi-process limitation |
| Capacity release | Semaphore release is performed in `finally` | Scanner-exception release path covered by an automated test |
| Sensitive logging | Unexpected exception details are omitted; a test checks that a sensitive target URL is not logged in the tested failure path | Tested for that path; full deployment logging review remains |
| Report privacy | Reports display the HTTPS origin only; credentials, path, query, and fragment are omitted | Implemented; report redaction regression tests cover displayed output |
| API report compatibility | Backend contract test checks response fields, five check IDs, statuses, summary, and limitations using mocked DNS and HTTP | Backend contract test passes; Flutter end-to-end integration remains pending |

## 3. Week 2 Priorities

1. Review the existing implementation before modifying it.
2. Implemented an initial total scan deadline and API timeout behavior; real-network limits still require verification.
3. Implemented an initial in-memory rate limit; coordinate multi-process behavior with Bailsan.
4. Expanded SSRF and TLS regression coverage; real-network validation remains outstanding.
5. Reviewed finding statuses, evidence, confidence, and limitations; added severity and confidence assertions for all five findings.
6. Added tests for response/session cleanup and semaphore release after scanner exceptions.
7. Added a backend contract-compatibility test with mocked DNS and HTTP dependencies; Flutter end-to-end integration remains pending.
8. Updated project documentation and retained unresolved real-network and deployment risks.

## 4. Testing Evidence

Latest command:
`python -m pytest -q`

Result:
`98 passed`

Passing tests establish the behavior covered by those tests. They do not prove complete SSRF protection or production readiness.

## 5. Outstanding Risks

- A 25-second monotonic budget is propagated across Flask, DNS waiting, and HTTPS requests. Real-network behavior still needs verification; an operating-system DNS lookup cannot be forcibly cancelled.
- In-process rate limiting is implemented: five scan requests per 60 seconds per source IP, returning 429 RATE_LIMIT_EXCEEDED. It is not shared across multiple server processes.
- DNS operations may continue after the caller's timeout.
- The concurrency semaphore is local to one Python process.
- Controlled integration testing and deployment security review remain necessary.