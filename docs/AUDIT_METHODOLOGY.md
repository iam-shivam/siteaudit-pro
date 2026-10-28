# Audit methodology

## Core rule

Report only what the selected audit mode and captured evidence support. Absence of public evidence is not proof that a private control is absent.

## Applicability

Each rule is `Applicable`, `Not applicable`, or `Unknown—owner answer needed`. Applicability is driven by site type and features such as accounts, payments, subscriptions, uploads, APIs, webhooks, user content, multi-tenancy, AI, trackers, and sensitive data.

## Evidence levels

| Level | Meaning |
|---|---|
| E0 | Not assessed |
| E1 | Inferred from public signals |
| E2 | Direct public response/page observation |
| E3 | Owner attestation with supporting evidence |
| E4 | Verified in repository, configuration, or read-only integration |
| E5 | Behaviorally verified in an authorized environment |
| E6 | Continuously monitored evidence |

## Result statuses

- Verified pass
- Verified finding
- Likely concern—manual verification needed
- Owner evidence required
- Authorized test required
- Not applicable
- Not tested or blocked
- Risk accepted with owner and expiry

## Scoring

Health and coverage are intentionally separate.

```text
finding penalty = severity × confidence × prevalence × business relevance
health = normalized score over applicable controls actually tested
coverage = weighted evidence achieved / weighted evidence required
```

Rules that were not tested do not create health penalties. They reduce coverage and remain visible as unknown residual risk. Repeated page-level evidence for one site-wide defect is de-duplicated.

## Finding quality

Every finding should contain observation, sampled URL, timestamp, evidence, scope, status, severity, confidence, business impact, effort, responsible role, remediation, rule version, and retest state. Sensitive values must be redacted.

## False positives and disputes

- Prefer deterministic checks and repeat unstable observations when safe.
- Label heuristics as likely concerns rather than verified findings.
- Preserve minimal raw evidence internally and expose redacted evidence.
- Let an owner dispute, suppress, accept, or request retest.
- Never describe a missing header as proof of compromise or exploitability.

## Standards mapping

Security rules may reference versioned OWASP ASVS, OWASP API Security, and OWASP GenAI guidance. Accessibility automation is partial and cannot establish full conformance. Legal-page checks verify presence and obvious completeness only, not legal adequacy.

