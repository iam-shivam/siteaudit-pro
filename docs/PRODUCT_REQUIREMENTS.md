# Product requirements

## Product statement

SiteAudit Pro helps agencies, developers, and website owners turn observable website evidence into a credible, prioritized improvement plan. It combines website quality, production readiness, document readiness, and passive security posture without pretending that a public scan is a penetration test.

## Primary users

- Agency/freelancer preparing a prospect audit
- Small-business or product owner reviewing a live site
- Product team preparing a release
- Technical owner monitoring regressions

## Goals

- Produce useful evidence within one public scan.
- Explain issues in business language and provide implementation guidance.
- Activate checks based on site type, features, data, and audit access.
- Separate control health from assessment coverage.
- Support a professional, shareable report and machine-readable export.

## Non-goals for the MVP

- Penetration testing or compliance certification
- Authenticated crawling, port scanning, credential testing, or exploitation
- Monetary-loss claims without verified traffic and business inputs
- Jurisdiction-specific legal conclusions
- Automated code changes on a target site

## MVP journey

1. User enters an HTTP(S) URL.
2. User selects a site type and applicable features.
3. Product explains the passive-scan boundary and starts a bounded scan.
4. Product extracts public evidence and evaluates applicable rules.
5. Report shows executive summary, category scores, coverage, findings, evidence, and solutions.
6. User filters findings and exports report data.

## Functional requirements

- Normalize and validate URLs before network access.
- Reject unsafe protocols, ports, destinations, and redirects.
- Apply feature-aware rule packs.
- Record `Not tested` and `Owner evidence required` rather than guessing.
- Show exact sampled URL, timestamp, evidence, severity, confidence, effort, and remediation.
- De-duplicate site-wide findings.
- Provide category health and coverage plus overall residual unknowns.
- Preserve rule version so historical reports remain explainable.

## Non-functional requirements

- Responsive and keyboard-accessible UI
- Scan timeout, response-size, redirect, and concurrency limits
- No target credentials or authenticated cookies in public mode
- Stable JSON report contract
- Clear error states, retry behavior, and no duplicate scan submissions
- Privacy-minimizing logs and evidence

## MVP acceptance

The MVP is complete when a user can scan a safe public URL, receive deterministic evidence-based findings, distinguish tested from untested controls, view health and coverage scores, and export a report without any intrusive target interaction.

