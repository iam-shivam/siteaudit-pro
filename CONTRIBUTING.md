# Contributing

## Principles

Contributions must preserve SiteAudit Pro's evidence-first and low-impact behavior. A dramatic finding without strong evidence is a product defect.

## Workflow

1. Open an issue describing the user problem and intended evidence source.
2. Keep changes focused and add or update tests for scoring, applicability, and safety boundaries.
3. Run the build and relevant checks.
4. Document user-visible rule, report, privacy, or operational changes.

## Adding an audit rule

Each rule must define:

- Stable, versioned identifier and category
- `applies_if` conditions
- Audit modes and authorization level
- Required evidence and freshness
- Pass, finding, uncertain, and unavailable criteria
- Severity, confidence, business impact, effort, and responsible role
- Remediation and a standards reference when appropriate

Rules must not infer server-side controls from browser-visible absence. Subjective design preferences—fonts, gradients, icon libraries, card styles—are not production defects unless tied to measurable accessibility, usability, credibility, or performance evidence.

## Pull-request checklist

- [ ] No active or intrusive scanning was introduced into public mode.
- [ ] SSRF, redirect, size, timeout, and rate limits remain intact.
- [ ] Unknown/not-tested results do not reduce health scores as failures.
- [ ] New collected data is documented with a retention purpose.
- [ ] UI remains keyboard accessible and responsive.
- [ ] `npm run build` succeeds.

