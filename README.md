# SiteAudit Pro

SiteAudit Pro turns publicly observable website evidence into a prioritized improvement report covering discoverability, performance, accessibility, trust, document readiness, UX resilience, and passive security hygiene.

The product is intentionally evidence-first: an unavailable or untested control is never reported as a pass or a failure. Deeper application-security conclusions require owner verification, appropriate evidence, or separately authorized testing.

## MVP capabilities

- Adaptive profiles for brochure sites, ecommerce, SaaS, marketplaces, content sites, and AI products.
- Conservative public URL analysis with explicit network and request limits.
- Versioned findings with evidence, severity, confidence, effort, and remediation guidance.
- Separate control-health and assessment-coverage scores.
- Rule packs for base web quality, SEO, accessibility, trust/documents, authentication, payments, APIs, uploads, multi-tenancy, AI, operations, and UX state coverage.
- A client-ready report with `Fix now`, `Fix next`, and `Improve later` priorities.

The MVP does **not** perform penetration testing, credential checks, form submission, path brute-forcing, exploit payloads, or authenticated crawling.

## Audit modes

1. **Public prospect scan** — low-impact observations from ordinary public pages and responses.
2. **Verified-owner audit** — owner questionnaire plus read-only evidence and integrations.
3. **Launch-readiness review** — staging, test accounts, repository/configuration evidence, and separately authorized behavioral tests.
4. **Continuous monitoring** — scheduled rescans and material-change detection.

Only the first mode is implemented in the initial product experience. The other modes are modeled so future results remain honest and comparable.

## Technical shape

```text
Browser
  -> /api/audit
  -> URL safety boundary
  -> bounded passive fetch and evidence extraction
  -> adaptive rule engine
  -> health + coverage scoring
  -> report UI / JSON export
```

The application uses Next.js-compatible Vinext and deploys as a Cloudflare Worker through OpenAI Sites. See [Architecture](docs/ARCHITECTURE.md) and [Security boundaries](docs/SECURITY_BOUNDARIES.md).

## Local development

Prerequisites:

- Node.js 22.13 or newer
- npm

```bash
npm ci
npm run dev
```

Open the loopback URL printed by the development server. Useful checks:

```bash
npm run build
npm run lint
```

Do not add real credentials to `.env` files committed to source control. Hosted runtime values belong in the Sites environment-variable store.

## Evidence contract

Every check has an applicability outcome, result status, evidence strength, timestamp, and rule version. Supported result statuses include:

- Verified pass
- Verified finding
- Likely concern
- Owner evidence required
- Authorized test required
- Not applicable
- Not tested
- Test blocked
- Risk accepted

See [Audit methodology](docs/AUDIT_METHODOLOGY.md) and [Report schema](docs/REPORT_SCHEMA.md).

## Administrator access

Administrator access is layered: Sites-hosted ChatGPT identity, the configured administrator email, a secondary credential check, and a signed short-lived session cookie. The password is verified only against a salted PBKDF2 hash; plaintext credentials are never stored. The page and audit API enforce the same server-side boundary and fail closed when configuration is missing.

Configure these server-side Sites runtime values and keep their real values out of source: `SITEAUDIT_ADMIN_EMAIL`, `SITEAUDIT_ADMIN_PASSWORD_HASH`, and `SITEAUDIT_SESSION_SECRET`. The secondary credential is defense in depth, not a replacement for Sites identity or per-user MFA.

## Documentation

- [Product requirements](docs/PRODUCT_REQUIREMENTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Audit methodology](docs/AUDIT_METHODOLOGY.md)
- [Report schema](docs/REPORT_SCHEMA.md)
- [Security boundaries](docs/SECURITY_BOUNDARIES.md)
- [Privacy and data retention](docs/PRIVACY_DATA_RETENTION.md)
- [Operations runbook](docs/OPERATIONS_RUNBOOK.md)
- [Product/site document matrix](docs/DOCUMENT_MATRIX.md)
- [Roadmap](docs/ROADMAP.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Important limitations

A live URL cannot prove the safety of server-side authorization, database permissions, backups, CI/CD, tenant isolation, secret handling, or incident response. Page presence also does not prove legal adequacy. SiteAudit Pro reports evidence and gaps; it does not provide legal advice, certification, or a guarantee that a site is secure.

