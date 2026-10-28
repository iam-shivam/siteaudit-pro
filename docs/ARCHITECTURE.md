# Architecture

## Components

```text
Client dashboard
  -> Audit API route
     -> URL normalization and SSRF guard
     -> Bounded fetch/evidence extractor
     -> Profile-aware rule engine
     -> Score/report assembler
  <- Structured report JSON
```

The current release is stateless. Durable projects, histories, screenshots, and scheduled monitoring are later phases.

## Responsibilities

### Client

- Collect URL and site profile
- Explain authorization and evidence limits
- Display scan states and report filters
- Export client-visible report data

### API and scanner

- Accept only supported profile fields and HTTP(S) targets
- Resolve/reject unsafe destinations where the runtime permits
- Revalidate bounded redirects
- Fetch with strict time and size limits
- Extract response and HTML evidence without executing target code

### Rule engine

- Decide applicability independently from result status
- Convert evidence into deterministic findings
- Keep public, owner-evidence, repository, authorized-test, and monitoring methods distinct
- Calculate health only from tested applicable controls
- Calculate coverage from evidence strength and rule weight

## Future durable model

- `organizations`, `users`, `memberships`
- `projects`, `domains`, `domain_verifications`
- `audits`, `pages`, `measurements`
- `findings`, `finding_evidence`, `exceptions`
- `score_snapshots`, `reports`, `share_links`
- `authorization_records`, `audit_events`

Screenshots and raw artifacts belong in object storage; normalized metadata belongs in the database. Tenant isolation must be enforced in every query, with database row-level controls where available.

## Deployment

The application targets OpenAI Sites and Cloudflare Workers through Vinext. The Worker runtime provides HTTP fetch but no raw TCP; this matches the MVP's HTTP-only boundary. The tracked `.openai/hosting.json` is deployment configuration, while secrets remain in the hosted environment store.

## Evolution

When scans become multi-page or scheduled, move acquisition to isolated queued workers. Keep report generation and rule evaluation deterministic so the same evidence plus rule version produces the same result.

