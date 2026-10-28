# Operations runbook

## Pre-deployment

- Review source and lockfile changes.
- Run the production build and relevant automated checks.
- Confirm hosting manifest and environment bindings.
- Verify no secrets or target response bodies were committed.
- Smoke-test safe and blocked URLs, timeouts, errors, keyboard navigation, report filters, and export.
- Record the rule-catalog and report-schema versions.

## Deployment verification

- Confirm deployment reaches a terminal success state.
- Open the private production URL and run a permitted sample audit.
- Verify blocked destinations fail safely without leaked infrastructure detail.
- Confirm report health, coverage, limitations, and evidence render correctly.

## Monitoring

Track API error rate, scan latency, timeout rate, response sizes, blocked-target counts, destination-domain concentration, and report-generation failures. Alert on unusual scan volume, repeated restricted targets, or a sudden safety-check bypass.

## Incident response

1. Contain: disable or restrict scanning if target safety is uncertain.
2. Preserve minimal logs and identify affected requests/users.
3. Eradicate the vulnerability and rotate affected secrets.
4. Recover with a verified build and focused smoke tests.
5. Notify affected parties and authorities when legally required.
6. Document cause, impact, timeline, actions, and follow-up owners.

## Target complaint

Record target domain, reporter verification, scan identifiers, timestamps, source account, and requested action. Suspend scans to the target while abuse is investigated. Never disclose another customer's report or identity to an unverified requester.

## Rollback

Use the hosting platform's last known-good saved version. After rollback, verify scanner restrictions and the affected workflow before reopening scanning.

## Future durable storage

Before enabling saved projects, document backup frequency, encryption, restore objectives, tenant-isolation tests, and quarterly restore exercises. A backup is not considered operational evidence until restore is successfully tested.

