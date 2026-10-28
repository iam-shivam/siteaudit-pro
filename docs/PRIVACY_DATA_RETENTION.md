# Privacy and data retention

This document defines product defaults, not a jurisdiction-specific privacy notice.

## Data minimization

Collect only what is required to produce and secure an audit:

- Requested URL and normalized target
- User-selected site profile
- Response metadata and limited HTML-derived evidence
- Scan timestamps, rule versions, findings, and operational errors
- Account/organization identifiers when saved projects are introduced

Do not intentionally collect authenticated cookies, credentials, form submissions, private pages, or unrelated page content. Redact tokens, query secrets, personal data, and sensitive paths from evidence and logs.

## Proposed retention defaults

| Data | Default |
|---|---|
| Unsaved raw fetch content | Process in memory; discard after extraction |
| Operational error logs | 14 days |
| Public scan/report | Browser session in MVP; 30 days when saved reports launch |
| Screenshots/raw artifacts | 30 days unless owner retains them |
| Authorization/scope records | Engagement term plus legally reviewed retention period |
| Security audit events | 12 months when accounts launch |

Retention must become configurable and documented before durable production storage is enabled.

## Owner controls

Future saved projects need export, deletion, retention settings, membership/role controls, and an audit trail. Deletion must include stored reports and artifacts subject to documented security, billing, and legal exceptions.

## Vendors and locations

Maintain a subprocessor/vendor register describing purpose, data class, storage region, retention, security review, and contract owner. Do not represent a site as legally compliant merely because a privacy page or cookie banner exists; qualified counsel must determine requirements for countries served and data handled.

