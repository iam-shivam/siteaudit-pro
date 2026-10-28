# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to the project owner through the repository's private security-reporting channel. Include the affected route or component, impact, reproducible steps, and a safe proof of concept. Do not include customer data, credentials, destructive payloads, or public disclosure before remediation is coordinated.

## Research expectations

- Test only environments and accounts you own or are explicitly authorized to assess.
- Do not access another user's data, degrade service, send unsolicited traffic, or attempt persistence.
- Stop immediately if a test exposes secrets or personal data and report only the minimum evidence required.
- Do not use the public scanner as permission to perform active security testing against its target.

## Product security invariants

- Public scans use normal, bounded HTTP requests only.
- Targets resolving to loopback, private, link-local, multicast, reserved, or cloud-metadata addresses are rejected.
- Redirect destinations must be revalidated.
- The scanner does not submit forms, authenticate, brute-force paths, scan ports, or inject attack payloads.
- Missing evidence is never converted into a pass.
- Detailed security findings are shared only with the requester and, in future owner modes, a verified owner.

## Secrets and dependencies

Never commit credentials, API keys, cookies, scan tokens, or production response bodies. Runtime secrets must use the deployment platform's secret store. Dependency changes require lockfile review, build verification, and a security-impact check.

## Administrator authentication invariants

- Sites identity and the administrator email allowlist remain the primary access boundary; the secondary credential never grants access by itself.
- Only a salted PBKDF2 password record and a separate cookie-signing secret may be stored in Sites runtime secrets. Plaintext credentials, password records, session tokens, and signing material must never be logged or committed.
- Successful verification creates a user-bound, HMAC-signed `__Host-` cookie with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and an absolute short expiry.
- Every protected page, API route, and future server action must validate both the hosted identity and the signed credential session. Missing or malformed configuration fails closed.
- Login failures are generic and throttled. The current in-memory throttle is best-effort per Worker isolate; the private Sites allowlist remains the primary brute-force boundary until durable throttling is added.
- Logout clears the credential cookie and ends the hosted Sites session. Rotate the signing secret whenever the password record changes to invalidate existing sessions.
- The credential gate protects access to SiteAudit Pro; it does not authorize active testing against any target website.

## Supported versions

During MVP development, only the most recently deployed version is supported. Security fixes should be deployed promptly and recorded in release notes.

