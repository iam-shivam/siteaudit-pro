# Security boundaries

## Public mode

Permitted operations are conservative HTTP(S) requests to ordinary public resources, response-header inspection, HTML metadata extraction, and bounded link/document discovery.

Public mode must not:

- Submit forms, create accounts, or authenticate
- Guess directories or enumerate services
- Send SQL, XSS, SSRF, traversal, deserialization, or other attack payloads
- Scan ports or non-HTTP services
- Test credentials, passwords, resets, or authorization boundaries
- Trigger payments, uploads, emails, webhooks, or destructive actions

## Owner and authorized modes

Domain verification proves control of a name; it is not permission to test third-party hosting, payment providers, CDNs, or shared infrastructure. Active tests require a separate written scope naming exact targets, dates, methods, accounts, rate limits, exclusions, stop conditions, data handling, and emergency contacts.

## Scanner abuse prevention

- Allow only HTTP and HTTPS on ports 80 and 443.
- Reject credentials in URLs.
- Block loopback, private, link-local, multicast, reserved, and metadata destinations.
- Revalidate DNS and every redirect destination where runtime APIs permit.
- Limit redirects, requests, bytes, duration, and concurrency.
- Use GET/HEAD only and a clear user agent.
- Rate-limit users and destination domains before public scale.
- Maintain an emergency disable switch and complaint process.

## Scanner isolation

Treat every target response as hostile. Do not execute downloaded scripts, open downloads, follow non-HTTP schemes, or expose the scanner's local network. Future browser workers require sandboxing, restricted egress, clean per-job state, and resource limits.

## Report disclosure

Avoid fear-based or definitive claims beyond evidence. Public prospect reports should not expose secrets, sensitive paths, exploitable details, personal data, or customer information. Higher-risk detail belongs only in verified-owner channels.

