# Security and Scan Safety

## Authorized Use Only

Run this platform only against websites and applications you own or are explicitly authorized to assess. The existence of a scanner does not create permission to test arbitrary targets.

## Verification and Target Controls

The product-readiness extension adds target verification to reduce the risk of running deeper browser-based analysis against third-party systems.

Verification methods:

- HTML meta tag
- well-known verification file

Production deployments should keep `REQUIRE_VERIFIED_TARGETS=true` for product-readiness and full-launch scans.

## SSRF and Unsafe Target Protections

Target validation rejects:

- localhost
- `.local`
- embedded credentials
- private IPs
- loopback IPs
- link-local IPs
- reserved and non-global IPs

Verification fetches and browser-scan support helpers also validate redirects to avoid redirecting into disallowed network destinations.

## Browser Scan Scope

The current MVP is intentionally conservative.

It does not attempt:

- destructive actions
- purchases
- file uploads
- authenticated user workflows
- irreversible settings changes
- payment flow completion

Verified pre-production scans may optionally run bounded active checks against auth or account-management endpoints. These checks are capped by request budget and look for throttle signals such as HTTP 429, `Retry-After`, rate-limit headers, CAPTCHA text, cooldown text, or lockout text. They do not brute-force real credentials.

Verified pre-production scans also run bounded exposed-service checks against a configured small port list. This is not broad internet port scanning; it is intended to catch accidental exposure of development servers, databases, caches, mail catchers, and admin ports before launch.

Default UX scanning limits exist to reduce blast radius:

- capped page count
- capped timeouts
- capped screenshot generation
- capped active auth/API check requests
- capped exposed-service port list
- public-page focus only
- separate queueing for browser-heavy UX scans when configured

Recommended local worker split:

- a general worker for `security_scans`
- a constrained worker for `ux_scans`, especially on lower-memory machines

## Screenshot Handling

Screenshots may contain sensitive content. The implementation therefore:

- stores screenshots in a controlled directory
- uses generated filenames
- serves them only through authenticated report asset routes
- avoids exposing raw local paths in JSON responses
- removes referenced screenshots when a scan result is deleted
- supports retention-based cleanup through `cleanup-report-artifacts`

## AI Output Safety

AI-generated visual findings are intentionally separated from measured technical findings.

They must be treated as:

- advisory
- non-authoritative
- not direct evidence of a security vulnerability
- not direct evidence of a WCAG failure

They should not be allowed on their own to mark a launch as blocked.

## Operational Recommendations

- keep Playwright browsers and dependencies current
- keep verification required in non-development environments
- scan only public pages unless you later implement explicit authenticated-scan safeguards
- re-scan after remediation to verify fixes rather than assuming suggested changes worked
- review screenshot retention policies before production rollout
- keep any configured Lighthouse CLI and AI provider credentials under normal secret-management controls
