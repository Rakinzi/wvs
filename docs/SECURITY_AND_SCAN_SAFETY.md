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

Default UX scanning limits exist to reduce blast radius:

- capped page count
- capped timeouts
- capped screenshot generation
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
