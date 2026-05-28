# UX Product-Readiness Extension

## Goal

The product-readiness extension expands WVS from a security-only scanner into a launch-readiness platform for websites and AI-built applications. It keeps the existing Flask, Celery, React, and PDF-report architecture and adds browser-based UX analysis where it fits the current system safely.

## What Was Added

### Verified target ownership

Before deeper UX/product scans, a user can verify a target domain using:

- an HTML meta tag
- a `/.well-known/wvs-site-verification.txt` file

This is backed by:

- `VerifiedTarget` model
- `/targets` API routes
- React target-management UI

### New scan profiles

- `security_only`
- `product_readiness`
- `full_launch_audit`

### New finding categories

- Accessibility
- Mobile and Responsive UX
- Performance UX
- Form and Interaction Usability
- Broken Links
- Abuse Controls and Exposed Routes
- Exposed Services
- Visual UX Recommendations

### New finding contract

New UX findings are normalized with:

- stable IDs
- normalized severities
- normalized confidence values
- evidence payloads
- user impact text
- technical remediation text
- deterministic AI-builder-ready prompts

Supported confidence labels:

- `measured`
- `heuristic`
- `ai_assisted`

Supported severity values:

- `critical`
- `high`
- `medium`
- `low`
- `recommendation`
- `informational`

## MVP Scanner Coverage

### Accessibility

Current checks cover measured issues such as:

- missing labels
- buttons without accessible names
- images missing alt text
- missing document language
- duplicate IDs
- conservative heading and keyboard coverage
- mobile tap target checks

The scanner now injects a pinned local browser-side accessibility ruleset from `app/assets/axe.min.js` rather than relying only on ad-hoc DOM checks.

Additional local checks now cover:

- missing document title
- iframes without titles
- invalid fields missing associated error-feedback references

### Responsive UX

Current checks include:

- horizontal overflow
- off-screen or clipped interactive elements
- clipped forms
- conservative mobile navigation problems

### Performance UX

Current implementation prefers Lighthouse CLI when enabled and installed. When Lighthouse is unavailable, it falls back to measured browser timing data gathered through Playwright.

Recommended local setup:

```bash
npm install -g lighthouse
export LIGHTHOUSE_ENABLED=true
```

### Form and interaction usability

Current checks stay non-destructive and focus on:

- missing labels
- missing required-field indications
- weak or absent validation feedback
- obvious interaction friction

### Abuse controls and exposed routes

Verified pre-production scans can optionally run bounded active checks for authentication and account-management abuse controls. The scanner:

- discovers common exposed auth and admin routes such as `/login`, `/signup`, `/forgot-password`, `/reset-password`, and `/admin`
- accepts explicit active-check paths such as `POST /login` or `GET /admin`
- sends only a capped request budget
- treats HTTP 429, `Retry-After`, rate-limit headers, CAPTCHA text, cooldown text, or lockout text as control signals
- reports missing throttling on auth endpoints as launch blockers

This is designed for staging or owner-authorized pre-production targets, not open-ended brute-force testing.

### Broken links

The product-readiness scan renders configured pages, extracts anchors, and checks link targets. Broken same-origin links are treated more severely than external links because they usually indicate missing routes, bad navigation, or launch packaging mistakes.

### Exposed services

The product-readiness scan performs a bounded TCP check against a configured launch-relevant port list. It flags public databases, caches, remote-admin ports, development servers, and non-standard web services so staging-only components are not accidentally shipped.

### Visual AI review

This module is feature-flagged and now supports a provider abstraction for OpenAI-compatible vision analysis when credentials are configured.

## Frontend Changes

The SPA now supports:

- scan profile selection
- page path entry
- AI review toggle
- verified target selection
- dedicated verified target management
- UX category rendering in reports
- screenshot evidence rendering in reports
- copyable remediation prompts

## Reporting

The new UX findings flow through the existing summary/sections/report model.

That means:

- existing security report rendering remains intact
- PDF generation remains intact
- new UX sections appear additively
- screenshot asset URLs are authenticated

## What Is Still Deferred

- broader accessibility rule coverage through the full upstream axe-core ruleset
- authenticated-area scanning

## Local Development Notes

Install Playwright browsers for backend UX scanning:

```bash
cd wvs_backend
uv run playwright install chromium
```

Run UX scans only against targets you control. The system is designed for conservative checks, but it still visits live pages and may capture evidence screenshots.
