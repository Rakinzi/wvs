# Architecture

## Overview

WVS is a React + Flask + Celery application that stores scan jobs and results, generates PDF reports, and exposes report JSON that the SPA renders directly.

Flow:

```txt
React SPA
  -> Flask API routes
  -> scanner modules / Celery full-scan task
  -> normalized findings + summary + sections
  -> ScanResult persistence + PDF generation
  -> report JSON / dashboard / history / assets
```

## Frontend

Main frontend paths live in `wvs/src/`.

Important files:

- `App.jsx`: route wiring and authenticated layout
- `components/Scanners.jsx`: scan launch UI, including scan profile selection and embedded verified target controls
- `components/ScanReport.jsx`: report rendering for legacy security and new UX findings
- `components/VerifiedTargets.jsx`: dedicated target ownership management view
- `hooks/useScansData.js`: async scan state and scan launch payload construction
- `hooks/useScanReportData.js`: report JSON fetch handling
- `hooks/useVerifiedTargetsData.js`: CRUD and verification calls for target ownership
- `lib/api.js`: fetch wrapper, cookie auth, CSRF handling
- `lib/auth.js`: client-side session metadata

The SPA now uses route-level lazy loading and Vite manual chunking to reduce the initial bundle cost for reports, charts, and icon-heavy views.

## Backend

Main backend paths live in `wvs_backend/app/`.

Important modules:

- `__init__.py`: Flask app factory, extensions, blueprint registration, security headers, JWT config
- `models.py`: `User`, `ScanJob`, `ScanResult`, `MaliciousSite`, `BlockedRequest`, `VerifiedTarget`
- `schemas.py`: request validation contracts for auth, scans, malicious URLs, and verified targets
- `routes/scans.py`: scan launch, job status, report APIs, report asset serving, history, deletion
- `routes/targets.py`: verified target ownership lifecycle
- `routes/dashboard.py`: dashboard metrics
- `tasks/scan_jobs.py`: Celery orchestration and progress state mapping
- `utils/scan_pipeline.py`: full security scan, product-readiness scan, and full launch audit composition
- `utils/scan_helpers.py`: URL validation, summary/section/report shaping, legacy compatibility helpers
- `utils/finding_normalizer.py`: normalized contract for new UX/product findings
- `utils/reports.py`: PDF generation
- `utils/ux_scan_helpers.py`: page selection and UX scan support helpers
- `utils/ux_screenshot_manager.py`: screenshot storage and evidence path handling
- `utils/remediation_prompts.py`: deterministic AI-builder-ready remediation prompts

## Scanner Layers

Legacy security scanners remain under `app/scanners/` and preserve their original output shapes.

New product-readiness scanners:

- `accessibility_scanner.py`
- `responsive_scanner.py`
- `performance_ux_scanner.py`
- `form_usability_scanner.py`
- `visual_ai_scanner.py`

The new UX scanners normalize findings so downstream report generation can stay additive instead of forcing a rewrite of older security scanner outputs.

Accessibility scanning now injects a pinned local browser-side ruleset from `app/assets/axe.min.js`, then layers in conservative keyboard and tap-target checks.

Performance UX scanning now prefers Lighthouse CLI when enabled and installed locally, with a browser-metric fallback when Lighthouse is unavailable.

## Scan Profiles

The async `/scan` route accepts a scan profile:

- `security_only`
- `product_readiness`
- `full_launch_audit`

`ScanJob.scan_type` stores the requested profile and the Celery worker dispatches to the appropriate pipeline builder.

## Verified Targets

`VerifiedTarget` exists to restrict deeper product-readiness scanning to domains the current user controls.

Supported verification methods:

- HTML meta tag
- `/.well-known/wvs-site-verification.txt`

The verification fetch path reuses hardened URL validation and rejects:

- localhost and `.local`
- loopback, private, reserved, and link-local IPs
- embedded credentials
- unsafe redirects

## Reports

`ScanResult.findings` remains the primary persisted JSON payload.

The compatibility contract still centers on:

- `summary`
- `sections`
- `findings`
- `best_practices`
- `meta`

New UX categories extend that contract with additive sections rather than replacing the original report schema.

## Evidence Files

PDFs and UX screenshots are stored on disk and referenced from persisted scan results.

Safety measures:

- screenshots use generated filenames
- API responses expose authenticated asset URLs, not raw filesystem paths
- scan deletion removes referenced screenshots and the report PDF
- retention cleanup is available through the `cleanup-report-artifacts` CLI

## Worker Controls

The async scan path now supports queue separation and rate limiting:

- `SECURITY_SCAN_QUEUE`
- `UX_SCAN_QUEUE`
- `UX_SCAN_RATE_LIMIT`

Security-only scans can be routed separately from browser-heavy UX/full-launch jobs.

## Known MVP Limits

- AI visual review requires external provider credentials before live use
- product-readiness scanning is limited to configured public pages and conservative non-destructive checks
