# WVS Frontend

This directory contains the React SPA for WVS. It is the operator-facing interface for:

- authentication and account flows
- dashboard metrics
- scan setup and async job tracking
- verified target ownership management
- scan history
- report viewing for security and product-readiness findings

## Main Files

- `src/App.jsx`: route wiring and authenticated layout
- `src/components/Scanners.jsx`: scan launcher for sync scanners and async scan profiles
- `src/components/VerifiedTargets.jsx`: dedicated target ownership management screen
- `src/components/ScanReport.jsx`: report rendering, including screenshot evidence and remediation prompts
- `src/hooks/useScansData.js`: async scan submission and job polling
- `src/hooks/useScanReportData.js`: report data fetching
- `src/hooks/useVerifiedTargetsData.js`: verified target API integration
- `src/lib/api.js`: fetch wrapper with cookie auth and CSRF handling

## Commands

Install dependencies:

```bash
npm install
```

Start development server:

```bash
npm run dev
```

Create a production build:

```bash
npm run build
```

## Backend Expectations

The SPA expects the FastAPI backend to expose:

- cookie-based JWT auth
- CSRF support via `X-CSRF-TOKEN`
- `/scan` async job creation
- `/scan/jobs` polling
- `/report/:id?format=json`
- `/targets` verified target management

## Product-Readiness UI

The frontend now supports three async scan profiles:

- `Security Scan`
- `Product Readiness Scan`
- `Full Launch Audit`

For product-readiness and full-launch flows, the UI can also:

- create verification tokens
- show meta-tag and well-known-file instructions
- verify target ownership
- select a saved verified target
- include page paths and optional AI review configuration in the scan request
