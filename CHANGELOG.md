# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - 2026-11-14

### Added
- Portable CLI entrypoint ([src/cli.js](src/cli.js)) with `shodan_reconsx`-style Unicode block ASCII banner on `stderr`, `--input`, `--output`, `--format txt|json|csv`, `--passive`, `--all-batches`, `--max-batches`, `--color`/`--no-color`, `--help`, and `--version`.
- Cross-platform shell launchers ([scan.sh](scan.sh) and [scan.ps1](scan.ps1)).
- Async streaming scan API (`POST /api/scans`, `GET /api/scans/:id`, `GET /api/scans/:id/events` SSE, and `POST /api/scans/:id/cancel`) while preserving `/api/lookup`, `/api/progress`, and `/api/health`.
- Modular scanner architecture separating [src/advisories.json](src/advisories.json), [src/classifier.js](src/classifier.js), [src/discovery.js](src/discovery.js), [src/network.js](src/network.js), and [src/probe.js](src/probe.js).
- TLS fallback error capture (`tlsError`) in HTTP probe evidence, partial-result retention on scan cancellation, configurable batch continuation (`stopOnCandidate`, `maxBatches`), and web UI evidence filter pills (`#checks-filter`).
- Cross-platform CI (`Node.js 20`, `22`, `24` + Windows/macOS checks) and tag-driven CD release workflow ([.github/workflows/release.yml](.github/workflows/release.yml)).

### Fixed
- Strict ICANN TLD validation in `normalizeDomain` so invalid suffixes such as `gob.mex` fail fast with HTTP `400`.
- Replaced the legacy SVG image banner in the web UI with the matching Unicode block ASCII banner.
