# Changelog

## 0.8.1-rc.6 (development channel)
### Added
- Control Center published on a configurable secret port and path (default 9443); the apex domain serves the fallback website on every port (ADR-036/037).
- Complete, bilingual starter content for all six website templates, and a styled custom 404 page.
- Certificate download as `fullchain.pem` and `privkey.pem` (step-up MFA for the key, audited; ADR-040).
- UDP (Layer 4) forwarding on stream listeners (ADR-038).
- ACME DNS-01 through Cloudflare, with wildcard certificates, read-only Cloudflare zone discovery, TXT helpers and an automatic subdomain label generator (ADR-039).
- One-line signed installer: `curl -fsSL https://github.com/Saj-1992/ngm/releases/latest/download/install.sh | sudo sh`.
- Fallback website, release signing, update/rollback/repair/uninstall, CI install matrix (earlier 0.8.x).
### Fixed
- Safe Apply rolled back healthy UDP listeners because verification probed TCP only.
- An interrupted ACME test could leave a staging certificate on the published panel; the test now uses an isolated route.
- The fresh installer left nginx stopped.
- A pre-release ordering bug (rc.10 sorted below rc.9).
