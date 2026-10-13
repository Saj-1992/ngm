# Changelog

## 0.8.2 (development channel)
### Fixed
- **The one-line installer never actually worked.** `deploy/install.sh.in`'s "no download source" guard compared `$SRC` against the literal `@@DEFAULT_SRC@@` placeholder text; the release build script substitutes that placeholder everywhere, including inside the guard's own string, so the check always matched the real default URL and `curl ... | sudo sh` (no `--from`) always failed with "no download source: pass --from URL|DIR". Explicit `--from` (used by every CI install job and by every `ngm update`) was unaffected, which is why this was never caught. Found live while installing on a second server. Fixed, with a build-time regression guard in `scripts/release.sh` that runs the built installer and fails the release build if the default source is ever rejected again.

## 0.8.1 (development channel — final build of this release line)
### Removed
- The Landing and Documentation website templates (ADR-042). Four complete branded templates remain: corporate, blog, portfolio, app showcase.
### Added
- `scripts/ops/cleanup_vm.cjs`: dry-run-first removal of test leftovers (keeps the published panel, the four sites, owner accounts and the newest five backups).

## 0.8.1-rc.9 (development channel)
### Added
- Four complete, branded, bilingual (fa/en) starter websites — corporate (villa advisory), blog (magazine), portfolio (design studio) and app showcase (trip-planner app) — each with 6–11 pages, generated artwork (deterministic PNGs in the site's brand colours), a favicon, social meta tags, a skip link, footer navigation, Solar Hijri dates for Persian readers, and a privacy page (ADR-041). Landing and documentation keep their compact starters.
- New content blocks: stats, steps, team, pricing, timeline, contact; per-page cover image; internal links written as `page:<slug>` resolve per locale and work under any base path.
- Cloudflare zones page: zone discovery and search, subdomain creation (automatic or manual label, A/AAAA/CNAME, TTL, proxy flag default off), collision checks, DNS plan updates when only the proxy flag differs (never overwrites records NGM does not manage).
- `scripts/ops/seed_sites.cjs` creates, builds and publishes the four sites (`--refresh` replaces content with the current starter).
### Fixed
- Pages were ordered with a non-transitive comparator once posts and pages were mixed, so newly added posts could appear in the wrong place.
- Page cover images were left out of the built site.

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
