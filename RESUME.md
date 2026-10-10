# RESUME — where work stands (read this first after an interruption)

Updated by Claude Code after every completed step. If a session stops (token limit, crash),
the next session continues from **Next steps**, the first unchecked item. Do not redo checked items.

## Context
- Deployed build on the VM: 0.8.1-rc.2. (build with GOPROXY=https://goproxy.cn,direct so toolchain go1.26.9 resolves); next rc.9. Build with GOPROXY=https://goproxy.cn,direct (toolchain go1.26.9). (upload binaries gzip-compressed; the link drops large transfers) (development channel). Ship new builds with
  `sh scripts/release.sh <ver> development .local/release-keys/dev-2026a.key`, then upload to
  `/tmp/rel-<ver>` and run `ngm update apply --from /tmp/rel-<ver> --yes` (see TEST_REPORT Phase 7).
- Full E2E runner: `sh scripts/e2e/run_all.sh`. Summary in `dist/e2e/summary.txt`, logs in `dist/e2e/*.log`.
- Status per requirement: PROGRESS.md. Evidence: TEST_REPORT.md. Open items: PROGRESS "Open items".
- Owner instructions in force:
  - Reply in Persian and keep token use low.
  - Delete nothing.
  - Never claim Verified without evidence.
  - Make every unknown or probing visitor see a real-looking website (no routing fingerprint), to avoid abuse flags from crawlers and scanners (Cloudflare, Hetzner, firewalls).

## Next steps
### Owner requirements 2026-10-10 (do in order)
- [x] R1 DONE (live): panel at https://<domain>:9443/<secret>/ only. api.public_path config, API prefix-strip + <base> injection, SPA base-aware (base.ts), managementOnly accepts host+path route, set-origin takes port+path. Verified in a real browser. The panel at https://<domain>:9443/<secret-path>/ only: API/SPA served under a base path (config api.public_path); managementOnly accepts a host + path_prefix route on an https listener; set-origin with port+path.
- [x] R2 DONE (live): apex on 80/443/9443 = decoy site (global fallback + compiler catch-all location / in named vhosts). Verified. The apex <domain> on ANY port/request shows the fallback website (80 and 443 = fallback site with the panel-prod cert; 9443 outside the secret path = fallback site). Move the test routes off the apex: the gateway suite uses t.<domain> via Host/--resolve; the ACME test verifies on a private 127.0.0.1 listener.
- [ ] R3. All tests on this one server (VM); update the suites; full run green.
- [ ] R4. Make the repo Saj-1992/ngm PUBLIC (owner chose this; re-scan history for secrets first). GitHub Release with signed binaries + install.sh; one-link install: curl -fsSL https://github.com/Saj-1992/ngm/releases/latest/download/install.sh | sudo sh. install.sh defaults --from to releases/latest/download. Test it on the VM.
- [x] 15. Incident: the ACME E2E attached its staging cert to the published panel route, so the panel served an untrusted cert. Fixed: the ACME test restores the cert in a finally block, publish_panel repairs cert/destination, and the TLS tests use gw.<domain>.
- [x] 17. CI 50dfb01 all green: install matrix (4 OS/arch) + keep-data/purge + cross-host restore + govulncheck. PROGRESS rows with live evidence marked Verified. Remaining: O-24 (owner key), O-18/O-19 (tokens), O-27, O-10/O-23/O-32 (owner).
- [x] 16. 0.8.1-rc.3 deployed + full E2E running (background). Then check CI on GitHub (install matrix + uninstall with sudo checks), record results.
- [x] 13. The Control Center is PUBLISHED at https://example.test (real Let's Encrypt cert "panel-prod", route "ngm-panel-public", backend "ngm-panel", origin set). Owner account "sajjad" (Owner); credentials in .local/panel-credentials.txt. The E2E suites protect these resources; run_all ends with scripts/ops/publish_panel.cjs (re-runnable check/repair).
- [x] 14. CI found that a fresh install left nginx stopped; the installer now starts nginx (after nginx -t) before NGM services (0.8.1-rc.2 deployed).
- [x] 8. Local git: branch ngm-0.8, commit 063df51 (304 files, secret scan clean) + .gitattributes. Next: the owner creates a private GitHub repo and pushes, then CI runs (O-1). The owner generates the stable key offline and sends the public key (O-24).
- [x] 9. GitHub: private repo Saj-1992/ngm created; pushed ngm-0.8 and main (token never stored; the owner should revoke it). CI runs started.
- [x] 10a. CI run 37944749243 (6fcb021): all green (go 22.04/24.04/24.04-arm, web, security/govulncheck). Fixed an IPC EPIPE race found by CI.
- [ ] 12. Live uninstall/purge + restore on the VM: blocked by the Claude Code auto-mode safety classifier (needs an explicit permission rule from the owner). A safety backup exists in /root/ngm-safe on the VM; the passphrase is in .local/backup-passphrase.txt.
- [ ] 11. CI install job (fresh install + keep-data/purge uninstall on 22.04/24.04 x amd64/arm64) pushed in 5db8a2f; check the result, fix, then record in TEST_REPORT/PROGRESS (O-2, O-25, O-26, O-1, O-30).
- [ ] 10. Check the CI results (GitHub Actions), fix failures, re-push. The owner must provide a token again if needed (never write it to files).
(All self-contained work is done. Remaining items need the owner: see PROGRESS open items O-1, O-2, O-10, O-12, O-18, O-19, O-23, O-24, O-25, O-26, O-27, O-30, O-32.)
- [x] 1. (rc.7: all suites pass except 3 test/version artifacts, now fixed; saved in dist/e2e/summary_rc7.txt) Read `dist/e2e/summary.txt` from the full run (started 2026-10-09 on rc.7). Record the result in TEST_REPORT ("Post-RC 2") and fix any failure.
- [x] 2. (decoy E2E 13/13 on rc.8) **Fallback / decoy website (ADR-036)**. Progress: code, API, OpenAPI, UI card, messages and ADR done; still to do: VM probe E2E (after the full run ends):
  - unknown Host and IP-only access on HTTP, plus unknown or missing SNI on shared 443, are served a real published NGM website with a real certificate, instead of 444 or a reset;
  - no NGM or Nginx fingerprints (server tokens, NGM headers, default error pages);
  - ACME challenges keep working;
  - unit tests, a live probe E2E (`e2e_p9_decoy.cjs`), UI setting, en/fa messages, docs.
- [x] 3. (rc.8 installed; affected suites green) Ship as rc.8 via `ngm update`, then run the full E2E again.
- [x] 4. Update PROGRESS/TEST_REPORT/README, then give the owner the final report in Persian.

- [x] 5. O-29: an offline OSV scan (scripts/vulncheck, vulndb from GitHub) found Go 1.26.5 stdlib vulnerabilities in imported packages. Fixed with toolchain go1.26.9 (downloaded via GOPROXY=https://goproxy.cn) and x/crypto v0.57.0. Rescan is clean (only openpgp, which is not imported).
- [x] 7. The template root page is now the real home page (no meta-refresh). Validation issue codes are translated (O-7).
- [x] 6a. The rc.9 full E2E found a real bug: the fallback certificate file was not emitted when no route used it, so deploys rolled back. Fixed with a unit test; the gateway suite now disables the fallback (baseline) and the decoy suite re-enables it.
- [x] 6b. rc.10 was refused by rc.9 (lexical pre-release ordering), fixed in release.CompareVersions; shipped 0.8.1-rc.1, decoy 14/14.
- [x] 6. (0.8.1-rc.1) Final full E2E: 204/204 checks green; record dist/e2e/summary.txt in TEST_REPORT "Post-RC run 3". Old step text: Build and ship rc.10 (gzip upload), run the full E2E (sh scripts/e2e/run_all.sh), record the results in TEST_REPORT, PROGRESS and RESUME.

- [x] 5. O-29: offline OSV scan (, vulndb from GitHub) found Go 1.26.5 stdlib vulns in imported packages. Fixed with toolchain go1.26.9 (download via GOPROXY=https://goproxy.cn) and x/crypto v0.57.0; rescan clean.
- [ ] 6. Ship rc.9, run the full E2E (), record the results.
- [ ] 7. Make the fallback/template root page realistic (no meta-refresh language list for single-locale sites); translate validation issue codes (O-7).

## Done (most recent last)
- Phases 1–8 complete; RC built. Post-RC: O-3, O-5, O-6, O-8, O-11, O-13, O-14, O-15, O-21, O-22, O-28 and O-31 closed; O-7 partially closed.
