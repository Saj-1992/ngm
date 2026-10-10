# RELEASE_CHECKLIST

Stable is forbidden until every item is checked with evidence links in TEST_REPORT.md.
State as of 0.8.1-rc.3 (development channel) + CI 50dfb01, 2026-10-09. `[x]` = evidenced, `[~]` = partial, `[ ]` = not met.

## Artifacts
- [~] linux/amd64 and linux/arm64 binaries are built from commits in Saj-1992/ngm (CI builds both and runs them natively). No tag yet, and reproducibility has not been compared byte for byte.
- [x] Manifest: version, arch, OS support, schema/API version, migrations (db_schema), dependencies, nginx module expectations (TEST_REPORT Phase 7)
- [x] Ed25519 signature over the manifest, with artifact sha256 sums in the manifest (Phase 7)
- [x] Installer pins the publisher public key and fails closed, tested with a tampered artifact, a tampered manifest, a foreign key, a missing signature and a wrong expected fingerprint (Phase 7 `bootstrap-reject-*`)
- [ ] Production (stable/beta) publisher key with an out-of-band fingerprint. Only `dev-2026a` exists (O-24).

## Gates
- [~] Functional: all P1 features Verified. Features are Implemented with live evidence on one host. None is marked Verified, because the compatibility matrix and CI are missing (PROGRESS).
- [x] Routing: §18 scenarios 2–5 on a real VM. Gateway E2E 26/26 was rerun on 0.7.6-dev (Phase 8). HTTPS backends (verify on/off) and WebSocket over terminated TLS now pass (post-RC).
- [~] Security: live sweep of 136 operations, MFA/CSRF/SSRF/ZIP/IPC tests, govulncheck and npm audit clean in CI. No third-party penetration test.
- [x] Reliability: §18 scenarios 6–8 and 12 on the VM, including disk pressure and KEK rotation killed mid-rewrap; cross-host restore on 4 CI hosts.
- [x] Compatibility: fresh install on 22.04 AMD64, 22.04 ARM64, 24.04 AMD64 and 24.04 ARM64 (CI install job, machine identity in the logs). Full E2E on the 24.04 AMD64 VM.
- [x] Delivery: §18.14 (signed update, automatic and explicit rollback, Nginx drift) on the VM; §18.16 (keep-data, purge, safeguards, third-party preserved) on 4 CI hosts; docs: README plus contracts.

## P0 blockers (all must be absent)
Each item below is a statement about evidence on the test VM, not a guarantee.
- [x] Incorrect route dispatch: no dispatch errors in gateway E2E (26/26) or route simulation comparisons
- [x] Management lockout: SSH guard rule, dead-man revert and the purge SSH rule are protected (Phase 4/7)
- [x] Unauthenticated privileged operations: all 136 operations were swept (Phase 8)
- [x] Secret exposure: log redaction, no token echo, vault-only secrets (Phases 2, 6, 8)
- [x] Loss of Active config without recovery evidence: crash/kill-point/drift tests (Phase 4), CLI rollback (Phase 7)
- [x] Invalid signed-update verification: tamper suite (Phase 7)
- [x] False health/success claims: Unknown ≠ Healthy, `no_changes` is Blocked rather than Succeeded, and verification happens over real HTTP (Phases 4–6)
- [x] Broken backup integrity: checksummed, verified on creation and restore (Phase 4)
- [~] Unresolved high/critical exploitable findings: none known, but scanner coverage is incomplete (see Security)

**Verdict:** 0.8.1-rc.3 meets every gate that can be evidenced without the production signing key. A stable or beta release still needs the offline publisher key (O-24) and its fingerprint published out of band, plus a tagged commit.
