# NGM — Nginx Gateway Manager

NGM manages Ubuntu's Nginx as a gateway: HTTP/HTTPS reverse proxy, TCP/UDP streams, TLS passthrough on a shared port 443 (SNI routing), certificates (ACME), static websites, a managed UFW firewall, encrypted backups, logs, monitoring and alerts. It ships as one Go binary with a React control center. Every change goes through **Safe Apply**: validate → stage → `nginx -t` → reload → verify, with automatic return to the last known-good configuration.

> **Status:** release candidate on the development channel. Read the [known limitations](#known-limitations) before production use. The normative specification is [MASTER_SPEC.md](MASTER_SPEC.md), and the real per-requirement status is in [PROGRESS.md](PROGRESS.md).

## Requirements
- Ubuntu 22.04 or 24.04 (amd64 or arm64), root access, the Ubuntu `nginx` package (installed if absent), and the stream module for TCP/TLS routes.
- The installer never edits third-party Nginx or UFW configuration. An existing customised Nginx needs `--adopt-existing-nginx`.

## Install (signed, one line)
```sh
curl -fsSL https://github.com/Saj-1992/ngm/releases/latest/download/install.sh | sudo sh
```
This downloads the latest signed release, verifies the Ed25519 signature of `manifest.json` against the publisher key pinned inside `install.sh`, checks the binary's SHA-256, and only then runs `ngm install`, which verifies everything again before changing anything. Any mismatch stops the installation and nothing is changed.

Pin the publisher key out of band for extra assurance (compare with the fingerprint in the release notes):
```sh
curl -fsSL https://github.com/Saj-1992/ngm/releases/latest/download/install.sh -o install.sh
sudo NGM_EXPECT_KEY=sha256:<published-fingerprint> sh install.sh
```
Offline or air-gapped: download the release assets, then `sudo sh install.sh --from /path/to/release/dir`.

First run: `ssh -L 9999:127.0.0.1:9999 root@<server>`, open `http://127.0.0.1:9999/setup`, then use the bootstrap token the installer printed (`ngm admin bootstrap-token` issues a new one). Create the owner account and enrol MFA.

## Everyday operations
| Task | Command / place |
|---|---|
| Status and diagnostics | `ngm status`, `ngm doctor` |
| Test the full Nginx config | `ngm config test` |
| Return to the previous known-good gateway config | `ngm rollback [GENERATION]` (or Deployments in the UI) |
| Backups | `ngm backup set-passphrase`, `ngm backup create`, `ngm restore --preview FILE` |
| Firewall emergency revert | `ngm fw-revert` |
| Rebuild the log index | `ngm logs reindex` |
| Vault key rotation | `ngm vault status \| rotate \| retire N` |
| Lost owner password / MFA | `ngm admin reset USER` |

## Fallback website (recommended)
In **Websites → Fallback website**, choose a published website and a certificate, then deploy. Every visitor that matches no route sees that website, with a real certificate, instead of a closed connection or a TLS error. This covers unknown host names, direct IP access, unknown or missing SNI on 443, crawlers and scanners. NGM also turns off Nginx version tokens. Publish realistic content (see ADR-036 for the limits).

## Updates and rollback
```sh
ngm update check --from /path/to/release      # verify only
sudo ngm update apply --from /path/to/release --yes
sudo ngm update rollback --yes                 # back to the previous release
```
The **installed** binary verifies the new release with its pinned keys. Before installing, NGM takes a database snapshot and an encrypted backup (if a passphrase is set). If the new version is not healthy, NGM rolls back automatically. Downgrades are possible only through `update rollback`. The UI (Settings → Updates) shows the status but never installs.

**Nginx package upgrades:** `sudo ngm nginx upgrade` shows the plan, and with `--yes` it backs up, upgrades with your config files kept, tests and restarts. Upgrades made outside NGM (for example unattended-upgrades) are detected and raise an alert. `sudo ngm nginx reconcile` re-verifies and accepts them. NGM does not downgrade packages.

## Repair and uninstall
- `sudo ngm repair` re-verifies the installed release against its signed manifest and re-applies directories, permissions, accounts and units. It refuses to run a modified binary.
- `ngm uninstall --keep-data` or `--purge` prints the plan and dependency warnings. Add `--yes` to execute. Purge additionally needs `--confirm "purge <hostname>"`.
  - **Keep Data** removes the program and disconnects NGM from Nginx. It keeps `/etc/ngm`, `/var/lib/ngm`, logs, websites and NGM's UFW rules.
  - **Purge** also deletes those, NGM-tagged UFW rules (never the only SSH rule) and NGM accounts.
  - Third-party files and rules are never touched. Copy `/var/lib/ngm/backups` off the server first.

## Building a release (publisher)
```sh
sh scripts/release.sh VERSION CHANNEL path/to/key.pem   # → dist/release/VERSION/
```
Keys come from `ngm release keygen`. Public keys are pinned in `internal/release/trusted/`, and keys named `dev-*` may sign only the development channel. Private keys never enter the repository.

## Documentation
[SECURITY_MODEL.md](SECURITY_MODEL.md) · [DEPLOYMENT_CONTRACT.md](DEPLOYMENT_CONTRACT.md) · [API_CONTRACT.md](API_CONTRACT.md) (OpenAPI in [api/openapi.json](api/openapi.json)) · [DECISIONS.md](DECISIONS.md) · [TEST_REPORT.md](TEST_REPORT.md) · [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)

## Known limitations
See the open items in [PROGRESS.md](PROGRESS.md#open-items-consolidated-updated-every-phase). Most importantly:
- Only Ubuntu 24.04 AMD64 has been exercised live. 22.04 and ARM64 binaries are built but untested.
- Only a development signing key exists, so there is no stable channel yet.
- Cloudflare and Telegram integrations have not been tested against the real services.
- Benchmarks are same-host loopback measurements on a 2-vCPU VM. They are not a capacity guarantee.
