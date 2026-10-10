# CLAUDE.md — NGM operating instructions

`MASTER_SPEC.md` is the normative contract. Read it before changing behavior. This file
covers how to work in this repo. It does not define product behavior.

## Non-negotiables
- Do not mock, fake, or skip a P0/P1 requirement, or claim it is done when it is not. Record
  status per requirement ID in `PROGRESS.md`, with evidence in `TEST_REPORT.md`.
- Valid statuses: `Not Started`, `In Progress`, `Implemented` (code exists, not fully evidenced),
  and `Verified` (all Definition-of-Done items from MASTER_SPEC §19.3, with evidence).
  `Skipped` and `Not Tested` never count as Pass.
- Do not put secrets in the repo, fixtures, logs, or screenshots. `example server detail.txt` is
  local-only and git-ignored. Code reads credentials at runtime and never copies them into files.
- Request handlers never run nginx, ufw, or system commands. Mutations go through a job, then
  `ngm-ops`, then `ngm-helper`, which only accepts typed, allowlisted operations.
- Do not edit or overwrite non-NGM Nginx or UFW resources.
- Nothing destructive on the test server without the owner's explicit authorization. Read-only
  probing and installing into NGM-owned paths on the designated test VM are authorized for
  development.

## Toolchain (Windows dev host)
- Go: `D:\Sajjad\tools\go\bin\go.exe` (1.26.x). It is not on PATH, so call it by full path or prepend it to PATH.
- Node 24 + npm 11 for `web/`.
- The dev host has no Linux runtime (no WSL or Docker). Linux-only tests (nginx, systemd, UFW, peercred)
  run on the test VM. Run them through `scripts/remote/vm.cjs` (exec/put), which reads credentials from the
  local, git-ignored file. In Git Bash set `MSYS_NO_PATHCONV=1`, otherwise `/tmp/...` arguments get rewritten to Windows paths.
- On the VM, run Linux tests as cross-compiled `go test -c` binaries, under `setpriv --reuid=nobody`.

## Layout
- `cmd/ngm` is a single binary with role modes: `api`, `ops`, `monitor`, `log-indexer`, `helper`, plus CLI subcommands.
- `internal/...` holds domain packages. See `IMPLEMENTATION_PLAN.md` for the map.
- `web/` holds the React + TS + Tailwind + Radix UI (shadcn pattern) Control Center.
- `api/openapi.json` is the API contract (JSON to avoid a YAML dependency). Contract tests check routes against it.
- `deploy/` holds systemd units and installer assets.

## Commands
- `make test`, or `go test ./...` with `CGO_ENABLED=0` (modernc sqlite is pure Go)
- `make build` cross-compiles linux/amd64 and linux/arm64
- `cd web && npm run build && npm test`

## Quality gates
These are Functional, Routing, Security, Reliability, Compatibility, and Delivery. A phase advances only
when its relevant gates actually pass, with evidence in `TEST_REPORT.md`.
