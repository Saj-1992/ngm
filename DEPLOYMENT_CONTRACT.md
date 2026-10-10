# DEPLOYMENT_CONTRACT

Refines MASTER_SPEC §7.2, §8, §9.

## Job state machine
```
Queued → Validating → ImpactAnalyzed → Staging → Preflight → Applying → Verifying → Succeeded
Any pre-Applying state → Blocked | Failed | Cancelled
Applying/Verifying → Compensating → RolledBack | RecoveryRequired
```
- Terminal states are `Succeeded`, `Failed`, `Cancelled`, `RolledBack`, and `Blocked` (a Blocked job can be resubmitted as a new job). `RecoveryRequired` is terminal
  until an operator resolves it through the Recovery Center.
- Cancellation is allowed only in `Queued`, `Validating`, `ImpactAnalyzed`, `Staging`, and `Preflight`. No external side effects have happened yet in those states.
- Transitions are enforced in `internal/jobs` (`ValidTransition`). Each transition is a row in `job_steps` with a timestamp,
  actor/worker, fencing token, and evidence JSON.

## Step classification (for crash reconciliation)
Each step declares `idempotent` (safe to re-run) or `external-effect` (ambiguous after a crash).
On startup, `ngm-ops` scans jobs that are not terminal:
- Last step completed and the next step idempotent: resume.
- Step started and external-effect with no completion record: compare observed runtime (include graph hash, listeners, UFW owned rules,
  cert files, website pointers) against the staged and the Active generation. If it matches exactly one, record that and continue or
  compensate. Otherwise mark `RecoveryRequired`.
- Never reload nginx or touch UFW blindly during reconciliation.

## Locks
Total order and fencing are defined in DECISIONS ADR-005. Lease TTL is 30 s and the heartbeat runs every 10 s. A job that loses its lease stops at the
next checkpoint. Its subsequent writes fail the fencing check.

## Generations
- Desired is the DB model plus a draft revision. A staged generation is rendered to `/var/lib/ngm/generations/<id>/` with
  `manifest.json` (file → sha256, ownership) and is immutable once hashed.
- Activation copies the staged files into the NGM-owned include tree `/etc/nginx/ngm/` via helper, runs `nginx -t -c /etc/nginx/nginx.conf`
  against the prospective tree (by staging into an alternate root first), then reloads, then verifies.
- Last-known-good is always retained. Rollback means re-activating the previous generation through the same path.

## Verification after reload
Check that the master PID is unchanged, workers re-spawned, the expected `ss` listeners exist, per-route probes pass (HTTP status/Host, TLS SNI cert
identity, TCP connect), and the management origin is reachable. Long-lived connections may stay on old workers.

## Firewall (UFW)
Only rules carrying the comment marker `ngm:<rule-id>` are owned. Before ingress changes, NGM detects the SSH port(s) from `sshd -T`
and the current session source. A change that could drop SSH needs explicit confirmation plus a watchdog: if the operator does not confirm
within N seconds, the helper reverts the owned-rule delta. `ufw reset` and flush are never used.
