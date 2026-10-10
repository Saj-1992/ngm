-- Phase 5: the dns-provider lock resource (Cloudflare jobs). SQLite cannot
-- alter a CHECK constraint, so lock_leases is rebuilt with the new list.
CREATE TABLE lock_leases_new (
  resource      TEXT PRIMARY KEY CHECK (resource IN ('system-update','backup-restore','gateway-config','certificate','website-publish','firewall','dns-provider')),
  holder_job_id TEXT NOT NULL,
  holder_worker TEXT NOT NULL,
  fencing_token INTEGER NOT NULL,
  acquired_at   TEXT NOT NULL,
  heartbeat_at  TEXT NOT NULL,
  expires_at    TEXT NOT NULL
) STRICT;
INSERT INTO lock_leases_new SELECT resource, holder_job_id, holder_worker, fencing_token, acquired_at, heartbeat_at, expires_at FROM lock_leases;
DROP TABLE lock_leases;
ALTER TABLE lock_leases_new RENAME TO lock_leases;
