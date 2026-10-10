-- Phase 6: alert de-duplication, notification delivery, system metrics,
-- performance settings.

CREATE UNIQUE INDEX alerts_open ON alerts(rule, subject) WHERE state <> 'resolved';
CREATE INDEX alerts_state ON alerts(state, last_at);
ALTER TABLE alerts ADD COLUMN acknowledged_by TEXT;
ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT;
ALTER TABLE alerts ADD COLUMN message TEXT NOT NULL DEFAULT '';

CREATE TABLE notification_deliveries (
  id          TEXT PRIMARY KEY,
  target_id   TEXT NOT NULL REFERENCES notification_targets(id) ON DELETE CASCADE,
  alert_id    TEXT REFERENCES alerts(id) ON DELETE SET NULL,
  event       TEXT NOT NULL CHECK (event IN ('firing','resolved','test')),
  status      TEXT NOT NULL CHECK (status IN ('pending','sent','failed','rate_limited')),
  attempts    INTEGER NOT NULL DEFAULT 0,
  next_at     TEXT NOT NULL,
  last_error  TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at  TEXT NOT NULL,
  sent_at     TEXT
) STRICT;
CREATE INDEX deliveries_due ON notification_deliveries(status, next_at);
CREATE INDEX deliveries_target ON notification_deliveries(target_id, created_at);

CREATE TABLE metric_samples (
  ts          INTEGER PRIMARY KEY, -- unix seconds
  cpu_pct     REAL NOT NULL,
  load1       REAL NOT NULL,
  mem_used    INTEGER NOT NULL,
  mem_total   INTEGER NOT NULL,
  disk_used   INTEGER NOT NULL,
  disk_total  INTEGER NOT NULL,
  nginx_conns INTEGER NOT NULL DEFAULT -1
) STRICT;
