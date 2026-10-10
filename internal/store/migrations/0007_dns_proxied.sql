-- Cloudflare proxy (orange cloud) is an explicit per-record choice; NGM's
-- default stays DNS-only because proxied hosts cannot carry non-HTTP ports,
-- TLS passthrough or UDP.
ALTER TABLE dns_record_expectations ADD COLUMN proxied INTEGER NOT NULL DEFAULT 0 CHECK (proxied IN (0,1));
