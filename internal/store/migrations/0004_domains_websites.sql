-- Phase 5: certificate key versions, domain registry/DNS evidence, ACME, websites.

-- Each private key version gets its own vault entry and deployed file, so a
-- generation always pairs its certificate with the exact key it was built
-- with (renewal never rewrites a key that an older generation still uses).
-- '' = legacy single key (vault name "key", file keys/<certificate id>.key).
ALTER TABLE certificates ADD COLUMN key_id TEXT NOT NULL DEFAULT '';

ALTER TABLE domains ADD COLUMN dns_provider TEXT NOT NULL DEFAULT 'manual' CHECK (dns_provider IN ('manual','cloudflare'));
ALTER TABLE domains ADD COLUMN provider_zone_id TEXT NOT NULL DEFAULT '';

-- Latest DNS evidence per (domain, name, type, source). source: authoritative | resolver.
CREATE TABLE dns_observations (
  domain_id   TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  rtype       TEXT NOT NULL,
  source      TEXT NOT NULL CHECK (source IN ('authoritative','resolver')),
  server      TEXT NOT NULL DEFAULT '',
  values_json TEXT NOT NULL DEFAULT '[]',
  ttl         INTEGER,
  rcode       TEXT NOT NULL DEFAULT '',
  error       TEXT NOT NULL DEFAULT '',
  observed_at TEXT NOT NULL,
  PRIMARY KEY (domain_id, name, rtype, source)
) STRICT;

CREATE TABLE acme_accounts (
  id            TEXT PRIMARY KEY,
  directory_url TEXT NOT NULL,
  email         TEXT NOT NULL DEFAULT '',
  account_url   TEXT NOT NULL DEFAULT '',
  key_secret_id TEXT REFERENCES vault_secrets(id) ON DELETE RESTRICT,
  created_at    TEXT NOT NULL,
  UNIQUE (directory_url)
) STRICT;

ALTER TABLE websites ADD COLUMN content_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE websites ADD COLUMN draft_revision INTEGER NOT NULL DEFAULT 1;

ALTER TABLE website_versions ADD COLUMN source_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE website_versions ADD COLUMN manifest_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE website_versions ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE website_versions ADD COLUMN published_at TEXT;
ALTER TABLE website_versions ADD COLUMN job_id TEXT;

CREATE TABLE website_media (
  id         TEXT PRIMARY KEY,
  website_id TEXT NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  mime       TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256     TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (website_id, name)
) STRICT;
