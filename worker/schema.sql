-- Table for the reports in D1. Apply once:
--   npx wrangler d1 execute csa-2026-01 --remote --file=schema.sql
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,        -- random, or the old KV key for reports moved over
  received TEXT NOT NULL,     -- time of receipt, ISO 8601 in UTC
  report TEXT NOT NULL        -- the report as JSON
);
CREATE INDEX IF NOT EXISTS reports_received ON reports (received, id);

-- Files known as malware, for the fingerprint check (POST /csa-2026-01-report/lookup).
-- Filled with tools/bad-hashes-sql.mjs; the worker also creates the table on first use.
-- answer 1: the check answers known_bad; 0: the entry waits and counts as not known.
-- asked, asked_last: on how many days a check asked for the file (at most one write a day),
-- and the last of them.
CREATE TABLE IF NOT EXISTS bad_hashes (
  sha256 TEXT PRIMARY KEY,             -- of the file, 64 lowercase hex characters
  note TEXT NOT NULL,                  -- what it is, for the maintainers; never sent
  answer INTEGER NOT NULL DEFAULT 0,
  by TEXT NOT NULL,                    -- who added or last changed the entry
  at TEXT NOT NULL,                    -- when, ISO 8601 in UTC
  asked INTEGER NOT NULL DEFAULT 0,
  asked_last TEXT NOT NULL DEFAULT ''  -- YYYY-MM-DD, empty until the first check
);
