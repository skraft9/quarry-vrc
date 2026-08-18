-- huntplatform schema. SQLite.
--
-- DESIGN CONTRACT: the markdown files under /workspace/vulns_* are the SOURCE OF TRUTH.
-- Every row here is an INDEX of a file on disk. `file_path` is the link back.
-- This database can be deleted and fully rebuilt by `python3 ingest.py --rebuild`.
-- Any write from the UI MUST write the file first, then re-index that one file.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- programs
CREATE TABLE IF NOT EXISTS programs (
  id          INTEGER PRIMARY KEY,
  slug        TEXT NOT NULL UNIQUE,      -- 'example', 'acme', 'globex'
  name        TEXT NOT NULL,
  platform    TEXT,                      -- 'hackerone'
  url         TEXT,
  workspace   TEXT,                      -- /workspace/vulns_example
  scope_md    TEXT,                      -- program/GUIDELINES.md body, HAND-ENTERED
  roe_md      TEXT,                      -- program/ROE.md body, HAND-ENTERED
  -- policy_md is the API's copy of the same thing and is DELIBERATELY a third column. scope_md
  -- and roe_md are pasted in by hand from the workdir program/ folder, are not reproducible from
  -- HackerOne, and are the authority where they exist. Nothing that talks to the API is allowed
  -- to write the two columns above it. See h1.sync_program_details.
  policy_md   TEXT,
  submission_state TEXT,                 -- 'open' | 'paused' | ...
  state            TEXT,                  -- HackerOne visibility: 'public_mode' | 'soft_launched' (private)
  offers_bounties  INTEGER,              -- 1 / 0 / NULL when never synced
  bounty_earned    TEXT,                 -- bounty_earned_for_user, TEXT like reports.bounty
  reports_90d      INTEGER,              -- reports the program received in 90 days.
                                         -- MANUAL: the hacker API does not expose it.
  currency         TEXT,
  synced_at   TEXT,                      -- last successful /hackers/programs/<handle> fetch
  updated_at  TEXT
);

-- ---------------------------------------------------------------- scopes
-- HackerOne structured scopes: the assets a program says are in scope, with their asset TYPE.
-- A SEPARATE TABLE from `targets` on purpose. A target is one local workspace directory that
-- leads and reports are keyed to by target_id; a scope is one of many API-owned rows per
-- program, carrying an axis (asset_type, eligible_for_bounty) targets do not have. Keeping them
-- apart means the scope sync can delete and rewrite freely without a workspace-derived target
-- ever being reachable by it.
CREATE TABLE IF NOT EXISTS scopes (
  id          INTEGER PRIMARY KEY,
  program_id  INTEGER REFERENCES programs(id) ON DELETE CASCADE,
  h1_id       TEXT NOT NULL UNIQUE,      -- structured scope id, globally unique on HackerOne
  identifier  TEXT NOT NULL,             -- '*.example.com', 'Example OneAgent'
  asset_type  TEXT,                      -- 'URL', 'WILDCARD', 'SOURCE_CODE', ... open set
  eligible_for_bounty INTEGER NOT NULL DEFAULT 0,
  synced_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(program_id);

-- ---------------------------------------------------------------- targets
CREATE TABLE IF NOT EXISTS targets (
  id          INTEGER PRIMARY KEY,
  program_id  INTEGER REFERENCES programs(id) ON DELETE SET NULL,
  slug        TEXT NOT NULL UNIQUE,      -- 'web-app', 'api-service'
  name        TEXT NOT NULL,
  version     TEXT,
  source_path TEXT,
  codeql_db   TEXT,
  workspace   TEXT NOT NULL,             -- /workspace/vulns_example
  updated_at  TEXT
);

-- ---------------------------------------------------------------- leads
-- A lead is any file under <workspace>/<CLASS>/notes/*.md or <workspace>/notes/*.md
-- status is parsed from the header line, see ingest.py STATUS_PATTERNS.
CREATE TABLE IF NOT EXISTS leads (
  id          INTEGER PRIMARY KEY,
  target_id   INTEGER REFERENCES targets(id) ON DELETE CASCADE,
  ref         TEXT,                      -- 'L2', 'G8', 'F3'  (nullable: round logs etc)
  title       TEXT NOT NULL,
  class       TEXT,                      -- 'BAC','DoS','SECRETS','INTEGRITY','RCE','API', NULL
  status      TEXT NOT NULL DEFAULT 'unknown',
                                         -- open | confirmed | ready | submitted | awarded
                                         -- | parked | killed | unknown (internal)
  severity    TEXT,
  file_path   TEXT NOT NULL UNIQUE,
  header      TEXT,                      -- verbatim first line
  body        TEXT NOT NULL,
  mtime       REAL,
  indexed_at  TEXT,
  UNIQUE(file_path)
);
CREATE INDEX IF NOT EXISTS idx_leads_target ON leads(target_id);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
CREATE INDEX IF NOT EXISTS idx_leads_class  ON leads(class);

-- ---------------------------------------------------------------- reports
-- Files under <workspace>/<CLASS>/reports/*.md, plus rows parsed from the
-- Vulnerability_Tracker.md markdown table (tracker_only=1 when no file exists).
CREATE TABLE IF NOT EXISTS reports (
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER REFERENCES targets(id) ON DELETE SET NULL,
  h1_id         TEXT,                    -- '3899885'
  ref           TEXT,                    -- 'F1','G8'
  title         TEXT NOT NULL,
  state         TEXT,                    -- triaged/resolved/duplicate/n-a/new
  severity      TEXT,
  bounty        TEXT,
  submitted_on  TEXT,
  resolved_on   TEXT,
  url           TEXT,
  class         TEXT,
  file_path     TEXT UNIQUE,
  body          TEXT,
  tracker_row   TEXT,                    -- verbatim '| ... |' line
  tracker_only  INTEGER NOT NULL DEFAULT 0,
  -- 'report' | 'rca'. RCA files are companion root-cause docs that share the
  -- parent report's H1 id; counting them as reports inflates the tracker.
  kind          TEXT NOT NULL DEFAULT 'report',
  -- HackerOne-synced fields. h1.py also adds these via ALTER TABLE for existing databases,
  -- but they must exist here so a FRESH database is queryable before any sync has run -
  -- the Tracker filters on `source`, so a missing column breaks GET /api/reports outright.
  source        TEXT,
  program       TEXT,
  weakness      TEXT,
  asset         TEXT,
  last_activity TEXT,
  h1_state      TEXT,
  synced_at     TEXT,
  cvss          TEXT,
  cvss_vector   TEXT,
  cwe           TEXT,
  cve           TEXT,
  currency      TEXT,
  reporter_username TEXT,
  reporter_id   TEXT,
  collaborators TEXT,
  payout_split  TEXT,
  my_bounty     TEXT,
  my_role       TEXT,
  h1_body_path  TEXT,
  -- Full HackerOne conversation as JSON: [{kind,actor,at,internal,message}].
  -- Only the DETAIL endpoint populates it; see h1.refresh_details().
  thread        TEXT,
  mtime         REAL,
  indexed_at    TEXT,
  -- When this row first appeared. NOT the same question as indexed_at, which means "content
  -- changed" and therefore moves every time HackerOne triages or pays a report. Written once on
  -- INSERT, never updated. See common.ensure_first_seen().
  first_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target_id);
CREATE INDEX IF NOT EXISTS idx_reports_h1 ON reports(h1_id);

-- ---------------------------------------------------------------- advisories
-- Not file-derived by default; created via the UI. If created from a file, file_path is set.
CREATE TABLE IF NOT EXISTS advisories (
  id          INTEGER PRIMARY KEY,
  target_id   INTEGER REFERENCES targets(id) ON DELETE SET NULL,
  lead_id     INTEGER REFERENCES leads(id) ON DELETE SET NULL,
  ref         TEXT,                      -- 'CVE-2026-1234', 'ESA-2026-07'
  source      TEXT,
  title       TEXT NOT NULL,
  url         TEXT,
  published   TEXT,
  status      TEXT DEFAULT 'watch',      -- watch | relevant | dismissed
  body        TEXT,
  file_path   TEXT,
  indexed_at  TEXT,
  -- When we first pulled this advisory. NOT indexed_at, which moves every time the vendor edits
  -- the advisory upstream. Written once on INSERT. See common.ensure_first_seen().
  first_seen_at TEXT
);

-- ---------------------------------------------------------------- uploads
CREATE TABLE IF NOT EXISTS uploads (
  id           INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL,
  stored_path  TEXT NOT NULL,
  filed_to     TEXT,                     -- workspace path if filed into a hunt folder
  mime         TEXT,
  size         INTEGER,
  sha256       TEXT,
  uploaded_at  TEXT,
  uploaded_by  TEXT
);

-- ---------------------------------------------------------------- audit
CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY,
  ts          TEXT NOT NULL,
  actor       TEXT,
  action      TEXT NOT NULL,             -- login|login_fail|create|update|upload|reindex|tracker_apply
  entity      TEXT,
  entity_id   INTEGER,
  detail      TEXT,
  remote      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);

-- ---------------------------------------------------------------- sessions
CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,          -- sha256 of the cookie value, never the raw token
  username    TEXT NOT NULL,
  created_at  REAL NOT NULL,
  expires_at  REAL NOT NULL,
  remote      TEXT
);

-- ---------------------------------------------------------------- search
CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
  kind,            -- lead|report|advisory|program
  rowid_ref UNINDEXED,
  ref,
  title,
  target,
  body,
  tokenize = 'porter unicode61'
);

-- ---------------------------------------------------------------- payloads
-- Attack payloads extracted from a third-party reference clone (PayloadsAllTheThings) that
-- lives OUTSIDE the hunt workspaces and is never committed. One row per fenced code block.
-- Owned entirely by payloads.py: `ingest.py --rebuild --hard` must never touch it, and it is
-- kept out of search_fts so reference material cannot rank against hunt research.
-- Rebuilt from disk by scripts/sync-payloads.sh; a fresh index.db starts empty.
CREATE TABLE IF NOT EXISTS payloads (
  id          INTEGER PRIMARY KEY,
  category    TEXT NOT NULL,          -- top-level directory: 'XSS Injection'
  technique   TEXT,                   -- document title: 'XSS Filter Bypass'
  section     TEXT,                   -- nearest heading above the block
  lang        TEXT,                   -- fence info string: 'python', 'sql', 'ps1'
  payload     TEXT NOT NULL,
  file_path   TEXT NOT NULL,          -- absolute, opens in the Files tab
  line        INTEGER,                -- 1-based line of the opening fence
  indexed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);

-- External content: the text is already in `payloads`, so the FTS index stores no copy.
-- Refill is truncate-then-'rebuild', which is why there are no sync triggers.
CREATE VIRTUAL TABLE IF NOT EXISTS payloads_fts USING fts5(
  category, technique, section, payload,
  content = 'payloads', content_rowid = 'id',
  tokenize = 'porter unicode61'
);

-- ---------------------------------------------------------------- api tokens
-- Staged API access. Bearer tokens for non-browser clients. Only the hash is stored.
CREATE TABLE IF NOT EXISTS api_tokens (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL,
  token_hash  TEXT NOT NULL UNIQUE,
  prefix      TEXT NOT NULL,             -- first 8 chars, shown in the UI for identification
  scope       TEXT NOT NULL DEFAULT 'read',   -- read | write
  created_at  TEXT,
  created_by  TEXT,
  last_used   TEXT,
  revoked     INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------- hacktivity
-- The program's own public activity feed (hackerone.com/<handle>/hacktivity?type=team),
-- refreshed every 5 minutes by scripts/sync-hacktivity.sh. It answers "is their triage team
-- moving", which is a question about the PROGRAM, so most rows are about other researchers'
-- reports; `is_mine` marks the ones that are not.
--
-- Deliberately NOT part of `reports`. These are third-party reports we do not own, cannot fetch
-- and hold no research on, and letting them near the tracker would inflate every report count in
-- the app. `awarded_total` is the program's payout on somebody else's report and is never summed
-- into any bounty figure. A ring buffer of the newest rows, not an archive: HackerOne owns the
-- history. Owned entirely by hacktivity.py.
CREATE TABLE IF NOT EXISTS hacktivity (
  h1_id         TEXT PRIMARY KEY,       -- one row per REPORT: the feed shows its latest action
  program       TEXT NOT NULL,
  action        TEXT NOT NULL,          -- raw: 'Activities::BugResolved'
  activity_at   TEXT NOT NULL,          -- ISO-8601 UTC, from the API, with its Z
  title         TEXT,                   -- populated only for reports we can see (ours)
  substate      TEXT,
  reporter      TEXT,
  url           TEXT,
  awarded_total TEXT,                   -- the PROGRAM's payout on that report. Never our money.
  is_mine       INTEGER NOT NULL DEFAULT 0,
  fetched_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_hacktivity_at ON hacktivity(activity_at);

-- ---------------------------------------------------------------- regressions
-- Verdicts from re-testing the fixes shipped for our resolved reports. Owned entirely by
-- regression.py.
--
-- The QUEUE is not stored. It is computed on every read from `reports` - every HackerOne-sourced
-- report in state `resolved` with a close date - so HackerOne stays the authority on which of our
-- findings were fixed, and a report the program reopens leaves the queue on the next sync with no
-- cleanup path having to exist. Every row HERE is a human judgement about one of those reports:
-- what a retest found, when, and whether the due date was pushed out. A report nobody has looked
-- at yet has no row.
--
-- Not a foreign key to reports(h1_id): the sync rewrites those rows, and a verdict has to outlive
-- a re-sync. Deleting this table loses opinions and nothing else.
CREATE TABLE IF NOT EXISTS regressions (
  h1_id       TEXT PRIMARY KEY,
  verdict     TEXT NOT NULL DEFAULT 'pending',   -- holds | broken | skipped
  note        TEXT,                       -- what the retest did, in the operator's words
  due_override TEXT,                      -- 'YYYY-MM-DD' snooze. NULL = derived from the window.
  last_tested TEXT,                       -- date of the most recent verdict
  attempts    INTEGER NOT NULL DEFAULT 0, -- how many times a verdict has been recorded
  lead_path   TEXT,                       -- the lead file a `broken` verdict was drafted into
  created_at  TEXT,
  updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_regressions_verdict ON regressions(verdict);
