#!/usr/bin/env python3
"""Incremental HackerOne polling. Stdlib only.

WHY THIS EXISTS
---------------
`h1.sync()` is the full two-phase pull: 2 list pages plus one detail fetch per report, ~150
requests across every program on the account. That is the right thing to run occasionally and
completely the wrong thing to run every quarter hour.

SCOPE: like h1.sync(), the poll covers EVERY program by default. The list pages are the same two
pages whether or not a handle is set, so narrowing them saved nothing and lost reports.

The optimisation is that the LIST endpoint hands us four change signals for free - `state`,
`last_activity_at`, `last_program_activity_at` and `bounty_awarded_at`. We remember them in
`h1_watch` and, on each poll, detail-fetch ONLY the reports whose signals moved. A quiet poll
costs 2 requests (the list pages) plus one per explicitly tracked collaborator report; a busy one
costs a handful.

    python3 h1_watch.py --poll          # what cron runs
    python3 h1_watch.py --events        # what changed, newest first
    python3 h1_watch.py --status        # job health: last run, failures, cumulative counters

MONEY SAFETY
------------
This module NEVER writes `bounty` itself. Every report row it touches goes through
`h1.upsert_report()`, which runs `h1._clean_amount()` and lets HackerOne own the money column.
Hand-recorded expectations live in `expected_bounty` and are never merged into confirmed figures.
Bounty EVENTS are derived by comparing cleaned numeric amounts, so a legacy '$783' string can
never be mistaken for an award.

BOUNTY DETECTION
----------------
`bounty_awarded_at` is a separate list attribute from `last_activity_at` and does not always move
together with it. A change in ANY of state / last_activity_at / last_program_activity_at /
bounty_awarded_at independently forces a detail fetch. A needless fetch is cheap; a missed payment
is not.

FIELD QUIRK (verified against the live list endpoint, 2026-07-30)
-----------------------------------------------------------------
`last_activity_at` comes back EMPTY for most reports in the list payload while
`last_program_activity_at` carries the real timestamp - and the detail payload fills them in
differently again. Comparing the two fields pairwise therefore marks nearly every report as
"changed" forever, which would turn every poll back into the ~110-request sync this module exists
to avoid. They are collapsed into one monotonic signal instead; see `_activity_max()`.

NOT ENUMERABLE
--------------
Collaborator reports never appear in /hackers/me/reports (HACKERONE_API.md section 6a), so they
have no list snapshot and no free change signal. Every id in `extra_report_ids` is therefore
detail-fetched on EVERY poll - one request each, which is the whole reason that list is explicit
and short. A collaborator report being closed as a duplicate is caught exactly this way.
"""
import argparse
import fcntl
import json
import os
import sys
import time

import common
import h1

JOB_NAME = "h1_poll"
LOCK_PATH = os.path.join(common.APP_DIR, ".h1_watch.lock")

POLITE_DELAY = 0.35          # between detail fetches, same courtesy as h1.sync()
MAX_ATTEMPTS = 4             # per request, for 429 and transient network failures
MAX_SLEEP = 60.0             # cap on any single backoff sleep inside a run
PAGE_SIZE = 100
MAX_PAGES = 100

# Between-run backoff, so a dead credential is not retried every 15 minutes forever.
# (kind, first failure, cap) in seconds.
BACKOFF_AUTH = (1800, 12 * 3600)     # 401: 30m, doubling, capped at 12h
BACKOFF_OTHER = (600, 2 * 3600)      # everything else: 10m, doubling, capped at 2h

EVENT_TYPES = ("new_report", "state_change", "bounty_awarded", "bounty_increased",
               "collaborator_added", "severity_change", "cve_assigned")


# ------------------------------------------------------------------ schema
def ensure_schema(conn):
    """Additive migration. Safe to call on every poll and on an already-migrated database."""
    h1.ensure_schema(conn)

    # What changed, and when we noticed. The point of the whole feature: it answers "what moved
    # since I last looked" without re-reading every report row.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS report_events (
          id          INTEGER PRIMARY KEY,
          h1_id       TEXT NOT NULL,
          event_type  TEXT NOT NULL,
          old_value   TEXT NOT NULL DEFAULT '',
          new_value   TEXT NOT NULL DEFAULT '',
          detected_at TEXT NOT NULL,
          report_id   INTEGER REFERENCES reports(id) ON DELETE SET NULL,
          seen        INTEGER NOT NULL DEFAULT 0,
          occurrences INTEGER NOT NULL DEFAULT 1,
          -- Monotonic touch counter. `detected_at` only has second resolution, so several events
          -- in one poll tie, and a re-armed row keeps its original id - neither can answer "which
          -- of this report's events did we observe most recently". This can.
          seq         INTEGER NOT NULL DEFAULT 0
        )""")
    for name, decl in (("seen", "INTEGER NOT NULL DEFAULT 0"),
                       ("occurrences", "INTEGER NOT NULL DEFAULT 1"),
                       ("seq", "INTEGER NOT NULL DEFAULT 0")):
        if name not in {r[1] for r in conn.execute(
                "PRAGMA table_info(report_events)").fetchall()}:
            conn.execute("ALTER TABLE report_events ADD COLUMN %s %s" % (name, decl))
    # Rows that predate `seq` get insertion order as their sequence, so ordering stays sane.
    conn.execute("UPDATE report_events SET seq = id WHERE seq = 0")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_report_events_detected"
                 " ON report_events(detected_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_report_events_h1 ON report_events(h1_id)")
    # THE DUPLICATE GUARD. One row per distinct transition, so a poll that re-observes the same
    # move - or a poll that died halfway and gets re-run - cannot record it twice. Combined with
    # INSERT OR IGNORE this is what makes the whole poll safely re-runnable.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_report_events_uniq"
                 " ON report_events(h1_id, event_type, old_value, new_value)")

    # The cheap-poll baseline: the last values we saw for each report, list-endpoint included.
    # Deliberately a separate table from `reports` so the diff state can never be confused with,
    # or corrupt, the synced report data (especially `bounty`).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS h1_watch (
          h1_id                    TEXT PRIMARY KEY,
          state                    TEXT,
          last_activity_at         TEXT,
          last_program_activity_at TEXT,
          bounty_awarded_at        TEXT,
          bounty                   TEXT,
          severity                 TEXT,
          cve                      TEXT,
          collaborators            TEXT,
          first_seen               TEXT,
          last_listed_at           TEXT,
          last_detail_at           TEXT
        )""")

    ensure_job_state(conn, JOB_NAME)
    conn.commit()
    _seed_watch_from_reports(conn)


def ensure_job_state(conn, job):
    """Scheduled-job health, keyed by job name so any cron job can register a row.

    Lives here rather than in schema.sql's own section because this module was the first job to
    need it; `hacktivity.py` is the second. Keeping ONE definition matters more than which file it
    sits in - two CREATE TABLE statements for the same table drift the moment a column is added.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS job_state (
          job                  TEXT PRIMARY KEY,
          last_run             TEXT,
          last_success         TEXT,
          last_status          TEXT,
          last_error           TEXT,
          last_error_at        TEXT,
          last_duration_ms     INTEGER,
          consecutive_failures INTEGER NOT NULL DEFAULT 0,
          backoff_until        REAL NOT NULL DEFAULT 0,
          runs                 INTEGER NOT NULL DEFAULT 0,
          failures             INTEGER NOT NULL DEFAULT 0,
          requests             INTEGER NOT NULL DEFAULT 0,
          detail_fetches       INTEGER NOT NULL DEFAULT 0,
          events               INTEGER NOT NULL DEFAULT 0,
          updated_at           TEXT
        )""")
    conn.execute("INSERT OR IGNORE INTO job_state (job) VALUES (?)", (job,))
    conn.commit()


def _seed_watch_from_reports(conn):
    """Bootstrap the baseline from rows a previous full sync already stored.

    Without this the very first poll would see 111 reports with no baseline and detail-fetch all
    of them - exactly the ~220-request sync we are trying to avoid. The already-synced rows ARE a
    valid baseline for state and activity.

    `bounty_awarded_at` and `last_program_activity_at` are left NULL because the full sync never
    recorded them. NULL means "unknown", and the diff treats unknown as "not a change" - with one
    deliberate exception: if HackerOne says a bounty was awarded and our row carries no confirmed
    amount, that is a possible missed payment and we fetch. See `_needs_detail()`.
    """
    rows = conn.execute(
        "SELECT h1_id, h1_state, state, last_activity, bounty, severity, cve, collaborators"
        " FROM reports WHERE source='hackerone' AND h1_id IS NOT NULL AND h1_id <> ''"
        "   AND kind='report'").fetchall()
    now = common.now_iso()
    for r in rows:
        conn.execute(
            "INSERT OR IGNORE INTO h1_watch (h1_id, state, last_activity_at,"
            " last_program_activity_at, bounty_awarded_at, bounty, severity, cve,"
            " collaborators, first_seen, last_listed_at, last_detail_at)"
            " VALUES (?,?,?,NULL,NULL,?,?,?,?,?,NULL,NULL)",
            (r["h1_id"], r["h1_state"] or r["state"] or "", r["last_activity"] or "",
             h1._clean_amount(r["bounty"]), r["severity"] or "", r["cve"] or "",
             r["collaborators"] or "", now))
    conn.commit()


# ------------------------------------------------------------------ job state
def job_row(conn, job=JOB_NAME):
    ensure_schema(conn)
    r = conn.execute("SELECT * FROM job_state WHERE job=?", (job,)).fetchone()
    return dict(r) if r else {}


def _backoff_seconds(code, consecutive_failures):
    base, cap = BACKOFF_AUTH if code == 401 else BACKOFF_OTHER
    n = max(1, int(consecutive_failures))
    return min(cap, base * (2 ** (n - 1)))


def _record_success(conn, stats):
    conn.execute(
        "UPDATE job_state SET last_run=?, last_success=?, last_status='ok', last_error='',"
        " last_duration_ms=?, consecutive_failures=0, backoff_until=0, runs=runs+1,"
        " requests=requests+?, detail_fetches=detail_fetches+?, events=events+?, updated_at=?"
        " WHERE job=?",
        (stats["started_at"], common.now_iso(), stats["elapsed_ms"], stats["requests"],
         stats["detail_fetched"], stats["events"], common.now_iso(), JOB_NAME))
    conn.commit()


def _record_failure(conn, stats, err, code=None):
    """One row, updated in place. A 401 every 15 minutes must not become 96 log lines a day."""
    cur = conn.execute("SELECT consecutive_failures FROM job_state WHERE job=?",
                       (JOB_NAME,)).fetchone()
    cf = (cur["consecutive_failures"] if cur else 0) + 1
    until = time.time() + _backoff_seconds(code, cf)
    conn.execute(
        "UPDATE job_state SET last_run=?, last_status=?, last_error=?, last_error_at=?,"
        " last_duration_ms=?, consecutive_failures=?, backoff_until=?, runs=runs+1,"
        " failures=failures+1, requests=requests+?, detail_fetches=detail_fetches+?,"
        " events=events+?, updated_at=? WHERE job=?",
        (stats["started_at"], "auth_failed" if code == 401 else "error", str(err)[:500],
         common.now_iso(), stats["elapsed_ms"], cf, until, stats["requests"],
         stats["detail_fetched"], stats["events"], common.now_iso(), JOB_NAME))
    conn.commit()


# ------------------------------------------------------------------ http
class _Session(object):
    """Counts requests and applies retry/backoff, so the caller can report real request counts."""

    def __init__(self, username, token, verbose=False):
        self.username = username
        self.token = token
        self.verbose = verbose
        self.requests = 0

    def get(self, path, params=None):
        attempt = 0
        while True:
            attempt += 1
            self.requests += 1
            try:
                return h1._request(path, self.username, self.token, params)
            except h1.H1Error as e:
                code = getattr(e, "code", None)
                # A dead credential will not heal by retrying. Fail immediately and let the
                # between-run backoff decide when to look again.
                if code == 401 or attempt >= MAX_ATTEMPTS:
                    raise
                if code is not None and code not in (429, 500, 502, 503, 504):
                    raise
                delay = getattr(e, "retry_after", None)
                if not delay:
                    delay = 2.0 ** attempt          # 2s, 4s, 8s
                delay = min(float(delay), MAX_SLEEP)
                if self.verbose:
                    sys.stderr.write("  retry %d after %.1fs (%s)\n" % (attempt, delay, e))
                time.sleep(delay)


# ------------------------------------------------------------------ list snapshot
def _snapshot(node):
    """The four free change signals the list endpoint carries, plus identity."""
    a = node.get("attributes") or {}
    return {
        "h1_id": str(node.get("id") or ""),
        "state": a.get("state") or "",
        "last_activity_at": a.get("last_activity_at") or "",
        "last_program_activity_at": a.get("last_program_activity_at") or "",
        "bounty_awarded_at": a.get("bounty_awarded_at") or "",
        # Same normalisation as h1.normalize_report, so a title fixed there cannot come back
        # through the cheap list path and land in an event label still carrying its '# '.
        "title": h1.clean_title(a.get("title")),
    }


def list_snapshots(sess, program_handle, verbose=False):
    """Page /hackers/me/reports and return {h1_id: snapshot}. `program_handle=None` means all.

    There is no server-side program filter on the hacker API (HACKERONE_API.md section 2), so a
    handle, when one is given, is matched client-side on the embedded program relationship.
    """
    out = {}
    path = "/hackers/me/reports"
    params = {"page[size]": PAGE_SIZE}
    pages = 0
    listed_total = 0
    while pages < MAX_PAGES:
        d = sess.get(path, params)
        rows = d.get("data") or []
        if not rows:
            break
        pages += 1
        listed_total += len(rows)
        for node in rows:
            prog = h1._rel(node, "program").get("handle")
            if program_handle and prog != program_handle:
                continue
            snap = _snapshot(node)
            snap["program"] = prog or ""
            if snap["h1_id"]:
                out[snap["h1_id"]] = snap
        if verbose:
            print("  list page %d: %d rows (%d kept)" % (pages, len(rows), len(out)))
        nxt = (d.get("links") or {}).get("next")
        if not nxt:
            break
        import urllib.parse
        parsed = urllib.parse.urlparse(nxt)
        path = parsed.path.replace("/v1", "", 1)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        time.sleep(POLITE_DELAY)
    return out, pages, listed_total


def fetch_detail(sess, report_id, program_handle):
    """One request. Returns (normalized_row, raw_node) - we need both.

    The normalized row feeds `h1.upsert_report()`; the raw node carries the same activity and
    bounty timestamps the list endpoint gives, so the watch baseline stays consistent for reports
    that are only ever reachable by id (collaborator reports).
    """
    d = sess.get("/hackers/reports/%s" % report_id)
    node = d.get("data") or {}
    prog = h1._rel(node, "program").get("handle") or program_handle
    return h1.normalize_report(node, prog), node


# ------------------------------------------------------------------ diffing
def _activity_max(row):
    """The newest of the two activity timestamps, or ''.

    VERIFIED 2026-07-30 against the live list endpoint: `last_activity_at` comes back EMPTY for
    most reports while `last_program_activity_at` carries the real value - and the detail payload
    populates them differently again. Comparing the fields pairwise therefore produces a permanent
    false "changed" on almost every report, which is exactly the ~110-request sync this module
    exists to avoid.

    Both are ISO-8601 UTC with the same layout, so lexical max is chronological max, and activity
    timestamps only ever move forward. Taking the max of whichever fields are populated collapses
    the two into one monotonic signal that is immune to which field the API decides to fill in.
    """
    vals = [(row[k] or "") for k in ("last_activity_at", "last_program_activity_at")]
    return max(vals) if vals else ""


def _needs_detail(stored, snap):
    """Any one of the four signals moving is independently sufficient. Returns a reason list."""
    if stored is None:
        return ["first_seen"]
    reasons = []
    if (stored["state"] or "") != snap["state"]:
        reasons.append("state")
    # Strictly NEWER, not merely different: a field the API stopped populating is an absence of
    # data, not an event, and must not cost a request on every poll from now until forever.
    if _activity_max(snap) > _activity_max(stored):
        reasons.append("activity")
    old_awarded = stored["bounty_awarded_at"]
    if old_awarded is None:
        # Unknown award timestamp. Only suspicious if HackerOne says money moved and we hold no
        # confirmed amount for it - that is the missed-payment case, and it is worth a request.
        if snap["bounty_awarded_at"] and not (stored["bounty"] or ""):
            reasons.append("bounty_awarded_at")
    elif (old_awarded or "") != snap["bounty_awarded_at"]:
        reasons.append("bounty_awarded_at")
    return reasons


def _amount(value):
    v = h1._clean_amount(value)
    try:
        return float(v) if v else 0.0
    except ValueError:
        return 0.0


def record_event(conn, h1_id, event_type, old_value, new_value, report_id=None):
    """Record a transition once. Returns True if anything was surfaced to the user.

    One row per distinct transition, enforced by the uniqueness index, so re-observing the same
    move on the next poll - or re-running a poll that died halfway - cannot duplicate it.

    A transition CAN legitimately happen again though (a duplicate gets reopened and re-closed,
    a state flip-flops during a dispute). Distinguishing the two cases: if the stored row is
    still the newest thing we know about this report, we are simply looking at the same move
    again and stay silent. If other events have landed since, this is a genuine recurrence, so
    the row is re-armed - bumped to now, marked unseen, occurrence count incremented - rather
    than being silently swallowed forever by the index.
    """
    h1_id = str(h1_id)
    old_value = str(old_value or "")[:200]
    new_value = str(new_value or "")[:200]
    now = common.now_iso()
    seq = (conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM report_events").fetchone()[0])
    cur = conn.execute(
        "INSERT OR IGNORE INTO report_events (h1_id, event_type, old_value, new_value,"
        " detected_at, report_id, seq) VALUES (?,?,?,?,?,?,?)",
        (h1_id, event_type, old_value, new_value, now, report_id, seq))
    if cur.rowcount:
        return True

    existing = conn.execute(
        "SELECT id FROM report_events WHERE h1_id=? AND event_type=? AND old_value=?"
        " AND new_value=?", (h1_id, event_type, old_value, new_value)).fetchone()
    newest = conn.execute(
        "SELECT id FROM report_events WHERE h1_id=? ORDER BY seq DESC, id DESC LIMIT 1",
        (h1_id,)).fetchone()
    if not existing or not newest or existing["id"] == newest["id"]:
        return False          # same move, seen again: the consecutive-poll duplicate case
    conn.execute(
        "UPDATE report_events SET detected_at=?, seen=0, occurrences=occurrences+1, seq=?,"
        " report_id=COALESCE(?, report_id) WHERE id=?",
        (now, seq, report_id, existing["id"]))
    return True


def _report_id(conn, h1_id):
    r = conn.execute("SELECT id FROM reports WHERE h1_id=? AND kind='report'"
                     " ORDER BY (source='hackerone') DESC, id ASC LIMIT 1", (str(h1_id),)).fetchone()
    return r["id"] if r else None


def _sev_label(row):
    sev = (row.get("severity") or "").strip()
    cvss = (row.get("cvss") or "").strip()
    if sev and cvss:
        return "%s (%s)" % (sev, cvss)
    return sev or cvss or ""


def _collab_set(value):
    return {c.strip() for c in (value or "").split(",") if c.strip()}


def _csv_set(value):
    return {c.strip().upper() for c in (value or "").split(",") if c.strip()}


def derive_events(conn, stored, detail, snap):
    """Compare a freshly fetched report against the stored baseline. Returns a list of events.

    Pure apart from the report-id lookup: no writes happen here.
    """
    h1_id = detail["h1_id"]
    rid = _report_id(conn, h1_id)
    events = []

    def add(t, old, new):
        events.append((h1_id, t, old, new, rid))

    if stored is None:
        add("new_report", "", "%s [%s]" % ((detail.get("title") or "")[:120],
                                           detail.get("state") or ""))

    old_state = (stored["state"] if stored else "") or ""
    new_state = detail.get("state") or (snap or {}).get("state") or ""
    if new_state and old_state and new_state != old_state:
        add("state_change", old_state, new_state)

    # SILENT ACTIVITY. Until 2026-08-04 the two activity timestamps were stored as a baseline and
    # never compared, so a program that touched a report without changing its state, severity,
    # bounty, CVE or collaborators produced NO event and the dashboard stayed dark. That is most of
    # what actually happens to a live report: a comment, an internal reassignment, a triager
    # reading it. Six reports were sitting with a moved `last_activity` and not one event between
    # them when this was found.
    #
    # `last_program_activity_at` is the one that matters, because it moves only when THEY do
    # something. `last_activity_at` also moves when WE comment, and badging our own comment as an
    # update to chase would be noise - so the broader event is emitted only when the program
    # timestamp did not already explain the move.
    old_prog = (stored["last_program_activity_at"] if stored else "") or ""
    new_prog = (snap or {}).get("last_program_activity_at") or ""
    prog_moved = bool(new_prog and old_prog and new_prog > old_prog)
    if prog_moved:
        add("program_activity", old_prog, new_prog)

    old_act = (stored["last_activity_at"] if stored else "") or ""
    new_act = (snap or {}).get("last_activity_at") or ""
    if new_act and old_act and new_act > old_act and not prog_moved:
        add("activity", old_act, new_act)

    # MONEY. Both sides are run through h1._clean_amount() first, so a hand-recorded '$783'
    # expectation from the old markdown tracker can never register as an award.
    old_amt = _amount(stored["bounty"] if stored else "")
    new_amt = _amount(detail.get("bounty"))
    cur = detail.get("currency") or "USD"
    if new_amt > 0 and old_amt <= 0:
        add("bounty_awarded", "", "%.2f %s" % (new_amt, cur))
    elif new_amt > old_amt > 0:
        add("bounty_increased", "%.2f" % old_amt, "%.2f %s" % (new_amt, cur))

    # A severity appearing where there was none is news too - triagers set it on triage - so an
    # empty baseline still fires. An empty NEW value does not: that is missing data, not a change.
    old_sev = (stored["severity"] if stored else "") or ""
    new_sev = detail.get("severity") or ""
    if new_sev and new_sev != old_sev:
        add("severity_change", old_sev, _sev_label(detail))

    old_cves = _csv_set(stored["cve"] if stored else "")
    new_cves = _csv_set(detail.get("cve"))
    gained = sorted(new_cves - old_cves)
    if gained:
        add("cve_assigned", ",".join(sorted(old_cves)), ",".join(gained))

    old_collab = _collab_set(stored["collaborators"] if stored else "")
    for name in sorted(_collab_set(detail.get("collaborators")) - old_collab):
        add("collaborator_added", "", name)

    return events


def _write_watch(conn, h1_id, snap, detail=None, listed=True):
    """Persist the new baseline. Called after every processed report so the NEXT poll is cheap."""
    now = common.now_iso()
    row = conn.execute("SELECT h1_id FROM h1_watch WHERE h1_id=?", (str(h1_id),)).fetchone()
    vals = {"state": (detail or {}).get("state") or (snap or {}).get("state") or ""}
    # NEVER regress a timestamp baseline to ''. The API populates last_activity_at inconsistently
    # (see _activity_max); overwriting a known timestamp with the empty value it happens to return
    # this minute would throw away the very baseline that keeps the next poll cheap.
    for field in ("last_activity_at", "last_program_activity_at", "bounty_awarded_at"):
        v = (snap or {}).get(field) or ""
        if v:
            vals[field] = v
    if detail is not None:
        vals["bounty"] = h1._clean_amount(detail.get("bounty"))
        vals["severity"] = detail.get("severity") or ""
        vals["cve"] = detail.get("cve") or ""
        vals["collaborators"] = detail.get("collaborators") or ""
        vals["last_detail_at"] = now
    if listed:
        vals["last_listed_at"] = now

    if row is None:
        vals["h1_id"] = str(h1_id)
        vals["first_seen"] = now
        cols = sorted(vals)
        conn.execute("INSERT INTO h1_watch (%s) VALUES (%s)"
                     % (",".join(cols), ",".join("?" * len(cols))),
                     [vals[c] for c in cols])
        return
    cols = sorted(vals)
    conn.execute("UPDATE h1_watch SET %s WHERE h1_id=?"
                 % ", ".join("%s=?" % c for c in cols),
                 [vals[c] for c in cols] + [str(h1_id)])


# ------------------------------------------------------------------ poll
def poll(conn, verbose=False, program_handle=None, force=False, write_files=True):
    """One incremental poll. 2 requests when nothing moved.

    Returns a stats dict: listed, changed, detail_fetched, events, errors, elapsed_ms, requests.
    """
    ensure_schema(conn)
    t0 = time.time()
    stats = {"listed": 0, "changed": 0, "detail_fetched": 0, "events": 0, "errors": 0,
             "elapsed_ms": 0, "requests": 0, "pages": 0, "listed_all_programs": 0,
             "status": "ok", "program": "", "started_at": common.now_iso(), "error": "",
             "reasons": {}, "new_rows": 0, "updated_rows": 0}

    job = conn.execute("SELECT backoff_until, consecutive_failures, last_error FROM job_state"
                       " WHERE job=?", (JOB_NAME,)).fetchone()
    if job and not force and (job["backoff_until"] or 0) > time.time():
        # Deliberately silent and request-free: this is the anti-spam path for a dead credential.
        stats["status"] = "backoff"
        stats["error"] = job["last_error"] or ""
        stats["elapsed_ms"] = int((time.time() - t0) * 1000)
        if verbose:
            print("h1 poll: backing off until %s after %d consecutive failures (%s)"
                  % (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(job["backoff_until"])),
                     job["consecutive_failures"], stats["error"][:120]))
        return stats

    username, token, _primary = h1.get_credentials()
    # None means every program, matching h1.sync(). The poll is 2 requests either way: the list
    # pages are the same pages, and narrowing them only threw reports away.
    handle = program_handle or None
    stats["program"] = handle or h1.ALL_PROGRAMS
    if not (username and token):
        stats["status"] = "error"
        stats["error"] = "No HackerOne credential stored."
        stats["elapsed_ms"] = int((time.time() - t0) * 1000)
        _record_failure(conn, stats, stats["error"], code=None)
        return stats

    # normalize_report() reads h1._ME to decide reporter vs collaborator. h1.sync() sets it the
    # same way; without it every report looks like someone else's.
    setattr(h1, "_ME", username)

    sess = _Session(username, token, verbose=verbose)
    try:
        snaps, pages, listed_all = list_snapshots(sess, handle, verbose=verbose)
        stats["pages"] = pages
        stats["listed"] = len(snaps)
        stats["listed_all_programs"] = listed_all

        stored_rows = {r["h1_id"]: r for r in conn.execute("SELECT * FROM h1_watch").fetchall()}

        todo = []           # (h1_id, snapshot_or_None, reasons)
        for h1_id, snap in snaps.items():
            reasons = _needs_detail(stored_rows.get(h1_id), snap)
            if reasons:
                todo.append((h1_id, snap, reasons))
            else:
                # Nothing moved: refresh the "still listed" marker only. No request, no write to
                # `reports`, and above all no touch of the money column.
                _write_watch(conn, h1_id, snap, detail=None, listed=True)

        # COLLABORATOR REPORTS ARE NOT ENUMERABLE (HACKERONE_API.md section 6a). A report someone
        # invited us onto never appears in /hackers/me/reports, so it has no list snapshot and no
        # free change signal. The only way to notice anything happening on it is to fetch it every
        # time. That is one request per tracked id, which is why the list is explicit and short.
        seen_extra = set()
        for x in (h1.load_secrets().get("hackerone") or {}).get("extra_report_ids", []):
            rid = str(x).strip()
            if rid and rid not in snaps and rid not in seen_extra:
                seen_extra.add(rid)          # a repeated id in secrets.json must not cost 2 requests
                todo.append((rid, None, ["tracked_id"]))

        stats["changed"] = len(todo)
        for h1_id, snap, reasons in todo:
            stats["reasons"][h1_id] = reasons
            try:
                if stats["detail_fetched"]:
                    time.sleep(POLITE_DELAY)
                detail, node = fetch_detail(sess, h1_id, handle)
                stats["detail_fetched"] += 1
            except h1.H1Error as e:
                stats["errors"] += 1
                sys.stderr.write("detail fetch failed for %s: %s\n" % (h1_id, e))
                if getattr(e, "code", None) == 401:
                    raise
                continue

            # SANITY GATE. A truncated, empty or otherwise unexpected payload normalizes to a row
            # with an empty h1_id, and passing that to upsert_report() inserts a junk report with
            # no id. Insist the response is the report we asked for before writing anything.
            if str(detail.get("h1_id") or "") != str(h1_id):
                stats["errors"] += 1
                sys.stderr.write("detail for %s returned id %r; skipping\n"
                                 % (h1_id, detail.get("h1_id")))
                continue

            if handle and detail.get("program") and detail["program"] != handle:
                if verbose:
                    print("  skipping %s: program is %s" % (h1_id, detail["program"]))
                continue

            if snap is None:                 # id-only report: derive the baseline from the detail
                snap = _snapshot(node)
                snap["program"] = detail.get("program") or handle

            stored = stored_rows.get(h1_id)
            events = derive_events(conn, stored, detail, snap)

            if write_files:
                try:
                    fp = h1.write_report_file(detail)
                    if fp:
                        detail["h1_body_path"] = fp
                except OSError as werr:
                    sys.stderr.write("report file write failed for %s: %s\n" % (h1_id, werr))

            # h1.upsert_report() owns the write to `reports`, including _clean_amount() on both
            # bounty columns. This module never writes money itself.
            outcome = h1.upsert_report(conn, detail)
            if outcome == "new":
                stats["new_rows"] += 1
            elif outcome == "updated":
                stats["updated_rows"] += 1

            rid_db = _report_id(conn, h1_id)
            for (eid, etype, old, new, _r) in events:
                if record_event(conn, eid, etype, old, new, rid_db):
                    stats["events"] += 1
                    if verbose:
                        print("  event %s %s: %s -> %s" % (eid, etype, old or "-", new or "-"))
            _write_watch(conn, h1_id, snap, detail=detail, listed=(h1_id in snaps))
            conn.commit()

        if stats["detail_fetched"]:
            # Idempotent, no network: keeps expected_* aligned after new rows appear. It only ever
            # FILLS expectations - it cannot promote one into a confirmed bounty.
            h1.recover_expected_from_tracker(conn)
            # A first report to a program we have never seen makes that program real. Insert-only.
            h1.index_programs(conn)

        conn.commit()
        stats["requests"] = sess.requests
        stats["elapsed_ms"] = int((time.time() - t0) * 1000)
        _record_success(conn, stats)
        if stats["events"] or stats["errors"]:
            common.audit(conn, "cron", "h1_poll", "reports", None,
                         "listed=%d changed=%d detail=%d events=%d errors=%d req=%d"
                         % (stats["listed"], stats["changed"], stats["detail_fetched"],
                            stats["events"], stats["errors"], stats["requests"]))
    except h1.H1Error as e:
        conn.commit()          # keep whatever completed; the poll is re-runnable
        stats["requests"] = sess.requests
        stats["elapsed_ms"] = int((time.time() - t0) * 1000)
        stats["status"] = "auth_failed" if getattr(e, "code", None) == 401 else "error"
        stats["error"] = str(e)
        _record_failure(conn, stats, e, code=getattr(e, "code", None))
        # A FAILED poll is always audited, even though a quiet successful one is not. The success
        # path stays silent on purpose - 96 runs a day with nothing to report would bury the
        # audit log in noise, and the Status tab carries that heartbeat instead. But a failure is
        # exactly the thing you go to the audit log to find, and it used to leave no trace there
        # at all: a dead credential looked identical to a healthy quiet week.
        common.audit(conn, "cron", "h1_poll_failed", "reports", None,
                     "status=%s req=%d: %s" % (stats["status"], stats["requests"], str(e)[:300]))
        if verbose:
            sys.stderr.write("h1 poll failed: %s\n" % e)
        return stats

    if verbose:
        print("h1 poll (%s): listed=%d changed=%d detail=%d events=%d errors=%d requests=%d in %dms"
              % (handle, stats["listed"], stats["changed"], stats["detail_fetched"],
                 stats["events"], stats["errors"], stats["requests"], stats["elapsed_ms"]))
    return stats


# ------------------------------------------------------------------ read side
def recent_events(conn, limit=50, since=None, unseen_only=False, event_type=None):
    """Newest first, joined to the report so the UI can render a title without a second query."""
    ensure_schema(conn)
    sql = ("SELECT e.id, e.h1_id, e.event_type, e.old_value, e.new_value, e.detected_at,"
           " e.report_id, e.seen, e.occurrences, r.title, r.url, r.state, r.severity, r.program"
           " FROM report_events e LEFT JOIN reports r ON r.id = e.report_id WHERE 1=1")
    args = []
    if since:
        sql += " AND e.detected_at > ?"
        args.append(since)
    if unseen_only:
        sql += " AND e.seen = 0"
    if event_type:
        sql += " AND e.event_type = ?"
        args.append(event_type)
    sql += " ORDER BY e.detected_at DESC, e.id DESC LIMIT ?"
    args.append(int(limit))
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def mark_seen(conn, ids=None):
    """Mark events read. ids=None marks everything. Returns the number of rows changed."""
    ensure_schema(conn)
    if ids:
        marks = ",".join("?" * len(ids))
        cur = conn.execute("UPDATE report_events SET seen=1 WHERE id IN (%s)" % marks,
                           [int(i) for i in ids])
    else:
        cur = conn.execute("UPDATE report_events SET seen=1 WHERE seen=0")
    conn.commit()
    return cur.rowcount


def status(conn):
    """Job health for the Audit Log 'Scheduled job health' card."""
    ensure_schema(conn)
    j = job_row(conn)
    bu = j.get("backoff_until") or 0
    counts = {r["event_type"]: r["n"] for r in conn.execute(
        "SELECT event_type, COUNT(*) n FROM report_events GROUP BY 1").fetchall()}
    unseen = conn.execute("SELECT COUNT(*) FROM report_events WHERE seen=0").fetchone()[0]
    watched = conn.execute("SELECT COUNT(*) FROM h1_watch").fetchone()[0]
    return {
        "job": JOB_NAME,
        "last_run": j.get("last_run"),
        "last_success": j.get("last_success"),
        "last_status": j.get("last_status"),
        "last_error": j.get("last_error") or "",
        "last_error_at": j.get("last_error_at"),
        "last_duration_ms": j.get("last_duration_ms"),
        "consecutive_failures": j.get("consecutive_failures") or 0,
        "backoff_until": (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(bu)) if bu else ""),
        "in_backoff": bool(bu and bu > time.time()),
        "runs": j.get("runs") or 0,
        "failures": j.get("failures") or 0,
        "cumulative_requests": j.get("requests") or 0,
        "cumulative_detail_fetches": j.get("detail_fetches") or 0,
        "cumulative_events": j.get("events") or 0,
        "watched_reports": watched,
        "events_total": sum(counts.values()),
        "events_unseen": unseen,
        "events_by_type": counts,
        "interval_hint": "every 15 minutes (cron), offset from the advisory job",
    }


# ------------------------------------------------------------------ cli
def _lock():
    """Stop two polls overlapping when a slow run runs into the next cron tick."""
    fh = open(LOCK_PATH, "a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def main():
    ap = argparse.ArgumentParser(description="Incremental HackerOne polling")
    ap.add_argument("--poll", action="store_true", help="one incremental poll (cron mode)")
    ap.add_argument("--events", action="store_true", help="show recent change events")
    ap.add_argument("--status", action="store_true", help="job health")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--since", help="only events after this ISO timestamp")
    ap.add_argument("--program",
                    help="narrow the poll to one program handle. Omitted, or '%s', means every"
                         " program on the account" % h1.ALL_PROGRAMS)
    ap.add_argument("--force", action="store_true", help="ignore the failure backoff window")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    if (args.program or "").strip().lower() == h1.ALL_PROGRAMS:
        args.program = None

    conn = common.connect()
    common.init_db(conn)
    try:
        if args.poll:
            lock = _lock()
            if lock is None:
                if not args.quiet:
                    print("h1 poll: another poll is already running; skipping")
                return
            try:
                st = poll(conn, verbose=not args.quiet, program_handle=args.program,
                          force=args.force)
            finally:
                lock.close()
            if args.json:
                print(json.dumps(st, indent=2, sort_keys=True))
            elif args.quiet and (st["events"] or st["errors"] or st["status"] != "ok"):
                # Quiet means quiet UNLESS something happened. A cron log full of "nothing
                # changed" every 15 minutes is a log nobody reads.
                print("%s h1 poll [%s]: listed=%d changed=%d detail=%d events=%d errors=%d "
                      "requests=%d %s" % (common.now_iso(), st["status"], st["listed"],
                                          st["changed"], st["detail_fetched"], st["events"],
                                          st["errors"], st["requests"], st["error"][:160]))
                for e in recent_events(conn, limit=st["events"]):
                    print("    %-18s #%-9s %s -> %s  %s"
                          % (e["event_type"], e["h1_id"], (e["old_value"] or "-")[:24],
                             (e["new_value"] or "-")[:32], (e["title"] or "")[:60]))
            if st["status"] not in ("ok", "backoff"):
                sys.exit("h1 poll: %s" % st["error"])
        if args.events:
            rows = recent_events(conn, limit=args.limit, since=args.since)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True))
            else:
                for r in rows:
                    print("%s  %-18s #%-9s %s -> %s  %s"
                          % (r["detected_at"], r["event_type"], r["h1_id"],
                             (r["old_value"] or "-")[:28], (r["new_value"] or "-")[:38],
                             (r["title"] or "")[:48]))
                if not rows:
                    print("(no events recorded yet)")
        if args.status or not (args.poll or args.events):
            st = status(conn)
            if args.json:
                print(json.dumps(st, indent=2, sort_keys=True))
            else:
                for k, v in st.items():
                    print("  %-26s %s" % (k, v))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
