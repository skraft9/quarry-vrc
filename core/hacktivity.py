#!/usr/bin/env python3
"""Program hacktivity: is the <program> triage team moving right now?

WHAT THIS ANSWERS
-----------------
Not "what happened to my reports" - the Tracker already owns that. This answers the question
you ask before you decide whether it is worth chasing anything: is the program's triage team
working through its queue today, or has it gone quiet? The signal is the PROGRAM's activity as a
whole, so entries about other researchers' reports are the point, not noise.

Mirrors https://hackerone.com/<program>/hacktivity?type=team.

WHAT THE FEED CAN AND CANNOT SAY
--------------------------------
Hacktivity only carries DISCLOSABLE actions. On an undisclosed report that is a very short list:
resolved, and bounty awarded. Triage, duplicate closes and comments never appear, so a quiet feed
means "nothing has been resolved or paid lately", not "nobody is working". Verified over 200
consecutive <program> entries on 2026-08-01: 188 BugResolved, 12 BountyAwarded, nothing else.

Titles, `substate` and `url` come back populated ONLY for reports we can already see - in practice
our own. Everyone else's entry is an id, a reporter handle, an action and a timestamp. That is
enough for the activity question and is the reason the tile leads with the action and the age
rather than a title it usually does not have.

SCOPE AND MONEY
---------------
This module writes to ONE table, `hacktivity`, plus the shared `job_state` health row. It never
writes to `reports` or `leads`. `total_awarded_amount` on an entry is the PROGRAM's payout on
somebody else's report; it is public trivia, it is stored as `awarded_total` to keep that obvious,
and it is never summed into any bounty figure anywhere.

    python3 hacktivity.py --refresh     # what cron runs, every 5 minutes
    python3 hacktivity.py --show        # the stored entries, newest first
    python3 hacktivity.py --status      # job health
"""
import argparse
import json
import os
import sys
import time

import common
import h1

JOB_NAME = "hacktivity"
ENDPOINT = "/hackers/hacktivity"

# One request per refresh. The API caps `page[size]` at 50 whatever you ask for; 25 is plenty of
# depth for a five-row tile and leaves headroom to answer "which of these are mine".
FETCH_SIZE = 25
MAX_PAGE_SIZE = 50

# Ring buffer depth. This is a live-activity indicator, not an archive - HackerOne owns the
# history and re-serves it on request - so old rows are dropped rather than accumulated.
KEEP_ROWS = 50

# Three missed five-minute ticks. Below this a gap is a slow cron or a single failed request and
# saying so would be noise; above it, the "as of" time is telling the user something.
STALE_AFTER = 900

# Hacktivity is a nice-to-have. A failing one must never cost more than a single request per tick,
# so the backoff is gentler than the poller's but still real.
BACKOFF_AUTH = (3600, 12 * 3600)
BACKOFF_OTHER = (900, 4 * 3600)

# Only these two are reachable on an undisclosed report, but the feed also serves disclosed ones
# and the vocabulary is HackerOne's, not ours, so unknown values are de-camel-cased rather than
# dropped. An action we have never seen is still news.
ACTION_LABELS = {
    "Activities::BugResolved": "Resolved",
    "Activities::BountyAwarded": "Bounty awarded",
    "Activities::BugTriaged": "Triaged",
    "Activities::BugDuplicate": "Closed as duplicate",
    "Activities::BugInformative": "Closed as informative",
    "Activities::BugNotApplicable": "Closed as N/A",
    "Activities::BugReopened": "Reopened",
    "Activities::ReportBecamePublic": "Disclosed",
    "Activities::ExternalUserJoined": "Collaborator joined",
}


SCHEMA = """
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
"""


def ensure_job_state(conn, job):
    """Scheduled-job health, keyed by job name. Self-contained (creates its own table) so this
    module has no cross-job dependency."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS job_state (
          job TEXT PRIMARY KEY, last_run TEXT, last_success TEXT, last_status TEXT,
          last_error TEXT, last_error_at TEXT, last_duration_ms INTEGER,
          consecutive_failures INTEGER NOT NULL DEFAULT 0, backoff_until REAL NOT NULL DEFAULT 0,
          runs INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
          requests INTEGER NOT NULL DEFAULT 0, detail_fetches INTEGER NOT NULL DEFAULT 0,
          events INTEGER NOT NULL DEFAULT 0, updated_at TEXT
        )""")
    conn.execute("INSERT OR IGNORE INTO job_state (job) VALUES (?)", (job,))
    conn.commit()


def ensure_schema(conn):
    """Create the table if it is missing. schema.sql carries it for a fresh database; this covers
    one created before the tile existed."""
    conn.executescript(SCHEMA)
    ensure_job_state(conn, JOB_NAME)


# ------------------------------------------------------------------ fetch
def pretty_action(raw):
    """'Activities::BugResolved' -> 'Resolved'. Pure."""
    raw = str(raw or "").strip()
    if not raw:
        return "Activity"
    if raw in ACTION_LABELS:
        return ACTION_LABELS[raw]
    bare = raw.split("::")[-1]
    words = []
    for ch in bare:
        if ch.isupper() and words and words[-1] and not words[-1][-1].isupper():
            words.append("")
        if not words:
            words.append("")
        words[-1] += ch
    return " ".join(w for w in words if w) or bare


def _amount(value):
    """The feed sends a bare number or null. Anything else is not an amount."""
    if value is None or value == "":
        return ""
    try:
        return "%.2f" % float(value)
    except (TypeError, ValueError):
        return ""


def normalize(node, me="", program_handle=""):
    """Map one hacktivity_item onto our columns. Pure.

    `is_mine` is decided on the reporter handle, not on whether a title came back. Title presence
    happens to correlate today, but it is a visibility side effect and would silently mislabel
    every entry the day HackerOne widens what it discloses.
    """
    a = (node or {}).get("attributes") or {}
    rels = (node or {}).get("relationships") or {}
    prog = (((rels.get("program") or {}).get("data") or {}).get("attributes") or {})
    rep = (((rels.get("reporter") or {}).get("data") or {}).get("attributes") or {})
    h1_id = str((node or {}).get("id") or "")
    reporter = rep.get("username") or ""
    action = a.get("latest_disclosable_action") or ""
    return {
        "h1_id": h1_id,
        "program": prog.get("handle") or program_handle or "",
        "action": action,
        "action_label": pretty_action(action),
        "activity_at": a.get("latest_disclosable_activity_at") or "",
        # Same normalisation as h1.normalize_report, so a title pasted with its markdown heading
        # cannot arrive here still carrying the '# '.
        "title": h1.clean_title(a.get("title")),
        "substate": a.get("substate") or "",
        "reporter": reporter,
        # Undisclosed entries carry a null url. The report page is still the right destination -
        # it is where hackerone.com's own hacktivity links - so synthesise it from the id.
        "url": a.get("url") or (("https://hackerone.com/reports/%s" % h1_id) if h1_id else ""),
        "awarded_total": _amount(a.get("total_awarded_amount")),
        "is_mine": 1 if (me and reporter and reporter.lower() == me.lower()) else 0,
    }


def fetch(username, token, program_handle, limit=FETCH_SIZE):
    """One request. Returns a list of normalised rows, newest first.

    THE PROGRAM FILTER IS `queryString=team_handle:<handle>`. `program:<handle>` returns zero rows
    and `filter[program][]` is ignored outright - see the HackerOne API notes section 12. The result
    is filtered on the embedded program handle again anyway: a search filter silently widening is
    exactly the failure that would fill an <program> tile with Valve entries.
    """
    limit = max(1, min(MAX_PAGE_SIZE, int(limit)))
    params = {"page[size]": limit}
    if program_handle:
        params["queryString"] = "team_handle:%s" % program_handle
    d = h1._request(ENDPOINT, username, token, params)
    out = []
    for node in (d.get("data") or []):
        row = normalize(node, me=username, program_handle=program_handle)
        if not row["h1_id"] or not row["activity_at"]:
            continue
        if program_handle and row["program"] and row["program"] != program_handle:
            continue
        out.append(row)
    out.sort(key=lambda r: r["activity_at"], reverse=True)
    return out


# ------------------------------------------------------------------ store
def store(conn, rows):
    """Replace what we hold for each report and trim to the newest KEEP_ROWS. Returns rows kept.

    INSERT OR REPLACE rather than a merge because every column is API-owned: there is no local
    edit on a hacktivity row that could be lost. Keyed on the report id, so a report that gets
    resolved and then paid updates in place instead of appearing twice, which is how the
    hacktivity page itself behaves.
    """
    ensure_schema(conn)
    now = common.now_iso()
    n = 0
    for r in rows:
        conn.execute(
            "INSERT OR REPLACE INTO hacktivity (h1_id, program, action, activity_at, title,"
            " substate, reporter, url, awarded_total, is_mine, fetched_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (r["h1_id"], r["program"], r["action"], r["activity_at"], r["title"], r["substate"],
             r["reporter"], r["url"], r["awarded_total"], int(r["is_mine"]), now))
        n += 1
    conn.execute(
        "DELETE FROM hacktivity WHERE h1_id NOT IN"
        " (SELECT h1_id FROM hacktivity ORDER BY activity_at DESC, h1_id DESC LIMIT ?)",
        (KEEP_ROWS,))
    conn.commit()
    return n


# ------------------------------------------------------------------ refresh
def _backoff_seconds(code, consecutive_failures):
    base, cap = BACKOFF_AUTH if code == 401 else BACKOFF_OTHER
    return min(cap, base * (2 ** (max(1, int(consecutive_failures)) - 1)))


def refresh(conn, verbose=False, program_handle=None, force=False, limit=FETCH_SIZE):
    """One poll: fetch, store, record health. Returns a stats dict and NEVER raises.

    This is the whole degradation strategy. A tile that shows stale entries with an honest "as of"
    is useful; a cron job that exits non-zero, an /api/hacktivity that 502s, or an exception that
    escapes into a shared script would all be worse than the outage they report. Every failure
    mode - no credential, 401, 429, 5xx, DNS, a malformed payload - lands in `status` and `error`
    on the returned dict and in `job_state`, and the previously stored rows are left untouched.
    """
    ensure_schema(conn)
    t0 = time.time()
    stats = {"status": "ok", "error": "", "fetched": 0, "stored": 0, "requests": 0,
             "program": "", "started_at": common.now_iso(), "elapsed_ms": 0}

    job = conn.execute("SELECT backoff_until, consecutive_failures, last_error FROM job_state"
                       " WHERE job=?", (JOB_NAME,)).fetchone()
    if job and not force and (job["backoff_until"] or 0) > time.time():
        stats["status"] = "backoff"
        stats["error"] = job["last_error"] or ""
        stats["elapsed_ms"] = int((time.time() - t0) * 1000)
        if verbose:
            print("hacktivity: backing off after %d failures (%s)"
                  % (job["consecutive_failures"], stats["error"][:120]))
        return stats

    username, token, handle = h1.get_credentials()
    handle = program_handle or handle
    stats["program"] = handle
    if not (username and token):
        # Not a failure to back off from: there is nothing to retry until a token is pasted in
        # the Integrations tab, and a failure streak here would only delay the first good poll.
        stats["status"] = "unconfigured"
        stats["error"] = "No HackerOne credential stored."
        stats["elapsed_ms"] = int((time.time() - t0) * 1000)
        return stats

    try:
        rows = fetch(username, token, handle, limit=limit)
        stats["requests"] = 1
        stats["fetched"] = len(rows)
        stats["stored"] = store(conn, rows)
    except h1.H1Error as e:
        code = getattr(e, "code", None)
        stats["status"] = "auth_failed" if code == 401 else "error"
        stats["error"] = str(e)
        stats["requests"] = 1
        stats["elapsed_ms"] = int((time.time() - t0) * 1000)
        _record_failure(conn, stats, code)
        if verbose:
            sys.stderr.write("hacktivity refresh failed: %s\n" % e)
        return stats
    except Exception as e:                       # malformed payload, sqlite, anything else
        stats["status"] = "error"
        stats["error"] = "%s: %s" % (e.__class__.__name__, e)
        stats["elapsed_ms"] = int((time.time() - t0) * 1000)
        _record_failure(conn, stats, None)
        if verbose:
            sys.stderr.write("hacktivity refresh failed: %s\n" % e)
        return stats

    stats["elapsed_ms"] = int((time.time() - t0) * 1000)
    conn.execute(
        "UPDATE job_state SET last_run=?, last_success=?, last_status='ok', last_error='',"
        " last_duration_ms=?, consecutive_failures=0, backoff_until=0, runs=runs+1,"
        " requests=requests+?, updated_at=? WHERE job=?",
        (stats["started_at"], common.now_iso(), stats["elapsed_ms"], stats["requests"],
         common.now_iso(), JOB_NAME))
    conn.commit()
    if verbose:
        print("hacktivity (%s): fetched=%d stored=%d in %dms"
              % (handle, stats["fetched"], stats["stored"], stats["elapsed_ms"]))
    return stats


def _record_failure(conn, stats, code):
    """One row, updated in place - 288 runs a day must not become 288 log lines."""
    cur = conn.execute("SELECT consecutive_failures FROM job_state WHERE job=?",
                       (JOB_NAME,)).fetchone()
    cf = (cur["consecutive_failures"] if cur else 0) + 1
    conn.execute(
        "UPDATE job_state SET last_run=?, last_status=?, last_error=?, last_error_at=?,"
        " last_duration_ms=?, consecutive_failures=?, backoff_until=?, runs=runs+1,"
        " failures=failures+1, requests=requests+?, updated_at=? WHERE job=?",
        (stats["started_at"], "auth_failed" if code == 401 else "error", stats["error"][:500],
         common.now_iso(), stats["elapsed_ms"], cf, time.time() + _backoff_seconds(code, cf),
         stats["requests"], common.now_iso(), JOB_NAME))
    conn.commit()


# ------------------------------------------------------------------ read side
def _age_seconds(stamp):
    """Seconds since a naive local-time stamp written by common.now_iso(). None if unparseable."""
    if not stamp:
        return None
    try:
        return max(0.0, time.time() - time.mktime(
            time.strptime(str(stamp)[:19], "%Y-%m-%dT%H:%M:%S")))
    except (ValueError, OverflowError):
        return None


def recent(conn, limit=5):
    """What the tile renders. Reads only; the browser must never trigger a HackerOne request.

    Returns the newest entries plus enough context to be honest about their age. `as_of` describes
    the ROWS, not the last attempt: it is the newer of the last successful refresh and the newest
    `fetched_at`, both of which are only ever written after HackerOne answered. A failed attempt
    moves neither, so a broken feed cannot make old rows look fresh. `status` and `error` report
    the failure separately, because "these entries are 4 minutes old" and "the feed has been
    failing for an hour" are both true at once and the tile has to say both.
    """
    ensure_schema(conn)
    limit = max(1, min(50, int(limit)))
    cols = ("h1_id, program, action, activity_at, title, substate, reporter, url,"
            " awarded_total, is_mine")
    rows = [dict(r) for r in conn.execute(
        "SELECT " + cols + " FROM hacktivity ORDER BY activity_at DESC, h1_id DESC LIMIT ?",
        (limit,)).fetchall()]
    for r in rows:
        r["action_label"] = pretty_action(r["action"])
        r["is_mine"] = bool(r["is_mine"])

    # The most recent entry on one of OUR reports, whether or not it made the top `limit`. This is
    # the half of the tile that is about us rather than about the program.
    mine = conn.execute(
        "SELECT " + cols + " FROM hacktivity WHERE is_mine=1"
        " ORDER BY activity_at DESC, h1_id DESC LIMIT 1").fetchone()
    mine = dict(mine) if mine else None
    if mine:
        mine["action_label"] = pretty_action(mine["action"])
        mine["is_mine"] = True

    job = conn.execute("SELECT * FROM job_state WHERE job=?", (JOB_NAME,)).fetchone()
    job = dict(job) if job else {}
    # Both are naive local ISO-8601 with a fixed layout, so lexical max is chronological max.
    as_of = max(job.get("last_success") or "",
                conn.execute("SELECT MAX(fetched_at) FROM hacktivity").fetchone()[0] or "")
    age = _age_seconds(as_of)
    username, _token, handle = h1.get_credentials()

    return {
        "items": rows,
        "mine_latest": mine,
        "stored": conn.execute("SELECT COUNT(*) FROM hacktivity").fetchone()[0],
        "mine_stored": conn.execute(
            "SELECT COUNT(*) FROM hacktivity WHERE is_mine=1").fetchone()[0],
        "as_of": as_of,
        # as_of is a naive host-local timestamp, and this host runs UTC while the person reading
        # it does not. Labelling the clock is the difference between "04:23" meaning something
        # and meaning nothing. Read from the host rather than hardcoded, so the label follows if
        # the machine's zone ever changes instead of quietly lying.
        "as_of_tz": time.strftime("%Z") or "local",
        "age_seconds": age,
        # Computed server-side. The browser's clock is on another machine and has been wrong here
        # before; a freshness verdict is not something to leave to it.
        "stale": bool(age is None or age > STALE_AFTER) if as_of else True,
        "stale_after": STALE_AFTER,
        "status": job.get("last_status") or ("never_run" if not as_of else "ok"),
        # Whatever the failure was, in the user's words. NEVER the credential: h1.get_credentials
        # is only ever consulted for the handle and a boolean here.
        "error": job.get("last_error") or "",
        "consecutive_failures": job.get("consecutive_failures") or 0,
        "program": handle or "",
        "configured": bool(username),
        "hacktivity_url": ("https://hackerone.com/%s/hacktivity?type=team" % handle)
                          if handle else "",
    }


def status(conn):
    """Job health, in the shape the Status tab's other job cards use."""
    ensure_schema(conn)
    j = dict(conn.execute("SELECT * FROM job_state WHERE job=?", (JOB_NAME,)).fetchone() or {})
    bu = j.get("backoff_until") or 0
    return {
        "job": JOB_NAME,
        "last_run": j.get("last_run"),
        "last_success": j.get("last_success"),
        "last_status": j.get("last_status"),
        "last_error": j.get("last_error") or "",
        "last_error_at": j.get("last_error_at"),
        "consecutive_failures": j.get("consecutive_failures") or 0,
        "in_backoff": bool(bu and bu > time.time()),
        "runs": j.get("runs") or 0,
        "failures": j.get("failures") or 0,
        "cumulative_requests": j.get("requests") or 0,
        "stored": conn.execute("SELECT COUNT(*) FROM hacktivity").fetchone()[0],
        "interval_hint": "every 5 minutes (cron), 1 request per run",
    }


# ------------------------------------------------------------------ cli
LOCK_PATH = os.path.join(common.APP_DIR, ".hacktivity.lock")


def _lock():
    """A five-minute tick and a slow request must not overlap."""
    import fcntl
    fh = open(LOCK_PATH, "a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def main():
    ap = argparse.ArgumentParser(description="Program hacktivity feed")
    ap.add_argument("--refresh", action="store_true", help="one poll (cron mode)")
    ap.add_argument("--show", action="store_true", help="stored entries, newest first")
    ap.add_argument("--status", action="store_true", help="job health")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--program")
    ap.add_argument("--force", action="store_true", help="ignore the failure backoff window")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    conn = common.connect()
    common.init_db(conn)
    try:
        if args.refresh:
            lock = _lock()
            if lock is None:
                if not args.quiet:
                    print("hacktivity: another refresh is running; skipping")
                return 0
            try:
                st = refresh(conn, verbose=not args.quiet, program_handle=args.program,
                             force=args.force)
            finally:
                lock.close()
            if args.json:
                print(json.dumps(st, indent=2, sort_keys=True))
            elif args.quiet and st["status"] not in ("ok", "backoff"):
                # Quiet means quiet unless something is wrong. Exit 0 regardless: this feed is
                # decoration, and a non-zero exit in cron would make a broken tile look like a
                # broken sync.
                print("%s hacktivity [%s]: %s" % (common.now_iso(), st["status"],
                                                  st["error"][:200]))
        if args.show:
            res = recent(conn, limit=args.limit)
            if args.json:
                print(json.dumps(res, indent=2, sort_keys=True))
            else:
                print("as of %s%s  (%d stored, %d mine)"
                      % (res["as_of"] or "never", "  STALE" if res["stale"] else "",
                         res["stored"], res["mine_stored"]))
                for r in res["items"]:
                    print("  %-24s %-18s #%-9s %-16s %s"
                          % (r["activity_at"], r["action_label"], r["h1_id"],
                             r["reporter"] or "-",
                             (r["title"] or ("(yours)" if r["is_mine"] else ""))[:52]))
                if not res["items"]:
                    print("  (nothing stored yet - run --refresh)")
        if args.status or not (args.refresh or args.show):
            st = status(conn)
            if args.json:
                print(json.dumps(st, indent=2, sort_keys=True))
            else:
                for k, v in st.items():
                    print("  %-22s %s" % (k, v))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
