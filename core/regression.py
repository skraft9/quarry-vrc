#!/usr/bin/env python3
"""Regression queue: which of our fixed bugs is due a second look, and what did the retest find?

WHAT THIS ANSWERS
-----------------
Not "what happened to my reports" - the Tracker owns that. This answers the question nobody asks
until it is too late: the program shipped a fix for our finding, so is the fix actually any good?

A resolved report is the one piece of attack surface a researcher has an unfair advantage on. The
patch is new code, written under deadline pressure, by someone who saw a single proof of concept
and very often defended against THAT REQUEST rather than against the bug. We already know the
class, the endpoint, the parameter and the exact bypass that worked once. Nobody else on the
program has that context, which is the opposite of the situation on a fresh target where the
duplicate rate lives.

The queue is a reminder with the evidence attached, not a scanner. It says "report #0000000 was
fixed 34 days ago and you have not looked at it since", puts the original body and the triage
thread one click away, and records what the retest found so the same report is not silently
re-checked every month forever.

DERIVED, NOT MAINTAINED
-----------------------
The candidate list is COMPUTED from `reports` on every read: any HackerOne-sourced report in state
`resolved` with a close date. It is never written down. That is deliberate and it is the same rule
the rest of the app follows - HackerOne owns which reports are resolved, so a resolved report can
never fail to appear here, and one the program reopens leaves on the next sync without a cleanup
path having to exist.

This module therefore owns exactly ONE table, `regressions`, and every row in it is a HUMAN
JUDGEMENT: the verdict a retest reached, a note, a due-date override, when it was last tested. A
report with no verdict has no row. Deleting the table loses opinions and nothing else; the queue
rebuilds itself from HackerOne on the next page load.

THE VERDICT VOCABULARY
----------------------
Four values, and the interesting one is `broken`:

    pending   no verdict yet. The implicit state of every resolved report; carries no row.
    holds     retested, the fix stands. Leaves the queue until the next window comes round.
    broken    the fix is incomplete or bypassable. This is a finding, and the point of the tab.
    skipped   deliberately not retesting - target retired, program closed, access gone.

`broken` is not a status the queue resolves. It is a hand-off: the row stays visible with its note
until a lead exists for the bypass, because an incomplete fix that nobody re-reports is worth
exactly as much as one that was never found.

WINDOWS AND DUE DATES
---------------------
A report becomes due `window_days` after its close date (default 30, `regression_window_days` in
config). That number is a prompt, not a deadline: fixes ship on the program's schedule and the
window only decides what order the list is read in. A due date can be pushed out per report
(snooze) when a fix is known to still be rolling out, and that override survives re-reads because
it is a judgement and lives in the table.

`resolved_on` CANNOT BE TRUSTED ALONE, and this is the one trap in the feature. h1.upsert_report
writes it as `resolved_on = COALESCE(?, resolved_on)`, so it records the FIRST time a report
closed and never moves again. A report that was reopened and re-resolved - which is precisely the
population an incomplete fix produces - therefore carries a close date from the fix BEFORE the one
we would be re-testing. Scheduling on that column alone would mis-date exactly the reports this
tab exists to catch.

So the window is not the only thing that puts a report in front of you. `last_activity` is
overwritten unconditionally on every sync, so any row whose activity is newer than the date its
verdict was recorded is surfaced again as `due` with `moved_since_test` set, whatever that verdict
was. A verdict answers the report as it stood when it was tested; the program touching it
afterwards is new evidence, and the note and attempt count are kept so the next look starts from
what the last one found.

Nothing here contacts HackerOne. The whole queue is a query over rows `h1.py --sync` already
wrote, so it works offline, costs no API budget and cannot be rate-limited.

    python3 regression.py --queue                # what is due now, most overdue first
    python3 regression.py --queue --bucket all   # every resolved report and its verdict
    python3 regression.py --verdict 0000000 --status holds --note "..."
    python3 regression.py --snooze 0000000 --days 30
    python3 regression.py --status              # counts, window, coverage
"""
import argparse
import datetime
import json
import sys

import common

#: Days after a report closes before it reads as due. Thirty is one full deploy cycle on most
#: programs - long enough that the fix has shipped and settled, short enough that the code is
#: still fresh in the program's mind if a bypass turns into a second report.
DEFAULT_WINDOW_DAYS = 30

#: Clamped, not validated: a window of zero makes every resolved report permanently due and a
#: window of years makes the tab empty, and neither is worth an error message.
MIN_WINDOW_DAYS = 1
MAX_WINDOW_DAYS = 3650

CONFIG_KEY = "regression_window_days"

#: The verdicts a human can record. `pending` is in the tuple because the UI has to be able to
#: CLEAR a verdict - undoing a misclick must not require deleting a database row by hand - and it
#: is stored as the absence of a row, not as the string.
VERDICTS = ("pending", "holds", "broken", "skipped")

#: Derived buckets, which is what the tab filters on. Three of them are verdicts; `due` and
#: `scheduled` split `pending` by whether the window has elapsed. Nothing computes a bucket into
#: the table - it is a function of today's date and would be wrong tomorrow.
BUCKETS = ("due", "scheduled", "holds", "broken", "skipped")

SCHEMA = """
CREATE TABLE IF NOT EXISTS regressions (
  h1_id       TEXT PRIMARY KEY,           -- the report retested. Not a foreign key: `reports`
                                          -- rows are rewritten by the sync, and a verdict must
                                          -- outlive a re-sync that recreates the row.
  verdict     TEXT NOT NULL DEFAULT 'pending',   -- holds | broken | skipped
  note        TEXT,                       -- what the retest actually did, in the operator's words
  due_override TEXT,                      -- 'YYYY-MM-DD' snooze. NULL = derived from the window.
  last_tested TEXT,                       -- date of the most recent verdict
  attempts    INTEGER NOT NULL DEFAULT 0, -- how many times a verdict has been recorded
  lead_path   TEXT,                       -- the lead file a `broken` verdict was written into
  created_at  TEXT,
  updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_regressions_verdict ON regressions(verdict);
"""


def ensure_schema(conn):
    """Create the table if it is missing. schema.sql carries it for a fresh database; this covers
    one created before the tab existed."""
    conn.executescript(SCHEMA)
    conn.commit()


# ------------------------------------------------------------------ dates
def today():
    """Local date, matching common.now_iso()'s clock so a due date and a timestamp agree."""
    return datetime.date.today().isoformat()


def _parse_date(value):
    """'2026-07-14' or '2026-07-14T09:12:33Z' -> date. None when it is not a date at all.

    HackerOne sends full timestamps and `resolved_on` stores the first ten characters, but a
    hand-edited database and an older sync can both put other things in the column, and a queue
    that raises on one malformed row is worse than one that skips it.
    """
    if not value:
        return None
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def _shift(date_str, days):
    """Add days to an ISO date string. Empty string when the input is not a date."""
    d = _parse_date(date_str)
    if d is None:
        return ""
    return (d + datetime.timedelta(days=int(days))).isoformat()


def _days_between(start, end):
    """Whole days from start to end, both ISO dates. None when either is unparseable."""
    a, b = _parse_date(start), _parse_date(end)
    if a is None or b is None:
        return None
    return (b - a).days


def window_days(cfg=None):
    """The configured window, clamped. Reads config at call time so a Settings change takes effect
    on the next request rather than the next restart."""
    cfg = cfg if cfg is not None else common.load_config()
    try:
        n = int(cfg.get(CONFIG_KEY, DEFAULT_WINDOW_DAYS))
    except (TypeError, ValueError):
        n = DEFAULT_WINDOW_DAYS
    return max(MIN_WINDOW_DAYS, min(MAX_WINDOW_DAYS, n))


# ------------------------------------------------------------------ the queue
#: Every resolved HackerOne report, with any verdict recorded against it. The exclusions match the
#: Tracker's (`server.ENTITIES['reports']`): RCAs share their parent's id and legacy markdown rows
#: were superseded by the API, so neither is a submission that a program could have fixed.
CANDIDATE_SQL = """
SELECT r.h1_id, r.title, r.program, r.severity, r.bounty, r.currency, r.weakness, r.cwe,
       r.asset, r.url, r.submitted_on, r.resolved_on, r.last_activity, r.my_role, r.my_bounty,
       g.verdict, g.note, g.due_override, g.last_tested, g.attempts, g.lead_path, g.updated_at
  FROM reports r
  LEFT JOIN regressions g ON g.h1_id = r.h1_id
 WHERE r.kind = 'report'
   AND r.source = 'hackerone'
   AND LOWER(COALESCE(r.h1_state, r.state, '')) = 'resolved'
   AND COALESCE(r.resolved_on, '') <> ''
"""


def _decorate(row, days, now):
    """One candidate row -> the shape the tab renders. Pure: every derived field is a function of
    the row, the window and today, so nothing has to be recomputed and stored when the date rolls.
    """
    item = dict(row)
    verdict = (item.get("verdict") or "pending").strip().lower()
    if verdict not in VERDICTS:
        verdict = "pending"
    item["verdict"] = verdict
    item["attempts"] = int(item.get("attempts") or 0)

    derived_due = _shift(item.get("resolved_on"), days)
    item["due_on"] = item.get("due_override") or derived_due
    item["due_derived"] = derived_due
    item["snoozed"] = bool(item.get("due_override"))

    item["days_since_fix"] = _days_between(item.get("resolved_on"), now)
    overdue = _days_between(item["due_on"], now)
    item["days_overdue"] = overdue if (overdue is not None and overdue > 0) else 0

    # The report moved after we last tested it. Strictly after, by date: `last_activity` is a UTC
    # stamp and `last_tested` a local date, and a same-day comparison across those two clocks would
    # re-surface every report the moment its verdict was recorded.
    moved = _days_between(item.get("last_tested"), (item.get("last_activity") or "")[:10])
    item["moved_since_test"] = bool(item.get("last_tested") and moved is not None and moved > 0)

    if verdict == "pending":
        # A row with no parseable due date reads as due rather than as scheduled forever. The
        # failure mode of showing it too early is a glance; of hiding it, a fix never checked.
        item["bucket"] = "scheduled" if (overdue is not None and overdue < 0) else "due"
    elif item["moved_since_test"]:
        # The verdict stands as a record - it is still on the row, and `attempts` still counts it -
        # but it no longer describes the report, so the report comes back to the top of the queue.
        item["bucket"] = "due"
    else:
        item["bucket"] = verdict
    return item


def _sort_key(item):
    """Reports that moved since we tested them, then most overdue, then oldest due date, then id.

    Movement outranks the clock because it is the only signal here that is evidence rather than a
    timer: a report the program touched after our verdict has something new on it, whereas an
    overdue one has only been waiting. Below that, the report left longest sorts up - the same
    ordering rule /api/queue uses for leads, and for the same reason.
    """
    return (0 if item.get("moved_since_test") else 1,
            -int(item.get("days_overdue") or 0),
            item.get("due_on") or "9999-12-31",
            str(item.get("h1_id") or ""))


def queue(conn, cfg=None, bucket="due", program="", q="", limit=200, offset=0):
    """The tab's payload: the filtered queue, the counts every bucket holds, and the window.

    Counts are computed over the WHOLE candidate set, not the filtered page, because they are what
    the filter chips display - a count that shrank to match the filter it is offered alongside
    would make the tab unnavigable.
    """
    ensure_schema(conn)
    days = window_days(cfg)
    now = today()

    items = [_decorate(r, days, now) for r in conn.execute(CANDIDATE_SQL).fetchall()]
    programs = sorted({it["program"] for it in items if it.get("program")})

    counts = {b: 0 for b in BUCKETS}
    for it in items:
        counts[it["bucket"]] = counts.get(it["bucket"], 0) + 1
    counts["all"] = len(items)
    # The one number worth reading on its own: fixes we have never once gone back to.
    counts["untested"] = sum(1 for it in items if it["verdict"] == "pending")

    bucket = (bucket or "due").strip().lower()
    if bucket and bucket != "all":
        items = [it for it in items if it["bucket"] == bucket]
    if program:
        items = [it for it in items if (it.get("program") or "") == program]
    if q:
        needle = q.lower()
        items = [it for it in items
                 if needle in (it.get("title") or "").lower()
                 or needle in str(it.get("h1_id") or "")
                 or needle in (it.get("asset") or "").lower()
                 or needle in (it.get("note") or "").lower()]

    items.sort(key=_sort_key)
    total = len(items)
    try:
        limit = max(1, min(500, int(limit)))
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        limit, offset = 200, 0

    return {
        "items": items[offset:offset + limit],
        "total": total,
        "counts": counts,
        "bucket": bucket,
        "window_days": days,
        "today": now,
        "programs": programs,
        "verdicts": list(VERDICTS),
        "buckets": list(BUCKETS),
    }


def detail(conn, h1_id, cfg=None):
    """One queue entry with the evidence attached: the original report body and the triage thread.

    Both come from the report row rather than a fresh fetch. The thread is where the program said
    what it fixed, which is the single most useful paragraph when deciding what to re-test, and it
    is already on disk after `h1.py --sync`.
    """
    ensure_schema(conn)
    row = conn.execute(CANDIDATE_SQL + " AND r.h1_id = ?", (str(h1_id),)).fetchone()
    if row is None:
        return None
    item = _decorate(row, window_days(cfg), today())
    extra = conn.execute(
        "SELECT body, thread, cvss, cvss_vector, collaborators FROM reports"
        " WHERE h1_id=? AND kind='report' AND source='hackerone'", (str(h1_id),)).fetchone()
    if extra:
        item["body"] = extra["body"] or ""
        item["cvss"] = extra["cvss"] or ""
        item["cvss_vector"] = extra["cvss_vector"] or ""
        item["collaborators"] = extra["collaborators"] or ""
        try:
            item["thread"] = json.loads(extra["thread"]) if extra["thread"] else []
        except (ValueError, TypeError):
            item["thread"] = []
    return item


# ------------------------------------------------------------------ write side
def is_candidate(conn, h1_id):
    """Whether this id is a resolved HackerOne report of ours.

    Checked before every write so a verdict cannot be recorded against a report that was never
    resolved, or against an id that is not in the database at all. Without it the table would
    accept any string as a primary key and the queue would silently ignore the row forever.
    """
    return conn.execute(
        "SELECT 1 FROM reports WHERE h1_id=? AND kind='report' AND source='hackerone'"
        " AND LOWER(COALESCE(h1_state, state, '')) = 'resolved'"
        " AND COALESCE(resolved_on,'') <> '' LIMIT 1", (str(h1_id),)).fetchone() is not None


def _upsert(conn, h1_id, **fields):
    """Create or update the verdict row, touching only the columns passed."""
    now = common.now_iso()
    conn.execute("INSERT OR IGNORE INTO regressions (h1_id, created_at, updated_at)"
                 " VALUES (?,?,?)", (str(h1_id), now, now))
    sets = ", ".join("%s=?" % k for k in fields)
    params = list(fields.values()) + [now, str(h1_id)]
    conn.execute("UPDATE regressions SET %s, updated_at=? WHERE h1_id=?" % sets, params)
    conn.commit()


def set_verdict(conn, h1_id, verdict, note=None, tested_on=None):
    """Record what a retest found. Returns the refreshed queue entry.

    `attempts` increments on every real verdict and NOT on a clearing back to pending, so the
    number answers "how many times has this fix been checked" rather than "how many times has this
    row been edited". Clearing also leaves the note and the attempt count alone: undoing a misclick
    should not destroy the notes taken during the retest it was recording.
    """
    ensure_schema(conn)
    verdict = (verdict or "").strip().lower()
    if verdict not in VERDICTS:
        raise ValueError("verdict must be one of: %s" % ", ".join(VERDICTS))
    if not is_candidate(conn, h1_id):
        raise ValueError("report %s is not a resolved HackerOne report in this database" % h1_id)

    fields = {"verdict": verdict}
    if note is not None:
        if not isinstance(note, str):
            raise ValueError("note must be a string")
        fields["note"] = note
    if verdict != "pending":
        fields["last_tested"] = tested_on or today()
        row = conn.execute("SELECT attempts FROM regressions WHERE h1_id=?",
                           (str(h1_id),)).fetchone()
        fields["attempts"] = int((row["attempts"] if row else 0) or 0) + 1
        # A verdict answers the window that prompted it, so the snooze that deferred it is spent.
        fields["due_override"] = None
    _upsert(conn, h1_id, **fields)
    return detail(conn, h1_id)


def snooze(conn, h1_id, days=None, due_on=None):
    """Push the due date out without recording a verdict. Returns the refreshed entry.

    For the fix that is known to still be rolling out, or the program that asked for time. Either
    an explicit date or a number of days FROM TODAY - not from the old due date, which on an
    already-overdue report would push it out to a date still in the past.
    """
    ensure_schema(conn)
    if not is_candidate(conn, h1_id):
        raise ValueError("report %s is not a resolved HackerOne report in this database" % h1_id)
    if due_on:
        if _parse_date(due_on) is None:
            raise ValueError("due_on must be a YYYY-MM-DD date")
        target = _parse_date(due_on).isoformat()
    else:
        try:
            n = int(days if days is not None else window_days())
        except (TypeError, ValueError):
            raise ValueError("days must be a whole number")
        if n < 1:
            raise ValueError("days must be at least 1")
        target = _shift(today(), n)
    _upsert(conn, h1_id, due_override=target)
    return detail(conn, h1_id)


def clear_snooze(conn, h1_id):
    """Drop the override and fall back to the derived due date."""
    ensure_schema(conn)
    if not is_candidate(conn, h1_id):
        raise ValueError("report %s is not a resolved HackerOne report in this database" % h1_id)
    _upsert(conn, h1_id, due_override=None)
    return detail(conn, h1_id)


def record_lead(conn, h1_id, lead_path):
    """Remember which lead file a `broken` verdict was written into, so the row links to it."""
    ensure_schema(conn)
    _upsert(conn, h1_id, lead_path=lead_path)
    return detail(conn, h1_id)


# ------------------------------------------------------------------ lead drafting
def lead_markdown(item, researcher=""):
    """The starting lead for a bypass of a shipped fix, in the LEAD_STANDARD header-table shape.

    Pre-filled with what the queue already knows and NOTHING it does not. Every line an operator
    still has to answer is left as an explicit prompt rather than a plausible guess: a lead that
    arrives with an invented claim in it is worse than an empty one, because the invented claim is
    what gets read six weeks later.
    """
    h1_id = str(item.get("h1_id") or "")
    title = (item.get("title") or "").strip() or ("report %s" % h1_id)
    rows = [
        ("**Status:**", "open"),
        ("**Researcher**", researcher or "<your-handle>"),
        ("**Date**", today()),
        ("**Target**", item.get("asset") or item.get("program") or ""),
        ("**Class**", item.get("weakness") or ""),
        ("**CWE**", item.get("cwe") or ""),
        ("**Severity**", item.get("severity") or ""),
        ("**Origin**", "regression retest of #%s (resolved %s)"
                       % (h1_id, item.get("resolved_on") or "")),
        ("**Original**", item.get("url") or ""),
    ]
    # Empty rows are DROPPED, not written blank: LEAD_STANDARD is explicit that a row is omitted
    # rather than filled with a nil, and a header full of empty cells reads as a lead somebody
    # started and abandoned rather than one a tool pre-filled.
    head = ["# Fix bypass - %s" % title, "", "| | |", "|---|---|"]
    head += ["| %s | %s |" % (k, v) for k, v in rows if str(v).strip()]

    note = (item.get("note") or "").strip()
    body = [
        "",
        "## Claim",
        "",
        "The fix shipped for #%s does not hold. State the bypass in one sentence here, and delete"
        " this line once it does." % h1_id,
        "",
        "## What was fixed",
        "",
        note or "What the program said it changed, from the triage thread on the original report.",
        "",
        "## What still works",
        "",
        "The request that still succeeds, verbatim, with the response that proves it. An incomplete"
        " fix is only a finding once this section holds a reproduction that a triager can run.",
        "",
        "## Why the fix misses it",
        "",
        "The reason the patch does not cover this path - a second endpoint, an alternate encoding,"
        " a check on the wrong object. This is the paragraph that decides whether the report reads"
        " as a new bug or as a re-send of the old one.",
        "",
        "## Impact",
        "",
        "What an attacker gets, in the same terms the original report used.",
        "",
    ]
    return "\n".join(head + body)


# ------------------------------------------------------------------ read-only summaries
def summary(conn, cfg=None):
    """The dashboard tile's numbers. Cheap enough to run on every stats call."""
    ensure_schema(conn)
    days = window_days(cfg)
    now = today()
    counts = {b: 0 for b in BUCKETS}
    total = moved = tested = broken_verdict = 0
    for row in conn.execute(CANDIDATE_SQL).fetchall():
        it = _decorate(row, days, now)
        counts[it["bucket"]] = counts.get(it["bucket"], 0) + 1
        total += 1
        moved += 1 if it["moved_since_test"] else 0
        # Counted off the VERDICT, not the bucket. A report that moved since its retest is back in
        # `due` while still carrying the verdict it was given, so counting buckets here would
        # report it as never looked at - which is the one thing this number must not do. The same
        # reasoning applies to `broken_verdict`: a fix found broken is still broken after the
        # program touches the report, so the Status count reads it off the verdict, not the bucket.
        tested += 1 if it["verdict"] != "pending" else 0
        broken_verdict += 1 if it["verdict"] == "broken" else 0
    return {
        "due": counts["due"],
        "scheduled": counts["scheduled"],
        "holds": counts["holds"],
        "broken": counts["broken"],
        "broken_verdict": broken_verdict,
        "skipped": counts["skipped"],
        "moved": moved,
        "tested": tested,
        "total": total,
        "window_days": days,
    }


def status(conn, cfg=None):
    """Feature health for the Status tab. No job, no credential, no failure mode to report: this
    is a query over synced rows, so the only honest health signal is coverage."""
    s = summary(conn, cfg)
    return {
        "feature": "regression",
        "resolved_reports": s["total"],
        "verdicts_recorded": s["tested"],
        "never_retested": s["total"] - s["tested"],
        "due_now": s["due"],
        "moved_since_test": s["moved"],
        "fixes_broken": s["broken_verdict"],
        "window_days": s["window_days"],
        "source": "derived from synced reports; makes no HackerOne request",
    }


# ------------------------------------------------------------------ cli
def _print_queue(res):
    items = res["items"]
    if not items:
        print("nothing in bucket '%s' (window %d days)" % (res["bucket"], res["window_days"]))
        return
    print("%-9s %-12s %-10s %-7s %-9s %s"
          % ("REPORT", "PROGRAM", "DUE", "OVERDUE", "VERDICT", "TITLE"))
    for it in items:
        print("%-9s %-12s %-10s %-7s %-9s %s"
              % (("#" + str(it["h1_id"]))[:9], (it.get("program") or "")[:12],
                 it.get("due_on") or "-",
                 str(it.get("days_overdue") or 0), it["bucket"], (it.get("title") or "")[:60]))
    print("\n%d of %d shown. due=%d scheduled=%d holds=%d broken=%d skipped=%d"
          % (len(items), res["total"], res["counts"]["due"], res["counts"]["scheduled"],
             res["counts"]["holds"], res["counts"]["broken"], res["counts"]["skipped"]))


def main():
    ap = argparse.ArgumentParser(description="Regression queue for shipped fixes")
    ap.add_argument("--queue", action="store_true", help="list the queue")
    ap.add_argument("--bucket", default="due",
                    help="due | scheduled | holds | broken | skipped | all")
    ap.add_argument("--program", default="", help="one program handle")
    ap.add_argument("--search", default="", help="substring of title, id, asset or note")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--show", metavar="H1_ID", help="one entry with its report body and thread")
    ap.add_argument("--verdict", metavar="H1_ID", help="record a verdict against this report")
    ap.add_argument("--set", dest="set_verdict", default="",
                    help="holds | broken | skipped | pending (with --verdict)")
    ap.add_argument("--note", default=None, help="what the retest found (with --verdict)")
    ap.add_argument("--snooze", metavar="H1_ID", help="push this report's due date out")
    ap.add_argument("--days", type=int, default=None, help="days from today (with --snooze)")
    ap.add_argument("--due-on", default="", help="explicit YYYY-MM-DD (with --snooze)")
    ap.add_argument("--draft", metavar="H1_ID",
                    help="print a starting lead for a bypass of this report's fix")
    ap.add_argument("--status", action="store_true", help="coverage and window")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    conn = common.connect()
    common.init_db(conn)
    cfg = common.load_config()
    try:
        if args.verdict:
            if not args.set_verdict:
                sys.stderr.write("--verdict needs --set <%s>\n" % "|".join(VERDICTS))
                return 2
            out = set_verdict(conn, args.verdict, args.set_verdict, note=args.note)
            common.audit(conn, "cli", "regression_verdict", "reports", None,
                         "#%s -> %s" % (args.verdict, args.set_verdict))
            print(json.dumps(out, indent=2, sort_keys=True) if args.json
                  else "#%s: %s" % (args.verdict, args.set_verdict))
            return 0

        if args.snooze:
            out = snooze(conn, args.snooze, days=args.days, due_on=args.due_on or None)
            common.audit(conn, "cli", "regression_snooze", "reports", None,
                         "#%s -> %s" % (args.snooze, out.get("due_on")))
            print(json.dumps(out, indent=2, sort_keys=True) if args.json
                  else "#%s due %s" % (args.snooze, out.get("due_on")))
            return 0

        if args.draft:
            item = detail(conn, args.draft, cfg)
            if item is None:
                sys.stderr.write("no resolved report #%s in this database\n" % args.draft)
                return 1
            print(lead_markdown(item))
            return 0

        if args.show:
            item = detail(conn, args.show, cfg)
            if item is None:
                sys.stderr.write("no resolved report #%s in this database\n" % args.show)
                return 1
            print(json.dumps(item, indent=2, sort_keys=True))
            return 0

        if args.status:
            st = status(conn, cfg)
            if args.json:
                print(json.dumps(st, indent=2, sort_keys=True))
            else:
                for k in ("resolved_reports", "verdicts_recorded", "never_retested", "due_now",
                          "moved_since_test", "fixes_broken", "window_days"):
                    print("  %-18s %s" % (k, st[k]))
            return 0

        res = queue(conn, cfg, bucket=args.bucket, program=args.program, q=args.search,
                    limit=args.limit)
        if args.json:
            print(json.dumps(res, indent=2, sort_keys=True))
        else:
            _print_queue(res)
        return 0
    except ValueError as e:
        sys.stderr.write("%s\n" % e)
        return 2
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
