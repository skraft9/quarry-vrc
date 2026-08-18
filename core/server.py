#!/usr/bin/env python3
"""HTTP(S) server. Stdlib only. Product name comes from config (see RENAME.md).

Run:  python3 server.py            (reads config.json)
      python3 server.py --adduser seth
      python3 server.py --gencert

See docs/app/ARCHITECTURE.md for the full stack description.
"""
import argparse
import bisect
import datetime
import getpass
import html
import io
import json
import mimetypes
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import auth
import common


def _read_version():
    """The single source of truth for the running version is the VERSION file at the repo root, so
    the sidebar, /api/health and the startup banner always reflect the build actually shipped. A
    hardcoded constant here drifted (it sat at 1.3.3 through several releases); reading the file
    makes that impossible. Falls back to 0.0.0 only if the file is somehow absent, which reads as
    an obviously-unidentified build rather than a wrong number."""
    try:
        with open(os.path.join(common.ROOT_DIR, "VERSION"), encoding="utf-8") as f:
            return f.read().strip() or "0.0.0"
    except OSError:
        return "0.0.0"


VERSION = _read_version()
MAX_BODY = 64 * 1024 * 1024  # 64 MB ceiling on any request body
COOKIE_MAX_AGE_NEVER = 10 * 365 * 24 * 3600  # see r_login: "never expires", in cookie terms

try:
    import ingest
except Exception:  # pragma: no cover - ingest is built in parallel
    ingest = None

import payloads

# Optional: the dashboard hacktivity tile. A checkout without it must still serve the dashboard,
# so the import failing is a degraded tile, not a dead app.
try:
    import hacktivity as hacktivity_mod
except Exception:  # pragma: no cover
    hacktivity_mod = None

# Optional for the same reason: without it the Status tab loses the interval editor, but every
# job keeps running on whatever the crontab already says.
try:
    import schedule as schedule_mod
except Exception:  # pragma: no cover
    schedule_mod = None

try:
    import screenshot as screenshot_mod
except Exception:  # pragma: no cover
    screenshot_mod = None

# Optional for the same reason: without it the Regression tab reports itself unavailable and the
# rest of the console is untouched. It reads only rows the HackerOne sync already wrote.
try:
    import regression as regression_mod
except Exception:  # pragma: no cover
    regression_mod = None


# ====================================================================== helpers
def _json_default(o):
    return str(o)


class Ctx:
    """Per-request context passed to handlers."""

    def __init__(self, handler, conn, cfg, identity, query, body):
        self.h = handler
        self.conn = conn
        self.cfg = cfg
        self.identity = identity
        self.query = query
        self.body = body
        self.remote = handler.client_address[0]

    @property
    def user(self):
        return (self.identity or {}).get("username")

    def q(self, key, default=None):
        vals = self.query.get(key)
        return vals[0] if vals else default


class HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


# ====================================================================== routes
ROUTES = []


def route(method, pattern, scope=None, public=False):
    """scope=None -> read access required; scope='write' -> write access required."""
    compiled = re.compile("^" + pattern + "$")

    def deco(fn):
        ROUTES.append((method, compiled, fn, scope, public))
        return fn

    return deco


# ---------------------------------------------------------------- auth routes
@route("GET", r"/api/health", public=True)
def r_health(ctx, m):
    return {"ok": True, "version": VERSION, "app_name": common.app_name(ctx.cfg)}


@route("POST", r"/api/login", public=True)
def r_login(ctx, m):
    if not auth.login_allowed(ctx.remote):
        common.audit(ctx.conn, None, "login_ratelimited", remote=ctx.remote)
        raise HttpError(429, "Too many login attempts. Wait 15 minutes.")
    username = (ctx.body or {}).get("username", "")
    password = (ctx.body or {}).get("password", "")
    users = ctx.cfg.get("users", {})
    record = users.get(username)
    if not auth.verify_password(password, record):
        auth.record_login_failure(ctx.remote)
        common.audit(ctx.conn, username or None, "login_fail", remote=ctx.remote)
        raise HttpError(401, "Invalid credentials")
    auth.clear_login_failures(ctx.remote)
    hours = int(ctx.cfg.get("session_hours", 0) or 0)
    token = auth.create_session(ctx.conn, username, ctx.remote, hours=hours)
    common.audit(ctx.conn, username, "login", remote=ctx.remote)
    # With the timeout off the server-side session never expires, so the cookie must outlive the
    # browser too - omitting Max-Age would make it a session cookie and close-the-tab would still
    # log him out, which is the behaviour being turned off. Ten years is "not in practice".
    ctx.h.set_cookie = (
        common.COOKIE_NAME + "=%s; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=%d"
        % (token, hours * 3600 if hours > 0 else COOKIE_MAX_AGE_NEVER)
    )
    return {"ok": True, "username": username}


@route("POST", r"/api/logout")
def r_logout(ctx, m):
    auth.destroy_session(ctx.conn, ctx.h.session_token)
    ctx.h.set_cookie = common.COOKIE_NAME + "=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
    return {"ok": True}


@route("GET", r"/api/me")
def r_me(ctx, m):
    return {"username": ctx.user, "scope": ctx.identity.get("scope"),
            "via": ctx.identity.get("via")}


@route("GET", r"/api/stats")
def r_stats(ctx, m):
    c = ctx.conn
    def group(sql):
        return {(r[0] or "unknown"): r[1] for r in c.execute(sql).fetchall()}

    counts = {}
    # payloads is in the list because the dashboard tallies it. The try/except below is what
    # makes that safe on a checkout whose arsenal has never been synced: the table may not exist
    # yet, and a missing arsenal must not take the whole stats endpoint down.
    for tbl in ("programs", "targets", "scopes", "uploads", "payloads"):
        try:
            counts[tbl] = c.execute("SELECT COUNT(*) FROM %s" % tbl).fetchone()[0]
        except Exception:
            counts[tbl] = 0
    # The three badged tiles count through entity_scope(), the same fragment their list endpoint
    # and /api/unseen use, so a tile number, its badge and the page it opens always describe one
    # set of rows. Reports means SUBMITTED reports: the raw table also holds RCAs, follow-up
    # comments and local drafts, which are documents ABOUT a submission rather than submissions,
    # and counting them made the dashboard read 137 when only 111 existed on HackerOne. Leads
    # means leads being worked, not every markdown file under a notes/ directory.
    for name in ("leads", "reports", "advisories"):
        try:
            counts[name] = c.execute(
                "SELECT COUNT(*) FROM %s l WHERE %s"
                % (ENTITIES[name]["table"], entity_scope(name))).fetchone()[0]
        except Exception:
            counts[name] = 0
    # Feed the regression tile's number into `counts` so its sparkline ends on the same figure the
    # tile prints, like every other overview tile. Computed once and reused for the tile below.
    reg = _regression_summary(c, ctx.cfg)
    counts["regression"] = reg.get("due", 0)
    return {
        # 'unknown' is excluded everywhere leads are counted, matching ENTITIES["leads"] above,
        # so the dashboard and the Leads tab never disagree on how many leads exist.
        "leads_by_status": group(
            "SELECT status, COUNT(*) FROM leads WHERE " + LEAD_IS_REAL + " GROUP BY status"),
        "leads_by_target": group(
            "SELECT t.slug, COUNT(*) FROM leads l LEFT JOIN targets t ON t.id=l.target_id"
            " WHERE " + LEAD_IS_REAL_L + " GROUP BY t.slug"),
        # PAID reports bucketed by class - the ones that actually earned money, not every
        # submission. Not a plain GROUP BY: reports that came straight from the API have no
        # local file and so no class, and theirs is derived from the CWE HackerOne assigned.
        # See common.class_for_report and PAID_TO_ME.
        "reports_by_class": _reports_by_class(c),
        # Same PAID_TO_ME filter as reports_by_class, for the same reason: an award is a result,
        # a submission is only an attempt.
        #
        # EVERY PROGRAM, and the program handle is the fallback bucket. A target comes from the
        # directory a local markdown file lives in, so a report that only ever existed in the API
        # has none - which is all five non-ExampleVendor awards. Grouped on t.slug alone they collapsed
        # into 'unknown', which the card omits, so $2000 of confirmed bounty was counted in the
        # money tiles and invisible here. Falling back to the handle keeps every paid report on
        # the card; app.js drills through on whichever kind of key it got.
        "reports_by_target": group(
            "SELECT COALESCE(NULLIF(t.slug,''), NULLIF(l.program,'')), COUNT(*)"
            " FROM reports l LEFT JOIN targets t ON t.id=l.target_id"
            " WHERE l.source='hackerone' AND l.kind='report' AND " + PAID_TO_ME_L
            + " GROUP BY 1"),
        "reports_by_state": group(
            "SELECT state, COUNT(*) FROM reports WHERE source='hackerone' GROUP BY state"),
        "counts": counts,
        # Per-overview-entity cumulative-count series, so each dashboard tile can draw a sparkline
        # of how its figure GREW to the count above. READ-ONLY: SELECTs of a timestamp column and
        # a COUNT, nothing else - no bounty/money column is read or written here. Each series ends
        # on the same number its tile prints (see _overview_sparklines).
        "sparklines": _overview_sparklines(c, counts),
        # The Regression tile: how many shipped fixes are due a look, and how many turned out not
        # to hold. Derived from `reports`, so it costs one extra pass over the resolved rows and
        # cannot fail on a database that has never synced - `summary` returns zeros.
        "regression": reg,
        # The client seeds its "new" watermark from this. Without it the dashboard fell back to
        # the browser clock, which runs on a different machine and in a different format from
        # the indexed_at values the watermark is compared against.
        "now": common.now_iso(),
        # Money and roles, computed the same way the Tracker does it so the two always agree.
        # CAST is safe here because phantom non-numeric values are cleared on sync.
        "bounty": _bounty_stats(c),
    }


def _regression_summary(c, cfg):
    """The dashboard's regression numbers, or zeros. Never raises: the dashboard is the first page
    every session lands on, and one optional tile must not be able to take /api/stats down."""
    if regression_mod is None:
        return {"due": 0, "broken": 0, "total": 0, "available": False}
    try:
        out = regression_mod.summary(c, cfg)
        out["available"] = True
        return out
    except Exception:
        return {"due": 0, "broken": 0, "total": 0, "available": False}


def _reports_by_class(c):
    """{class: count} over SUBMITTED reports, CWE-derived where there is no local class."""
    out = {}
    try:
        rows = c.execute(
            "SELECT class, cwe FROM reports"
            " WHERE source='hackerone' AND kind='report' AND " + PAID_TO_ME).fetchall()
    except Exception:
        return out
    for row in rows:
        key = common.class_for_report(row)
        out[key] = out.get(key, 0) + 1
    return out


#: Report states that mean "still waiting on the program". Everything else - resolved, duplicate,
#: informative, not-applicable, spam - is finished, whether or not it earned anything.
OPEN_REPORT_STATES = ("new", "pending-program-review", "triaged", "needs-more-info")


def _bounty_stats(c):
    def one(sql, default=0):
        try:
            r = c.execute(sql).fetchone()
            return r[0] if r and r[0] is not None else default
        except Exception:
            return default
    base = "FROM reports WHERE source='hackerone'"
    return {
        "reports": one("SELECT COUNT(*) " + base),
        "awards": one("SELECT COUNT(*) " + base + " AND bounty <> ''"),
        "total": round(float(one("SELECT SUM(CAST(bounty AS REAL)) " + base + " AND bounty <> ''")), 2),
        "my_share": round(float(one("SELECT SUM(CAST(my_bounty AS REAL)) " + base + " AND my_bounty <> ''")), 2),
        "splits": one("SELECT COUNT(*) " + base + " AND payout_split <> ''"),
        "as_collaborator": one("SELECT COUNT(*) " + base + " AND my_role='collaborator'"),
        "currency": one("SELECT currency " + base + " AND currency <> '' LIMIT 1", "USD"),
        # STILL LIVE, by naming the open states rather than excluding the closed ones. A state
        # HackerOne adds later would silently count as open under a NOT IN (closed) list, and
        # "open" is the number being read at a glance, so it is the one that must not drift.
        # `resolved` is deliberately closed: it is finished, not outstanding.
        "open": one("SELECT COUNT(*) " + base + " AND state IN (%s)"
                    % ",".join("'%s' " % st for st in OPEN_REPORT_STATES)),
    }


# ---------------------------------------------------------------- dashboard sparklines
# A tiny cumulative-count series per overview entity, drawn as a sparkline under each dashboard
# tile. Everything here is READ-ONLY: a SELECT of one timestamp column and a COUNT. No bounty or
# money column is ever read or written, so the money invariant is untouched. Each series is built
# from the timestamp the entity already carries and is pinned to END on the entity's live count,
# so the last point of the line agrees with the number printed on the tile.
SPARK_POINTS = 12


def _spark_epoch(v):
    """Best-effort epoch (float seconds) for a timestamp cell, or None.

    Cells are either ISO-ish strings ('YYYY-MM-DDTHH:MM:SS', optionally with a trailing Z or an
    offset, or a bare 'YYYY-MM-DD') or epoch floats (a filesystem mtime). The value is only used
    to ORDER and BUCKET rows, so the exact zone does not matter - a consistent parse does.
    """
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if not s:
        return None
    # A bare epoch stored as text (mtime): digits with an optional single dot, no date punctuation.
    if s.replace(".", "", 1).isdigit():
        try:
            return float(s)
        except ValueError:
            return None
    s = s.replace(" ", "T")
    core = s[:19] if len(s) >= 19 and s[10:11] == "T" else s[:10]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(core, fmt).timestamp()
        except ValueError:
            continue
    return None


def _cumulative_series(stamps, total, points=SPARK_POINTS):
    """A non-decreasing series of length `points`, ending EXACTLY at `total`.

    `stamps` is the timestamp of each in-scope row. Rows whose timestamp is missing or unparseable
    are folded into a constant baseline (treated as having existed from the start) so the line
    still ends at `total`. When no row carries a usable timestamp - or every row shares one - the
    series degrades to a smooth monotone ramp up to `total`, so the tile renders a rising line
    rather than a flat one.
    """
    total = int(total or 0)
    if points < 1:
        points = 1
    eps = sorted(e for e in (_spark_epoch(s) for s in stamps) if e is not None)
    if len(eps) < 2 or eps[0] == eps[-1]:
        if total <= 0:
            return [0] * points
        return [int(round(total * (i + 1) / points)) for i in range(points)]
    lo, hi = eps[0], eps[-1]
    span = (hi - lo) or 1.0
    n = len(eps)
    baseline = max(0, total - n)
    out = []
    for i in range(points):
        edge = lo + span * (i + 1) / points
        # Soften the SIGNAL above the undated-row baseline toward an even ramp, so a
        # batch-import burst relaxes into a full-width rise instead of a flat line with
        # a tail spike (the "hockey stick" the mockup never has). Blending only the
        # above-baseline signal keeps the baseline a floor: undated rows still hold the
        # line up from point zero, both terms stay non-decreasing, and it ends at total.
        timed = bisect.bisect_right(eps, edge)
        ramp = n * (i + 1) / points
        out.append(int(round(baseline + 0.5 * timed + 0.5 * ramp)))
    out[-1] = total  # pin the final point to the live count the tile prints
    return out


def _overview_sparklines(c, counts):
    """{entity: [cumulative counts]} for the six dashboard overview tiles. Read-only, and every
    query is wrapped so a missing table (a fresh or payload-only checkout) yields an empty series
    that still renders as a flat baseline rather than taking the whole stats endpoint down."""
    def stamps(sql):
        try:
            return [row[0] for row in c.execute(sql).fetchall()]
        except Exception:
            return []
    out = {}
    # Leads / reports / advisories reuse the SAME scope fragment as their tile count (entity_scope),
    # so the series ends on the exact number the tile prints.
    out["reports"] = _cumulative_series(
        stamps("SELECT COALESCE(submitted_on, first_seen_at, indexed_at) FROM reports l WHERE "
               + entity_scope("reports")),
        counts.get("reports", 0))
    out["leads"] = _cumulative_series(
        stamps("SELECT COALESCE(indexed_at, mtime) FROM leads l WHERE " + entity_scope("leads")),
        counts.get("leads", 0))
    out["advisories"] = _cumulative_series(
        stamps("SELECT COALESCE(published, first_seen_at, indexed_at) FROM advisories l WHERE "
               + entity_scope("advisories")),
        counts.get("advisories", 0))
    out["programs"] = _cumulative_series(
        stamps("SELECT COALESCE(updated_at, synced_at) FROM programs"),
        counts.get("programs", 0))
    # The Targets tile counts SCOPES (see the tiles array in app.js), so its series is over scopes.
    out["scopes"] = _cumulative_series(
        stamps("SELECT synced_at FROM scopes"),
        counts.get("scopes", 0))
    out["payloads"] = _cumulative_series(
        stamps("SELECT indexed_at FROM payloads"),
        counts.get("payloads", 0))
    # The Retests-due tile has no timeline of its own (the queue is derived, not a table), so its
    # line is a smooth ramp to the current due count rather than a reconstructed history. Still a
    # rising line like the others, ending on the exact number the tile prints. Passing real stamps
    # here would be wrong: their count is the resolved-report pool, not the due count, and the two
    # disagreeing makes _cumulative_series non-monotone.
    out["regression"] = _cumulative_series([], counts.get("regression", 0))
    return out


# ---------------------------------------------------------------- entities
# A LEAD is something being worked, not every markdown file under a notes/ directory. Research
# apparatus (CodeQL sweeps, hunt primers, round logs, steering docs) carries no `**Status:**`
# marker and indexes as 'unknown'. It stays on disk and stays in Notes/Files/Search; it just does
# not belong in the lead queue. Two spellings because some queries alias the table and some do not.
# PAID TO ME. `my_bounty`, not `bounty`: on a split those differ, and an award that went
# entirely to a co-reporter is not money I was paid. Empty string and '0' both mean unpaid.
PAID_TO_ME = "COALESCE(my_bounty,'') <> '' AND CAST(my_bounty AS REAL) > 0"
PAID_TO_ME_L = "COALESCE(l.my_bounty,'') <> '' AND CAST(l.my_bounty AS REAL) > 0"

LEAD_IS_REAL = "COALESCE(status,'') <> '' AND status <> 'unknown'"
LEAD_IS_REAL_L = "COALESCE(l.status,'') <> '' AND l.status <> 'unknown'"

ENTITIES = {
    "leads": {
        "table": "leads",
        # A LEAD is something being worked. Everything under a workspace's notes/ directory gets
        # indexed, but most of it is research apparatus - CodeQL sweep logs, hunt primers, round
        # logs, findings tables, steering docs - which is reference material, not a queue item.
        # Those carry no `**Status:**` marker, so they land as 'unknown' and are excluded here.
        #
        # NOT deleted, and the FILES are never touched: they remain in Notes, Files and Search,
        # and adding a status marker to one promotes it straight back into this list.
        "base_where": LEAD_IS_REAL_L,
        "filters": {"target": "t.slug", "class": "l.class", "status": "l.status"},
        "search": ["l.title", "l.ref", "l.body"],
        "editable": ["title", "status", "class", "severity", "body"],
    },
    "reports": {
        "table": "reports",
        # The Tracker is HackerOne-sourced, full stop. Three row types used to leak in and
        # inflate it, so all three are excluded here:
        #   * RCAs and follow-up comments  - share the parent's H1 id, not submissions (kind)
        #   * legacy markdown tracker rows - superseded by the API (tracker_only / source)
        #   * local report drafts with no H1 id - not submitted, so not tracker rows
        # 52 H1 ids were duplicated across the API and markdown rows before this.
        "base_where": "l.kind = 'report' AND l.source = 'hackerone'",
        # NOT in base_where, and not in entity_scope(). The database holds every program's
        # reports, and all of them are reports - the dashboard tile and the "new" badge must go
        # on counting all of them. The Tracker narrowing to one program is a VIEW decision, so it
        # lives here, applied by r_list as a default filter. See PROGRAM_COL below.
        "program_col": "l.program",
        "filters": {"target": "t.slug", "class": "l.class", "status": "l.state"},
        "predicates": {"paid": PAID_TO_ME_L},
        "search": ["l.title", "l.ref", "l.h1_id", "l.body"],
        "editable": ["title", "state", "severity", "bounty", "body"],
    },
    "rcas": {
        "table": "reports",
        "base_where": "l.kind = 'rca'",
        "filters": {"target": "t.slug", "class": "l.class"},
        "search": ["l.title", "l.ref", "l.h1_id", "l.body"],
        "editable": ["title", "body"],
    },
    "advisories": {
        "table": "advisories",
        "filters": {"target": "t.slug", "status": "l.status"},
        "search": ["l.title", "l.ref", "l.body"],
        "editable": ["title", "ref", "source", "url", "published", "status", "body"],
    },
    "programs": {
        "table": "programs",
        "filters": {},
        "search": ["l.name", "l.slug", "l.scope_md"],
        "editable": ["name", "platform", "url", "scope_md", "roe_md"],
        # Computed SELECT aliases (see _entity_select) that ORDER BY must reference bare, not as
        # l.<col>: there is no such column on the programs row, they are subquery results. Both are
        # already numeric, so no CAST is applied.
        "sort_aliases": frozenset(("award_count", "avg_bounty")),
    },
    "targets": {
        "table": "targets",
        "filters": {},
        "search": ["l.name", "l.slug"],
        "editable": ["name", "version", "source_path", "codeql_db"],
    },
    # HackerOne structured scopes. Read-only: HackerOne owns them, `editable` is empty so the
    # PUT route cannot write a single column even if a client asks it to.
    "scopes": {
        "table": "scopes",
        "filters": {"program": "p.slug", "type": "l.asset_type"},
        "search": ["l.identifier", "l.asset_type"],
        "editable": [],
    },
}


# The query-parameter value that opts OUT of the default program scope. Kept identical to
# h1.ALL_PROGRAMS so the CLI flag and the URL say the same word.
ALL_PROGRAMS = "all"
DEFAULT_PRIMARY_PROGRAM = ""


def primary_program():
    """The one program the Tracker shows unless asked otherwise.

    Sourced from the HackerOne credential's `program_handle`, because that is already the answer
    to "which program is this account primarily hunting" - it is what reports are submitted to and
    what weaknesses and scopes resolve against. Deriving it here rather than adding a second
    setting means the Tracker default cannot drift away from the program being worked.

    Falls back to the constant when the module or the credential is missing, so a checkout with
    no secrets.json still gets a deterministic, narrow default rather than every program at once.
    """
    try:
        return (h1_mod.get_credentials()[2] if h1_mod else "") or DEFAULT_PRIMARY_PROGRAM
    except Exception:
        return DEFAULT_PRIMARY_PROGRAM


def entity_scope(name):
    """The WHERE fragment defining which rows an entity CONSISTS OF, aliased `l`.

    One definition for the list, the dashboard tile and the "new" badge. When those were three
    separate literals they drifted, and a badge counted rows no tile could show. Entities with no
    `base_where` (advisories) are the whole table, so the fragment is a true constant.
    """
    return ENTITIES[name].get("base_where") or "1=1"


def _entity_select(name):
    """Base SELECT for an entity. `base_where` lets two entities share one table (reports/rcas)."""
    spec = ENTITIES[name]
    if spec["table"] in ("programs",):
        # Awards and the average award value are computed from `reports` so the Programs list can
        # show the n / mean / sum triplet: award_count x avg_bounty = bounty_earned. A VDP report
        # resolved with no money still carries bounty '0' (not ''), so it counts as an award - the
        # SAME predicate the money invariant uses, so these counts sum to it exactly. avg_bounty is
        # NULL, not 0, when a program has no awards, so the column shows a dash rather than $0.00.
        awards_sub = ("(SELECT COUNT(*) FROM reports r WHERE r.program = l.slug"
                      " AND r.source = 'hackerone' AND r.bounty <> '')")
        base = ("SELECT l.*, %s AS award_count,"
                " CASE WHEN %s > 0 THEN CAST(l.bounty_earned AS REAL) / %s ELSE NULL END"
                " AS avg_bounty FROM programs l" % (awards_sub, awards_sub, awards_sub))
    elif spec["table"] in ("targets", "scopes"):
        base = ("SELECT l.*, p.slug AS program, p.name AS program_name FROM %s l"
                " LEFT JOIN programs p ON p.id=l.program_id" % spec["table"])
    else:
        # The program reaches a lead through its target, so the join is two hops. Leads carry no
        # program column of their own: a lead belongs to whatever target owns its workspace, and
        # duplicating that on the row would be a second copy to keep in step.
        base = ("SELECT l.*, t.slug AS target, tp.slug AS program_slug, tp.name AS program_name"
                " FROM %s l LEFT JOIN targets t ON t.id = l.target_id"
                " LEFT JOIN programs tp ON tp.id = t.program_id" % spec["table"])
    return base, spec


@route("GET", r"/api/(leads|reports|rcas|advisories|programs|targets|scopes)")
def r_list(ctx, m):
    name = m.group(1)
    base, spec = _entity_select(name)
    where, params = [], []
    if spec.get("base_where"):
        where.append(spec["base_where"])
    # PROGRAM SCOPE. This used to default to primary_program(), on the reasoning that the Tracker
    # is the working list for ONE hunt. That stopped being true once a second program was
    # onboarded: a report filed against ExampleVendor simply did not appear, which reads as a lost
    # report rather than a filtered view. The default is now every program, and the picker in the
    # filter bar narrows it. `all` is explicit; any other value picks one handle.
    scope = None
    if spec.get("program_col"):
        # Handles are lowercase on HackerOne, so a hand-typed URL is folded rather than refused.
        scope = (ctx.q("program") or "").strip().lower() or ALL_PROGRAMS
        if scope != ALL_PROGRAMS:
            where.append("%s = ?" % spec["program_col"])
            params.append(scope)
    for key, col in spec["filters"].items():
        val = ctx.q(key)
        if val:
            where.append("%s = ?" % col)
            params.append(val)
    # `paid=1` is a predicate, not a column comparison, so it cannot live in spec["filters"].
    # It means MONEY REACHED ME: my_bounty, not bounty. On a split those differ, and a report
    # where a co-reporter took the whole award is not one I was paid for.
    for key, clause in (spec.get("predicates") or {}).items():
        if ctx.q(key):
            where.append(clause)
    q = ctx.q("q")
    if q:
        cols = spec["search"]
        where.append("(" + " OR ".join("%s LIKE ?" % c for c in cols) + ")")
        params.extend(["%" + q + "%"] * len(cols))
    sql = base + (" WHERE " + " AND ".join(where) if where else "")

    total = ctx.conn.execute(
        "SELECT COUNT(*) FROM (" + sql + ")", params).fetchone()[0]

    # Columns holding a number in a TEXT column. Sorting these as strings is the defect this
    # guards: SQLite compares '750.0' against '[amount]' character by character and puts the
    # smaller amount first.
    NUMERIC_TEXT_COLUMNS = frozenset((
        "bounty_earned", "bounty", "my_bounty", "expected_bounty", "h1_id", "entity_id",
    ))

    # Every sort gets a deterministic tiebreak. Without one, the Tracker's default
    # `-submitted_on` cannot separate two reports filed the same day: HackerOne's created_at is
    # truncated to a date on the way in, so a second report filed today ties with the first and
    # SQLite returns the pair in whatever order it likes. A report number is issued in submission
    # order, so it breaks the tie the way a human expects. Compared numerically because h1_id is
    # TEXT and '999' sorts above '3907102' as a string.
    tiebreak = "CAST(l.h1_id AS INTEGER) DESC" if spec["table"] == "reports" else "l.id DESC"
    sort = ctx.q("sort", "")
    order = " ORDER BY " + tiebreak
    if sort:
        col = re.sub(r"[^a-zA-Z_]", "", sort.lstrip("-"))
        if col:
            # Money is stored as TEXT, so a plain ORDER BY compares it lexically and '750.0' sorts
            # above '[amount]' - the Programs tab listed a [amount] program ahead of a [amount] one. The
            # tiebreak two lines up already casts h1_id for exactly this reason; the money columns
            # need the same. CAST of a non-numeric string is 0 in SQLite, which sorts an unparseable
            # value low rather than throwing.
            if col in (spec.get("sort_aliases") or ()):
                # A computed SELECT alias (Programs' award_count / avg_bounty). It is a top-level
                # result column, so it is referenced bare - `l.award_count` is not a real column.
                expr = col
            elif col in NUMERIC_TEXT_COLUMNS:
                expr = "CAST(l.%s AS REAL)" % col
            else:
                expr = "l.%s" % col
            order = " ORDER BY %s %s, %s" % (
                expr, "DESC" if sort.startswith("-") else "ASC", tiebreak)
    try:
        limit = max(1, min(500, int(ctx.q("limit", 100))))
        offset = max(0, int(ctx.q("offset", 0)))
    except ValueError:
        limit, offset = 100, 0

    rows = ctx.conn.execute(sql + order + " LIMIT ? OFFSET ?",
                            params + [limit, offset]).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        body = d.get("body") or d.get("scope_md") or ""
        # The workspace a lead lives in is not the asset the finding is against: four ExampleVendor
        # drivers share one workspace and therefore one `targets` row, while each driver is its
        # own HackerOne scope. The lead's `Target` header row says which, and here is the only
        # place it can be read - `body` is popped below and the excerpt stops well short of it.
        if spec["table"] == "leads":
            d["asset_label"] = lead_asset(body)
            d["lead_user"] = lead_researcher(body)
        elif d.get("asset"):
            d["asset_label"] = short_asset(d["asset"])
        d["excerpt"] = (body[:280] + "...") if len(body) > 280 else body
        d.pop("body", None)
        d.pop("scope_md", None)
        d.pop("roe_md", None)
        # The API policy is a full guidelines document, routinely tens of kilobytes. It belongs
        # in the detail pane, not in every row of an 18-program list.
        d.pop("policy_md", None)
        # Same decoding the detail pane gets, so a list COLUMN can show privileges-required or
        # impact without the browser having to parse CVSS vectors itself. One implementation,
        # in Python, where it is testable.
        if advisories_mod and d.get("cvss_vector"):
            try:
                d["cvss_decoded"] = advisories_mod.decode_cvss_vector(d["cvss_vector"])
            except Exception:
                pass
        items.append(d)
    out = {"items": items, "total": total}
    # Say which program scope was actually applied. The client cannot work it out: the default
    # comes from a credential it is never allowed to read, and a list that silently hides 35 rows
    # has to be able to say so.
    if scope is not None:
        out["program_scope"] = scope
    return out


@route("GET", r"/api/(leads|reports|rcas|advisories|programs|targets|scopes)/(\d+)")
def r_get(ctx, m):
    name, rid = m.group(1), int(m.group(2))
    base, spec = _entity_select(name)
    sql = base + " WHERE l.id = ?"
    if spec.get("base_where"):
        sql += " AND " + spec["base_where"]
    row = ctx.conn.execute(sql, (rid,)).fetchone()
    if not row:
        raise HttpError(404, "Not found")
    out = dict(row)
    # Same normalisation the list applies. Without it the detail pane fell back to parsing the
    # body in the browser and printed the whole `Target` row, lab conditions and all.
    if spec["table"] == "leads":
        out["asset_label"] = lead_asset(out.get("body") or "")
        out["lead_user"] = lead_researcher(out.get("body") or "")
    elif out.get("asset"):
        out["asset_label"] = short_asset(out["asset"])
    owner = retest_owner(out)
    if owner:
        out["retest_owner"] = owner
    # Detail panes show a CVSS vector in words, not as the raw run-on string. Decoding here
    # keeps one implementation for advisories and reports; the raw vector stays in the payload
    # so the UI can still expose it as a tooltip.
    if advisories_mod and out.get("cvss_vector"):
        try:
            out["cvss_decoded"] = advisories_mod.decode_cvss_vector(out["cvss_vector"])
        except Exception:
            pass
    return out


def _target_workspace(conn, target_slug):
    row = conn.execute("SELECT workspace FROM targets WHERE slug = ?", (target_slug,)).fetchone()
    return row["workspace"] if row else None


def _target_id(conn, target_slug):
    row = conn.execute("SELECT id FROM targets WHERE slug = ?", (target_slug,)).fetchone()
    return row["id"] if row else None


@route("POST", r"/api/(leads|reports|advisories)", scope="write")
def r_create(ctx, m):
    name = m.group(1)
    b = ctx.body or {}
    title = (b.get("title") or "").strip()
    if not title:
        raise HttpError(400, "title is required")
    body = b.get("body") or ""
    target = b.get("target")
    klass = b.get("class") or ("INTEGRITY" if name == "advisories" else None)

    ws = _target_workspace(ctx.conn, target) if target else None
    if not ws:
        raise HttpError(400, "unknown or missing target; create the workspace first")

    sub = {"leads": "notes", "reports": "reports", "advisories": "notes"}[name]
    folder = os.path.join(ws, klass, sub) if klass else os.path.join(ws, sub)
    fname = b.get("filename") or (common.slugify(title) + ".md")
    if not fname.endswith(".md"):
        fname += ".md"
    dest = common.safe_under(ws, os.path.join(folder, fname))
    if not dest:
        raise HttpError(400, "resolved path escapes the workspace")
    if os.path.exists(dest):
        raise HttpError(409, "file already exists: " + dest)

    if not body.lstrip().startswith("#"):
        body = "# %s\n\n%s" % (title, body)
    common.write_text_atomic(dest, body)
    _reindex(ctx.conn, dest)
    common.audit(ctx.conn, ctx.user, "create", name, None, dest, ctx.remote)

    base, _ = _entity_select(name)
    row = ctx.conn.execute(base + " WHERE l.file_path = ?", (dest,)).fetchone()
    return dict(row) if row else {"ok": True, "file_path": dest}


@route("PUT", r"/api/(leads|reports|rcas|advisories|programs|targets)/(\d+)", scope="write")
def r_update(ctx, m):
    name, rid = m.group(1), int(m.group(2))
    spec = ENTITIES[name]
    b = ctx.body or {}
    row = ctx.conn.execute("SELECT * FROM %s WHERE id = ?" % spec["table"], (rid,)).fetchone()
    if not row:
        raise HttpError(404, "Not found")
    row = dict(row)

    # Files are the source of truth: if this row has a backing file and the caller sent a body,
    # write the file first, then re-index. Never update the DB row directly for file-backed rows.
    fp = row.get("file_path")
    if fp and "body" in b:
        target_path = common.safe_under(common.HUNT_ROOT, fp)
        if not target_path:
            raise HttpError(400, "file_path escapes the hunt root")
        common.write_text_atomic(target_path, b["body"])
        _reindex(ctx.conn, target_path)
        common.audit(ctx.conn, ctx.user, "update", name, rid, target_path, ctx.remote)
        base, _ = _entity_select(name)
        out = ctx.conn.execute(base + " WHERE l.file_path = ?", (target_path,)).fetchone()
        return dict(out) if out else {"ok": True}

    sets, params = [], []
    for col in spec["editable"]:
        if col in b:
            sets.append("%s = ?" % col)
            params.append(b[col])
    if not sets:
        raise HttpError(400, "nothing to update")
    params.append(rid)
    ctx.conn.execute("UPDATE %s SET %s WHERE id = ?" % (spec["table"], ", ".join(sets)), params)
    ctx.conn.commit()
    common.audit(ctx.conn, ctx.user, "update", name, rid, ",".join(spec["editable"]), ctx.remote)
    base, _ = _entity_select(name)
    return dict(ctx.conn.execute(base + " WHERE l.id = ?", (rid,)).fetchone())


# ---------------------------------------------------------------- working a lead
# What a caller may SET, which is deliberately narrower than what ingest can PARSE: `unknown` is
# where an unmarked note lands and must never be settable, or a real lead could be pushed into the
# bucket the Leads list filters out. Mirrors ingest.PICKER_STATUSES, which the smoke suite asserts.
# Spelled out rather than aliased to ingest.PICKER_STATUSES, because `ingest` imports under a
# try/except and can be None on a partial checkout - a whitelist that evaluates to None would make
# every status write a 500. The smoke suite asserts the two tuples agree.
STATUS_VALUES = ("open", "confirmed", "ready", "submitted", "awarded", "parked", "killed")

#: `| **Target** | example-connector-nodejs (npm `example-sdk`) 3.1.0, current release |`
LEAD_TARGET_ROW_RE = re.compile(r"^\|\s*\*\*Target\*\*\s*\|\s*(.+?)\s*\|\s*$", re.M)
# The `Researcher` row of the lead header table. The colon is optional because leads carry it both
# ways in the wild (`**Researcher**` and `**Researcher:**`); case-insensitive for the same reason.
LEAD_RESEARCHER_ROW_RE = re.compile(
    r"^\|\s*\*\*Researcher:?\*\*\s*\|\s*(.+?)\s*\|\s*$", re.M | re.I)

#: A lead states its target in prose - package, version, and often the lab conditions, e.g.
#: "example-connector-python 4.7.1 (PyPI) against a hostile listener on <lab-host>:9443".
#: A table column needs the HackerOne ASSET instead, because that is what the report is filed
#: against and what a reader is deciding about. Longest match wins, so `example-connector-net`
#: cannot be claimed by a shorter `example` key.
ASSET_ALIASES = (
    ("example-connector-python", "Python Connector"),
    ("example-connector-nodejs", "NodeJS Driver"),
    ("example-sdk", "NodeJS Driver"),
    ("example-connector-net", ".NET Driver"),
    ("example.data", ".NET Driver"),
    ("example-go-driver", "Golang Driver"),
    ("example-jdbc", "JDBC Driver"),
    ("terraform-provider-example", "Terraform Provider"),
    ("example-app", "ExampleApp"),
    ("ExampleProduct", "ExampleProduct"),
    ("ExamplePipeline", "ExamplePipeline"),
    ("ExampleApp", "ExampleApp"),
)


#: Who runs a retest. HackerOne's own report page says "No action required. HackerOne Triage will
#: retest this report" while a report sits in `retesting`, but that sentence is UI CHROME and is
#: NOT in the API payload - verified against #0000000, whose thread carries only the state change
#: and "A fix has been deployed to remediate the vulnerability". So the default is that HackerOne
#: retests, matching what the page says, and we only claim it for ourselves when a human has
#: explicitly asked us to verify. Guessing the other way round would put a permanent false
#: to-do on the Tracker for every retest the program handles itself.
US_RETESTS_RE = re.compile(
    r"(please|could you|can you|would you)[^.?!]{0,60}"
    r"(retest|re-test|verify|confirm)[^.?!]{0,60}(fix|patch|remediat|resolv)"
    r"|(retest|re-test|verify)[^.?!]{0,40}\bon your (end|side)\b",
    re.I)


def retest_owner(row):
    """'hackerone', 'us', or None when the report is not being retested.

    A report in `retesting` is the one Tracker state that can sit still while waiting on US, so
    which of the two it is has to be visible rather than inferred each time it is looked at.
    """
    if (row.get("h1_state") or row.get("state") or "").lower() != "retesting":
        return None
    return "us" if US_RETESTS_RE.search(row.get("thread") or "") else "hackerone"


def short_asset(value):
    """A HackerOne asset identifier as a SHORT label for a table cell.

    The API returns whatever the program registered, and for a `SOURCE_CODE` scope that is a whole
    repository URL - `https://github.com/example-org/example-repo` in a column two words wide. The
    identifier is still the authority and is unchanged in the database; this is display only.

    Order matters: an alias wins first, so `example-connector-python` stays `Python Connector`
    rather than becoming the bare repo name. Anything we have no alias for falls back to the last
    meaningful path segment, which is the repository or product name in every form seen so far.
    A wildcard or bare hostname is already short and is returned untouched.
    """
    raw = (value or "").strip()
    if not raw:
        return None
    low = raw.lower()
    for key, label in ASSET_ALIASES:
        if key in low:
            return label
    if "://" not in low:
        return raw                       # '*.example.com', 'Some Product' - already short
    path = raw.split("://", 1)[1]
    host, _, rest = path.partition("/")
    segs = [s for s in rest.split("/") if s and s not in ("tree", "blob", "master", "main")]
    return segs[-1] if segs else host


def lead_asset(body):
    """The HackerOne asset a lead's `Target` row names, as a short label, or None.

    Falls back to the first clause of the row, cut at a comma or an ` against `, so a target we
    have no alias for still reads as something short rather than spilling the lab conditions
    into a table cell.
    """
    if not body:
        return None
    m = LEAD_TARGET_ROW_RE.search(body)
    if not m:
        return None
    stated = m.group(1)
    low = stated.lower()
    # EARLIEST mention wins, longest key breaking a tie at the same position. A ExampleApp lead whose
    # row reads "ExampleApp 9.4.4 with ExampleProduct 9.4.4" names its own target first; ranking by key
    # length alone handed it to ExampleProduct. The tie-break still stops a bare `example` from
    # claiming `example-connector-net`.
    best = None
    for key, label in ASSET_ALIASES:
        at = low.find(key)
        if at < 0:
            continue
        rank = (at, -len(key))
        if best is None or rank < best[0]:
            best = (rank, label)
    if best:
        return best[1]
    head = re.split(r",| against | @ | on ", stated)[0].replace("`", "").strip()
    if len(head) > 30:
        # Cut on a word boundary. "ExampleVendor hosted test accounts <" reads as a truncation bug.
        head = head[:30].rsplit(" ", 1)[0]
    return head or None


def lead_researcher(body):
    """The researcher a lead's header table names in its `Researcher` row, or None.

    This is lead-level attribution: a lead authored by a collaborator carries their handle here, so
    the detail pane can show whose lead it is beside Indexed. Parsed in Python, like lead_asset,
    rather than in the browser. Returns None when the row is absent - most leads are the operator's
    own and simply do not name a researcher, which is not the same as an empty one.
    """
    if not body:
        return None
    m = LEAD_RESEARCHER_ROW_RE.search(body)
    if not m:
        return None
    val = m.group(1).replace("`", "").strip()
    return val or None


def _file_backed_row(conn, entity, rid):
    spec = ENTITIES[entity]
    row = conn.execute("SELECT * FROM %s WHERE id = ?" % spec["table"], (rid,)).fetchone()
    if not row:
        raise HttpError(404, "Not found")
    row = dict(row)
    fp = row.get("file_path")
    if not fp:
        raise HttpError(409, "this row has no backing file, so it cannot be worked in place")
    resolved = common.safe_under(common.HUNT_ROOT, fp)
    if not resolved or not os.path.isfile(resolved):
        raise HttpError(409, "backing file is missing: %s" % fp)
    return row, resolved


def _set_status_marker(text, status):
    """Insert or update the `**Status:**` line, immediately after the H1 header.

    Chosen over rewriting the header line because the header carries the title and date and is
    prose - editing it programmatically would mangle notes. The marker is a single line the
    parser looks for first, so this is a lossless, repeatable edit.
    """
    marker = "**Status:** %s" % status
    lines = (text or "").splitlines()
    for i, line in enumerate(lines[:25]):
        # Matches a marker carrying detail too ("SUBMITTED H1 #0000000 (2026-08-01, ...)"), which
        # the anchored version did not: on a filed lead it found nothing and inserted a SECOND
        # marker line above the first. The detail is dropped rather than preserved, because it
        # described the status being replaced - a report id on a lead just moved to `killed` is
        # worse than no detail at all.
        # A table-form header carries the marker as `| **Status:** | submitted |`. Replacing that
        # whole line with a bare marker would punch a hole in the table and orphan every row under
        # it, so a row is rewritten AS a row and only the value cell changes.
        if re.match(r"^\s*\|\s*\*\*Status:?\*\*:?\s*\|", line):
            lines[i] = "| **Status:** | %s |" % status
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        if re.match(r"^\s*\*\*Status:\*\*\s*[A-Za-z]+\b.*$", line):
            lines[i] = marker
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    insert_at = 0
    for i, line in enumerate(lines[:5]):
        if line.lstrip().startswith("#"):
            insert_at = i + 1
            break
    lines.insert(insert_at, "")
    lines.insert(insert_at + 1, marker)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _sync_lead_title_inplace(conn, row, path):
    """Rewrite a lead's title to its draft report's title. Returns the new title, or None.

    Shared by the explicit sync-title action and the automatic sync on a status change, so the
    safety checks cannot drift apart. Returns None whenever there is nothing to do or nothing safe
    to do - a missing draft is normal at the moment a lead is confirmed and is not an error.
    """
    ref = (row.get("ref") or "").strip()
    report_path = _find_draft_report(path, ref)
    if not report_path:
        return None
    try:
        with open(report_path, "r", encoding="utf-8") as fh:
            report_title = _report_title(fh.read())
        if not report_title:
            return None
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        updated, _heading = _apply_lead_title(text, ref, report_title)
    except (OSError, ValueError):
        return None
    if updated == text:
        return None
    # Same belt and braces as the explicit action: a rewrite that lost the status marker, or moved
    # it past the 25 lines ingest reads, would drop the lead out of the queue while still looking
    # statused on disk.
    if ingest is not None and (ingest.parse_status_marker(updated)
                               != ingest.parse_status_marker(text)):
        return None
    common.write_text_atomic(path, updated)
    return report_title


@route("POST", r"/api/(leads|reports|advisories)/(\d+)/status", scope="write")
def r_set_status(ctx, m):
    """Change status without opening the editor. Writes the file, then re-indexes."""
    entity, rid = m.group(1), int(m.group(2))
    status = ((ctx.body or {}).get("status") or "").strip().lower()
    if entity == "leads" and status not in STATUS_VALUES:
        raise HttpError(400, "status must be one of: %s" % ", ".join(STATUS_VALUES))
    if not status:
        raise HttpError(400, "status is required")

    row, path = _file_backed_row(ctx.conn, entity, rid)
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    updated = _set_status_marker(text, status)
    if updated != text:
        common.write_text_atomic(path, updated)

    # The MOMENT a lead becomes drafted, its title becomes the report's. Seth monitors the pipeline
    # from another machine and a lead still carrying its working name reads as a different finding
    # from the report it produced - that ambiguity once nearly caused a wrong call about shipping.
    # Automatic here rather than a button, because the lag was the whole complaint. A missing draft
    # is normal at this instant and is silently no-op rather than an error.
    synced = None
    if entity == "leads" and status in TITLE_SYNC_STATUSES:
        fresh = dict(row)
        fresh["status"] = status
        synced = _sync_lead_title_inplace(ctx.conn, fresh, path)

    _reindex(ctx.conn, path)
    common.audit(ctx.conn, ctx.user, "status", entity, rid,
                 "%s -> %s%s" % (row.get("status") or row.get("state"), status,
                                 (", title synced to %r" % synced) if synced else ""), ctx.remote)
    base, _ = _entity_select(entity)
    out = ctx.conn.execute(base + " WHERE l.id = ?", (rid,)).fetchone()
    res = dict(out) if out else {"ok": True, "status": status}
    if synced:
        res["title_synced"] = synced
    return res


@route("POST", r"/api/(leads|reports|advisories)/(\d+)/append", scope="write")
def r_append_note(ctx, m):
    """Append a timestamped worklog entry to the note.

    Appending rather than replacing matters during a hunt: it is safe to fire off mid-test
    without first loading the whole document, and it cannot clobber anything already written.
    """
    entity, rid = m.group(1), int(m.group(2))
    text_in = ((ctx.body or {}).get("text") or "").rstrip()
    if not text_in.strip():
        raise HttpError(400, "text is required")
    heading = ((ctx.body or {}).get("heading") or "").strip()

    row, path = _file_backed_row(ctx.conn, entity, rid)
    with open(path, "r", encoding="utf-8") as fh:
        existing = fh.read()

    stamp = time.strftime("%Y-%m-%d %H:%M")
    title = heading or "Worklog %s" % stamp
    block = "\n\n## %s\n\n%s\n" % (title, text_in)
    if not existing.endswith("\n"):
        block = "\n" + block
    common.write_text_atomic(path, existing + block)
    _reindex(ctx.conn, path)
    common.audit(ctx.conn, ctx.user, "append", entity, rid, title, ctx.remote)
    base, _ = _entity_select(entity)
    out = ctx.conn.execute(base + " WHERE l.id = ?", (rid,)).fetchone()
    return dict(out) if out else {"ok": True}


#: A lead's header may name its draft explicitly. Both the bare and the table-row forms are
#: matched, since the header block became a table on 2026-08-02 and older leads still carry lines.
REPORT_ROW_RE = re.compile(
    r"^\s*\|?\s*\*\*Report:?\*\*:?\s*\|?\s*`?([^`|\n]+?)`?\s*\|?\s*$", re.M | re.I)


def _find_draft_report(lead_path, ref):
    """Resolve the draft report belonging to a lead. Returns an absolute path, or None.

    Two ways, in order of authority. An explicit `Report` row in the lead header wins, because a
    human wrote it and it survives renaming. Otherwise the convention is used: reports live in the
    workspace's `reports/` directory beside `notes/`, named `<REF>-<slug>.md` before submission and
    `<h1_id>_<REF>-<slug>.md` after it, so the newest match on the ref is the current one.

    Every candidate is re-checked with `safe_under` against the lead's own workspace. A `Report`
    row is note content, and note content is not trusted to address the filesystem.
    """
    if not lead_path or not os.path.isfile(lead_path):
        return None
    notes_dir = os.path.dirname(lead_path)
    workspace = os.path.dirname(notes_dir)          # <workspace>/<CLASS>
    reports_dir = os.path.join(workspace, "reports")

    try:
        with open(lead_path, "r", encoding="utf-8") as fh:
            head = "".join(fh.readlines()[:30])
    except OSError:
        head = ""
    m = REPORT_ROW_RE.search(head)
    if m:
        named = m.group(1).strip()
        cand = named if os.path.isabs(named) else os.path.join(notes_dir, named)
        cand = common.safe_under(workspace, cand)
        if cand and os.path.isfile(cand):
            return cand

    if not ref or not os.path.isdir(reports_dir):
        return None
    hits = []
    for name in os.listdir(reports_dir):
        if not name.endswith(".md"):
            continue
        stem = name[:-3]
        # `<REF>-slug` unsubmitted, or `<h1id>_<REF>-slug` once filed.
        if stem.startswith(ref + "-") or re.match(r"^\d+_%s-" % re.escape(ref), stem):
            full = common.safe_under(workspace, os.path.join(reports_dir, name))
            if full and os.path.isfile(full):
                hits.append(full)
    if not hits:
        return None
    # A submitted draft is renamed to carry its H1 id, so the most recently modified file is the
    # live one rather than a stale pre-submission copy left beside it.
    hits.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return hits[0]


# ---------------------------------------------------------------- lead title <- report title
# Once a lead is drafted, the REPORT's title is the authority: it is the sentence that appears on
# HackerOne, and a Leads tab disagreeing with it has twice made a lead look like a different
# finding from its own draft. The lead keeps its `<REF> - ` prefix, because that prefix is the
# join between a lead, its report file and the H1 id, and `common.REF_RE` parses it off the front.
#
# Only these statuses carry a drafted report. Before `confirmed` there is nothing to copy a title
# from, and a `killed` lead's title should stay whatever the kill was written against.
TITLE_SYNC_STATUSES = ("confirmed", "ready", "submitted", "awarded")

#: The lead's own H1 line. `#` and exactly one space, so a `##` section heading can never match.
LEAD_H1_RE = re.compile(r"^\s*#\s+\S")


def _report_title(text):
    """The report's own title line, cleaned. None when the file carries no heading.

    Deliberately the same two helpers ingest uses, so a synced lead title is character-for-
    character what the index already shows against the report row. There is NO filename fallback
    here: ingest guesses a title from the slug when a report has no heading, and a guess is not
    something to write into another file.
    """
    if ingest is None:
        return None
    head = ingest._first_heading(text or "")
    if not head:
        return None
    title = ingest._clean_title(head)
    # A report title is a bare sentence (REPORT_STANDARD.md). If one carries a ref prefix anyway,
    # strip it rather than emitting `# F49 - F49 - ...`.
    m = common.REF_RE.match(title)
    if m:
        title = ingest._clean_title(title[m.end():])
    title = " ".join(title.split())
    return title or None


def _lead_heading(ref, report_title):
    """The heading a drafted lead should carry: `# <REF> - <report title>`."""
    return "# %s - %s" % (ref, report_title)


def _apply_lead_title(text, ref, report_title):
    """Rewrite the lead's H1 to carry the report's title. Returns (new_text, heading).

    Raises ValueError when the file is not shaped like a lead, which is the safe outcome: this
    edits irreplaceable research markdown, so anything unexpected declines rather than guesses.

    The heading LINE IS REPLACED IN PLACE - never inserted, never split - so every line below it
    keeps its number and the `**Status:**` marker stays inside the 25 lines ingest reads. That is
    the property that makes this safe to run against a live lead, and it is checked again by the
    caller before anything is written.
    """
    ref = (ref or "").strip()
    report_title = " ".join((report_title or "").split())
    if not ref:
        raise ValueError("the lead carries no ref, so the join to its report cannot be preserved")
    if not report_title:
        raise ValueError("the report has no title line to copy")
    lines = (text or "").splitlines()
    for i, line in enumerate(lines[:25]):
        if not LEAD_H1_RE.match(line):
            continue
        m = common.REF_RE.match(line.strip())        # REF_RE eats the leading `#` itself
        if not m or m.group(1) != ref:
            raise ValueError("the lead heading does not open with %s" % ref)
        heading = _lead_heading(ref, report_title)
        if lines[i] == heading:
            return text, heading                      # already synced; idempotent by construction
        lines[i] = heading
        return "\n".join(lines) + ("\n" if (text or "").endswith("\n") else ""), heading
    raise ValueError("the lead has no `# <REF> - ...` heading in its first 25 lines")


@route("GET", r"/api/leads/(\d+)/report")
def r_lead_report(ctx, m):
    """The draft report belonging to a lead, as text, for the Copy report button.

    Read-only and scoped to the lead's own workspace. Returns `found: false` rather than 404 when
    there is no draft, because "this lead has no report yet" is a normal state the UI renders, not
    an error worth a red toast.

    It also answers whether the lead's title matches the report's, which is what puts the Sync
    title control in front of Seth at the moment he is looking at the two documents.
    """
    rid = int(m.group(1))
    base, _ = _entity_select("leads")
    row = ctx.conn.execute(base + " WHERE l.id = ?", (rid,)).fetchone()
    if not row:
        raise HttpError(404, "no such lead")
    row = dict(row)
    ref = (row.get("ref") or "").strip()
    path = _find_draft_report(row.get("file_path"), ref)
    if not path:
        return {"found": False, "lead_id": rid, "ref": ref}
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    rtitle = _report_title(text)
    lead_title = " ".join((row.get("title") or "").split())
    return {"found": True, "lead_id": rid, "ref": ref,
            "path": path, "name": os.path.basename(path),
            "bytes": len(text.encode("utf-8")), "text": text,
            "lead_title": lead_title, "report_title": rtitle or "",
            "title_synced": (lead_title == rtitle) if rtitle else None,
            "title_syncable": row.get("status") in TITLE_SYNC_STATUSES}


@route("POST", r"/api/leads/(\d+)/sync-title", scope="write")
def r_sync_lead_title(ctx, m):
    """Rewrite a drafted lead's title to its report's title, keeping the `<REF> - ` prefix.

    Explicit rather than automatic. Ingest could derive this at index time and it would always be
    true, but ingest has never opened a workspace file for writing and that property is worth more
    than the convenience: an indexer that rewrites research markdown turns every re-index into an
    edit, with no one having asked for one. So this is an action - a button, and a documented step
    in the staging gate - and it touches exactly the one lead it is called on.
    """
    rid = int(m.group(1))
    row, path = _file_backed_row(ctx.conn, "leads", rid)
    status = (row.get("status") or "").strip().lower()
    if status not in TITLE_SYNC_STATUSES:
        raise HttpError(409, "a %s lead has no drafted report to take a title from; this applies"
                             " from %s onwards" % (status or "statusless",
                                                   ", ".join(TITLE_SYNC_STATUSES)))
    report_path = _find_draft_report(path, (row.get("ref") or "").strip())
    if not report_path:
        raise HttpError(409, "no draft report found for this lead")
    with open(report_path, "r", encoding="utf-8") as fh:
        report_title = _report_title(fh.read())
    if not report_title:
        raise HttpError(409, "the draft report has no title line to copy")

    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        updated, heading = _apply_lead_title(text, (row.get("ref") or "").strip(), report_title)
    except ValueError as exc:
        raise HttpError(409, str(exc))

    changed = updated != text
    if changed:
        # Belt and braces on irreplaceable markdown: a rewrite that lost the status marker, or
        # moved it out of the 25 lines ingest reads, would drop the lead out of the queue while
        # still looking statused on disk. Refuse rather than write.
        if ingest is not None and (ingest.parse_status_marker(updated)
                                   != ingest.parse_status_marker(text)):
            raise HttpError(500, "refusing to write: the status marker would not survive")
        common.write_text_atomic(path, updated)
        _reindex(ctx.conn, path)
        common.audit(ctx.conn, ctx.user, "sync-title", "leads", rid,
                     "%s -> %s" % (row.get("title") or "", report_title), ctx.remote)

    base, _ = _entity_select("leads")
    out = ctx.conn.execute(base + " WHERE l.id = ?", (rid,)).fetchone()
    return {"ok": True, "changed": changed, "heading": heading,
            "title": report_title, "report": os.path.basename(report_path),
            "lead": dict(out) if out else None}


@route("GET", r"/api/queue")
def r_queue(ctx, m):
    """The actionable hunt queue: open and confirmed leads, oldest-touched first.

    Ordering is deliberate - the lead you have not touched in longest is the one most likely to
    be forgotten, so it surfaces at the top rather than the most recently edited.
    """
    try:
        limit = max(1, min(200, int(ctx.q("limit", 50))))
    except ValueError:
        limit = 50
    statuses = (ctx.q("status") or "open,confirmed").split(",")
    statuses = [s.strip() for s in statuses if s.strip()]
    placeholders = ",".join("?" for _ in statuses) or "''"
    rows = ctx.conn.execute(
        "SELECT l.id, l.ref, l.title, l.status, l.class, l.severity, l.mtime, l.file_path,"
        " t.slug AS target FROM leads l LEFT JOIN targets t ON t.id = l.target_id"
        " WHERE l.status IN (%s) ORDER BY COALESCE(l.mtime, 0) ASC LIMIT ?" % placeholders,
        statuses + [limit]).fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows), "statuses": statuses}


# ---------------------------------------------------------------- search
@route("GET", r"/api/search")
def r_search(ctx, m):
    q = (ctx.q("q") or "").strip()
    if not q:
        return {"items": []}
    kind = ctx.q("kind")
    try:
        limit = max(1, min(200, int(ctx.q("limit", 50))))
    except ValueError:
        limit = 50
    sql = ("SELECT kind, rowid_ref, ref, title, target,"
           " snippet(search_fts, 4, '<<', '>>', '...', 18) AS snippet,"
           " bm25(search_fts) AS score FROM search_fts WHERE search_fts MATCH ?")
    params = [q]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    sql += " ORDER BY score LIMIT ?"
    params.append(limit)
    try:
        rows = ctx.conn.execute(sql, params).fetchall()
    except Exception:
        # The raw string is FTS5 query syntax, so anything containing bare operator characters
        # ('|', '"', '(', '*', ':', '-') is a syntax error rather than a search. Real hunt terms
        # hit this constantly: "ES|QL", "CWE-639", "auth:none". Retry as a quoted term list so a
        # search never 500s, while still letting deliberate FTS5 syntax work on the first attempt.
        terms = re.findall(r"\w+", q)
        if not terms:
            return {"items": [], "fallback": True}
        safe = " ".join('"%s"' % t for t in terms)
        params[0] = safe
        try:
            rows = ctx.conn.execute(sql, params).fetchall()
        except Exception as e:
            raise HttpError(400, "bad search query: %s" % e)
        return {"items": [dict(r) for r in rows], "fallback": True, "interpreted_as": safe}
    return {"items": [dict(r) for r in rows]}


# ---------------------------------------------------------------- payloads
@route("GET", r"/api/payloads")
def r_payloads(ctx, m):
    """Search the payload arsenal. Its own table, never search_fts - third-party reference
    material must not rank against hunt notes. See payloads.py for the reasoning.

    `stats` and `categories` travel with every response: index.db is not committed, so an empty
    result has two very different causes ("no match" and "sync-payloads.sh was never run") and
    the UI can only tell them apart if it knows the table is empty.
    """
    try:
        limit = max(1, min(200, int(ctx.q("limit", 50))))
    except ValueError:
        limit = 50
    try:
        res = payloads.search(ctx.conn, ctx.q("q"), category=ctx.q("category"), limit=limit)
    except ValueError as e:
        raise HttpError(400, str(e))
    res["categories"] = payloads.categories(ctx.conn)
    res["stats"] = payloads.stats(ctx.conn)
    return res


# ---------------------------------------------------------------- file browser
def _resolve_browse(cfg, path):
    """Resolve a browse path against the configured roots. Raises HttpError on violation."""
    roots = [r["path"] for r in cfg.get("browse_roots", [])]
    if not path:
        raise HttpError(400, "path is required")
    for root in roots:
        resolved = common.safe_under(root, path)
        if resolved:
            if common.path_denied(resolved, cfg.get("browse_deny_globs")):
                raise HttpError(403, "path is on the deny-list")
            return resolved
    raise HttpError(403, "path is outside every configured browse root")


@route("GET", r"/api/fs/tree")
def r_fs_tree(ctx, m):
    cfg = ctx.cfg
    roots = cfg.get("browse_roots", [])
    path = ctx.q("path") or (roots[0]["path"] if roots else common.HUNT_ROOT)
    resolved = _resolve_browse(cfg, path)
    if not os.path.isdir(resolved):
        raise HttpError(400, "not a directory")
    entries = []
    try:
        names = sorted(os.listdir(resolved), key=lambda n: n.lower())
    except PermissionError:
        raise HttpError(403, "permission denied")
    for nm in names:
        full = os.path.join(resolved, nm)
        denied = common.path_denied(full, cfg.get("browse_deny_globs"))
        try:
            st = os.stat(full)
            is_dir = os.path.isdir(full)
            size, mtime = st.st_size, st.st_mtime
        except OSError:
            is_dir, size, mtime = False, 0, 0
        entries.append({"name": nm, "path": full, "is_dir": is_dir,
                        "size": size, "mtime": mtime, "denied": denied})
    parent = os.path.dirname(resolved)
    any_root = any(common.safe_under(r["path"], parent) for r in roots)
    return {"path": resolved, "parent": parent if any_root else None,
            "roots": roots, "entries": entries}


@route("GET", r"/api/fs/read")
def r_fs_read(ctx, m):
    resolved = _resolve_browse(ctx.cfg, ctx.q("path"))
    if not os.path.isfile(resolved):
        raise HttpError(400, "not a file")
    st = os.stat(resolved)
    cap = int(ctx.cfg.get("browse_max_bytes", 2_000_000))
    with open(resolved, "rb") as fh:
        raw = fh.read(cap + 1)
    truncated = len(raw) > cap
    raw = raw[:cap]
    try:
        text = raw.decode("utf-8")
        binary = False
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
        binary = True
    return {"path": resolved, "size": st.st_size, "mtime": st.st_mtime,
            "text": text, "truncated": truncated, "binary": binary}


@route("PUT", r"/api/fs/write", scope="write")
def r_fs_write(ctx, m):
    b = ctx.body or {}
    resolved = _resolve_browse(ctx.cfg, b.get("path"))
    if "text" not in b:
        raise HttpError(400, "text is required")
    common.write_text_atomic(resolved, b["text"])
    _reindex(ctx.conn, resolved)
    common.audit(ctx.conn, ctx.user, "fs_write", "file", None, resolved, ctx.remote)
    return {"ok": True, "path": resolved}


# ---------------------------------------------------------------- ingest/upload
def _reindex(conn, path):
    if ingest and hasattr(ingest, "reindex_path"):
        try:
            return ingest.reindex_path(conn, path)
        except Exception as e:
            sys.stderr.write("reindex failed for %s: %s\n" % (path, e))
    return None


@route("POST", r"/api/reindex", scope="write")
def r_reindex(ctx, m):
    if not (ingest and hasattr(ingest, "rebuild")):
        raise HttpError(503, "ingest module unavailable")
    t0 = time.time()
    res = ingest.rebuild(ctx.conn) or {}
    res.setdefault("elapsed_ms", int((time.time() - t0) * 1000))
    common.audit(ctx.conn, ctx.user, "reindex", detail=json.dumps(res), remote=ctx.remote)
    return res


@route("POST", r"/api/upload", scope="write")
def r_upload(ctx, m):
    parts = ctx.h.multipart
    if not parts or "file" not in parts:
        raise HttpError(400, "multipart field 'file' is required")
    filename = os.path.basename(parts["file"]["filename"] or "upload.bin")
    data = parts["file"]["data"]
    os.makedirs(common.UPLOAD_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    stored = os.path.join(common.UPLOAD_DIR, "%s_%s" % (stamp, common.slugify(filename, 80)))
    ext = os.path.splitext(filename)[1]
    if ext and not stored.endswith(ext):
        stored += ext
    with open(stored, "wb") as fh:
        fh.write(data)

    import hashlib
    digest = hashlib.sha256(data).hexdigest()

    filed_to = None
    dest_rel = (parts.get("file_to") or {}).get("data")
    if dest_rel:
        dest_rel = dest_rel.decode("utf-8", "replace").strip() if isinstance(dest_rel, bytes) else str(dest_rel).strip()
    if dest_rel:
        candidate = dest_rel if os.path.isabs(dest_rel) else os.path.join(common.HUNT_ROOT, dest_rel)
        resolved = _resolve_browse(ctx.cfg, candidate)
        if os.path.isdir(resolved):
            resolved = os.path.join(resolved, filename)
            resolved = _resolve_browse(ctx.cfg, resolved)
        os.makedirs(os.path.dirname(resolved), exist_ok=True)
        with open(resolved, "wb") as fh:
            fh.write(data)
        filed_to = resolved
        _reindex(ctx.conn, resolved)

    ctx.conn.execute(
        "INSERT INTO uploads (filename, stored_path, filed_to, mime, size, sha256,"
        " uploaded_at, uploaded_by) VALUES (?,?,?,?,?,?,?,?)",
        (filename, stored, filed_to, mimetypes.guess_type(filename)[0], len(data),
         digest, common.now_iso(), ctx.user))
    ctx.conn.commit()
    upload_id = ctx.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    common.audit(ctx.conn, ctx.user, "upload", "upload", upload_id, stored, ctx.remote)
    return {"ok": True, "upload_id": upload_id, "stored_path": stored,
            "filed_to": filed_to, "sha256": digest, "size": len(data)}


# ---------------------------------------------------------------- screenshot
@route("GET", r"/api/screenshot/backends")
def r_screenshot_backends(ctx, m):
    """Which screenshot backends are reachable right now."""
    if not screenshot_mod:
        raise HttpError(503, "screenshot module unavailable")
    return screenshot_mod.detect_backends()


@route("POST", r"/api/screenshot", scope="write")
def r_screenshot(ctx, m):
    """Capture a screenshot via one of the available backends.

    Body fields:
      backend      'auto' | 'caido' | 'burp' | 'os'  (default: auto)
      target       workspace target slug
      name         label for the filename
      request_id   Caido request id (for caido backend)
      item_index   Burp history index (for burp backend)
      mode         'interactive' | 'fullscreen' | 'window' (for os backend)
      caido_token  Caido auth token

    The Caido/Burp backend host is fixed by the CAIDO_URL / BURP_URL environment
    variables and is deliberately not taken from the request body, so a write-scoped
    request cannot steer the server's outbound host. See THREAT_MODEL.md.
    """
    if not screenshot_mod:
        raise HttpError(503, "screenshot module unavailable")
    b = ctx.body or {}
    try:
        result = screenshot_mod.capture(
            backend=b.get("backend", "auto"),
            target_slug=b.get("target"),
            name=b.get("name"),
            request_id=b.get("request_id"),
            item_index=b.get("item_index"),
            mode=b.get("mode", "interactive"),
            caido_token=b.get("caido_token"),
            conn=ctx.conn,
        )
    except RuntimeError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "screenshot", "upload",
                 result.get("upload_id"), result.get("path"), ctx.remote)
    return result


@route("GET", r"/api/evidence/(\w[\w-]*)")
def r_evidence_list(ctx, m):
    """List all evidence files for a target workspace."""
    if not screenshot_mod:
        raise HttpError(503, "screenshot module unavailable")
    target = m.group(1)
    files = screenshot_mod.collect_evidence(target)
    return {"target": target, "files": files, "count": len(files),
            "total_bytes": sum(f["size"] for f in files)}


@route("GET", r"/api/evidence/(\w[\w-]*)/timeline")
def r_evidence_timeline(ctx, m):
    """Build an evidence timeline for a target workspace."""
    if not screenshot_mod:
        raise HttpError(503, "screenshot module unavailable")
    target = m.group(1)
    ref = ctx.q("ref")
    result = screenshot_mod.build_timeline(target, lead_ref=ref)
    return result


@route("POST", r"/api/evidence/(\w[\w-]*)/timeline", scope="write")
def r_evidence_timeline_export(ctx, m):
    """Export the evidence timeline as a markdown file."""
    if not screenshot_mod:
        raise HttpError(503, "screenshot module unavailable")
    target = m.group(1)
    ref = (ctx.body or {}).get("ref") or ctx.q("ref")
    try:
        path = screenshot_mod.export_timeline(target, lead_ref=ref)
    except RuntimeError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "timeline_export", "evidence", None, path, ctx.remote)
    return {"ok": True, "path": path, "filename": os.path.basename(path)}


@route("POST", r"/api/evidence/(\w[\w-]*)/feed", scope="write")
def r_evidence_feed(ctx, m):
    """Pull matching proxy traffic for a target and save as evidence.

    Body fields:
      backend      'auto' | 'caido' | 'burp'
      hosts        list of hostnames to filter (overrides scope lookup)
      limit        max items to pull (default: 20)
      caido_token  Caido auth token

    The Caido/Burp backend host is fixed by the CAIDO_URL / BURP_URL environment
    variables and is deliberately not taken from the request body, so a write-scoped
    request cannot steer the server's outbound host. See THREAT_MODEL.md.
    """
    if not screenshot_mod:
        raise HttpError(503, "screenshot module unavailable")
    target = m.group(1)
    b = ctx.body or {}
    hosts = b.get("hosts")
    if isinstance(hosts, str):
        hosts = [h.strip() for h in hosts.split(",") if h.strip()]
    try:
        result = screenshot_mod.proxy_feed(
            target_slug=target,
            backend=b.get("backend", "auto"),
            hosts=hosts,
            limit=min(int(b.get("limit", 20)), 100),
            caido_token=b.get("caido_token"),
            conn=ctx.conn,
        )
    except RuntimeError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "proxy_feed", "evidence", None,
                 "%s: %d captured via %s" % (target, result["count"], result["backend"]),
                 ctx.remote)
    return result


# ---------------------------------------------------------------- tracker
TRACKER_PATH = os.environ.get("QUARRY_TRACKER_MD") or ""


def _tracker_rows(markdown):
    rows = []
    for line in (markdown or "").splitlines():
        s = line.strip()
        if s.startswith("|") and s.endswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c or "") for c in cells if c):
                continue
            rows.append({"raw": s, "cells": cells, "key": cells[1] if len(cells) > 1 else s})
    return rows


@route("POST", r"/api/tracker/diff")
def r_tracker_diff(ctx, m):
    incoming = _tracker_rows((ctx.body or {}).get("markdown", ""))
    try:
        with open(TRACKER_PATH, "r", encoding="utf-8") as fh:
            current = _tracker_rows(fh.read())
    except FileNotFoundError:
        current = []
    cur_by_key = {r["key"]: r for r in current}
    inc_by_key = {r["key"]: r for r in incoming}
    added = [r["raw"] for k, r in inc_by_key.items() if k not in cur_by_key]
    removed = [r["raw"] for k, r in cur_by_key.items() if k not in inc_by_key]
    changed = [{"before": cur_by_key[k]["raw"], "after": inc_by_key[k]["raw"]}
               for k in inc_by_key if k in cur_by_key and cur_by_key[k]["raw"] != inc_by_key[k]["raw"]]
    return {"added": added, "removed": removed, "changed": changed,
            "current_rows": len(current), "incoming_rows": len(incoming),
            "path": TRACKER_PATH}


@route("POST", r"/api/tracker/apply", scope="write")
def r_tracker_apply(ctx, m):
    markdown = (ctx.body or {}).get("markdown", "")
    if not markdown.strip():
        raise HttpError(400, "markdown is required")
    resolved = _resolve_browse(ctx.cfg, TRACKER_PATH)
    backup = resolved + ".bak-" + time.strftime("%Y%m%d-%H%M%S")
    if os.path.exists(resolved):
        with open(resolved, "r", encoding="utf-8") as fh:
            common.write_text_atomic(backup, fh.read())
    common.write_text_atomic(resolved, markdown)
    _reindex(ctx.conn, resolved)
    common.audit(ctx.conn, ctx.user, "tracker_apply", "file", None, resolved, ctx.remote)
    return {"ok": True, "path": resolved, "backup": backup,
            "rows": len(_tracker_rows(markdown))}


# ---------------------------------------------------------------- tokens
@route("GET", r"/api/tokens")
def r_tokens(ctx, m):
    rows = ctx.conn.execute(
        "SELECT id,name,prefix,scope,created_at,created_by,last_used,revoked"
        " FROM api_tokens ORDER BY id DESC").fetchall()
    return {"items": [dict(r) for r in rows]}


@route("POST", r"/api/tokens", scope="write")
def r_token_create(ctx, m):
    b = ctx.body or {}
    name = (b.get("name") or "").strip()
    if not name:
        raise HttpError(400, "name is required")
    tid, raw = auth.create_api_token(ctx.conn, name, b.get("scope", "read"), ctx.user)
    common.audit(ctx.conn, ctx.user, "token_create", "api_token", tid, name, ctx.remote)
    return {"id": tid, "token": raw,
            "warning": "This is the only time this token is shown. Store it now."}


@route("POST", r"/api/tokens/(\d+)/revoke", scope="write")
def r_token_revoke(ctx, m):
    tid = int(m.group(1))
    auth.revoke_api_token(ctx.conn, tid)
    common.audit(ctx.conn, ctx.user, "token_revoke", "api_token", tid, None, ctx.remote)
    return {"ok": True}


# ---------------------------------------------------------------- advisories
try:
    import advisories as advisories_mod
except Exception:
    advisories_mod = None


@route("POST", r"/api/advisories/sync", scope="write")
def r_advisories_sync(ctx, m):
    """Poll the advisory feeds now. Same code path cron runs."""
    if not advisories_mod:
        raise HttpError(503, "advisories module unavailable")
    t0 = time.time()
    res = advisories_mod.sync_rss(ctx.conn, ctx.cfg, verbose=False)
    res["elapsed_ms"] = int((time.time() - t0) * 1000)
    common.audit(ctx.conn, ctx.user, "advisory_sync", detail=json.dumps(res), remote=ctx.remote)
    return res


@route("GET", r"/api/unseen")
def r_unseen(ctx, m):
    """How many rows appeared since the caller last looked at each section.

    The client owns the watermark (it is per-browser, not per-account) and passes it in as
    `since_<entity>`. An absent or unparseable watermark yields 0 rather than "everything is
    new", so a fresh browser does not open on a wall of false badges.

    The count MUST be scoped to exactly the rows that section lists, via entity_scope(). It used
    to be a bare `COUNT(*) ... WHERE indexed_at > ?` over the whole table, which counted rows the
    tile does not display and cannot display. Submitting a report through h1.py renames the local
    markdown to prefix the H1 id; ingest keys report rows on `file_path`, so the renamed file
    indexes as a NEW file-derived row (`source` NULL) alongside the API row it duplicates. The
    badge went to +1 while the Reports tile stayed put - a "new report" the user could not find.
    Same shape on leads, where 42 of 60 rows are status 'unknown' research apparatus that the
    Leads list excludes but the badge was counting.
    """
    out = {}
    for entity in ("advisories", "reports", "leads"):
        since = ctx.q("since_" + entity)
        if not since:
            out[entity] = 0
            continue
        try:
            n = ctx.conn.execute(
                "SELECT COUNT(*) FROM %s l WHERE %s AND %s > ?"
                % (ENTITIES[entity]["table"], entity_scope(entity), _appeared_at(entity)),
                (since,)).fetchone()[0]
        except Exception:
            n = 0
        out[entity] = n
    out.update(_report_updates(ctx.conn, ctx.q("since_report_updates")))
    out["lead_updates"] = _lead_updates(ctx.conn, ctx.q("since_lead_updates"))
    out.update(_bounty_awards(ctx.conn, ctx.q("since_bounty_awards")))
    out["now"] = common.now_iso()
    return out


def _lead_updates(conn, since):
    """Leads that already existed and have since changed.

    A lead has no event log, so the signal is the pair of timestamps: `indexed_at` moved after the
    watermark while `first_seen_at` did not. That is precisely "was already here, and is
    different now", and it is what stops an edit reading as an arrival.

    Scoped by entity_scope so it counts only the rows the Leads tab actually lists, the same as
    every other badge.
    """
    if not since:
        return 0
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM leads l WHERE %s"
            "   AND l.indexed_at > ?"
            "   AND COALESCE(l.first_seen_at, l.indexed_at) <= ?" % entity_scope("leads"),
            (since, since)).fetchone()[0]
    except Exception:
        return 0


def _appeared_at(entity):
    """The column that answers "when did this row APPEAR", per entity.

    For reports that is not `indexed_at`. That column means "this row's content changed" by
    deliberate design, so HackerOne triaging a report bumps it and the New badge counts a report
    filed six weeks ago as new - which is exactly what #0000000 did on 2026-08-01. `first_seen_at`
    is written once on INSERT and never moves; see common.ensure_first_seen().

    COALESCE because the column is backfilled but a row inserted by an older build in between the
    migration and this query would hold NULL, and NULL > ? is never true - the badge would go
    quiet instead of wrong, which is harder to notice.

    Advisories have the same problem from the other direction: a vendor editing a title or adding
    a CVE bumps indexed_at, so a three-week-old ESA re-badges as new.

    Leads were left on `indexed_at` on the reasoning that only the user changes them, so "changed"
    and "appeared" were the same event. That was wrong in practice: editing a lead to record a
    kill, or a bulk header normalisation across eight files, re-badged every one of them as NEW.
    An edit is an update, not an arrival.
    """
    return "COALESCE(l.first_seen_at, l.indexed_at)"


#: What counts as a report being UPDATED, as a WHERE fragment over `report_events e`.
#:
#: Excluding `new_report` alone is not enough, and assuming otherwise is the whole subtlety here.
#: h1_watch's derive_events() compares a first sighting against an empty baseline, so a report
#: arriving ALSO emits severity_change (and collaborator_added, if it has any) in the very same
#: poll. #0000000 and #0000000 both landed as three-event bursts sharing one timestamp. Filtering
#: only on event_type would badge every brand new report as Updated as well as New - the same
#: double-count this badge exists to undo, just mirrored.
#:
#: So the burst is dropped as a unit: an event is not an update if that report's own new_report
#: event carries the identical timestamp. Anything later is a genuine move.
UPDATE_EVENT_WHERE = (
    " e.event_type <> 'new_report'"
    " AND NOT EXISTS (SELECT 1 FROM report_events b WHERE b.h1_id = e.h1_id"
    "                   AND b.event_type = 'new_report' AND b.detected_at = e.detected_at)")


def _report_updates(conn, since):
    """Reports HackerOne changed underneath us since the caller last looked.

    A different question from the `reports` badge above, and it needs its own watermark. That one
    means "a report appeared"; this one means "a report you already had moved" - triaged, awarded,
    severity set, CVE assigned. The transitions are recorded by h1_watch's incremental poll, so
    this is a local read: no HackerOne request is made to paint a badge.

    Counted DISTINCT BY REPORT, not by event. One triage writes both a state_change and a
    severity_change, and "+2" for a single report reads as two reports moving.

    Everything is wrapped: h1_watch may never have run on this checkout, in which case the table
    does not exist and a dashboard badge is not worth a 500.
    """
    out = {"report_updates": 0, "report_updates_latest": []}
    if not since:
        return out
    try:
        out["report_updates"] = conn.execute(
            "SELECT COUNT(DISTINCT e.h1_id) FROM report_events e"
            " WHERE e.detected_at > ? AND" + UPDATE_EVENT_WHERE, (since,)).fetchone()[0]
        if out["report_updates"]:
            # A few of the newest, for the badge tooltip. `seq` breaks the tie because
            # detected_at has second resolution and one poll writes several events in the
            # same second - see the seq column comment in h1_watch.ensure_schema.
            out["report_updates_latest"] = [dict(r) for r in conn.execute(
                "SELECT e.h1_id, e.event_type, e.old_value, e.new_value, e.detected_at,"
                " r.title FROM report_events e LEFT JOIN reports r ON r.id = e.report_id"
                " WHERE e.detected_at > ? AND" + UPDATE_EVENT_WHERE +
                " ORDER BY e.detected_at DESC, e.seq DESC LIMIT 6", (since,)).fetchall()]
    except Exception:
        return {"report_updates": 0, "report_updates_latest": []}
    return out


#: What counts as MONEY ARRIVING, as a WHERE fragment over `report_events e`.
#:
#: Unlike UPDATE_EVENT_WHERE this does NOT drop a first sighting's event burst. A report that is
#: already paid the first time we see it moves the confirmed total the moment it lands, so it is
#: real money arriving even though it arrived in the same poll as the report itself. The Updated
#: badge suppresses that burst because "arrived" and "changed" would otherwise double-count one
#: event; here there is nothing to double-count, the tile genuinely went up.
MONEY_EVENT_WHERE = " e.event_type IN ('bounty_awarded', 'bounty_increased')"

#: Same rule as h1._clean_amount: only a BARE number is money. h1_watch writes event values as
#: "1500.00 USD", so the currency word is split off before this is applied.
#:
#: This is the guard that keeps a hand-recorded expectation out of the badge. The old markdown
#: tracker held strings like '[amount]', and promoting one of those into a confirmed figure is the
#: exact mistake that has put the total wrong three times. Anything that is not a bare number
#: contributes 0 here rather than being coerced.
_BARE_AMOUNT = re.compile(r"\d+(\.\d+)?$")


def _event_amount(value):
    v = str(value or "").strip().split(" ")[0]
    return float(v) if _BARE_AMOUNT.match(v) else 0.0


def _bounty_awards(conn, since):
    """Confirmed money that landed since the caller last looked.

    READ-ONLY with respect to money, and deliberately narrow: it reports DELTAS for the dashboard
    Bounty tiles and never writes, adjusts or stores a `bounty` or `my_bounty` value. It also
    never reads `expected_bounty` - an expectation is not an award, and the Anticipated block on
    that card is where beliefs about unpaid money belong.

    Three figures, because the three badged tiles answer three different questions:

      bounty_awards      how many reports NEWLY carry an award. Only `bounty_awarded` counts: a
                         raise moves the money but not the number of reports that were paid, so
                         counting it here would make the badge disagree with the tile it sits on.
      bounty_delta_total the movement in the full award, both event types, summed.
      bounty_delta_mine  the movement in MY share of it, which differs on a split payout.

    The events record the FULL award (h1_watch diffs `bounty`, never `my_bounty`), so the share
    cannot be read off the event alone and is derived from the report row: my_bounty / bounty.
    For the common case that ratio is exact - a first award goes 0 -> bounty, so ratio * delta is
    my_bounty to the cent. For a raise it attributes the increase in the proportion the payout
    was actually split in, which is the best the recorded history supports. Missing or
    unparseable either side means no split is known, and an unknown split is 100% mine, matching
    what the tiles already show for a report with no payout_split.

    Rows are keyed on h1_id rather than report_events.report_id: the tiles sum `source='hackerone'`
    rows, and submitting through h1.py can leave a second file-derived row for the same report
    carrying a hand-typed amount. Preferring the API row is the same resolution h1_watch._report_id
    uses, so the delta is measured against the same row the total is summed from.

    Everything is wrapped, same as _report_updates: on a checkout where h1_watch has never run the
    table does not exist, and a dashboard badge is not worth a 500.
    """
    out = {"bounty_awards": 0, "bounty_delta_total": 0.0, "bounty_delta_mine": 0.0,
           "bounty_awards_latest": [], "bounty_awards_at": ""}
    if not since:
        return out
    try:
        rows = conn.execute(
            "SELECT e.h1_id, e.event_type, e.old_value, e.new_value, e.detected_at"
            " FROM report_events e WHERE e.detected_at > ? AND" + MONEY_EVENT_WHERE +
            " ORDER BY e.detected_at ASC, e.seq ASC LIMIT 200", (since,)).fetchall()
        if not rows:
            return out
        # `bounty` and `my_bounty` only. Never expected_bounty.
        share = {}
        for r in conn.execute(
                "SELECT h1_id, title, bounty, my_bounty FROM reports"
                " WHERE kind='report' AND h1_id IN (%s)"
                " ORDER BY (source='hackerone') DESC, id ASC"
                % ",".join("?" * len({row["h1_id"] for row in rows})),
                sorted({row["h1_id"] for row in rows})).fetchall():
            share.setdefault(r["h1_id"], r)
    except Exception:
        return out

    per = {}
    for row in rows:
        h1_id = row["h1_id"]
        delta = _event_amount(row["new_value"]) - _event_amount(row["old_value"])
        if delta <= 0:
            continue                      # a correction downward is not news the badge should cheer
        rep = share.get(h1_id)
        full = _event_amount(rep["bounty"]) if rep else 0.0
        mine = _event_amount(rep["my_bounty"]) if rep else 0.0
        ratio = min(mine / full, 1.0) if full > 0 and mine > 0 else 1.0
        e = per.setdefault(h1_id, {"h1_id": h1_id, "title": (rep["title"] if rep else "") or "",
                                   "delta": 0.0, "mine": 0.0, "awarded": False,
                                   "detected_at": row["detected_at"]})
        e["delta"] += delta
        e["mine"] += delta * ratio
        e["awarded"] = e["awarded"] or row["event_type"] == "bounty_awarded"
        e["detected_at"] = max(e["detected_at"], row["detected_at"])

    for e in per.values():
        e["delta"] = round(e["delta"], 2)
        e["mine"] = round(e["mine"], 2)
    latest = sorted(per.values(), key=lambda e: e["detected_at"], reverse=True)
    out["bounty_awards"] = sum(1 for e in latest if e["awarded"])
    out["bounty_delta_total"] = round(sum(e["delta"] for e in latest), 2)
    out["bounty_delta_mine"] = round(sum(e["mine"] for e in latest), 2)
    out["bounty_awards_at"] = latest[0]["detected_at"] if latest else ""
    out["bounty_awards_latest"] = latest[:6]
    return out


@route("GET", r"/api/schedule")
def r_schedule(ctx, m):
    """Configured poll intervals, and what is actually installed in the crontab.

    `installed` is read back from `crontab -l` rather than assumed from config, because the two
    genuinely can disagree: saving an interval writes config.json even if installing the block
    then fails, and a crontab edited by hand is not something this should paper over.
    """
    if not schedule_mod:
        raise HttpError(503, "schedule module unavailable")
    out = schedule_mod.status(ctx.cfg)
    try:
        current = schedule_mod.read_crontab()
        out["installed"] = [l for l in current if "/scripts/sync-" in l
                            and not l.strip().startswith("#")]
        out["in_sync"] = out["installed"] == [l for l in schedule_mod.render(ctx.cfg)
                                              if l and not l.startswith("#")]
    except Exception as e:
        out["installed"] = []
        out["in_sync"] = None
        out["error"] = str(e)
    return out


@route("POST", r"/api/schedule", scope="write")
def r_schedule_set(ctx, m):
    """Set poll intervals in minutes and install them.

    Config is saved BEFORE the crontab is written and the two are reported separately. If the
    crontab write fails the setting is still stored and the UI can say "saved but not installed",
    which is recoverable; the reverse - cron changed but config not - would leave the running
    schedule with nothing describing it.

    Only `poll_intervals` is touched. config.json also holds the user table, so this reloads,
    mutates one key and saves, rather than writing back whatever the client sent.
    """
    if not schedule_mod:
        raise HttpError(503, "schedule module unavailable")
    updates = (ctx.body or {}).get("intervals") or {}
    if not isinstance(updates, dict) or not updates:
        raise HttpError(400, "intervals must be a non-empty object of job -> minutes")

    cfg = common.load_config()
    cfg, applied, rejected = schedule_mod.set_intervals(cfg, updates)
    if rejected and not applied:
        raise HttpError(400, "no valid intervals: %s" % json.dumps(rejected))
    common.save_config(cfg)
    # The process holds its own copy; without this the GET above would keep reporting the old
    # values until a restart.
    ctx.cfg.update(cfg)

    out = {"applied": applied, "rejected": rejected, "saved": True, "installed": False}
    try:
        res = schedule_mod.apply(cfg)
        out["installed"] = True
        out["block"] = res["block"]
        out["preserved"] = res["preserved"]
    except Exception as e:
        out["error"] = str(e)
    out.update(schedule_mod.status(cfg))
    common.audit(ctx.conn, ctx.user, "schedule_set", None, None,
                 "applied=%s installed=%s" % (json.dumps(applied, sort_keys=True),
                                              out["installed"]), ctx.remote)
    return out


# ---------------------------------------------------------------- settings
# Everything on the Settings tab that is not the schedule. Deliberately a SHORT allow-list rather
# than "write back what the client sent": config.json also holds the user table, the TLS paths and
# the browse deny-globs, and a settings form must never be able to reach any of them.
SETTINGS_FIELDS = {
    # key -> (type, minimum, maximum). 0 is in range for session_hours and means "never expires".
    "session_hours": (int, 0, 24 * 365),
    # Days after a report closes before the Regression tab calls its fix due a retest. Not zero:
    # a window of zero makes every resolved report permanently due, which is the same as having no
    # queue at all. See regression.window_days, which clamps to the same range.
    "regression_window_days": (int, 1, 3650),
}


def _settings_payload(cfg):
    hours = int(cfg.get("session_hours", 0) or 0)
    return {
        "session_hours": hours,
        "session_expiry_enabled": hours > 0,
        # Read through the module so the value the Settings tab shows is the CLAMPED one actually
        # in force, not whatever integer happens to be sitting in config.json.
        "regression_window_days": (regression_mod.window_days(cfg) if regression_mod
                                   else int(cfg.get("regression_window_days", 30) or 30)),
        # Said here rather than only in the UI copy, so anyone reading the API sees the trade.
        "session_note": ("With expiry off the login cookie stays valid until you log out. This "
                         "app binds to loopback and holds unreported findings, so that is a "
                         "deliberate convenience, not an oversight."),
    }


@route("GET", r"/api/settings")
def r_settings(ctx, m):
    return _settings_payload(ctx.cfg)


@route("POST", r"/api/settings", scope="write")
def r_settings_set(ctx, m):
    """Update the allow-listed settings. Reloads, mutates, saves - never writes back the body.

    Same ordering discipline as the schedule endpoint: config is the record, and the process copy
    is updated after the file so a failed write cannot leave the two disagreeing.
    """
    body = ctx.body or {}
    updates = {}
    for key, (kind, lo, hi) in SETTINGS_FIELDS.items():
        if key not in body:
            continue
        try:
            val = kind(body[key])
        except (TypeError, ValueError):
            raise HttpError(400, "%s must be %s" % (key, kind.__name__))
        if val < lo or val > hi:
            raise HttpError(400, "%s must be between %d and %d" % (key, lo, hi))
        updates[key] = val
    if not updates:
        raise HttpError(400, "no known settings in body; accepted: %s"
                        % ", ".join(sorted(SETTINGS_FIELDS)))

    cfg = common.load_config()
    cfg.update(updates)
    common.save_config(cfg)
    ctx.cfg.update(cfg)
    common.audit(ctx.conn, ctx.user, "settings_set", None, None,
                 json.dumps(updates, sort_keys=True), ctx.remote)
    out = _settings_payload(ctx.cfg)
    # Changing the timeout does not retroactively expire or extend sessions already open. Said
    # plainly, because "I turned it off and it still logged me out" is otherwise a bug report.
    out["applies_to"] = "sessions created from the next login onward"
    return out


@route("GET", r"/api/advisories/status")
def r_advisories_status(ctx, m):
    """Feed health: how many we hold, and how fresh."""
    if advisories_mod:
        try:
            advisories_mod.ensure_schema(ctx.conn)
        except Exception:
            pass
    def one(sql, default=None):
        try:
            r = ctx.conn.execute(sql).fetchone()
            return r[0] if r else default
        except Exception:
            return default
    feeds = []
    if advisories_mod:
        for f in advisories_mod.feeds(ctx.cfg):
            feeds.append({"name": f.get("name"), "rss": f.get("rss")})
    last_audit = None
    try:
        r = ctx.conn.execute("SELECT ts, detail FROM audit WHERE action='advisory_sync'"
                             " ORDER BY id DESC LIMIT 1").fetchone()
        if r:
            last_audit = {"ts": r["ts"], "detail": r["detail"]}
    except Exception:
        pass
    return {
        "count": one("SELECT COUNT(*) FROM advisories", 0),
        "newest_published": one("SELECT MAX(published) FROM advisories"),
        "last_fetched": one("SELECT MAX(fetched_at) FROM advisories"),
        "with_cve": one("SELECT COUNT(*) FROM advisories WHERE cve IS NOT NULL AND cve <> ''", 0),
        "feeds": feeds,
        "last_sync": last_audit,
    }


# ------------------------------------------------- advisory <-> report matching
# ExampleVendor advisories never name the reporter, so `matcher` INFERS which of our reports each
# advisory came from. Everything these endpoints return is a hypothesis carrying the signals
# that produced it; only `confirmed` rows rest on a CVE HackerOne itself recorded. The UI must
# show `signals` alongside any match - see the honesty contract at the top of matcher.py.
try:
    import matcher as matcher_mod
except Exception:
    matcher_mod = None


def _require_matcher():
    if not matcher_mod:
        raise HttpError(503, "matcher module unavailable")
    return matcher_mod


@route("GET", r"/api/advisories/matches")
def r_advisory_matches(ctx, m):
    """Persisted matches, strongest confidence first. Read-only; never recomputes.

    `confidence` filters to a minimum bucket ('confirmed' | 'likely' | 'possible'),
    `advisory_id` narrows to one advisory. `summary` carries the per-bucket counts so the UI
    never has to derive them from a truncated page.
    """
    mm = _require_matcher()
    try:
        limit = max(1, min(5000, int(ctx.q("limit", 1000))))
    except ValueError:
        limit = 1000
    items = mm.load_matches(ctx.conn,
                            min_confidence=ctx.q("confidence"),
                            advisory_id=ctx.q("advisory_id"),
                            limit=limit)
    return {"items": items, "total": len(items), "summary": mm.summary(ctx.conn)}


@route("POST", r"/api/advisories/matches/recompute", scope="write")
def r_advisory_matches_recompute(ctx, m):
    """Re-score every advisory against every H1 report and store the result.

    Human confirm/reject verdicts are preserved: `matcher.persist` never writes the
    `confirmed` column and never deletes a row a human has ruled on.
    """
    mm = _require_matcher()
    t0 = time.time()
    body = ctx.body or {}
    try:
        min_score = float(body.get("min_score", mm.DEFAULT_MIN_SCORE))
    except (TypeError, ValueError):
        raise HttpError(400, "min_score must be a number")
    matches = mm.match_all(ctx.conn, min_score)
    res = mm.persist(ctx.conn, matches)
    res["elapsed_ms"] = int((time.time() - t0) * 1000)
    res["min_score"] = min_score
    common.audit(ctx.conn, ctx.user, "advisory_match_recompute", "advisory", None,
                 json.dumps(res), ctx.remote)
    return res


@route("POST", r"/api/advisories/(\d+)/match/(\d+)", scope="write")
def r_advisory_match_confirm(ctx, m):
    """Record a human verdict on one pairing: {"confirmed": true|false|null}.

    This is the only writer of `advisory_matches.confirmed`, and recompute will not undo it.
    `null` clears the verdict and hands the row back to the scorer.
    """
    mm = _require_matcher()
    advisory_id, report_id = int(m.group(1)), int(m.group(2))
    body = ctx.body or {}
    if "confirmed" not in body:
        raise HttpError(400, "confirmed is required (true, false or null)")
    confirmed = body["confirmed"]
    if confirmed is not None and not isinstance(confirmed, bool):
        raise HttpError(400, "confirmed must be true, false or null")
    row = mm.set_confirmed(ctx.conn, advisory_id, report_id, confirmed)
    if row is None:
        raise HttpError(404, "no such match")
    common.audit(ctx.conn, ctx.user, "advisory_match_verdict", "advisory", advisory_id,
                 "report %d -> %s" % (report_id, confirmed), ctx.remote)
    return {"ok": True, "advisory_id": advisory_id, "report_id": report_id,
            "confirmed": row["confirmed"]}


# ---------------------------------------------------------------- integrations
try:
    import h1 as h1_mod
except Exception:
    h1_mod = None

try:
    import h1_graphql as h1_gql
except Exception:
    h1_gql = None


@route("GET", r"/api/integrations/hackerone")
def r_h1_status(ctx, m):
    """Credential state and sync health. NEVER returns the token, only a mask and a hash prefix."""
    if not h1_mod:
        raise HttpError(503, "hackerone module unavailable")
    return h1_mod.status(ctx.conn)


@route("PUT", r"/api/integrations/hackerone", scope="write")
def r_h1_set(ctx, m):
    """Store the HackerOne credential.

    The token is VERIFIED against the live API before it is written, so a typo cannot silently
    replace a working credential. It is written to secrets.json at mode 0600, never to
    config.json and never to the database, and no endpoint can read it back.
    """
    if not h1_mod:
        raise HttpError(503, "hackerone module unavailable")
    b = ctx.body or {}
    username = (b.get("username") or "").strip()
    token = (b.get("api_token") or "").strip()
    handle = (b.get("program_handle") or "").strip() or None
    if not username or not token:
        raise HttpError(400, "username and api_token are required")

    try:
        probe = h1_mod.test_credentials(username, token)
    except h1_mod.H1Error as e:
        raise HttpError(400, str(e))

    h1_mod.set_credentials(username, token, handle)
    # Log that a credential was set, and its fingerprint - never the value.
    common.audit(ctx.conn, ctx.user, "integration_credential", "hackerone", None,
                 "set for %s (%s)" % (username, h1_mod.fingerprint(token)), ctx.remote)
    out = h1_mod.status(ctx.conn)
    out["verified"] = probe
    return out


@route("POST", r"/api/integrations/hackerone/test", scope="write")
def r_h1_test(ctx, m):
    if not h1_mod:
        raise HttpError(503, "hackerone module unavailable")
    u, t, _h = h1_mod.get_credentials()
    if not (u and t):
        raise HttpError(400, "no credential stored")
    try:
        return h1_mod.test_credentials(u, t)
    except h1_mod.H1Error as e:
        raise HttpError(502, str(e))


# The H1 sync runs in the background so the request returns at once and the page polls progress,
# rather than holding one request open for the ~1 minute a full two-phase sync takes. One operator,
# so a single module-level state is enough; the lock guards the worker thread's writes to it.
_H1_SYNC = {"running": False, "phase": "idle", "done": 0, "total": 0,
            "result": None, "error": None, "started_at": 0.0, "finished_at": 0.0}
_H1_SYNC_LOCK = threading.Lock()


def _run_h1_sync(program_handle, user, remote):
    """Worker with its OWN connection (a sqlite handle cannot cross threads), publishing progress
    into _H1_SYNC. h1.sync does not commit, so we commit here, exactly as the request framework did
    for the old synchronous endpoint - otherwise the whole sync (bounties included) is lost."""
    conn = common.connect()
    t0 = time.time()
    try:
        def cb(done, total):
            with _H1_SYNC_LOCK:
                _H1_SYNC["phase"] = "enriching"
                _H1_SYNC["done"] = done
                _H1_SYNC["total"] = total
        res = h1_mod.sync(conn, verbose=False, program_handle=program_handle, progress=cb)
        res["elapsed_ms"] = int((time.time() - t0) * 1000)
        try:
            common.audit(conn, user, "h1_sync", detail=json.dumps(res), remote=remote)
        except Exception:
            pass
        conn.commit()
        with _H1_SYNC_LOCK:
            _H1_SYNC["result"] = res
            _H1_SYNC["phase"] = "done"
            _H1_SYNC["total"] = res.get("fetched", _H1_SYNC["total"]) or _H1_SYNC["total"]
            _H1_SYNC["done"] = _H1_SYNC["total"]
    except Exception as e:
        with _H1_SYNC_LOCK:
            _H1_SYNC["error"] = str(e)
            _H1_SYNC["phase"] = "error"
    finally:
        try:
            conn.close()
        except Exception:
            pass
        with _H1_SYNC_LOCK:
            _H1_SYNC["running"] = False
            _H1_SYNC["finished_at"] = time.time()


@route("POST", r"/api/integrations/hackerone/sync", scope="write")
def r_h1_sync(ctx, m):
    if not h1_mod:
        raise HttpError(503, "hackerone module unavailable")
    u, t, _ = h1_mod.get_credentials()
    if not (u and t):
        raise HttpError(400, "no HackerOne credential stored")
    with _H1_SYNC_LOCK:
        if _H1_SYNC["running"]:
            return dict(_H1_SYNC)          # already in flight; the page just polls the status route
        _H1_SYNC.update({"running": True, "phase": "listing", "done": 0, "total": 0,
                         "result": None, "error": None,
                         "started_at": time.time(), "finished_at": 0.0})
    handle = (ctx.body or {}).get("program_handle")
    threading.Thread(target=_run_h1_sync, args=(handle, ctx.user, ctx.remote),
                     daemon=True).start()
    return {"started": True, "running": True}


@route("GET", r"/api/integrations/hackerone/sync/status")
def r_h1_sync_status(ctx, m):
    """Progress for the in-flight (or last) H1 sync, so the Integrations page can draw a bar."""
    with _H1_SYNC_LOCK:
        return dict(_H1_SYNC)


# The accessible-programs list is 6+ paged requests, so it is cached in memory for a few minutes:
# the add-program picker hits it once per keystroke (debounced), and re-paging HackerOne each time
# would be both slow and rude. Bypassed with ?refresh=1.
_ACCESSIBLE_PROGRAMS = {"at": 0.0, "rows": []}
_ACCESSIBLE_TTL = 300


@route("GET", r"/api/integrations/hackerone/programs")
def r_h1_programs(ctx, m):
    """The programs this credential can see on HackerOne, for the add-program picker. `?q` filters
    by handle or name (case-insensitive); `?refresh=1` re-pages the API. Each row carries `tracked`
    so the picker can show what is already onboarded. Private/invited programs are here even though
    they never appear in the operator's reports - that is the whole point of the picker."""
    if not h1_mod:
        raise HttpError(503, "hackerone module unavailable")
    u, t, _ = h1_mod.get_credentials()
    if not (u and t):
        raise HttpError(400, "no HackerOne credential stored")
    now = time.time()
    if ctx.q("refresh") or not _ACCESSIBLE_PROGRAMS["rows"] \
            or now - _ACCESSIBLE_PROGRAMS["at"] > _ACCESSIBLE_TTL:
        try:
            _ACCESSIBLE_PROGRAMS["rows"] = h1_mod.fetch_accessible_programs(u, t)
            _ACCESSIBLE_PROGRAMS["at"] = now
        except h1_mod.H1Error as e:
            raise HttpError(502, str(e))
    rows = _ACCESSIBLE_PROGRAMS["rows"]
    q = (ctx.q("q") or "").strip().lower()
    if q:
        rows = [p for p in rows
                if q in p["handle"].lower() or q in (p["name"] or "").lower()]
    tracked = {r[0] for r in ctx.conn.execute("SELECT slug FROM programs").fetchall()}
    limit = 50
    return {"items": [dict(p, tracked=(p["handle"] in tracked)) for p in rows[:limit]],
            "total": len(rows), "shown": min(len(rows), limit),
            "cached_at": _ACCESSIBLE_PROGRAMS["at"]}


@route("POST", r"/api/integrations/hackerone/programs", scope="write")
def r_h1_program_add(ctx, m):
    """Onboard one accessible program into the tracked set: insert the stub, then fill its policy,
    scopes and API columns for that single handle. Idempotent - adding one already tracked just
    re-syncs its details."""
    if not h1_mod:
        raise HttpError(503, "hackerone module unavailable")
    u, t, _ = h1_mod.get_credentials()
    if not (u and t):
        raise HttpError(400, "no HackerOne credential stored")
    handle = ((ctx.body or {}).get("handle") or "").strip()
    if not handle:
        raise HttpError(400, "handle is required")
    try:
        res = h1_mod.onboard_program(ctx.conn, u, t, handle)
    except h1_mod.H1Error as e:
        raise HttpError(502, str(e))
    # Invalidate the picker cache's tracked flags on the next read by leaving rows but letting the
    # caller re-read; the tracked set is recomputed per request, so nothing else to do here.
    common.audit(ctx.conn, ctx.user, "program_add", "programs", handle,
                 "onboarded %s (created=%s)" % (handle, res.get("created")), ctx.remote)
    return res


# ------------------------------------------------------- H1 GraphQL (invitations + collabs)

def _need_gql():
    if not h1_gql:
        raise HttpError(503, "h1_graphql module unavailable")
    return h1_gql


@route("GET", r"/api/integrations/hackerone/session")
def r_h1_session_status(ctx, m):
    """Session token state. NEVER returns the token, only a mask."""
    gql = _need_gql()
    return gql.status()


@route("PUT", r"/api/integrations/hackerone/session", scope="write")
def r_h1_session_set(ctx, m):
    """Store the HackerOne session cookie. Verified before saving."""
    gql = _need_gql()
    b = ctx.body or {}
    token = (b.get("session_token") or "").strip()
    if not token:
        raise HttpError(400, "session_token is required")
    try:
        probe = gql.test_session(session_token=token)
    except gql.GQLError as e:
        raise HttpError(400, str(e))
    gql.set_session(token)
    common.audit(ctx.conn, ctx.user, "h1_session_set", "hackerone", None,
                 "verified as %s" % probe.get("username", "?"), ctx.remote)
    out = gql.status()
    out["verified"] = probe
    return out


@route("GET", r"/api/h1/invitations")
def r_h1_invitations(ctx, m):
    """Pending private program invitations."""
    gql = _need_gql()
    try:
        return gql.list_program_invitations()
    except gql.GQLError as e:
        raise HttpError(502, str(e))


@route("POST", r"/api/h1/invitations/accept", scope="write")
def r_h1_invitation_accept(ctx, m):
    """Accept a program invitation."""
    gql = _need_gql()
    token = ((ctx.body or {}).get("token") or "").strip()
    if not token:
        raise HttpError(400, "token is required")
    try:
        result = gql.accept_program_invitation(token)
    except gql.GQLError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "h1_invite_accept", "program", None,
                 "token=%s..." % token[:12], ctx.remote)
    return result


@route("POST", r"/api/h1/invitations/reject", scope="write")
def r_h1_invitation_reject(ctx, m):
    """Reject a program invitation."""
    gql = _need_gql()
    token = ((ctx.body or {}).get("token") or "").strip()
    if not token:
        raise HttpError(400, "token is required")
    try:
        result = gql.reject_program_invitation(token)
    except gql.GQLError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "h1_invite_reject", "program", None,
                 "token=%s..." % token[:12], ctx.remote)
    return result


@route("GET", r"/api/h1/collabs")
def r_h1_collabs(ctx, m):
    """Pending report collaboration invitations."""
    gql = _need_gql()
    try:
        return gql.list_collab_invitations()
    except gql.GQLError as e:
        raise HttpError(502, str(e))


@route("POST", r"/api/h1/collabs/accept", scope="write")
def r_h1_collab_accept(ctx, m):
    """Accept a collaboration invitation."""
    gql = _need_gql()
    token = ((ctx.body or {}).get("token") or "").strip()
    if not token:
        raise HttpError(400, "token is required")
    try:
        result = gql.accept_collab_invitation(token)
    except gql.GQLError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "h1_collab_accept", "report", None,
                 "token=%s..." % token[:12], ctx.remote)
    return result


@route("POST", r"/api/h1/collabs/invite", scope="write")
def r_h1_collab_invite(ctx, m):
    """Invite a collaborator to a report."""
    gql = _need_gql()
    b = ctx.body or {}
    report_id = (b.get("report_id") or "").strip()
    username = (b.get("username") or "").strip()
    if not report_id or not username:
        raise HttpError(400, "report_id and username are required")
    try:
        result = gql.invite_collaborator(report_id, username)
    except gql.GQLError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "h1_collab_invite", "report", report_id,
                 "invited %s" % username, ctx.remote)
    return result


@route("POST", r"/api/h1/collabs/split", scope="write")
def r_h1_collab_split(ctx, m):
    """Set the bounty split percentage for a collaborator."""
    gql = _need_gql()
    b = ctx.body or {}
    report_id = (b.get("report_id") or "").strip()
    username = (b.get("username") or "").strip()
    percentage = b.get("percentage")
    if not report_id or not username or percentage is None:
        raise HttpError(400, "report_id, username, and percentage are required")
    try:
        pct = int(percentage)
        if pct < 0 or pct > 100:
            raise ValueError
    except (TypeError, ValueError):
        raise HttpError(400, "percentage must be an integer 0-100")
    try:
        result = gql.update_bounty_split(report_id, username, pct)
    except gql.GQLError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "h1_collab_split", "report", report_id,
                 "%s -> %d%%" % (username, pct), ctx.remote)
    return result


# ------------------------------------------------------- incremental H1 poller
try:
    import h1_watch as h1_watch_mod
except Exception:
    h1_watch_mod = None


def _need_watch():
    if not h1_watch_mod:
        raise HttpError(503, "h1_watch module unavailable")
    return h1_watch_mod


@route("GET", r"/api/h1/job")
def r_h1_job(ctx, m):
    """Health of the incremental poller: last run, failure streak, backoff, cumulative cost.

    This is the answer to "is the sync actually running?". The cron job runs with --quiet and
    writes nothing to its log on success, so an empty log is the HEALTHY case, not a broken one.
    """
    return _need_watch().status(ctx.conn)


@route("GET", r"/api/h1/events")
def r_h1_events(ctx, m):
    """Upstream changes the poller noticed: state transitions, bounties, collaborators."""
    w = _need_watch()
    try:
        limit = min(int(ctx.q("limit") or 50), 500)
    except ValueError:
        limit = 50
    events = w.recent_events(
        ctx.conn, limit=limit, since=ctx.q("since") or None,
        unseen_only=ctx.q("unseen") == "1", event_type=ctx.q("type") or None)
    return {"events": events, "count": len(events)}


@route("POST", r"/api/h1/events/seen", scope="write")
def r_h1_events_seen(ctx, m):
    """Mark events read. No ids means all of them."""
    w = _need_watch()
    ids = (ctx.body or {}).get("ids")
    n = w.mark_seen(ctx.conn, ids=ids)
    return {"ok": True, "marked": n}


@route("POST", r"/api/h1/poll", scope="write")
def r_h1_poll(ctx, m):
    """Run one incremental poll now, without waiting for cron.

    `force` skips the failure backoff window - the button exists precisely for the case where
    the credential was just fixed and you do not want to wait out the backoff.
    """
    w = _need_watch()
    t0 = time.time()
    try:
        res = w.poll(ctx.conn, verbose=False,
                     program_handle=(ctx.body or {}).get("program_handle"),
                     force=bool((ctx.body or {}).get("force")))
    except Exception as e:
        raise HttpError(502, str(e))
    res = dict(res or {})
    res["elapsed_ms"] = int((time.time() - t0) * 1000)
    common.audit(ctx.conn, ctx.user, "h1_poll", detail=json.dumps(res), remote=ctx.remote)
    return res


def effective_hacktivity_program(ctx):
    """Which program the hacktivity tile watches: the operator's persisted pick, or - absent one -
    the alphabetically first program they track. Defaulting to a real program keeps the picker from
    showing a magic 'credential' fallback nobody recognises, and keeps the polled feed and the
    selected option in step. Returns '' only when no programs are tracked yet."""
    chosen = (ctx.cfg.get("hacktivity_program") or "").strip()
    if chosen:
        return chosen
    row = ctx.conn.execute(
        "SELECT slug FROM programs WHERE slug <> '' "
        "ORDER BY LOWER(COALESCE(NULLIF(name, ''), slug)) LIMIT 1").fetchone()
    return (row["slug"] if row else "") or ""


@route("GET", r"/api/hacktivity")
def r_hacktivity(ctx, m):
    """The program's public activity feed, served from storage. Never calls HackerOne.

    Every open tab polls this endpoint; cron polls HackerOne. Fetching here instead would turn
    "three browser tabs left open overnight" into 864 API requests, and would make the dashboard's
    render time depend on HackerOne being up.

    Degradation is the point of the extra fields. `as_of`, `age_seconds` and `stale` describe how
    old the stored rows are, so the tile can show the last known entries with an honest timestamp
    instead of going blank the moment the feed breaks. Nothing here can raise: a missing module or
    an empty table returns an empty list with `configured: false`, not a 5xx.
    """
    if hacktivity_mod is None:
        return {"items": [], "stored": 0, "as_of": "", "age_seconds": None, "stale": True,
                "status": "unavailable", "error": "hacktivity module unavailable",
                "configured": False, "program": ""}
    try:
        limit = max(1, min(50, int(ctx.q("limit", 5))))
    except ValueError:
        limit = 5
    out = hacktivity_mod.recent(ctx.conn, limit=limit)
    # The dashboard's program picker reads this to show which program is being monitored; an unset
    # pick resolves to the alphabetically first program, not a magic credential fallback.
    out["program"] = effective_hacktivity_program(ctx)
    return out


@route("POST", r"/api/hacktivity/refresh", scope="write")
def r_hacktivity_refresh(ctx, m):
    """Refresh now rather than waiting for the next 5-minute tick.

    One request to HackerOne, and it reports its own failure in the response body rather than
    raising, so the button never leaves the tile in an error state the stored rows could have
    answered.
    """
    if hacktivity_mod is None:
        # Degrade, do not raise: the button should never leave the tile in a red error state.
        # Matches GET /api/hacktivity's unavailable shape, with a refresh outcome the tile reads.
        return {"items": [], "stored": 0, "as_of": "", "age_seconds": None, "stale": True,
                "status": "unavailable", "error": "hacktivity module unavailable",
                "configured": False, "program": "",
                "refresh": {"ok": False, "error": "hacktivity module unavailable"}}
    body = ctx.body or {}
    # The dashboard's program picker POSTs {program} to change which feed is watched; persist the
    # choice so it sticks, then poll THAT program. Absent a pick, refresh() falls back to the
    # HackerOne credential's own program handle.
    if "program" in body:
        ctx.cfg["hacktivity_program"] = (body.get("program") or "").strip()
        common.save_config(ctx.cfg)
    # Absent a pick, poll the alphabetically first program - the same default the picker shows -
    # rather than the credential's own program, so the feed matches the selected option.
    program = effective_hacktivity_program(ctx) or None
    res = hacktivity_mod.refresh(ctx.conn, verbose=False, force=bool(body.get("force")),
                                 program_handle=program)
    # The refreshed view travels back with the outcome, so the tile re-renders from one response.
    # Nested rather than merged: `stored` means "rows written this run" in one and "rows held" in
    # the other, and flattening those into one key is how a number starts lying.
    # Honour the caller's row count. This used to be a hardcoded 5 while GET /api/hacktivity took
    # a limit, so pressing Refresh silently shrank a full card to five rows and only a reload put
    # them back. recent() clamps to 1..50 itself.
    try:
        limit = int(body.get("limit") or 5)
    except (TypeError, ValueError):
        limit = 5
    out = hacktivity_mod.recent(ctx.conn, limit=limit)
    out["refresh"] = res
    out["program"] = program or ""
    return out


# ------------------------------------------------------------------ regression
# The queue over shipped fixes. Every one of these reads or writes rows that are already local -
# `reports` for the candidates, `regressions` for the verdicts - so none of them can be slowed
# down, rate-limited or made to fail by HackerOne being unreachable.
def _regression_mod():
    """The module or a 503. Every route below opens with this, so a checkout missing the module
    answers honestly on the tab instead of 500ing somewhere deeper."""
    if regression_mod is None:
        raise HttpError(503, "regression module unavailable")
    return regression_mod


@route("GET", r"/api/regression")
def r_regression(ctx, m):
    """The queue, its bucket counts and the window in force."""
    mod = _regression_mod()
    return mod.queue(ctx.conn, ctx.cfg,
                     bucket=ctx.q("bucket", "due"),
                     program=ctx.q("program", ""),
                     q=ctx.q("q", ""),
                     limit=ctx.q("limit", 200),
                     offset=ctx.q("offset", 0))


@route("GET", r"/api/regression/(\d+)")
def r_regression_detail(ctx, m):
    """One entry with the original report body and the triage thread attached.

    The thread is the point: it is where the program said what it changed, and deciding what to
    re-test without re-reading it is guesswork. Served from the local row, so it is only as current
    as the last `h1.py --sync`.
    """
    mod = _regression_mod()
    item = mod.detail(ctx.conn, m.group(1), ctx.cfg)
    if item is None:
        raise HttpError(404, "no resolved report #%s in this database" % m.group(1))
    return item


@route("POST", r"/api/regression/(\d+)/verdict", scope="write")
def r_regression_verdict(ctx, m):
    """Record what a retest found: holds, broken, skipped - or pending to clear a misclick."""
    mod = _regression_mod()
    h1_id = m.group(1)
    body = ctx.body or {}
    verdict = (body.get("verdict") or "").strip().lower()
    note = body.get("note")
    before = mod.detail(ctx.conn, h1_id, ctx.cfg)
    if before is None:
        raise HttpError(404, "no resolved report #%s in this database" % h1_id)
    try:
        out = mod.set_verdict(ctx.conn, h1_id, verdict, note=note)
    except ValueError as e:
        raise HttpError(400, str(e))
    common.audit(ctx.conn, ctx.user, "regression_verdict", "reports", None,
                 "#%s %s -> %s" % (h1_id, before.get("verdict"), verdict), ctx.remote)
    return out


@route("POST", r"/api/regression/(\d+)/snooze", scope="write")
def r_regression_snooze(ctx, m):
    """Push the due date out, or clear the override and fall back to the window."""
    mod = _regression_mod()
    h1_id = m.group(1)
    body = ctx.body or {}
    try:
        if body.get("clear"):
            out = mod.clear_snooze(ctx.conn, h1_id)
        else:
            out = mod.snooze(ctx.conn, h1_id, days=body.get("days"), due_on=body.get("due_on"))
    except ValueError as e:
        raise HttpError(400, str(e))
    if out is None:
        raise HttpError(404, "no resolved report #%s in this database" % h1_id)
    common.audit(ctx.conn, ctx.user, "regression_snooze", "reports", None,
                 "#%s due %s" % (h1_id, out.get("due_on")), ctx.remote)
    return out


@route("POST", r"/api/regression/(\d+)/lead", scope="write")
def r_regression_lead(ctx, m):
    """Draft the bypass lead for a fix that did not hold, and file it in a target's workspace.

    Same contract as POST /api/leads - write the file, then re-index that one file - because the
    markdown is the record and the row is the index of it. What this adds is the pre-fill: the
    original report id, its close date, its asset, its CWE and the retest note, which are the
    fields a bypass lead would otherwise be re-typed from the Tracker.

    The lead is deliberately NOT written for any other verdict. A lead is a claim that something is
    wrong, and drafting one for a fix that holds would put a false finding in the queue.
    """
    mod = _regression_mod()
    h1_id = m.group(1)
    item = mod.detail(ctx.conn, h1_id, ctx.cfg)
    if item is None:
        raise HttpError(404, "no resolved report #%s in this database" % h1_id)
    if item.get("verdict") != "broken":
        raise HttpError(400, "record a 'broken' verdict first; a lead states that a fix failed")

    b = ctx.body or {}
    target = (b.get("target") or "").strip()
    ws = _target_workspace(ctx.conn, target) if target else None
    if not ws:
        raise HttpError(400, "unknown or missing target; pick the workspace to file the lead in")
    # The report's own class where the CWE maps to one, and NOT common.UNCLASSED when it does not:
    # that is a display label, and a literal `Unclassified/` directory in the workspace would be a
    # class invented by a fallback. A lead with no class lands in the workspace's own notes/, which
    # is exactly what ingest.classify_path expects.
    klass = (b.get("class") or "").strip() or common.class_for_report(item)
    if klass == common.UNCLASSED:
        klass = None

    folder = os.path.join(ws, klass, "notes") if klass else os.path.join(ws, "notes")
    fname = common.slugify("%s-fix-bypass-%s" % (h1_id, item.get("title") or "")) + ".md"
    dest = common.safe_under(ws, os.path.join(folder, fname))
    if not dest:
        raise HttpError(400, "resolved path escapes the workspace")
    if os.path.exists(dest):
        raise HttpError(409, "file already exists: " + dest)

    common.write_text_atomic(dest, mod.lead_markdown(item, researcher=ctx.user or ""))
    _reindex(ctx.conn, dest)
    mod.record_lead(ctx.conn, h1_id, dest)
    common.audit(ctx.conn, ctx.user, "regression_lead", "leads", None,
                 "#%s -> %s" % (h1_id, dest), ctx.remote)
    out = mod.detail(ctx.conn, h1_id, ctx.cfg)
    out["lead_path"] = dest
    return out


@route("GET", r"/api/status")
def r_status(ctx, m):
    """Everything the Status tab needs, in one request.

    Deliberately one endpoint rather than five: the page is a health dashboard, and a partial
    render where three cards loaded and two failed is worse than one honest error.
    """
    out = {"version": VERSION, "now": common.now_iso()}

    out["integration"] = h1_mod.status(ctx.conn) if h1_mod else {"configured": False}
    out["poller"] = h1_watch_mod.status(ctx.conn) if h1_watch_mod else None
    out["hacktivity"] = hacktivity_mod.status(ctx.conn) if hacktivity_mod else None
    # No job, no credential and no request, so there is no run history to report: the only honest
    # health signal for the regression queue is how much of it has ever been looked at.
    out["regression"] = regression_mod.status(ctx.conn, ctx.cfg) if regression_mod else None

    # Advisory feed freshness. The Audit Log already warns past 24h; the number belongs here too.
    def one(sql, default=None):
        try:
            r = ctx.conn.execute(sql).fetchone()
            return r[0] if r else default
        except Exception:
            return default

    out["advisories"] = {
        "count": one("SELECT COUNT(*) FROM advisories", 0),
        "latest_published": one("SELECT MAX(published) FROM advisories"),
        "last_fetched": one("SELECT MAX(fetched_at) FROM advisories"),
        "matches": one("SELECT COUNT(*) FROM advisory_matches", 0),
    }
    out["index"] = {
        "reports": one("SELECT COUNT(*) FROM reports WHERE source='hackerone'"
                       " AND kind='report'", 0),
        "reports_with_body": one("SELECT COUNT(*) FROM reports WHERE source='hackerone'"
                                 " AND COALESCE(body,'') <> ''", 0),
        "reports_with_thread": one("SELECT COUNT(*) FROM reports WHERE source='hackerone'"
                                   " AND COALESCE(thread,'') <> ''", 0),
        "leads": one("SELECT COUNT(*) FROM leads WHERE " + LEAD_IS_REAL, 0),
        "shadow_rows": one("SELECT COUNT(*) FROM reports WHERE tracker_only=1", 0),
        "last_indexed": one("SELECT MAX(indexed_at) FROM reports"),
    }
    out["bounty"] = _bounty_stats(ctx.conn)
    return out


# ---------------------------------------------------------------- certificates
def _cert_info(path):
    """Parse a certificate with the openssl CLI. Returns {} if it cannot be read."""
    if not os.path.exists(path):
        return {}
    def run(*args):
        try:
            r = subprocess.run(["openssl", "x509", "-in", path, "-noout"] + list(args),
                               capture_output=True, text=True, timeout=10)
            return r.stdout.strip()
        except Exception:
            return ""
    san = run("-ext", "subjectAltName")
    san_line = ""
    for line in san.splitlines():
        line = line.strip()
        if line.startswith(("DNS:", "IP Address:", "IP:")):
            san_line = line
    dates = run("-dates")
    not_before = not_after = ""
    for line in dates.splitlines():
        if line.startswith("notBefore="):
            not_before = line.split("=", 1)[1]
        elif line.startswith("notAfter="):
            not_after = line.split("=", 1)[1]
    fp = run("-fingerprint", "-sha256")
    return {
        "path": path,
        "exists": True,
        "subject": run("-subject").replace("subject=", "").strip(),
        "issuer": run("-issuer").replace("issuer=", "").strip(),
        "san": san_line,
        "not_before": not_before,
        "not_after": not_after,
        "sha256": fp.split("=", 1)[1].strip() if "=" in fp else "",
        "serial": run("-serial").replace("serial=", "").strip(),
    }


@route("GET", r"/api/certs")
def r_certs(ctx, m):
    """TLS material for the Certificates view.

    Only public certificate data is returned. Private keys are never read, never parsed and
    never served - see r_certs_ca for the single file this app will hand out.
    """
    cfg = ctx.cfg
    cert = cfg.get("tls_cert", "")
    ca = os.path.join(os.path.dirname(cert), "ca.pem") if cert else ""
    server_info = _cert_info(cert)
    ca_info = _cert_info(ca) if ca else {}
    self_signed = bool(server_info) and server_info.get("subject") == server_info.get("issuer")
    return {
        "app_name": common.app_name(cfg),
        "bind_host": cfg.get("bind_host"),
        "bind_port": cfg.get("bind_port"),
        "url": "https://%s:%s/" % (cfg.get("bind_host"), cfg.get("bind_port")),
        "server": server_info,
        "ca": ca_info,
        "ca_available": bool(ca_info),
        "self_signed": self_signed,
        "download": "/api/certs/ca",
    }


@route("GET", r"/api/certs/ca")
def r_certs_ca(ctx, m):
    """Download the CA certificate.

    Deliberately its own endpoint rather than /api/fs/download: the browse deny-list blocks
    `*.pem` (correctly - it also matches key.pem and ca.key), but the CA CERTIFICATE is public
    material whose whole purpose is distribution. This path is hardcoded to ca.pem so it can
    never be steered at a private key.
    """
    cert = ctx.cfg.get("tls_cert", "")
    if not cert:
        raise HttpError(404, "no TLS material configured")
    ca = os.path.join(os.path.dirname(cert), "ca.pem")
    if not os.path.isfile(ca):
        raise HttpError(404, "no local CA - the server cert is self-signed")
    with open(ca, "rb") as fh:
        raw = fh.read()
    name = common.slugify(common.app_name(ctx.cfg)) + "-ca.crt"
    return (raw, "application/x-x509-ca-cert",
            {"Content-Disposition": 'attachment; filename="%s"' % name})


@route("GET", r"/api/notes/tree")
def r_notes_tree(ctx, m):
    """All indexed markdown grouped by containing folder.

    This is the 'Notes by folder' view: an organisational tree over the notes themselves,
    distinct from /api/fs/tree (which is the raw filesystem) and from /api/leads (flat list).
    Optional ?target= filters to one workspace.
    """
    target = ctx.q("target")
    folders = {}

    def add(row, entity):
        fp = row["file_path"]
        if not fp:
            return
        folder = os.path.dirname(fp)
        g = folders.setdefault(folder, {"folder": folder, "files": []})
        g["files"].append({
            "id": row["id"], "entity": entity, "path": fp,
            "name": os.path.basename(fp),
            "ref": row["ref"] if "ref" in row.keys() else None,
            "title": row["title"], "target": row["target"] if "target" in row.keys() else None,
            "status": (row["status"] if "status" in row.keys() else
                       (row["state"] if "state" in row.keys() else None)),
            "mtime": row["mtime"] if "mtime" in row.keys() else None,
        })

    for entity, sql in (
        ("leads", "SELECT l.*, t.slug AS target FROM leads l"
                  " LEFT JOIN targets t ON t.id=l.target_id WHERE l.file_path IS NOT NULL"),
        ("reports", "SELECT l.*, t.slug AS target FROM reports l"
                    " LEFT JOIN targets t ON t.id=l.target_id WHERE l.file_path IS NOT NULL"),
    ):
        if target:
            sql += " AND t.slug = ?"
            rows = ctx.conn.execute(sql, (target,)).fetchall()
        else:
            rows = ctx.conn.execute(sql).fetchall()
        for r in rows:
            add(r, entity)

    out = []
    for folder, g in folders.items():
        rel = folder[len(common.HUNT_ROOT):].lstrip("/") if folder.startswith(common.HUNT_ROOT) else folder
        g["label"] = rel
        g["count"] = len(g["files"])
        g["files"].sort(key=lambda f: (f["ref"] or "zzz", f["name"]))
        out.append(g)
    out.sort(key=lambda g: g["label"])
    return {"folders": out, "total_files": sum(g["count"] for g in out)}


@route("GET", r"/api/audit")
def r_audit(ctx, m):
    try:
        limit = max(1, min(500, int(ctx.q("limit", 100))))
    except ValueError:
        limit = 100
    rows = ctx.conn.execute(
        "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"items": [dict(r) for r in rows]}


# ====================================================================== handler
def _no_crlf(value):
    """Strip CR and LF from an outgoing header value so a user-influenced string - a guessed
    MIME type, a Content-Disposition filename built from a browse path - can never inject
    additional response headers or split the response (CWE-113). Header NAMES in this server
    are all internal constants, but values are sanitised at the single choke point in _send."""
    return re.sub(r"[\r\n]", "", str(value))


class Handler(BaseHTTPRequestHandler):
    server_version = "app/" + VERSION   # name-independent on purpose
    sys_version = ""
    protocol_version = "HTTP/1.1"

    cfg = None
    conn_factory = staticmethod(common.connect)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s - %s\n" % (self.client_address[0],
                                             time.strftime("%H:%M:%S"), fmt % args))

    # ------------------------------------------------------------ plumbing
    def _send(self, status, payload=None, raw=None, content_type="application/json",
              extra_headers=None):
        if raw is None:
            raw = json.dumps(payload, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", _no_crlf(content_type))
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if getattr(self, "set_cookie", None):
            self.send_header("Set-Cookie", self.set_cookie)
        for k, v in (extra_headers or {}).items():
            self.send_header(_no_crlf(k), _no_crlf(v))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise HttpError(413, "request body too large")
        return self.rfile.read(length) if length else b""

    def _parse_multipart(self, raw, content_type):
        """Minimal, defensive multipart/form-data parser. Returns {name: {filename, data}}."""
        m = re.search(r'boundary="?([^";]+)"?', content_type)
        if not m:
            raise HttpError(400, "missing multipart boundary")
        boundary = ("--" + m.group(1)).encode("ascii")
        out = {}
        for chunk in raw.split(boundary):
            if not chunk or chunk in (b"--\r\n", b"--", b"\r\n"):
                continue
            chunk = chunk.lstrip(b"\r\n")
            if b"\r\n\r\n" not in chunk:
                continue
            head, data = chunk.split(b"\r\n\r\n", 1)
            data = data.rstrip(b"\r\n")
            head_s = head.decode("utf-8", "replace")
            nm = re.search(r'name="([^"]*)"', head_s)
            if not nm:
                continue
            fn = re.search(r'filename="([^"]*)"', head_s)
            out[nm.group(1)] = {"filename": fn.group(1) if fn else None, "data": data}
        return out

    def _identity(self, conn):
        authz = self.headers.get("Authorization") or ""
        if authz.startswith("Bearer "):
            return auth.lookup_api_token(conn, authz[7:].strip()), True
        cookie = self.headers.get("Cookie") or ""
        token = None
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == common.COOKIE_NAME:
                token = v
        self.session_token = token
        return auth.lookup_session(conn, token), False

    # ------------------------------------------------------------ dispatch
    def _handle(self, method):
        self.set_cookie = None
        self.session_token = None
        self.multipart = None
        cfg = Handler.cfg

        # 1. IP allowlist, before anything else including auth.
        if not common.client_allowed(self.client_address[0], cfg.get("allow_remote")):
            self._send(403, {"error": "client address not permitted"})
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if not path.startswith("/api/"):
            self._serve_static(path)
            return

        conn = None
        try:
            conn = self.conn_factory()
            identity, via_bearer = self._identity(conn)

            match = None
            handler_fn = scope = None
            public = False
            allowed_methods = set()
            for m_method, pattern, fn, sc, pub in ROUTES:
                mm = pattern.match(path)
                if mm:
                    allowed_methods.add(m_method)
                    if m_method == method:
                        match, handler_fn, scope, public = mm, fn, sc, pub
                        break
            if handler_fn is None:
                if allowed_methods:
                    raise HttpError(405, "method not allowed")
                raise HttpError(404, "no such endpoint")

            if not public:
                if not identity:
                    raise HttpError(401, "authentication required")
                # CSRF: cookie-authenticated mutations must carry the custom header.
                if method in ("POST", "PUT", "DELETE") and not via_bearer:
                    if self.headers.get(common.CSRF_HEADER) != "1":
                        raise HttpError(403, "missing %s header" % common.CSRF_HEADER)
                if scope == "write" and identity.get("scope") != "write":
                    raise HttpError(403, "write scope required")

            body = None
            if method in ("POST", "PUT"):
                raw = self._read_body()
                ctype = self.headers.get("Content-Type") or ""
                if ctype.startswith("multipart/form-data"):
                    self.multipart = self._parse_multipart(raw, ctype)
                elif raw:
                    try:
                        body = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        raise HttpError(400, "body must be valid JSON")

            ctx = Ctx(self, conn, cfg, identity, query, body)
            result = handler_fn(ctx, match)
            if isinstance(result, tuple):  # (raw_bytes, content_type, headers)
                raw, ctype, hdrs = result
                self._send(200, raw=raw, content_type=ctype, extra_headers=hdrs)
            else:
                self._send(200, result)
        except HttpError as e:
            self._send(e.status, {"error": e.message})
        except BrokenPipeError:
            pass
        except Exception as e:  # never leak a traceback to the client
            sys.stderr.write("ERROR %s %s: %r\n" % (method, path, e))
            self._send(500, {"error": "internal error"})
        finally:
            if conn:
                conn.close()

    def _serve_static(self, path):
        # The download endpoint is special-cased here so it can stream raw bytes.
        if path == "/api/fs/download":
            return
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        target = common.safe_under(common.STATIC_DIR, os.path.join(common.STATIC_DIR, rel))
        if not target or not os.path.isfile(target):
            # SPA fallback
            target = os.path.join(common.STATIC_DIR, "index.html")
            if not os.path.isfile(target):
                self._send(404, {"error": "static assets not built yet"})
                return
        ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"
        with open(target, "rb") as fh:
            raw = fh.read()
        # NO CACHE HEADERS AT ALL used to be sent here, which is not the same as "do not cache".
        # With nothing to go on a browser falls back to heuristic caching and may hold app.css or
        # app.js for as long as it likes, so a restart deployed CSS that never reached the tab
        # looking at it. That cost two rounds of "I do not see the change on my live" in one
        # evening, both times against code that was correct and already serving.
        #
        # no-store rather than an ETag and 304s: this is a single-operator LAN app serving three
        # small files off local disk, so revalidation logic buys nothing and the failure mode it
        # would add - a stale validator - is the exact bug being fixed.
        self._send(200, raw=raw, content_type=ctype,
                   extra_headers={"Cache-Control": "no-store, must-revalidate"})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/fs/download":
            self._download(urllib.parse.parse_qs(parsed.query))
            return
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_HEAD(self):
        self._handle("GET")

    def _download(self, query):
        cfg = Handler.cfg
        if not common.client_allowed(self.client_address[0], cfg.get("allow_remote")):
            self._send(403, {"error": "client address not permitted"})
            return
        conn = None
        try:
            conn = self.conn_factory()
            identity, _ = self._identity(conn)
            if not identity:
                raise HttpError(401, "authentication required")
            path = (query.get("path") or [None])[0]
            resolved = _resolve_browse(cfg, path)
            if not os.path.isfile(resolved):
                raise HttpError(400, "not a file")
            with open(resolved, "rb") as fh:
                raw = fh.read()
            self._send(200, raw=raw, content_type="application/octet-stream",
                       extra_headers={"Content-Disposition":
                                      'attachment; filename="%s"' % os.path.basename(resolved)})
        except HttpError as e:
            self._send(e.status, {"error": e.message})
        finally:
            if conn:
                conn.close()


# ====================================================================== cli
def gencert(cfg, use_ca=True):
    """Issue the server certificate.

    Default path creates a small local CA (once) and signs the server cert with it. You then
    import ca.pem into the client trust store ONE time; every future re-issue is trusted
    automatically. Importing a bare self-signed leaf has to be redone on every regeneration,
    which is why that is no longer the default.
    """
    cert, key = cfg["tls_cert"], cfg["tls_key"]
    tls_dir = os.path.dirname(cert)
    os.makedirs(tls_dir, exist_ok=True)
    host = cfg["bind_host"]
    name = common.app_name(cfg)
    san = "IP:%s,IP:127.0.0.1,DNS:localhost" % host

    if not use_ca:
        cmd = ["openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "825",
               "-nodes", "-keyout", key, "-out", cert,
               "-subj", "/CN=" + name.lower(), "-addext", "subjectAltName=" + san]
        subprocess.run(cmd, check=True, capture_output=True)
        os.chmod(key, 0o600)
        os.chmod(cert, 0o644)
        print("wrote self-signed %s and %s (SAN: %s)" % (cert, key, san))
        return

    ca_cert = os.path.join(tls_dir, "ca.pem")
    ca_key = os.path.join(tls_dir, "ca.key")

    if not (os.path.exists(ca_cert) and os.path.exists(ca_key)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "3650",
             "-nodes", "-keyout", ca_key, "-out", ca_cert,
             "-subj", "/CN=%s Local CA/O=%s" % (name, name),
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
            check=True, capture_output=True)
        os.chmod(ca_key, 0o600)
        os.chmod(ca_cert, 0o644)
        print("created CA: %s (valid 10 years)" % ca_cert)
    else:
        print("reusing existing CA: %s" % ca_cert)

    csr = os.path.join(tls_dir, "server.csr")
    ext = os.path.join(tls_dir, "server.ext")
    with open(ext, "w") as fh:
        fh.write("basicConstraints=CA:FALSE\n"
                 "keyUsage=critical,digitalSignature,keyEncipherment\n"
                 "extendedKeyUsage=serverAuth\n"
                 "subjectAltName=%s\n" % san)
    subprocess.run(["openssl", "req", "-newkey", "rsa:4096", "-nodes", "-keyout", key,
                    "-out", csr, "-subj", "/CN=%s" % host], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
                    "-CAcreateserial", "-out", cert, "-days", "825", "-sha256",
                    "-extfile", ext], check=True, capture_output=True)
    os.remove(csr)
    os.remove(ext)
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    print("issued server cert %s (SAN: %s), signed by the local CA" % (cert, san))
    print("\nIMPORT THIS ON THE CLIENT (one time):\n  %s\n" % ca_cert)


def adduser(cfg, username, from_stdin=False):
    if from_stdin:
        pw1 = sys.stdin.readline().rstrip("\n")
        if not pw1:
            sys.exit("no password on stdin")
    else:
        pw1 = getpass.getpass("Password for %s: " % username)
        pw2 = getpass.getpass("Repeat: ")
        if pw1 != pw2:
            sys.exit("passwords do not match")
    minlen = int(cfg.get("min_password_length", 12))
    if len(pw1) < minlen:
        sys.exit("use at least %d characters (min_password_length in config.json)" % minlen)
    cfg.setdefault("users", {})[username] = auth.hash_password(pw1)
    common.save_config(cfg)
    print("user %s saved to %s" % (username, common.CONFIG_PATH))


def main():
    ap = argparse.ArgumentParser(description=common.app_name() + " server")
    ap.add_argument("--adduser", metavar="USERNAME")
    ap.add_argument("--password-stdin", action="store_true",
                    help="read the password for --adduser from stdin (scripted setup)")
    ap.add_argument("--gencert", action="store_true",
                    help="issue the server cert from a local CA (creates the CA on first run)")
    ap.add_argument("--self-signed", action="store_true",
                    help="with --gencert: bare self-signed leaf instead of a CA-signed cert")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--no-tls", action="store_true", help="HTTP only (loopback testing)")
    args = ap.parse_args()

    cfg = common.load_config()
    if args.host:
        cfg["bind_host"] = args.host
    if args.port:
        cfg["bind_port"] = args.port

    if args.gencert:
        gencert(cfg, use_ca=not args.self_signed)
        return
    if args.adduser:
        adduser(cfg, args.adduser, from_stdin=args.password_stdin)
        return

    if not cfg.get("users"):
        sys.exit("No users configured. Run:  python3 server.py --adduser <name>")

    conn = common.connect()
    common.init_db(conn)
    auth.purge_expired_sessions(conn)
    conn.close()

    Handler.cfg = cfg
    httpd = ThreadingHTTPServer((cfg["bind_host"], int(cfg["bind_port"])), Handler)
    scheme = "http"
    if not args.no_tls:
        if not (os.path.exists(cfg["tls_cert"]) and os.path.exists(cfg["tls_key"])):
            sys.exit("TLS material missing. Run:  python3 server.py --gencert")
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sslctx.load_cert_chain(cfg["tls_cert"], cfg["tls_key"])
        httpd.socket = sslctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    print("%s %s on %s://%s:%s" % (common.app_name(cfg), VERSION, scheme, cfg["bind_host"], cfg["bind_port"]))
    print("allowlist: %s" % (cfg.get("allow_remote") or "ALL (open)"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
