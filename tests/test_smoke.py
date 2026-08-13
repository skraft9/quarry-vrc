#!/usr/bin/env python3
"""Smoke test for the dashboard sparkline aggregation added to /api/stats.

Imports the real server module and exercises its read-only sparkline helpers directly, plus one
end-to-end call of r_stats against a THROWAWAY in-memory database built from core/schema.sql. It
never opens a socket, never touches config.json, and opens the checked-in index.db read-only, so
the live 9443 / private 8443 instances and the operator's data are untouched.

    python3 tests/test_smoke.py

Exits non-zero on the first failure and prints what broke.
"""
import os
import sqlite3
import sys
import types

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(APP, "core"))

import server  # noqa: E402

results = []


def check(name, cond, detail=""):
    ok = bool(cond)
    results.append((name, ok, detail))
    print(("  PASS  " if ok else "  FAIL  ") + name
          + (("  <- " + str(detail)) if detail and not ok else ""))
    return ok


def nondecreasing(seq):
    return all(seq[i] <= seq[i + 1] for i in range(len(seq) - 1))


# ---------------------------------------------------------------- _spark_epoch
print("-- _spark_epoch: timestamp parsing --")
check("None -> None", server._spark_epoch(None) is None)
check("empty -> None", server._spark_epoch("") is None)
check("junk -> None", server._spark_epoch("not-a-date") is None)
check("ISO datetime parses", isinstance(server._spark_epoch("2026-08-06T20:02:24"), float))
check("bare date parses", isinstance(server._spark_epoch("2026-08-06"), float))
check("trailing Z tolerated", server._spark_epoch("2026-08-06T20:02:24.338Z")
      == server._spark_epoch("2026-08-06T20:02:24"))
check("offset tolerated", server._spark_epoch("2026-08-06T20:02:24+00:00")
      == server._spark_epoch("2026-08-06T20:02:24"))
check("epoch float passthrough", server._spark_epoch(1670000000) == 1670000000.0)
check("epoch string parses", server._spark_epoch("1670000000.5") == 1670000000.5)
check("ordering is preserved",
      server._spark_epoch("2026-01-01") < server._spark_epoch("2026-06-01"))


# ---------------------------------------------------------------- _cumulative_series
print("\n-- _cumulative_series: shape + invariants --")
P = server.SPARK_POINTS
check("length is SPARK_POINTS", len(server._cumulative_series([], 9)) == P)

empty0 = server._cumulative_series([], 0)
check("empty entity is a flat zero series", empty0 == [0] * P, empty0)

ramp = server._cumulative_series([], 9)
check("no-timestamp entity ramps monotonically", nondecreasing(ramp), ramp)
check("ramp ends at the total", ramp[-1] == 9, ramp)
check("ramp starts at or below the total", ramp[0] <= 9)

uniform = server._cumulative_series(["2026-01-01"] * 5, 5)
check("single shared timestamp degrades to a ramp ending at total",
      nondecreasing(uniform) and uniform[-1] == 5, uniform)

bucketed = server._cumulative_series(
    ["2026-01-01", "2026-02-01", "2026-03-01", "2026-06-01"], 4)
check("distinct timestamps bucket monotonically", nondecreasing(bucketed), bucketed)
check("bucketed series ends exactly at total", bucketed[-1] == 4, bucketed)

# Rows with no usable timestamp are folded into a baseline so the line still ends at `total`.
baseline = server._cumulative_series([None, None, "2026-01-01", "2026-06-01"], 5)
check("undated rows raise the baseline, end stays at total",
      nondecreasing(baseline) and baseline[-1] == 5 and baseline[0] >= 3, baseline)


# ---------------------------------------------------------------- end to end r_stats
print("\n-- r_stats: sparklines wired into /api/stats --")
conn = sqlite3.connect(":memory:")
conn.executescript(open(os.path.join(APP, "core", "schema.sql")).read())
conn.executescript("""
INSERT INTO programs(id,slug,name,updated_at,synced_at) VALUES
 (1,'acme','Acme','2026-07-01T10:00:00','2026-07-02T10:00:00');
INSERT INTO targets(id,slug,name,workspace) VALUES (1,'web','Web','/ws');
INSERT INTO scopes(id,program_id,h1_id,identifier,synced_at) VALUES
 (1,1,'s1','*.acme.com','2026-06-01T10:00:00'),(2,1,'s2','api.acme.com','2026-07-15T10:00:00');
INSERT INTO leads(id,target_id,title,status,file_path,body,indexed_at) VALUES
 (1,1,'L1','open','/a.md','b','2026-05-01T00:00:00'),
 (2,1,'L2','confirmed','/b.md','b','2026-06-10T00:00:00'),
 (3,1,'apparatus','unknown','/c.md','b','2026-06-20T00:00:00');
INSERT INTO reports(id,title,state,source,kind,submitted_on,bounty,my_bounty) VALUES
 (1,'R1','triaged','hackerone','report','2026-04-01T00:00:00','',''),
 (2,'R2','resolved','hackerone','report','2026-05-01T00:00:00','500','500'),
 (3,'R3','resolved','hackerone','report','2026-06-01T00:00:00','0','0');
INSERT INTO advisories(id,title,published,indexed_at) VALUES
 (1,'A1','2026-03-01','2026-03-02T00:00:00'),(2,'A2','2026-05-01','2026-05-02T00:00:00');
INSERT INTO payloads(id,category,payload,file_path,indexed_at) VALUES
 (1,'XSS','x','/p','2026-01-01T00:00:00'),(2,'SQL','y','/q','2026-02-01T00:00:00');
""")
conn.commit()

res = server.r_stats(types.SimpleNamespace(conn=conn), None)
check("response carries a sparklines block", isinstance(res.get("sparklines"), dict))
sp = res.get("sparklines", {})
counts = res.get("counts", {})
check("all six overview entities have a series",
      set(sp) == {"reports", "leads", "advisories", "programs", "scopes", "payloads"}, sorted(sp))
for name, series in sp.items():
    check("%s series has SPARK_POINTS points" % name, len(series) == P, len(series))
    check("%s series is non-decreasing" % name, nondecreasing(series), series)
# The end of every line must equal the number its tile prints.
check("reports series ends at the reports count", sp["reports"][-1] == counts["reports"] == 3, (sp["reports"][-1], counts.get("reports")))
check("leads series ends at the scoped leads count (excludes 'unknown')",
      sp["leads"][-1] == counts["leads"] == 2, (sp["leads"][-1], counts.get("leads")))
check("scopes series ends at the scopes count", sp["scopes"][-1] == counts["scopes"] == 2, (sp["scopes"][-1], counts.get("scopes")))
check("payloads series ends at the payloads count", sp["payloads"][-1] == counts["payloads"] == 2, (sp["payloads"][-1], counts.get("payloads")))
conn.close()


# ---------------------------------------------------------------- real index.db (payload-only ok)
print("\n-- _overview_sparklines: against the checked-in index.db --")
db = os.path.join(APP, "index.db")
if os.path.exists(db):
    rc = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    live_counts = {}
    for tbl in ("programs", "targets", "scopes", "uploads", "payloads"):
        try:
            live_counts[tbl] = rc.execute("SELECT COUNT(*) FROM %s" % tbl).fetchone()[0]
        except Exception:
            live_counts[tbl] = 0
    for nm in ("leads", "reports", "advisories"):
        try:
            live_counts[nm] = rc.execute(
                "SELECT COUNT(*) FROM %s l WHERE %s"
                % (server.ENTITIES[nm]["table"], server.entity_scope(nm))).fetchone()[0]
        except Exception:
            live_counts[nm] = 0
    live = server._overview_sparklines(rc, live_counts)
    check("every series is present and length SPARK_POINTS",
          all(len(live[k]) == P for k in live), {k: len(v) for k, v in live.items()})
    check("every series is non-decreasing", all(nondecreasing(v) for v in live.values()))
    check("every series ends on its live count",
          all(live[k][-1] == live_counts.get(k, 0) for k in live),
          {k: (live[k][-1], live_counts.get(k)) for k in live})
    # A missing table (this checkout ships payloads only) degrades to a flat zero series, never a crash.
    check("a missing-table entity is a 12-point zero series", live["reports"] == [0] * P, live["reports"])
    rc.close()
else:
    check("index.db present to sample", False, "no index.db in checkout")


# ---------------------------------------------------------------- money safety
print("\n-- money safety: the aggregation never reads a bounty/money column --")
src = open(os.path.join(APP, "core", "server.py")).read()
start = src.index("def _spark_epoch")
end = src.index("---- entities", start)          # the entities banner right after the helpers
region = src[start:end]
# Strip line comments so a comment that merely MENTIONS bounty cannot trip the guard; what matters
# is that no executable SQL or identifier references a money column.
code = "\n".join(line.split("#", 1)[0] for line in region.splitlines()).lower()
check("no 'bounty' column read in the sparkline SQL", "bounty" not in code)
check("no 'payout' column read in the sparkline SQL", "payout" not in code)


passed = sum(1 for _, ok, _ in results if ok)
failed = [n for n, ok, _ in results if not ok]
print("\n%d/%d passed" % (passed, len(results)))
if failed:
    print("FAILED: " + ", ".join(failed))
    sys.exit(1)
print("ALL GREEN")
sys.exit(0)
