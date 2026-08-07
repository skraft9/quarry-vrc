#!/usr/bin/env python3
"""Payload arsenal: a queryable index of attack payloads extracted from a local reference clone.

WHAT THIS IS. `scripts/sync-payloads.sh` keeps a shallow clone of PayloadsAllTheThings at
`payloads_root` (default `your home/arsenal/PayloadsAllTheThings`). This module reads the fenced
code blocks out of that clone's markdown and stores one row per block in `payloads`, so a hunt can
ask "what do SSTI payloads for Jinja2 look like" and get answers instead of a directory listing.

THE CLONE IS NEVER COMMITTED and never ingested:

  * Not committed, because Quarry is headed for open source. Redistributing a few thousand attack
    payloads from a public repo carries someone else's licence and attribution obligations, trips
    push protection and secret scanning, and buries the real history under refresh diffs.
  * Not ingested, because `ingest.py` turns markdown into `leads` rows and finds that markdown by
    walking `the workspace volume`. The clone sits outside that prefix, so ingest cannot see it. Were
    it inside, third-party cheatsheets would outnumber real leads and the Leads tab - the app's
    core surface - would be worthless. Nothing in this module writes to `leads` or `reports`.

The unit of a row is the CODE BLOCK, not the line. A block is what an author grouped together
under one heading, so it arrives with its context intact; splitting it would turn "40 Jinja2 SSTI
payloads from this file" into 40 anonymous strings. Wordlists under `Intruder/` and `Files/` are
fuzzer input rather than documented payloads and are left out entirely - they are still reachable
in the Files tab, which is where you go once a hit has named the folder.

Because `index.db` is not committed, a fresh checkout starts with zero payloads. The refresh
script is the way to populate it:

    ./scripts/sync-payloads.sh              # clone or pull, then rebuild the table
    python3 payloads.py --rebuild           # rebuild only, clone already on disk
    python3 payloads.py --search "jinja2 ssti"
    python3 payloads.py --stats
"""
import argparse
import os
import re
import sys
import time

import common

# Where the clone lives when config.json does not say otherwise.
DEFAULT_ROOT = "your home/arsenal/PayloadsAllTheThings"

# A block bigger than this is a dump that happens to be fenced (a whole config file, a stack
# trace), not a payload. Indexing it would let one row win every query it shares a word with.
MAX_PAYLOAD_BYTES = 20_000

SCHEMA = """
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

-- External-content FTS: the payload text is already in `payloads`, so storing it twice would
-- double the table for nothing. Refill is truncate-and-rebuild, which is why no sync triggers
-- exist - see rebuild().
CREATE VIRTUAL TABLE IF NOT EXISTS payloads_fts USING fts5(
  category, technique, section, payload,
  content = 'payloads', content_rowid = 'id',
  tokenize = 'porter unicode61'
);
"""

# Indent is captured, not bounded. CommonMark stops treating a fence as a fence past three
# spaces, but this repo nests fences inside list items at four and up, and enforcing the spec
# here silently dropped a quarter of the corpus - including every XSS polyglot.
_FENCE_RE = re.compile(r"^([ \t]*)(`{3,}|~{3,})[ \t]*([^\s`]*)")
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*$")


def ensure_schema(conn):
    """Create the payload tables if they are missing. schema.sql carries them for a fresh
    database; this covers one created before they existed."""
    conn.executescript(SCHEMA)


def root_dir(cfg=None):
    """Absolute path of the reference clone."""
    if cfg is None:
        cfg = common.load_config()
    return os.path.abspath(cfg.get("payloads_root") or DEFAULT_ROOT)


# --------------------------------------------------------------- extraction

def _technique_of(text, path):
    """The document's own name. A file called README says nothing, so those take the name of the
    directory they document."""
    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            return m.group(2).strip()
    stem = os.path.splitext(os.path.basename(path))[0]
    if stem.lower() == "readme":
        return os.path.basename(os.path.dirname(path)) or stem
    return stem


def extract(text, path, category):
    """Yield one dict per fenced code block in a markdown document.

    `section` is the last heading seen above the block, which is what makes a hit usable: it is
    the line that says 'Jinja2 - Basic injection' rather than just naming the file.
    """
    technique = _technique_of(text, path)
    section = ""
    fence = None
    lang = ""
    indent = 0
    start = 0
    buf = []
    for no, line in enumerate(text.splitlines(), 1):
        if fence is None:
            m = _FENCE_RE.match(line)
            if m:
                indent, fence = len(m.group(1)), m.group(2)[0] * 3
                lang, start, buf = m.group(3).strip(), no, []
                continue
            h = _HEADING_RE.match(line)
            if h:
                section = h.group(2).strip()
            continue
        if line.strip().startswith(fence):
            body = "\n".join(buf).strip("\n")
            fence = None
            if body.strip() and len(body) <= MAX_PAYLOAD_BYTES:
                yield {"category": category, "technique": technique, "section": section,
                       "lang": lang, "payload": body, "file_path": path, "line": start}
            continue
        # Undo the list indentation the fence carried, so a copied payload is the payload.
        buf.append(line[indent:] if not line[:indent].strip() else line)


def iter_payloads(root):
    """Walk the clone and yield every payload row it contains.

    Category is the top-level directory, which is how the upstream repo is organised and the only
    grouping worth exposing as a filter. Files at the root ('README.md') have no category and are
    skipped: they are the repo's own front matter, not payloads.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            if not name.lower().endswith(".md"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if os.sep not in rel:
                continue
            category = rel.split(os.sep)[0]
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            for row in extract(text, path, category):
                yield row


# --------------------------------------------------------------- indexing

def rebuild(conn, root=None, cfg=None):
    """Re-read the clone into `payloads`. Idempotent: truncate and refill, so running it twice
    leaves the same rows and a deleted upstream file cannot linger.

    Returns {root, payloads, files, categories, elapsed_ms}. Touches no other table.
    """
    started = time.time()
    root = root or root_dir(cfg)
    ensure_schema(conn)
    conn.execute("DELETE FROM payloads")
    stamp = common.now_iso()
    files, cats, n = set(), set(), 0
    for row in iter_payloads(root):
        conn.execute(
            "INSERT INTO payloads (category, technique, section, lang, payload, file_path,"
            " line, indexed_at) VALUES (?,?,?,?,?,?,?,?)",
            (row["category"], row["technique"], row["section"], row["lang"], row["payload"],
             row["file_path"], row["line"], stamp))
        files.add(row["file_path"])
        cats.add(row["category"])
        n += 1
    # Resyncs the whole FTS index from the content table in one statement, which is why the
    # delete above needs no triggers to keep the two in step.
    conn.execute("INSERT INTO payloads_fts(payloads_fts) VALUES('rebuild')")
    conn.commit()
    return {"root": root, "payloads": n, "files": len(files), "categories": len(cats),
            "elapsed_ms": int(round((time.time() - started) * 1000))}


def stats(conn):
    ensure_schema(conn)
    row = conn.execute(
        "SELECT COUNT(*) AS payloads, COUNT(DISTINCT category) AS categories,"
        " COUNT(DISTINCT file_path) AS files, MAX(indexed_at) AS indexed_at"
        " FROM payloads").fetchone()
    out = dict(row)
    out["root"] = root_dir()
    return out


def categories(conn):
    """Category names with a payload count, for the UI filter."""
    ensure_schema(conn)
    return [dict(r) for r in conn.execute(
        "SELECT category, COUNT(*) AS n FROM payloads GROUP BY category"
        " ORDER BY category COLLATE NOCASE")]


# --------------------------------------------------------------- searching

_SELECT = ("SELECT p.id, p.category, p.technique, p.section, p.lang, p.payload,"
           " p.file_path, p.line")


def search(conn, q=None, category=None, limit=50):
    """Query the arsenal. Returns {items, interpreted_as?, fallback?}.

    With no query this is a browse: the category filter alone is a legitimate way in, since
    'show me everything filed under Prompt Injection' is how you use an arsenal you have not
    read yet.

    Payload text is an FTS5 syntax hazard by nature - `${jndi:`, `<script>`, `../../` and
    `' OR 1=1--` are all things you would type here and all are either an operator or a syntax
    error. The raw query goes first so deliberate FTS5 syntax still works, and anything that
    raises is retried as a quoted term list rather than returned as an error.
    """
    ensure_schema(conn)
    q = (q or "").strip()
    limit = max(1, min(200, int(limit)))
    if not q:
        sql = _SELECT + ", 0 AS score FROM payloads p"
        params = []
        if category:
            sql += " WHERE p.category = ?"
            params.append(category)
        sql += " ORDER BY p.category, p.file_path, p.line LIMIT ?"
        params.append(limit)
        return {"items": [dict(r) for r in conn.execute(sql, params)]}

    sql = (_SELECT + ", bm25(payloads_fts) AS score FROM payloads_fts"
           " JOIN payloads p ON p.id = payloads_fts.rowid WHERE payloads_fts MATCH ?")
    params = [q]
    if category:
        sql += " AND p.category = ?"
        params.append(category)
    sql += " ORDER BY score LIMIT ?"
    params.append(limit)
    try:
        rows = conn.execute(sql, params).fetchall()
    except Exception:
        terms = re.findall(r"\w+", q)
        if not terms:
            return {"items": [], "fallback": True}
        params[0] = " ".join('"%s"' % t for t in terms)
        try:
            rows = conn.execute(sql, params).fetchall()
        except Exception as exc:
            raise ValueError("bad search query: %s" % exc)
        return {"items": [dict(r) for r in rows], "fallback": True,
                "interpreted_as": params[0]}
    return {"items": [dict(r) for r in rows]}


# ------------------------------------------------------------------ cli
def main():
    ap = argparse.ArgumentParser(description="Index and search the local payload arsenal.")
    ap.add_argument("--rebuild", action="store_true", help="re-read the clone into `payloads`")
    ap.add_argument("--stats", action="store_true", help="row counts and last index time")
    ap.add_argument("--search", metavar="QUERY", help="run a query and print the hits")
    ap.add_argument("--category", help="restrict to one category, with or without --search")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--root", help="override the configured payloads_root")
    args = ap.parse_args()

    conn = common.connect()
    if args.rebuild:
        res = rebuild(conn, root=args.root)
        print("payloads: %(payloads)d from %(files)d files in %(categories)d categories"
              " (%(root)s) in %(elapsed_ms)d ms" % res)
    if args.search or args.category:
        res = search(conn, args.search, category=args.category, limit=args.limit)
        if res.get("interpreted_as"):
            print("(interpreted as %s)" % res["interpreted_as"])
        for it in res["items"]:
            print("\n%s / %s%s" % (it["category"], it["technique"],
                                   (" / " + it["section"]) if it["section"] else ""))
            print("%s:%s" % (it["file_path"], it["line"]))
            print(it["payload"])
        print("\n%d hit(s)" % len(res["items"]))
    if args.stats or not (args.rebuild or args.search or args.category):
        s = stats(conn)
        print("root       %(root)s\npayloads   %(payloads)s\nfiles      %(files)s\n"
              "categories %(categories)s\nindexed    %(indexed_at)s" % s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
