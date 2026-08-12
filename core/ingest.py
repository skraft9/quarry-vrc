#!/usr/bin/env python3
"""Ingest: scan the hunt workspaces on disk and index them into SQLite.

AUTHORITY: the markdown files under the workspace volume are the authority for everything THIS
module indexes (leads, RCAs, notes, programs, targets). This module is READ-ONLY against those
trees - it never opens a workspace file for writing - and `--rebuild` recreates its rows.

It is NOT the authority for reports. HackerOne is. `--rebuild --hard` therefore deletes
file-derived rows only and leaves `source = 'hackerone'` alone, because a rebuild has nothing
to reconstruct those from. See "Systems of record" in the README.

Layout indexed per workspace (see README of each workspace):

    <workspace>/README.md              -> lead   (workspace-level note, class NULL)
    <workspace>/*.md                   -> lead   (loose workspace notes / analyses)
    <workspace>/program/*.md           -> program (scope / ROE docs)
    <workspace>/notes/*.md             -> lead   (round logs, surface maps, class NULL)
    <workspace>/<CLASS>/**/*.md        -> lead   (per-hunt lead notes)
    <workspace>/<CLASS>/reports/*.md   -> report
    <workspace>/<CLASS>/{evidence,bin} -> ignored

Plus the markdown table in <workspace>/*_Vulnerability_Tracker.md, which decorates the
report rows that already have a file and creates `tracker_only=1` rows for the rest.

The tracker is LEGACY. HackerOne is the source of truth for reports, so the fold-in now
skips any h1_id the API already owns rather than shadowing it with a hand-typed stub.
It survives only to carry `tracker_row`, which h1.recover_expected_from_tracker() reads
to find ANTICIPATED payments that HackerOne has not confirmed.

Public API (server.py imports these; keep the names and signatures stable):

    rebuild(conn)              -> {"scanned": int, "changed": int, "elapsed_ms": int}
    reindex_path(conn, path)   -> dict describing what happened to that one path
    parse_lead(path, text)     -> dict of `leads` columns          (pure, no DB)
    parse_report(path, text)   -> dict of `reports` columns        (pure, no DB)
    parse_tracker(markdown)    -> list of dicts, one per table row (pure, no DB)

Stdlib only. No third-party imports, ever.
"""
import argparse
import os
import re
import sys
import time

import common

# --------------------------------------------------------------------------- config

#: Directories that never hold indexable notes (artifacts, PoC code, captures).
IGNORE_DIRS = {
    "evidence", "bin", "__pycache__", ".git", "node_modules", ".venv", "venv",
    # HackerOne-synced report bodies. They are already represented by source='hackerone'
    # rows, so indexing the files too would double-count every submission.
    "h1_reports",
    # Lab harness runbooks and superseded/folded notes. These carry finding-shaped
    # headings but are not leads, so indexing them would create blank-ref rows.
    "harness", "archive",
}

#: Workspace-root file that carries the submitted-report tracker table.
TRACKER_SUFFIX = "_Vulnerability_Tracker.md"

#: Skip anything bigger than this; a hunt note is never megabytes of text.
MAX_FILE_BYTES = 4_000_000

#: `Software` column value -> target slug. Anything else is lowercased as-is.
TRACKER_SOFTWARE_ALIASES = {
    "ExampleProduct": "ExampleProduct",
    "ExampleApp": "ExampleApp",
    "ExamplePipeline": "ExamplePipeline",
    "UpstreamLib": "UpstreamLib",
    "apache UpstreamLib": "UpstreamLib",
    "example-vendor": "example-vendor",
}

#: Tracker `Impact` column -> the class vocabulary used elsewhere in the schema.
#: Anything not listed stays NULL rather than being invented.
IMPACT_TO_CLASS = {
    "crash": "DoS", "hang": "DoS", "dos": "DoS", "429": "DoS", "close": "DoS",
    "urc": "DoS", "oom": "DoS", "bac": "BAC", "c:l": "BAC", "idor": "BAC",
    "privesc": "PRIVESC", "rce": "RCE", "xss": "BAC",
}

#: Normalised tracker header -> canonical field. Derived from the real header row at
#: parse time; this map only says which *names* mean which field, never which position.
TRACKER_HEADER_ALIASES = {
    "software": "software", "product": "software", "target": "software",
    "component": "software",
    "report": "report", "h1": "report", "hackerone": "report", "report_id": "report",
    "endpoint": "title", "summary": "title", "title": "title",
    "description": "title", "vulnerability": "title", "issue": "title",
    "impact": "impact",
    "cvss": "severity", "severity": "severity", "score": "severity",
    "notes": "notes", "status": "notes", "state": "notes", "result": "notes",
    "amt": "bounty", "amount": "bounty", "bounty": "bounty", "payout": "bounty",
    "reward": "bounty",
    "original_report_date": "submitted_on", "report_date": "submitted_on",
    "date": "submitted_on", "submitted": "submitted_on", "submitted_on": "submitted_on",
    "resolved": "resolved_on", "resolved_on": "resolved_on", "paid_on": "resolved_on",
    "cve": "cve",
    "pr": "pr", "a": "a",
}

#: Ordered. First match against the combined tracker Notes+CVE text wins.
TRACKER_STATE_PATTERNS = [
    ("resolved", re.compile(r"\bPAID\b|\bRESOLVED\b|\bBOUNTY\s+AWARDED\b", re.I)),
    ("duplicate", re.compile(r"\bDUPE\b|\bDUPLICATE\b", re.I)),
    ("triaged", re.compile(r"\bTRIAGED?\b|\bVENDOR\s+TRIAGE\b|\bRE-?OPENED\b", re.I)),
    ("n/a", re.compile(r"CLOSED\s+AS\s+INFO|\bINFORMATIVE\b|\bOOS\b|\bNOT\s+APPLICABLE\b", re.I)),
    ("pending", re.compile(r"\bPENDING\b|\bLAST\s+REPLY\b", re.I)),
]

#: 'F1_UpstreamLib_expression_dos_report.md' / 'F10-phrase-suggester-...md' -> ref without an H1 id.
REPORT_REF_ONLY_RE = re.compile(r"^([A-Z]{1,2}\d{1,3})[-_.]")

#: trailing '2026-07-30.' / '- 2026-07-30' on a header line. The leading separator class
#: deliberately excludes brackets so '(documented). 2026-07-30.' keeps its ')'.
TRAILING_DATE_RE = re.compile(r"[\s.,:;-]*\b\d{4}-\d{2}-\d{2}\b\s*\.?\s*$")

SEVERITY_WORDS = r"critical|high|medium|moderate|low|informational|none"

#: a severity statement leading a line in the opening of a note, e.g. "**Severity:** high",
#: "CVSS 7.5". The lookahead drops a CVSS *vector* ("CVSS:3.1/AV:N/..."), where the number
#: straight after the label is the spec version and not a score.
SEVERITY_LINE_RE = re.compile(
    r"^[\s>*_#|-]*(?:CVSS|Severity)\b(?!\s*:?\s*\d+\.\d+\s*/)[^A-Za-z0-9]{0,12}"
    r"(\d+(?:\.\d+)?|" + SEVERITY_WORDS + r")\b",
    re.I,
)

#: the same statement embedded mid-line, which is how the status marker on a filed lead carries
#: it: "**Status:** SUBMITTED H1 #0000000 (2026-07-31, severity medium, state new)". Words only,
#: on purpose - a bare number mid-line is far more often a CVSS score being quoted about some
#: other CVE ("same class, same CVSS (6.5)") than this note's own rating.
SEVERITY_INLINE_RE = re.compile(
    r"\bseverity\b[^A-Za-z0-9]{0,12}(" + SEVERITY_WORDS + r")\b", re.I)

#: the parenthesis on a filed lead's `Submitted` row, where the severity leads and the word
#: `severity` never appears:  "| **Submitted** | 2026-08-03 as #0000000 (high, scope 47515) |".
#: The inline pattern above needs that word, so it matched the older
#: "SUBMITTED H1 #0000000 (2026-07-31, severity medium, ...)" form and missed every lead filed
#: under the current header-table convention - 9 of 138 leads carried a severity because of it.
#: Anchored on the H1 id so a bare parenthesis elsewhere in the header cannot be mistaken for one.
SEVERITY_FILED_RE = re.compile(
    r"#\d{5,9}\s*\(\s*(" + SEVERITY_WORDS + r")\b", re.I)

FENCE_RE = re.compile(r"^\s*(```|~~~)")
HEADING_RE = re.compile(r"^#\s+(.+?)\s*$")
MD_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")
MD_SEP_RE = re.compile(r"^\s*\|[\s:|+-]+\|\s*$")
#: cells are separated by ' | '; a bare '|' with no surrounding space (ES|QL) is content.
CELL_SPLIT_RE = re.compile(r"\s\|\s")
H1_URL_RE = re.compile(r"hackerone\.com/reports/(\d{4,12})")
H1_HASH_RE = re.compile(r"#(\d{5,12})")
US_DATE_RE = re.compile(r"\b(\d{1,2})[-/](\d{1,2})[-/](\d{4})\b")
ISO_DATE_RE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
PAID_ON_RE = re.compile(r"(?:paid|resolved|triaged|closed)\s+on\s+([\d/-]+)", re.I)


def _warn(msg):
    sys.stderr.write("ingest: WARNING: %s\n" % msg)


# --------------------------------------------------------------- workspace discovery

def list_workspaces(root=common.HUNT_ROOT):
    """Absolute paths of every the workspace volume hunt workspace, sorted."""
    out = []
    try:
        names = os.listdir(root)
    except OSError as exc:
        _warn("cannot list %s: %s" % (root, exc))
        return out
    for name in sorted(names):
        if not name.startswith(common.WORKSPACE_GLOB_PREFIX):
            continue
        slug = name[len(common.WORKSPACE_GLOB_PREFIX):]
        if slug in getattr(common, "EXCLUDE_WORKSPACES", set()):
            continue
        path = os.path.join(root, name)
        if os.path.isdir(path):
            out.append(path)
    return out


def workspace_slug(workspace):
    """the workspace ExamplePipeline -> 'ExamplePipeline'."""
    return os.path.basename(workspace.rstrip(os.sep))[len(common.WORKSPACE_GLOB_PREFIX):]


def workspace_for(path, root=common.HUNT_ROOT):
    """The workspace directory containing `path`, or None if it sits outside them all."""
    ap = os.path.abspath(path)
    for ws in list_workspaces(root):
        if ap == ws or ap.startswith(ws + os.sep):
            return ws
    return None


def classify_path(path, root=common.HUNT_ROOT):
    """Decide what a path is. Returns a dict or None when the path is not indexable.

    keys: kind (lead|report|program|tracker), workspace, target_slug, class, rel
    """
    ws = workspace_for(path, root)
    if ws is None:
        return None
    ap = os.path.abspath(path)
    if not ap.lower().endswith(".md"):
        return None
    rel = os.path.relpath(ap, ws)
    parts = rel.split(os.sep)
    if any(p in IGNORE_DIRS for p in parts[:-1]):
        return None
    if any(p.startswith(".") for p in parts):
        return None

    info = {"workspace": ws, "target_slug": workspace_slug(ws), "class": None, "rel": rel}
    if len(parts) == 1:
        info["kind"] = "tracker" if parts[0].endswith(TRACKER_SUFFIX) else "lead"
    elif parts[0] == "program":
        info["kind"] = "program"
    elif parts[0] == "notes":
        info["kind"] = "lead"
    else:
        info["class"] = parts[0]
        info["kind"] = "report" if len(parts) > 2 and parts[1] == "reports" else "lead"
    return info


def iter_markdown(workspace):
    """Yield every indexable .md path under a workspace, pruning ignored directories."""
    for dirpath, dirnames, filenames in os.walk(workspace):
        dirnames[:] = sorted(
            d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")
        )
        for name in sorted(filenames):
            if name.lower().endswith(".md") and not name.startswith("."):
                yield os.path.join(dirpath, name)


def read_text(path):
    """Read a markdown file defensively. Returns None for binary/oversized/unreadable."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        _warn("stat failed %s: %s" % (path, exc))
        return None
    if size > MAX_FILE_BYTES:
        _warn("skipping oversized file (%d bytes): %s" % (size, path))
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        _warn("unreadable %s: %s" % (path, exc))
        return None
    if b"\x00" in raw:
        _warn("skipping binary file: %s" % path)
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


# --------------------------------------------------------------------- pure parsers

def _first_line(text):
    for line in (text or "").splitlines():
        if line.strip():
            return line.rstrip()
    return ""


def _first_heading(text):
    """First `# ` heading that is not inside a fenced code block. None if there is none."""
    fence = None
    for line in (text or "").splitlines():
        m = FENCE_RE.match(line)
        if m:
            tok = m.group(1)
            if fence is None:
                fence = tok
            elif line.strip().startswith(fence):
                fence = None
            continue
        if fence is not None:
            continue
        h = HEADING_RE.match(line)
        if h:
            return h.group(1).strip()
    return None


def _clean_title(text):
    """Trim markdown decoration and separator noise off a title fragment."""
    s = (text or "").strip()
    s = re.sub(r"^#+\s*", "", s)
    s = s.strip().strip("*_ \t")
    s = re.sub(r"^[\s:.,–—-]+", "", s)
    s = re.sub(r"[\s:.,–—-]+$", "", s)
    return s.strip()


def _prettify_slug(slug):
    s = re.sub(r"[-_]+", " ", slug or "").strip()
    return s[:1].upper() + s[1:] if s else ""


# Lifecycle order is open -> confirmed -> ready -> submitted -> awarded, with parked and killed
# off to the side. `awarded` is one step PAST `submitted`: the report was filed AND a bounty was
# paid, which makes it the only terminal GOOD outcome and the opposite of `killed`.
#
# `backlog` was dropped on 2026-08-03. It sat between open and parked and nothing ever used it -
# a lead is either being worked or it is parked, and a third shade of "not now" only made the
# queue harder to read.
PICKER_STATUSES = ("open", "confirmed", "ready", "submitted", "awarded", "parked", "killed")

# `unknown` is NOT pickable and never appears in the UI. It is where a note with no `**Status:**`
# marker lands - advisory trackers, sweep logs, findings tables, 59 of them - and the server keeps
# those out of the Leads list entirely (server.LEAD_IS_REAL). It has to stay in the vocabulary
# because the parser needs a bucket for them; offering it as a choice was the mistake.
INTERNAL_STATUSES = ("unknown",)

VALID_STATUSES = PICKER_STATUSES + INTERNAL_STATUSES

# An explicit marker the UI can rewrite deterministically, e.g.  **Status:** open
# Keyword-sniffing the header line works for reading, but is far too fragile to WRITE back to,
# so anything that changes status from the UI emits this line instead and it wins on re-read.
# The line may carry detail after the status word, and on a filed lead it always does:
#   **Status:** SUBMITTED H1 #0000000 (2026-08-01, severity high, state new)
# Anchoring the old pattern to end-of-line meant those matched NOTHING and every submitted
# lead fell through to header keyword sniffing, which indexed it as `unknown`.
# The leading `\|?` and the one after the label are what let the marker live inside a markdown
# TABLE ROW (`| **Status:** | submitted |`), which is how a lead header block is written as of
# 2026-08-02. Anchoring to the start of a line without allowing the pipe meant a table-form header
# matched NOTHING and every lead using it indexed as `unknown`. The colon is optional on both
# sides so `**Status**` in a cell parses too, since a table cell reads fine without it.
STATUS_MARKER_RE = re.compile(r"^\s*\|?\s*\*\*Status:?\*\*:?\s*\|?\s*([A-Za-z]+)\b.*$", re.M)


def parse_status_marker(text, max_lines=25):
    """Return the explicit **Status:** value from the opening lines, or None."""
    head = "\n".join((text or "").splitlines()[:max_lines])
    m = STATUS_MARKER_RE.search(head)
    if not m:
        return None
    val = m.group(1).lower()
    return val if val in VALID_STATUSES else None


def parse_status(header):
    """Map a header line onto the leads.status vocabulary. First match wins."""
    up = (header or "").upper()
    for status, pattern in common.STATUS_PATTERNS:
        if pattern.search(up):
            return status
    return "unknown"


def parse_severity(text, max_lines=40):
    """Pull a stated severity/CVSS out of the opening lines. None when not stated.

    Three passes, not one, in descending order of how strong the claim is: a line that LEADS
    with the label, then the parenthesis on a filed lead's `Submitted` row (the rating actually
    sent to HackerOne), then a severity mentioned in passing mid-line.
    """
    lines = (text or "").splitlines()[:max_lines]
    for line in lines:
        m = SEVERITY_LINE_RE.match(line)
        if m:
            return m.group(1).strip()
    # A filed lead states its severity in the `Submitted` row, and that is the rating actually
    # sent to HackerOne, so it outranks anything mentioned in passing further down.
    for line in lines:
        m = SEVERITY_FILED_RE.search(line)
        if m:
            return m.group(1).strip()
    for line in lines:
        m = SEVERITY_INLINE_RE.search(line)
        if m:
            return m.group(1).strip()
    return None


def parse_lead(path, text):
    """Parse a lead/notes markdown file. Pure: no filesystem and no DB access.

    Returns the `leads` columns this file determines, plus `target_slug` (the DB layer
    resolves that to target_id). ref/class/severity are None when the file does not say.
    """
    text = text or ""
    header = _first_line(text)
    ref = None
    title_src = header
    m = common.REF_RE.match(header)
    if m:
        ref = m.group(1)
        title_src = header[m.end():]
    title = _clean_title(TRAILING_DATE_RE.sub("", _clean_title(title_src)))
    if not title:
        title = _prettify_slug(os.path.splitext(os.path.basename(path))[0])
    if not title:
        title = os.path.basename(path)

    info = classify_path(path) or {}
    return {
        "ref": ref,
        "title": title,
        "class": info.get("class"),
        # Explicit marker wins; header keyword sniffing is the fallback for older notes.
        "status": parse_status_marker(text) or parse_status(header),
        "severity": parse_severity(text),
        "file_path": os.path.abspath(path),
        "header": header or None,
        "body": text,
        "target_slug": info.get("target_slug"),
    }


# Companion root-cause-analysis documents sit beside the report they belong to and share its
# H1 id, e.g. 3899885_G8-slug.md and 3899885_G8-slug-rca.md. They are NOT separate submissions,
# so counting them as reports inflates the tracker.
RCA_SUFFIX_RE = re.compile(r"[-_]rca$", re.I)

# Follow-up comments, live-repro addenda and similar are correspondence ON a report, not a
# separate submission. They share the parent's H1 id, so without this they both inflate the
# tracker AND get mistaken for the report itself by the HackerOne sync.
# The trailing guard is NOT \b. A word boundary cannot match between "followup" and the "_" that
# usually follows it, because underscore is itself a word character, so "G4_followup_live_repro"
# was classified as a report and counted as a second submission of its parent. Excluding only
# alphanumerics keeps "_responsetime" from matching while letting "_response_" through.
FOLLOWUP_RE = re.compile(
    r"[-_](followup|follow_up|comment|reply|addendum|response)(?![A-Za-z0-9])", re.I)


def is_rca_path(path):
    return bool(RCA_SUFFIX_RE.search(os.path.splitext(os.path.basename(path))[0]))


def is_followup_path(path):
    return bool(FOLLOWUP_RE.search(os.path.splitext(os.path.basename(path))[0]))


def report_kind(path):
    if is_rca_path(path):
        return "rca"
    if is_followup_path(path):
        return "followup"
    return "report"


def parse_report(path, text):
    """Parse a report markdown file. Pure: no filesystem and no DB access.

    Filename carries the identity (`3899885_G8-slug.md` -> h1_id 3899885, ref G8);
    drafts not yet submitted have no numeric prefix and get h1_id None.

    `kind` is 'rca' for companion root-cause documents, 'report' otherwise.
    """
    text = text or ""
    name = os.path.basename(path)
    h1_id = ref = None
    slug = os.path.splitext(name)[0]

    m = common.REPORT_FILE_RE.match(name)
    if m:
        h1_id, ref, slug = m.group(1), m.group(2), m.group(3)
    else:
        m2 = REPORT_REF_ONLY_RE.match(name)
        if m2:
            ref = m2.group(1)
            slug = os.path.splitext(name)[0][m2.end():]

    title = _clean_title(_first_heading(text) or "")
    if not title:
        title = _prettify_slug(slug) or _prettify_slug(os.path.splitext(name)[0]) or name

    info = classify_path(path) or {}
    return {
        "h1_id": h1_id,
        "ref": ref,
        "title": title,
        "state": None,
        "severity": None,
        "bounty": None,
        "submitted_on": None,
        "resolved_on": None,
        "url": "https://hackerone.com/reports/%s" % h1_id if h1_id else None,
        "class": info.get("class"),
        "file_path": os.path.abspath(path),
        "body": text,
        "tracker_row": None,
        "tracker_only": 0,
        "kind": report_kind(path),
        "target_slug": info.get("target_slug"),
    }


def _norm_header(cell):
    s = re.sub(r"[*_`]", "", cell or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s


def _clean_cell(cell):
    """Strip markdown bold from a table cell. Bold in this table is emphasis, not data,
    and it is often unbalanced ('_ingest)**' with the opening pair elsewhere)."""
    s = (cell or "").strip()
    s = s.replace("**", "")
    return s.strip("*").strip()


def _split_row(line):
    """Split a markdown table row into cells.

    Cells are separated by ' | '. A pipe with no surrounding whitespace is content,
    not a separator - the tracker contains unescaped 'ES|QL' inside title cells.
    """
    padded = " " + line.strip() + " "
    cells = CELL_SPLIT_RE.split(padded)
    if cells and not cells[0].strip():
        cells = cells[1:]
    if cells and not cells[-1].strip():
        cells = cells[:-1]
    return [_clean_cell(c) for c in cells]


def _norm_date(value):
    """'7-29-2026' / '3/29/2026' -> '2026-07-29'. Unparseable input is returned as-is."""
    s = (value or "").strip()
    if not s:
        return None
    m = ISO_DATE_RE.search(s)
    if m:
        return "%s-%s-%s" % m.groups()
    m = US_DATE_RE.search(s)
    if m:
        month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if 1 <= month <= 12 and 1 <= day <= 31:
            return "%04d-%02d-%02d" % (year, month, day)
    return s


def _tracker_state(blob):
    """Map the tracker's free-text Notes/CVE columns onto the reports.state vocabulary.

    Nothing recognisable means the report is simply open with no recorded outcome, which
    is 'new' - better than echoing an unrelated cell ('CVE-2026-63143', '300+% CPU')
    into a field the UI filters on.
    """
    for state, pattern in TRACKER_STATE_PATTERNS:
        if pattern.search(blob or ""):
            return state
    return "new"


def parse_tracker(markdown):
    """Parse the markdown table in the vulnerability tracker. Pure: no DB access.

    Column meaning is derived from the real header row, never from position. Returns one
    dict per data row with the canonical fields plus `cells` (every column, verbatim).
    """
    lines = (markdown or "").splitlines()
    header = None
    rows = []
    fence = None

    for idx, line in enumerate(lines):
        m = FENCE_RE.match(line)
        if m:
            tok = m.group(1)
            if fence is None:
                fence = tok
            elif line.strip().startswith(fence):
                fence = None
            continue
        if fence is not None:
            continue
        if not MD_ROW_RE.match(line):
            continue
        if MD_SEP_RE.match(line):
            continue
        cells = _split_row(line)
        if header is None:
            nxt = lines[idx + 1] if idx + 1 < len(lines) else ""
            if MD_SEP_RE.match(nxt):
                header = [_norm_header(c) for c in cells]
            continue
        rows.append((line.rstrip(), cells))

    if header is None:
        return []

    fields = [TRACKER_HEADER_ALIASES.get(h) for h in header]
    out = []
    for raw, cells in rows:
        by_name = {}
        canon = {}
        for i, name in enumerate(header):
            value = cells[i] if i < len(cells) else ""
            if name:
                by_name[name] = value
            field = fields[i] if i < len(fields) else None
            if field and not canon.get(field):
                canon[field] = value

        report_cell = canon.get("report", "")
        h1_id = None
        m = H1_URL_RE.search(report_cell) or H1_HASH_RE.search(report_cell)
        if m:
            h1_id = m.group(1)
        if not h1_id:
            continue  # a table row with no report id is not a report

        software = _clean_cell(canon.get("software", ""))
        slug = TRACKER_SOFTWARE_ALIASES.get(software.lower(), software.lower() or None)

        notes = canon.get("notes", "") or ""
        cve = canon.get("cve", "") or ""
        blob = (notes + " " + cve).strip()

        resolved_on = _norm_date(canon.get("resolved_on", "")) if canon.get("resolved_on") else None
        if not resolved_on:
            pm = PAID_ON_RE.search(blob)
            if pm:
                resolved_on = _norm_date(pm.group(1))

        impact = (canon.get("impact", "") or "").strip()
        cls = IMPACT_TO_CLASS.get(impact.lower())

        title = _clean_cell(canon.get("title", "")) or "H1 #%s" % h1_id
        severity = _clean_cell(canon.get("severity", "")) or None
        bounty = _clean_cell(canon.get("bounty", "")) or None

        out.append({
            "h1_id": h1_id,
            "url": "https://hackerone.com/reports/%s" % h1_id,
            "title": title,
            "target_slug": slug,
            "software": software or None,
            "impact": impact or None,
            "class": cls,
            "state": _tracker_state(blob),
            "severity": severity,
            "bounty": bounty,
            "submitted_on": _norm_date(canon.get("submitted_on", "")),
            "resolved_on": resolved_on,
            "notes": notes or None,
            "cve": cve or None,
            "tracker_row": raw,
            "cells": by_name,
        })
    return out


def find_tracker_files():
    """Every workspace-root *_Vulnerability_Tracker.md on disk."""
    out = []
    for ws in list_workspaces():
        try:
            names = os.listdir(ws)
        except OSError:
            continue
        for name in sorted(names):
            if name.endswith(TRACKER_SUFFIX):
                out.append(os.path.join(ws, name))
    return out


# --------------------------------------------------------------------- search index

def fts_delete(conn, kind, rowid_ref):
    # fts5 columns carry no affinity, so the id must be compared as the text it is
    # stored as; passing a bare int here silently matches nothing.
    conn.execute(
        "DELETE FROM search_fts WHERE kind = ? AND rowid_ref = ?", (kind, str(rowid_ref))
    )


def fts_insert(conn, kind, rowid_ref, ref, title, target, body):
    conn.execute(
        "INSERT INTO search_fts (kind, rowid_ref, ref, title, target, body)"
        " VALUES (?,?,?,?,?,?)",
        (kind, str(rowid_ref), ref or "", title or "", target or "", body or ""),
    )


def _target_names(conn):
    return {row["id"]: row["slug"] for row in conn.execute("SELECT id, slug FROM targets")}


def fts_rebuild(conn):
    """Clear search_fts and repopulate it from the DB rows (not from disk)."""
    conn.execute("DELETE FROM search_fts")
    targets = _target_names(conn)
    for row in conn.execute("SELECT id, ref, title, target_id, body FROM leads"):
        fts_insert(conn, "lead", row["id"], row["ref"], row["title"],
                   targets.get(row["target_id"]), row["body"])
    for row in conn.execute("SELECT id, ref, title, target_id, body FROM reports"):
        fts_insert(conn, "report", row["id"], row["ref"], row["title"],
                   targets.get(row["target_id"]), row["body"])
    for row in conn.execute("SELECT id, ref, title, target_id, body FROM advisories"):
        fts_insert(conn, "advisory", row["id"], row["ref"], row["title"],
                   targets.get(row["target_id"]), row["body"])
    for row in conn.execute("SELECT id, slug, name, scope_md, roe_md FROM programs"):
        body = "\n".join(x for x in (row["scope_md"], row["roe_md"]) if x)
        fts_insert(conn, "program", row["id"], row["slug"], row["name"], row["slug"], body)


def fts_sync_one(conn, kind, rowid_ref):
    """Refresh the single search_fts entry for one row."""
    fts_delete(conn, kind, rowid_ref)
    targets = _target_names(conn)
    if kind == "lead":
        row = conn.execute(
            "SELECT id, ref, title, target_id, body FROM leads WHERE id = ?", (rowid_ref,)
        ).fetchone()
    elif kind == "report":
        row = conn.execute(
            "SELECT id, ref, title, target_id, body FROM reports WHERE id = ?", (rowid_ref,)
        ).fetchone()
    elif kind == "advisory":
        row = conn.execute(
            "SELECT id, ref, title, target_id, body FROM advisories WHERE id = ?", (rowid_ref,)
        ).fetchone()
    elif kind == "program":
        row = conn.execute(
            "SELECT id, slug, name, scope_md, roe_md FROM programs WHERE id = ?", (rowid_ref,)
        ).fetchone()
        if row:
            body = "\n".join(x for x in (row["scope_md"], row["roe_md"]) if x)
            fts_insert(conn, "program", row["id"], row["slug"], row["name"], row["slug"], body)
        return
    else:
        return
    if row:
        fts_insert(conn, kind, row["id"], row["ref"], row["title"],
                   targets.get(row["target_id"]), row["body"])


# ------------------------------------------------------------------ programs/targets

def sync_programs(conn):
    """Upsert one program per workspace that carries program/*.md. Returns (map, changed).

    map is slug -> program id. GUIDELINES/SCOPE/POLICY docs become scope_md; ROE/RULES
    docs become roe_md. Fields with no document on disk are left NULL.
    """
    changed = 0
    programs = {}
    for ws in list_workspaces():
        pdir = os.path.join(ws, "program")
        if not os.path.isdir(pdir):
            continue
        scope_parts, roe_parts = [], []
        try:
            names = sorted(os.listdir(pdir))
        except OSError as exc:
            _warn("cannot list %s: %s" % (pdir, exc))
            continue
        for name in names:
            if not name.lower().endswith(".md"):
                continue
            text = read_text(os.path.join(pdir, name))
            if text is None:
                continue
            if re.search(r"ROE|RULES|ENGAGEMENT", name, re.I):
                roe_parts.append(text)
            else:
                scope_parts.append(text)
        if not scope_parts and not roe_parts:
            continue

        slug = workspace_slug(ws)
        name = slug.capitalize()
        scope_md = "\n\n".join(scope_parts) or None
        roe_md = "\n\n".join(roe_parts) or None
        row = conn.execute("SELECT * FROM programs WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            cur = conn.execute(
                "INSERT INTO programs (slug, name, platform, url, workspace, scope_md,"
                " roe_md, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (slug, name, "hackerone", None, ws, scope_md, roe_md, common.now_iso()),
            )
            programs[slug] = cur.lastrowid
            changed += 1
        else:
            programs[slug] = row["id"]
            if (row["scope_md"], row["roe_md"], row["workspace"]) != (scope_md, roe_md, ws):
                conn.execute(
                    "UPDATE programs SET workspace = ?, scope_md = ?, roe_md = ?,"
                    " updated_at = ? WHERE id = ?",
                    (ws, scope_md, roe_md, common.now_iso(), row["id"]),
                )
                changed += 1
    return programs, changed


def _guess_source_path(slug):
    """your home/<slug> if the checkout is there. Never invented."""
    for candidate in (slug, "apache-" + slug):
        path = os.path.join(common.HUNT_ROOT, candidate)
        if os.path.isdir(os.path.join(path, ".git")) or os.path.isdir(path):
            if os.path.isdir(path):
                return path
    return None


def _guess_codeql_db(slug):
    for candidate in ("codeql-db-%s" % slug, "codeql-db-apache-%s" % slug):
        path = os.path.join(common.HUNT_ROOT, candidate)
        if os.path.isdir(path):
            return path
    return None


def sync_targets(conn, programs):
    """Upsert one target per workspace. Returns (slug -> target id, changed count).

    Every workspace is a target EXCEPT the program workspaces (common.PROGRAM_WORKSPACES).
    `vulns_example` is the program itself - it holds program/GUIDELINES.md, the report standard
    and the advisory analyses - so "ExampleVendor" is a program name, not a hunt target. Notes living
    there are still indexed; they just carry no target_id.
    """
    changed = 0
    targets = {}
    # Only usable while the account has exactly ONE program. A second program workspace made this
    # None and every target silently lost its program_id, which is why the mapping below exists.
    default_program = None
    if len(programs) == 1:
        default_program = next(iter(programs.values()))

    def program_for(slug):
        named = getattr(common, "TARGET_PROGRAM", {}).get(slug)
        if named and named in programs:
            return programs[named]
        if slug in programs:
            return programs[slug]
        for pslug, pid in programs.items():
            if slug.startswith(pslug + "-"):
                return pid
        return default_program

    for ws in list_workspaces():
        slug = workspace_slug(ws)
        if not slug:
            continue
        if slug in getattr(common, "PROGRAM_WORKSPACES", set()):
            continue
        program_id = program_for(slug)
        name = slug.capitalize()
        source_path = _guess_source_path(slug)
        codeql_db = _guess_codeql_db(slug)

        row = conn.execute("SELECT * FROM targets WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            cur = conn.execute(
                "INSERT INTO targets (program_id, slug, name, version, source_path,"
                " codeql_db, workspace, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (program_id, slug, name, None, source_path, codeql_db, ws, common.now_iso()),
            )
            targets[slug] = cur.lastrowid
            changed += 1
        else:
            targets[slug] = row["id"]
            current = (row["program_id"], row["source_path"], row["codeql_db"], row["workspace"])
            wanted = (program_id, source_path, codeql_db, ws)
            if current != wanted:
                conn.execute(
                    "UPDATE targets SET program_id = ?, source_path = ?, codeql_db = ?,"
                    " workspace = ?, updated_at = ? WHERE id = ?",
                    (program_id, source_path, codeql_db, ws, common.now_iso(), row["id"]),
                )
                changed += 1
    return targets, changed


# ----------------------------------------------------------------------- row upserts

LEAD_FIELDS = ("target_id", "ref", "title", "class", "status", "severity",
               "file_path", "header", "body", "mtime")
REPORT_FILE_FIELDS = ("target_id", "h1_id", "ref", "title", "url", "class",
                      "file_path", "body", "kind", "mtime")

# Columns HackerOne owns. On a row where source='hackerone' the local markdown file must never
# write these: the API is the authority for what a report is called, what it says, and where it
# lives. A local hunt note is the researcher's working copy, often a different document entirely -
# #0000000 is filed on disk as an Apache UpstreamLib write-up while HackerOne knows it as
# "Denial of Service in ExampleProduct Expression Scripts via Deeply Nested Parentheses".
#
# The file still contributes the columns the API has no concept of (local taxonomy and the link
# back to disk), which is why this is a subset and not the whole tuple.
H1_OWNED_FIELDS = ("title", "url", "body")
REPORT_FILE_ONLY_FIELDS = tuple(
    f for f in REPORT_FILE_FIELDS if f not in H1_OWNED_FIELDS)


def upsert_lead(conn, parsed, target_id, mtime):
    """Insert or update one leads row keyed on file_path. Returns (id, changed)."""
    values = {
        "target_id": target_id,
        "ref": parsed["ref"],
        "title": parsed["title"],
        "class": parsed["class"],
        "status": parsed["status"],
        "severity": parsed["severity"],
        "file_path": parsed["file_path"],
        "header": parsed["header"],
        "body": parsed["body"],
        "mtime": mtime,
    }
    row = conn.execute(
        "SELECT * FROM leads WHERE file_path = ?", (parsed["file_path"],)
    ).fetchone()
    if row is None:
        cols = ", ".join('"%s"' % f for f in LEAD_FIELDS)
        marks = ", ".join("?" for _ in LEAD_FIELDS)
        cur = conn.execute(
            'INSERT INTO leads (%s, indexed_at) VALUES (%s, ?)' % (cols, marks),
            tuple(values[f] for f in LEAD_FIELDS) + (common.now_iso(),),
        )
        return cur.lastrowid, True
    if all(row[f] == values[f] for f in LEAD_FIELDS):
        return row["id"], False
    sets = ", ".join('"%s" = ?' % f for f in LEAD_FIELDS)
    conn.execute(
        "UPDATE leads SET %s, indexed_at = ? WHERE id = ?" % sets,
        tuple(values[f] for f in LEAD_FIELDS) + (common.now_iso(), row["id"]),
    )
    return row["id"], True


def upsert_report(conn, parsed, target_id, mtime):
    """Insert or update one file-backed reports row. Returns (id, changed).

    Tracker-owned columns (state/severity/bounty/dates/tracker_row) are NOT touched here;
    apply_tracker owns them.
    """
    values = {
        "target_id": target_id,
        "h1_id": parsed["h1_id"],
        "ref": parsed["ref"],
        "title": parsed["title"],
        "url": parsed["url"],
        "class": parsed["class"],
        "file_path": parsed["file_path"],
        "body": parsed["body"],
        "kind": parsed.get("kind", "report"),
        "mtime": mtime,
    }
    row = conn.execute(
        "SELECT * FROM reports WHERE file_path = ?", (parsed["file_path"],)
    ).fetchone()

    # Adoption has to work in BOTH directions or one report becomes two rows.
    #
    # h1.upsert_report already adopts a file-backed row by (h1_id, kind='report'). The reverse
    # never happened: a report submitted through the API lands as a row keyed on h1_id with no
    # file_path, and its markdown only gets the H1 number in the filename afterwards. Matching
    # on file_path alone then found nothing and inserted a second row for the same report. That
    # is where the 143-rows-for-114-reports drift came from, and it is what made the sidebar
    # badge a freshly submitted report as new a second time.
    #
    # Same rule as the H1 side: never match an RCA or a follow-up. Those share the parent's H1
    # id deliberately and are separate documents, so they must stay separate rows.
    if row is None and parsed.get("h1_id") and values["kind"] == "report":
        row = conn.execute(
            "SELECT * FROM reports"
            " WHERE h1_id = ? AND kind = 'report' AND file_path IS NULL"
            " ORDER BY (source = 'hackerone') DESC, id ASC LIMIT 1",
            (parsed["h1_id"],)).fetchone()

    if row is None:
        cols = ", ".join('"%s"' % f for f in REPORT_FILE_FIELDS)
        marks = ", ".join("?" for _ in REPORT_FILE_FIELDS)
        # first_seen_at is set here and nowhere else. See h1.ensure_schema: indexed_at moves
        # whenever content changes, so it cannot answer "is this row new".
        now = common.now_iso()
        cur = conn.execute(
            "INSERT INTO reports (%s, tracker_only, indexed_at, first_seen_at)"
            " VALUES (%s, 0, ?, ?)" % (cols, marks),
            tuple(values[f] for f in REPORT_FILE_FIELDS) + (now, now),
        )
        return cur.lastrowid, True

    # The H1 sync ADOPTS a file-backed row when one exists, so a row can carry both
    # source='hackerone' and a file_path. On those, write only what the API has no concept of.
    fields = REPORT_FILE_ONLY_FIELDS if row["source"] == "hackerone" else REPORT_FILE_FIELDS

    if all(row[f] == values[f] for f in fields) and row["tracker_only"] == 0:
        return row["id"], False
    sets = ", ".join('"%s" = ?' % f for f in fields)
    conn.execute(
        "UPDATE reports SET %s, tracker_only = 0, indexed_at = ? WHERE id = ?" % sets,
        tuple(values[f] for f in fields) + (common.now_iso(), row["id"]),
    )
    return row["id"], True


def index_file(conn, path, targets, force=False):
    """Index one markdown file. Returns (kind, row_id, changed, action).

    action is one of created|updated|unchanged|skipped. `force` re-reads even when the
    mtime matches the indexed value.
    """
    info = classify_path(path)
    if info is None or info["kind"] in ("program", "tracker"):
        return None, None, False, "skipped"

    try:
        mtime = os.path.getmtime(path)
    except OSError as exc:
        _warn("stat failed %s: %s" % (path, exc))
        return None, None, False, "skipped"

    table = "leads" if info["kind"] == "lead" else "reports"
    ap = os.path.abspath(path)
    existing = conn.execute(
        "SELECT id, mtime FROM %s WHERE file_path = ?" % table, (ap,)
    ).fetchone()
    if existing is not None and not force and existing["mtime"] == mtime:
        return info["kind"], existing["id"], False, "unchanged"

    text = read_text(path)
    if text is None:
        return None, None, False, "skipped"

    target_id = targets.get(info["target_slug"])
    try:
        if info["kind"] == "lead":
            parsed = parse_lead(ap, text)
            row_id, changed = upsert_lead(conn, parsed, target_id, mtime)
        else:
            parsed = parse_report(ap, text)
            row_id, changed = upsert_report(conn, parsed, target_id, mtime)
    except Exception as exc:  # a single bad file must never abort the scan
        _warn("parse failed %s: %s: %s" % (path, type(exc).__name__, exc))
        return None, None, False, "skipped"

    action = "updated" if existing is not None else "created"
    return info["kind"], row_id, changed, action


# --------------------------------------------------------------------------- tracker

TRACKER_APPLY_FIELDS = ("state", "severity", "bounty", "submitted_on",
                        "resolved_on", "tracker_row", "url")


def apply_tracker(conn, targets, rows):
    """Fold parsed tracker rows into `reports`. Returns the number of rows changed.

    A row whose h1_id already has a file-backed report UPDATES that report (all of its
    file-backed rows: a submission usually has both a -dos and an -rca file). A row with
    no file on disk becomes / refreshes a tracker_only=1 row.

    An h1_id that HackerOne owns is skipped entirely - see the guard below.
    """
    changed = 0
    seen_h1 = set()

    for row in rows:
        h1 = row["h1_id"]
        seen_h1.add(h1)
        target_id = targets.get(row["target_slug"]) if row["target_slug"] else None
        values = {
            "state": row["state"],
            "severity": row["severity"],
            "bounty": row["bounty"],
            "submitted_on": row["submitted_on"],
            "resolved_on": row["resolved_on"],
            "tracker_row": row["tracker_row"],
            "url": row["url"],
        }

        # HackerOne is the SOURCE OF TRUTH for reports. If the API owns this id, the markdown
        # tracker has nothing to add and a stub would only resurrect a stale shadow row carrying
        # a hand-typed bounty - the exact shape of the money bug, which reappeared three times.
        #
        # `tracker_row` is rescued onto the API row before the stub goes, because
        # h1.recover_expected_from_tracker() reads it to find ANTICIPATED payments. Losing it
        # would silently zero the anticipated total on the next sync.
        owned = conn.execute(
            "SELECT id, tracker_row FROM reports WHERE source = 'hackerone' AND h1_id = ?",
            (h1,),
        ).fetchall()
        if owned:
            for api_row in owned:
                if not (api_row["tracker_row"] or "").strip():
                    conn.execute(
                        "UPDATE reports SET tracker_row = ?, indexed_at = ? WHERE id = ?",
                        (row["tracker_row"], common.now_iso(), api_row["id"]),
                    )
                    changed += 1
            cur = conn.execute(
                "DELETE FROM reports WHERE h1_id = ? AND tracker_only = 1", (h1,)
            )
            if cur.rowcount:
                changed += cur.rowcount
            continue

        # NEVER fold markdown values onto a row HackerOne owns. The H1 sync adopts a file-backed
        # row when one exists, so `source='hackerone'` and `file_path` can both be set on the same
        # row - matching on file_path alone let a hand-recorded '[amount]' overwrite the API's
        # authoritative (empty) bounty, turning an expectation into a confirmed award.
        backed = conn.execute(
            "SELECT * FROM reports WHERE h1_id = ? AND file_path IS NOT NULL"
            " AND (source IS NULL OR source <> 'hackerone')", (h1,)
        ).fetchall()
        if backed:
            for existing in backed:
                if all(existing[f] == values[f] for f in TRACKER_APPLY_FIELDS):
                    continue
                sets = ", ".join('"%s" = ?' % f for f in TRACKER_APPLY_FIELDS)
                conn.execute(
                    "UPDATE reports SET %s, indexed_at = ? WHERE id = ?" % sets,
                    tuple(values[f] for f in TRACKER_APPLY_FIELDS)
                    + (common.now_iso(), existing["id"]),
                )
                changed += 1
            # a tracker-only stub is now redundant
            cur = conn.execute(
                "DELETE FROM reports WHERE h1_id = ? AND tracker_only = 1", (h1,)
            )
            if cur.rowcount:
                changed += cur.rowcount
            continue

        existing = conn.execute(
            "SELECT * FROM reports WHERE h1_id = ? AND tracker_only = 1", (h1,)
        ).fetchone()
        stub = dict(values)
        stub["title"] = row["title"]
        stub["class"] = row["class"]
        stub["target_id"] = target_id
        stub["h1_id"] = h1
        fields = ("target_id", "h1_id", "title", "state", "severity", "bounty",
                  "submitted_on", "resolved_on", "url", "class", "tracker_row")
        if existing is None:
            cols = ", ".join('"%s"' % f for f in fields)
            marks = ", ".join("?" for _ in fields)
            conn.execute(
                "INSERT INTO reports (%s, tracker_only, indexed_at) VALUES (%s, 1, ?)"
                % (cols, marks),
                tuple(stub[f] for f in fields) + (common.now_iso(),),
            )
            changed += 1
        elif not all(existing[f] == stub[f] for f in fields):
            sets = ", ".join('"%s" = ?' % f for f in fields)
            conn.execute(
                "UPDATE reports SET %s, indexed_at = ? WHERE id = ?" % sets,
                tuple(stub[f] for f in fields) + (common.now_iso(), existing["id"]),
            )
            changed += 1

    # tracker rows that disappeared from the table
    stale = conn.execute(
        "SELECT id, h1_id FROM reports WHERE tracker_only = 1"
    ).fetchall()
    for row in stale:
        if row["h1_id"] not in seen_h1:
            conn.execute("DELETE FROM reports WHERE id = ?", (row["id"],))
            changed += 1
    return changed


def ingest_trackers(conn, targets):
    """Read every tracker file on disk and fold it into `reports`."""
    rows = []
    for path in find_tracker_files():
        text = read_text(path)
        if text is None:
            continue
        try:
            rows.extend(parse_tracker(text))
        except Exception as exc:
            _warn("tracker parse failed %s: %s: %s" % (path, type(exc).__name__, exc))
    return apply_tracker(conn, targets, rows), len(rows)


# ------------------------------------------------------------------ freshness across a hard pass

# What the UI means by "this row changed": the text of the row, not the bookkeeping around it.
# mtime and target_id are excluded deliberately - touching a file or re-deriving a target is not
# an edit anyone made, and both move for reasons that have nothing to do with content.
LEAD_SIGNATURE = ("ref", "title", "class", "status", "severity", "header", "body")
REPORT_SIGNATURE = ("h1_id", "ref", "title", "class", "body", "tracker_row",
                    "state", "severity", "bounty", "url")


def _freshness_key(row):
    """Stable identity for a row across a delete-and-reinsert. file_path where there is one,
    otherwise the HackerOne id, which is what a tracker-only row has instead."""
    fp = row["file_path"] if "file_path" in row.keys() else None
    if fp:
        return ("path", fp)
    h1 = row["h1_id"] if "h1_id" in row.keys() else None
    return ("h1", h1) if h1 else None


def _snapshot_freshness(conn):
    """Capture indexed_at, first_seen_at and a content signature for every row, keyed on identity.

    A hard rebuild DELETES file-derived rows and re-inserts them, so both timestamps are reset to
    the moment of the rebuild and the content comparison in upsert_* never gets to run. The UI
    then paints the entire corpus 'new' or 'updated', which is how 85 rows came to be tagged after
    a parser change on 2026-08-03. A reindex is not an edit and must not look like one.
    """
    snap = {"leads": {}, "reports": {}}
    for table, sig in (("leads", LEAD_SIGNATURE), ("reports", REPORT_SIGNATURE)):
        for row in conn.execute("SELECT * FROM %s" % table):
            key = _freshness_key(row)
            if key is None:
                continue
            snap[table][key] = (row["indexed_at"], row["first_seen_at"],
                                tuple(row[f] for f in sig))
    return snap


def _restore_freshness(conn, snap):
    """Put the captured timestamps back. Returns how many rows were corrected.

    `first_seen_at` is restored unconditionally, because a row we have seen before was not first
    seen during a rebuild. `indexed_at` is restored only where the content signature is identical,
    so a hard pass that genuinely picks up an edited file still reports it as edited.
    """
    fixed = 0
    for table, sig in (("leads", LEAD_SIGNATURE), ("reports", REPORT_SIGNATURE)):
        for row in conn.execute("SELECT * FROM %s" % table).fetchall():
            key = _freshness_key(row)
            was = snap[table].get(key) if key else None
            if was is None:
                continue
            old_indexed, old_first, old_sig = was
            first = old_first or row["first_seen_at"]
            indexed = old_indexed if old_sig == tuple(row[f] for f in sig) else row["indexed_at"]
            if indexed == row["indexed_at"] and first == row["first_seen_at"]:
                continue
            conn.execute("UPDATE %s SET indexed_at = ?, first_seen_at = ? WHERE id = ?" % table,
                         (indexed, first, row["id"]))
            fixed += 1
    return fixed


# ---------------------------------------------------------------------- entry points

def rebuild(conn, hard=False):
    """Full rescan of every workspace. Returns {scanned, changed, elapsed_ms}.

    Reconciles the index against disk: creates/updates rows for changed files, drops rows
    whose file is gone, folds in the tracker table, and rebuilds search_fts from scratch.
    Unchanged files are skipped by mtime, so a second consecutive run reports changed=0.
    With hard=True the file-derived rows are deleted first and everything is re-read.
    """
    started = time.time()
    changed = 0
    scanned = 0

    snap = None
    if hard:
        # A rebuild reconstructs the index FROM THE FILES, so it may only delete file-derived
        # rows. Rows synced from an external API (HackerOne) have no file to rebuild from, and
        # wiping them silently destroyed 111 reports plus their bounty history once already.
        snap = _snapshot_freshness(conn)
        conn.execute("DELETE FROM reports WHERE source IS NULL OR source <> 'hackerone'")
        # `programs` is NOT in this list, and that is the whole point of the sentence above.
        # Only 2 of 19 programs have a workspace to be rebuilt from; the other 17 came from the
        # HackerOne API. Worse, scopes.program_id cascades on delete, so wiping programs took all
        # 970 structured scopes with it and the dashboard's Targets tile read 0. sync_programs
        # upserts by slug, so deleting first buys nothing. A program whose workspace is gone
        # lingers, which is the same trade already made for reports and the right way round.
        for table in ("leads", "targets"):
            conn.execute("DELETE FROM %s" % table)
        conn.execute("DELETE FROM search_fts")

    programs, delta = sync_programs(conn)
    changed += delta
    targets, delta = sync_targets(conn, programs)
    changed += delta

    seen = set()
    for ws in list_workspaces():
        for path in iter_markdown(ws):
            info = classify_path(path)
            if info is None or info["kind"] in ("program", "tracker"):
                continue
            scanned += 1
            kind, _row_id, was_changed, _action = index_file(conn, path, targets, force=hard)
            if kind is not None:
                seen.add(os.path.abspath(path))
            if was_changed:
                changed += 1

    # drop index rows whose file no longer exists (or moved out of a scanned workspace)
    for table in ("leads", "reports"):
        rows = conn.execute(
            "SELECT id, file_path FROM %s WHERE file_path IS NOT NULL" % table
        ).fetchall()
        for row in rows:
            fp = row["file_path"]
            if fp in seen:
                continue
            if workspace_for(fp) is None:
                continue  # not ours to reconcile (UI-created row outside the workspaces)
            conn.execute("DELETE FROM %s WHERE id = ?" % table, (row["id"],))
            changed += 1

    delta, tracker_rows = ingest_trackers(conn, targets)
    changed += delta

    # After every write, so nothing downstream can move the timestamps again.
    restored = _restore_freshness(conn, snap) if snap is not None else 0

    fts_rebuild(conn)
    conn.commit()

    return {
        "scanned": scanned,
        "changed": changed,
        "restored": restored,
        "elapsed_ms": int(round((time.time() - started) * 1000)),
        "targets": len(targets),
        "programs": len(programs),
        "tracker_rows": tracker_rows,
    }


def reindex_path(conn, path):
    """Re-index a single file after a UI write. Always re-reads (no mtime shortcut).

    Handles create, update and delete (a path that no longer exists drops its row).
    Returns {ok, path, kind, id, action, scanned, changed, elapsed_ms}.
    """
    started = time.time()
    ap = os.path.abspath(path)
    result = {
        "ok": True, "path": ap, "kind": None, "id": None,
        "action": "skipped", "scanned": 0, "changed": 0, "elapsed_ms": 0,
    }

    def finish():
        result["elapsed_ms"] = int(round((time.time() - started) * 1000))
        return result

    if not os.path.exists(ap):
        removed = 0
        for table, kind in (("leads", "lead"), ("reports", "report")):
            row = conn.execute(
                "SELECT id FROM %s WHERE file_path = ?" % table, (ap,)
            ).fetchone()
            if row is None:
                continue
            if table == "reports":
                # keep the row if the tracker still knows about it, just detach the file
                tracked = conn.execute(
                    "SELECT tracker_row FROM reports WHERE id = ?", (row["id"],)
                ).fetchone()
                if tracked and tracked["tracker_row"]:
                    conn.execute(
                        "UPDATE reports SET file_path = NULL, body = NULL, mtime = NULL,"
                        " tracker_only = 1, indexed_at = ? WHERE id = ?",
                        (common.now_iso(), row["id"]),
                    )
                    fts_sync_one(conn, kind, row["id"])
                    removed += 1
                    result.update(kind=kind, id=row["id"], action="detached")
                    continue
            conn.execute("DELETE FROM %s WHERE id = ?" % table, (row["id"],))
            fts_delete(conn, kind, str(row["id"]))
            removed += 1
            result.update(kind=kind, id=row["id"], action="deleted")
        result["changed"] = removed
        conn.commit()
        return finish()

    info = classify_path(ap)
    if info is None:
        conn.commit()
        return finish()

    programs, delta = sync_programs(conn)
    targets, delta2 = sync_targets(conn, programs)
    result["changed"] += delta + delta2

    if info["kind"] == "program":
        pid = programs.get(info["target_slug"])
        if pid:
            fts_sync_one(conn, "program", pid)
            result.update(kind="program", id=pid, action="updated", scanned=1)
        conn.commit()
        return finish()

    if info["kind"] == "tracker":
        delta, _rows = ingest_trackers(conn, targets)
        result["changed"] += delta
        result.update(kind="tracker", action="updated", scanned=1)
        fts_rebuild(conn)
        conn.commit()
        return finish()

    result["scanned"] = 1
    kind, row_id, was_changed, action = index_file(conn, ap, targets, force=True)
    if kind is None:
        conn.commit()
        return finish()
    if was_changed:
        result["changed"] += 1
    result.update(kind=kind, id=row_id, action=action)

    if kind == "report":
        # a fresh report file may already have a tracker row waiting for it
        delta, _rows = ingest_trackers(conn, targets)
        result["changed"] += delta

    fts_sync_one(conn, kind, row_id)
    conn.commit()
    return finish()


# ------------------------------------------------------------------------------- cli

def open_db(db_path=common.DB_PATH):
    """Connect, creating the database and applying schema.sql when it is absent."""
    fresh = not os.path.exists(db_path)
    conn = common.connect(db_path)
    if fresh or not conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='leads'"
    ).fetchone():
        common.init_db(conn)
    return conn


def collect_stats(conn):
    stats = {"counts": {}, "leads_by_status": {}, "leads_by_target": {},
             "reports_by_state": {}, "leads_by_class": {}}
    for table in ("programs", "targets", "leads", "reports", "advisories", "uploads"):
        stats["counts"][table] = conn.execute(
            "SELECT COUNT(*) AS n FROM %s" % table
        ).fetchone()["n"]
    stats["counts"]["reports_tracker_only"] = conn.execute(
        "SELECT COUNT(*) AS n FROM reports WHERE tracker_only = 1"
    ).fetchone()["n"]
    stats["counts"]["reports_with_file"] = conn.execute(
        "SELECT COUNT(*) AS n FROM reports WHERE file_path IS NOT NULL"
    ).fetchone()["n"]
    stats["counts"]["search_fts"] = conn.execute(
        "SELECT COUNT(*) AS n FROM search_fts"
    ).fetchone()["n"]

    for row in conn.execute(
        "SELECT status, COUNT(*) AS n FROM leads GROUP BY status ORDER BY n DESC"
    ):
        stats["leads_by_status"][row["status"]] = row["n"]
    for row in conn.execute(
        "SELECT COALESCE(t.slug,'(none)') AS slug, COUNT(*) AS n FROM leads l"
        " LEFT JOIN targets t ON t.id = l.target_id GROUP BY slug ORDER BY n DESC"
    ):
        stats["leads_by_target"][row["slug"]] = row["n"]
    for row in conn.execute(
        "SELECT COALESCE(class,'(none)') AS c, COUNT(*) AS n FROM leads"
        " GROUP BY c ORDER BY n DESC"
    ):
        stats["leads_by_class"][row["c"]] = row["n"]
    for row in conn.execute(
        "SELECT COALESCE(state,'(none)') AS s, COUNT(*) AS n FROM reports"
        " GROUP BY s ORDER BY n DESC"
    ):
        stats["reports_by_state"][row["s"]] = row["n"]
    return stats


def print_stats(conn):
    stats = collect_stats(conn)
    print("counts")
    for key, value in stats["counts"].items():
        print("  %-22s %d" % (key, value))
    for section in ("leads_by_status", "leads_by_class", "leads_by_target",
                    "reports_by_state"):
        print(section)
        for key, value in stats[section].items():
            print("  %-22s %d" % (key, value))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rebuild", action="store_true",
                    help="rescan every workspace and reconcile the index")
    ap.add_argument("--hard", action="store_true",
                    help="with --rebuild: drop the file-derived rows first, re-read all")
    ap.add_argument("--reindex", metavar="PATH",
                    help="re-index a single path (create/update/delete)")
    ap.add_argument("--stats", action="store_true", help="print index counts")
    ap.add_argument("--quiet", action="store_true",
                    help="only print when something actually changed (cron mode)")
    ap.add_argument("--db", default=common.DB_PATH, help="database path")
    args = ap.parse_args(argv)

    if not (args.rebuild or args.stats or args.reindex):
        ap.print_help()
        return 2

    conn = open_db(args.db)
    try:
        if args.rebuild:
            result = rebuild(conn, hard=args.hard)
            # Quiet means quiet UNLESS something moved. Every 10 minutes, a line saying nothing
            # changed is a log nobody reads, which is the same as no log at all.
            if not args.quiet or result["changed"]:
                print("%srebuild: scanned=%d changed=%d elapsed_ms=%d "
                      "targets=%d programs=%d tracker_rows=%d"
                      % (common.now_iso() + " " if args.quiet else "",
                         result["scanned"], result["changed"], result["elapsed_ms"],
                         result["targets"], result["programs"], result["tracker_rows"]))
        if args.reindex:
            result = reindex_path(conn, args.reindex)
            print("reindex: %s kind=%s id=%s action=%s changed=%d elapsed_ms=%d"
                  % (result["path"], result["kind"], result["id"], result["action"],
                     result["changed"], result["elapsed_ms"]))
        if args.stats:
            print_stats(conn)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
