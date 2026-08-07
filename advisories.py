#!/usr/bin/env python3
"""Advisory ingestion. Stdlib only.

Pulls security advisories from one or more configured feeds (CISA and VulDB by default; add your
own in config.json under `advisory_feeds`) and stores them in the `advisories` table.

Two modes:

  --sync       poll each feed's RSS/Atom. Cheap, one request per feed. This is what cron runs.
  --backfill   for a Discourse-type feed, walk its JSON category listing page by page to enumerate
               every topic ever posted, then fetch each body. Slow; run once (and after outages).

Both are idempotent and safe to re-run: rows are keyed on the canonical entry URL.

    python3 advisories.py --sync          # ongoing, what cron calls
    python3 advisories.py --backfill      # one-time deep pull for a Discourse feed
    python3 advisories.py --stats
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

import common

USER_AGENT = "quarry-advisory-sync/1.0 (+local research tool)"
HTTP_TIMEOUT = 30
MAX_BYTES = 8 * 1024 * 1024
PAGE_LIMIT = 60          # backfill safety stop; 60 pages x 30 = 1800 topics
POLITE_DELAY = 0.6       # seconds between requests during backfill

# Advisory feeds. Each entry is {name, type, url}; `type` selects the handler ("rss" for any
# RSS 2.0 or Atom feed - 90% of security bulletins - or "discourse" for a category the deep
# backfill can walk via the Discourse API). Override or extend this in config.json under
# `advisory_feeds`; a HackerOne hunter points it at the vendors whose targets they hunt.
DEFAULT_FEEDS = [
    {"name": "CISA Advisories",  "type": "rss", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"name": "VulDB Recent",     "type": "rss", "url": "https://vuldb.com/?rss.recent"},
]

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

CWE_RE = re.compile(r"\bCWE-(\d{1,4})\b", re.I)


def parse_cwe(body):
    """Comma-separated unique CWE ids found anywhere in the text, '' when none. Generic: any
    standard CWE-XXX token, no vendor-specific labelled-line parsing."""
    seen, out = set(), []
    for n in CWE_RE.findall(body or ""):
        cid = ("CWE-" + n).upper()
        if cid not in seen:
            seen.add(cid); out.append(cid)
    return ",".join(out)
CVSS_LOOSE_RE = re.compile(
    r"CVSS(?:v[0-9.]+)?\s*(?:base\s*)?score[:\s]*([0-9]{1,2}(?:\.[0-9])?)", re.I)
SEVERITY_LOOSE_RE = re.compile(r"\b(critical|high|medium|moderate|low)\b", re.I)
CVSS_VECTOR_RE = re.compile(r"CVSS:[0-9.]+/(?:[A-Z]+:[A-Z]+/?)+")


# ------------------------------------------------------------------ vector -> words
# A raw vector ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H") is unreadable at a glance and
# wraps badly in a detail pane. `describe_vector` turns it into words so the UI can show what
# an advisory actually costs the victim (impact) and what it costs the attacker (privileges)
# instead of the string. v3.x uses C/I/A; v4.0 renames them VC/VI/VA and adds subsequent-system
# SC/SI/SA - both spellings are handled.
_METRIC_WORDS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "AT": {"N": "None", "P": "Present"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required", "P": "Passive", "A": "Active"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "_IMPACT": {"H": "High", "L": "Low", "N": "None"},
}
# metric key -> label, in the order they should be displayed.
_IMPACT_METRICS = [
    ("C", "Confidentiality"), ("I", "Integrity"), ("A", "Availability"),
    ("VC", "Confidentiality"), ("VI", "Integrity"), ("VA", "Availability"),
    ("SC", "Subsequent confidentiality"), ("SI", "Subsequent integrity"),
    ("SA", "Subsequent availability"),
]


def parse_vector(vector):
    """'CVSS:3.1/AV:N/...' -> {'CVSS': '3.1', 'AV': 'N', ...}. {} when unparseable."""
    out = {}
    for part in (vector or "").split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        out[key.strip().upper()] = val.strip().upper()
    return out


def decode_cvss_vector(vector):
    """Spell a CVSS vector out in words. Pure; safe on junk input.

    Returns {version, impact: [{metric,label,level}], impact_text, privileges, attack_vector,
    user_interaction, complexity, scope, metrics}. Impacts scored None are OMITTED - listing
    "Availability: None" three times is noise, and the absence is already implied.

    NO CVSS v2 SUPPORT, deliberately: every vector in this archive is CVSS:3.0, 3.1 or 4.0
    (checked across all 266 advisories and all 111 H1 reports - zero `Au:` metrics), so v2
    decoding would be untested dead code. Unknown metric letters fall through as themselves
    rather than being dropped, which is what a v2 vector would do if one ever appeared.
    """
    m = parse_vector(vector)
    if not m:
        return {}
    impacts = []
    for key, label in _IMPACT_METRICS:
        val = m.get(key)
        if not val or val == "N":            # drop the Nones, as requested
            continue
        word = _METRIC_WORDS["_IMPACT"].get(val, val)
        impacts.append({"metric": key, "label": label, "level": word})
    out = {
        "version": m.get("CVSS", ""),
        "impact": impacts,
        "impact_text": ", ".join("%s: %s" % (i["label"], i["level"]) for i in impacts),
        "metrics": m,
    }
    for key, name in (("PR", "privileges"), ("AV", "attack_vector"),
                      ("UI", "user_interaction"), ("AC", "complexity"), ("S", "scope")):
        val = m.get(key)
        if val:
            out[name] = _METRIC_WORDS[key].get(val, val)
    return out


def score_band(score):
    """CVSS v3 qualitative band, used when the advisory gives a number but no word."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "none"

# Product tag. Generic: taken from the RSS <category> tags or the feed name in normalize(); there
# is no vendor-specific product taxonomy in the public build.


# ------------------------------------------------------------------ http
def fetch(url):
    """GET a URL with a timeout, a UA and a hard size cap. Returns bytes."""
    if not url.lower().startswith("https://"):
        raise ValueError("refusing non-https feed URL: %r" % url)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response from %s exceeded %d bytes" % (url, MAX_BYTES))
    return data


# ------------------------------------------------------------------ html -> markdown
# The UI renders `advisories.body` through renderMarkdown(), so the body is stored as MARKDOWN,
# not flat text. Everything emitted here is limited to what that renderer understands: ATX
# headings, blank-line paragraphs, `-`/`1.` lists (nested by two-space indent), **bold**,
# _italic_, `code`, fenced blocks, [text](url), `>` quotes, `|` tables and `---` rules.
#
# THE PARSERS DOWNSTREAM READ THIS OUTPUT. `parse_severity_line`, `CVE_LINE_RE` and
# `normalize` all scan the converted body, and ExampleVendor bolds those labels
# (`<strong>CVE ID:</strong> CVE-2026-63145`), so the markdown carries `**CVE ID:**`. The
# regexes above are written to step over emphasis runs for exactly that reason - if you change
# what this emitter produces around `Severity:` or `CVE ID:`, change them too and re-check the
# coverage numbers in `--stats`.
_HEADINGS = {"h1": 1, "h2": 2, "h3": 3, "h4": 4, "h5": 5, "h6": 6}
_BLOCK_TAGS = {"p", "div", "section", "article", "header", "footer", "aside", "figure"}
_DROP_TAGS = {"script", "style", "noscript", "svg", "iframe"}
# Discourse wraps every heading in an empty `<a class="anchor" href="#p-123-...">`. Converting
# those literally would put `[](#p-1031833-subject-...)` at the head of most older advisories.
_LOCAL_HREF = ("#",)


def _md_escape_cell(text):
    return text.replace("|", "\\|").replace("\n", " ").strip()


class _Markdownify(HTMLParser):
    """HTML -> Markdown. Stdlib html.parser only.

    Structure is built on a STACK OF BUFFERS: entering a construct that needs its content
    transformed as a unit (table cell, blockquote, preformatted block) pushes a buffer, and the
    closing tag pops it and rewrites it. Inline emphasis uses the same idea in miniature - the
    opening marker is written as a placeholder whose index is remembered, so an empty
    `<strong></strong>` or an empty anchor can be erased instead of leaving `****` behind.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = [[]]
        self.skip = 0
        self.pre = 0
        self.lists = []          # [{"ordered": bool, "n": int}]
        self.tables = []         # [{"rows": [[str]], "row": [str]|None, "header": bool}]
        self.marks = []          # open inline constructs: [tag, buffer_index, href]

    # -- buffer plumbing ---------------------------------------------------
    @property
    def buf(self):
        return self.stack[-1]

    def _emit(self, text):
        self.buf.append(text)

    def _tail(self):
        for chunk in reversed(self.buf):
            if chunk:
                return chunk[-1]
        return "\n"

    def _block(self):
        """Start a new markdown block, without stacking blank lines."""
        text = "".join(self.buf)
        if not text.strip():
            del self.buf[:]
            return
        if not text.endswith("\n\n"):
            self._emit("\n" if text.endswith("\n") else "\n\n")

    def _line(self, indent=""):
        if self._tail() != "\n":
            self._emit("\n")
        if indent:
            self._emit(indent)

    def _push(self):
        self.stack.append([])

    def _pop(self):
        return "".join(self.stack.pop())

    # -- tags --------------------------------------------------------------
    def handle_starttag(self, tag, attrs):
        if self.skip:
            if tag in _DROP_TAGS:
                self.skip += 1
            return
        if tag in _DROP_TAGS:
            self.skip = 1
            return
        adict = dict(attrs)

        if tag == "pre":
            self.pre += 1
            self._block()
            self._push()
            return
        if self.pre:
            if tag == "br":
                self._emit("\n")
            return

        if tag in _HEADINGS:
            self._block()
            self._emit("#" * _HEADINGS[tag] + " ")
        elif tag in _BLOCK_TAGS:
            self._block()
        elif tag == "br":
            # renderMarkdown turns a newline inside a paragraph into <br>, and a list item
            # continues across an indented line, so the right hard break depends on context.
            self._line("  " * len(self.lists) if self.lists else "")
        elif tag == "hr":
            self._block()
            self._emit("---")
            self._block()
        elif tag in ("ul", "ol"):
            if not self.lists:
                self._block()
            self.lists.append({"ordered": tag == "ol", "n": 0})
        elif tag == "li":
            if not self.lists:
                self.lists.append({"ordered": False, "n": 0})
            lvl = self.lists[-1]
            lvl["n"] += 1
            self._line("  " * (len(self.lists) - 1))
            self._emit(("%d. " % lvl["n"]) if lvl["ordered"] else "- ")
        elif tag == "blockquote":
            self._block()
            self._push()
        elif tag == "table":
            self._block()
            self.tables.append({"rows": [], "row": None, "header": False})
        elif tag == "tr" and self.tables:
            self.tables[-1]["row"] = []
        elif tag in ("td", "th") and self.tables:
            if self.tables[-1]["row"] is None:
                self.tables[-1]["row"] = []
            if tag == "th":
                self.tables[-1]["header"] = True
            self._push()
        elif tag in ("strong", "b"):
            self.marks.append([tag, len(self.buf), None])
            self._emit("**")
        elif tag in ("em", "i"):
            self.marks.append([tag, len(self.buf), None])
            self._emit("_")
        elif tag in ("del", "s", "strike"):
            self.marks.append([tag, len(self.buf), None])
            self._emit("~~")
        elif tag == "code":
            self.marks.append([tag, len(self.buf), None])
            self._emit("`")
        elif tag == "a":
            self.marks.append([tag, len(self.buf), adict.get("href") or ""])
            self._emit("[")
        elif tag == "img":
            alt = (adict.get("alt") or "image").strip()
            src = adict.get("src") or ""
            if src:
                self._emit("![%s](%s)" % (alt, src))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if self.skip:
            if tag in _DROP_TAGS:
                self.skip -= 1
            return

        if tag == "pre" and self.pre:
            self.pre -= 1
            code = self._pop().strip("\n")
            fence = "```"
            while fence in code:
                fence += "`"
            self._emit("%s\n%s\n%s" % (fence, code, fence))
            self._block()
            return
        if self.pre:
            return

        if tag in _HEADINGS or tag in _BLOCK_TAGS:
            self._block()
        elif tag in ("ul", "ol"):
            if self.lists:
                self.lists.pop()
            if not self.lists:
                self._block()
        elif tag == "blockquote":
            inner = self._pop().strip()
            if inner:
                quoted = "\n".join("> " + ln if ln.strip() else ">"
                                   for ln in inner.split("\n"))
                self._emit(quoted)
            self._block()
        elif tag in ("td", "th") and self.tables:
            cell = _md_escape_cell(re.sub(r"\s+", " ", self._pop()))
            self.tables[-1]["row"].append(cell)
        elif tag == "tr" and self.tables:
            row = self.tables[-1]["row"]
            if row:
                self.tables[-1]["rows"].append(row)
            self.tables[-1]["row"] = None
        elif tag == "table" and self.tables:
            self._emit(self._render_table(self.tables.pop()))
            self._block()
        elif self.marks and self.marks[-1][0] == tag:
            self._close_mark()

    def _close_mark(self):
        kind, idx, href = self.marks.pop()
        inner = "".join(self.buf[idx + 1:])
        if not inner.strip():
            del self.buf[idx:]            # empty emphasis / Discourse anchor: drop it whole
            return
        if kind == "a":
            if not href or href.startswith(_LOCAL_HREF):
                self.buf[idx] = ""        # in-page anchor: keep the text, drop the link
                return
            self._emit("](%s)" % href.replace(" ", "%20"))
            return
        if kind == "code":
            ticks = "`"
            while ticks in inner:
                ticks += "`"
            self.buf[idx] = ticks
            self._emit(ticks)
            return
        # Emphasis must not straddle a line: renderMarkdown's ** and _ rules are line-scoped.
        if "\n" in inner:
            self.buf[idx] = ""
            return
        self._emit({"strong": "**", "b": "**", "em": "_", "i": "_"}.get(kind, "~~"))

    @staticmethod
    def _render_table(state):
        rows = [r for r in state["rows"] if any(c for c in r)]
        if not rows:
            return ""
        width = max(len(r) for r in rows)
        if width < 2:
            # A one-column "table" is a layout hack, not data. Render it as a list so the
            # markdown table syntax is not spent on something that reads worse as a table.
            return "\n".join("- " + (r[0] if r else "") for r in rows)
        rows = [r + [""] * (width - len(r)) for r in rows]
        head, body = rows[0], rows[1:]
        out = ["| " + " | ".join(head) + " |",
               "|" + "|".join([" --- "] * width) + "|"]
        out.extend("| " + " | ".join(r) + " |" for r in body)
        return "\n".join(out)

    # -- text --------------------------------------------------------------
    def handle_data(self, data):
        if self.skip or not data:
            return
        if self.pre:
            self._emit(data)
            return
        text = re.sub(r"\s+", " ", data)
        if not text:
            return
        if self._tail() in ("\n", " ") and text.startswith(" "):
            text = text.lstrip()
        if text:
            self._emit(text)


def html_to_markdown(html):
    """Convert advisory HTML to markdown. Never raises: falls back to tag-stripped text."""
    if not html:
        return ""
    parser = _Markdownify()
    try:
        parser.feed(html)
        parser.close()
        text = "".join(parser.stack[0])
    except Exception:                                  # malformed HTML must not kill a sync
        text = re.sub(r"<[^>]+>", " ", html)
    # Protect fenced code from the whitespace tidy-up below.
    blocks = []

    def _stash(m):
        blocks.append(m.group(0))
        return "\x00%d\x00" % (len(blocks) - 1)

    text = re.sub(r"(?ms)^(`{3,})[^\n]*\n.*?^\1[ \t]*$", _stash, text)
    # Collapse runs of spaces, but ONLY after a non-space: leading indentation is what makes a
    # nested list nest, and squashing it to one space silently flattens every sub-list.
    text = re.sub(r"(?<=\S)[ \t]+", " ", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"\x00(\d+)\x00", lambda m: blocks[int(m.group(1))], text)
    return _strip_discourse_footer(text.strip())


# The RSS `description` is the post plus Discourse's own footer ("3 posts - 2 participants",
# "[Read full topic](...)"). It is not part of the advisory and, left in, it is the last thing
# the reader sees in the detail pane.
_FOOTER_RE = re.compile(
    r"(?:\n\s*(?:\d+\s+posts?\s+-\s+\d+\s+participants?"
    r"|\[Read full topic\]\([^)]*\)))+\s*$", re.I)


def _strip_discourse_footer(text):
    return _FOOTER_RE.sub("", text).strip()


def html_to_text(html):
    """Back-compat shim. The stored body is markdown now; see `html_to_markdown`."""
    return html_to_markdown(html)


# ------------------------------------------------------------------ parsing
def _iso_from_rfc822(value):
    """'Tue, 21 Jul 2026 23:08:36 +0000' -> '2026-07-21T23:08:36'. Returns '' on failure."""
    if not value:
        return ""
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(
                time.mktime(time.strptime(value.strip(), fmt)) if "%z" not in fmt
                else _epoch_with_tz(value.strip(), fmt)))
        except Exception:
            continue
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", value)
    return "%s-%s-%s" % m.groups() if m else ""


def _epoch_with_tz(value, fmt):
    import datetime
    return datetime.datetime.strptime(value, fmt).timestamp()


ATOM_NS = "{http://www.w3.org/2005/Atom}"
_CONTENT_NS = "{http://purl.org/rss/1.0/modules/content/}encoded"
_DC_DATE = "{http://purl.org/dc/elements/1.1/}date"


def _parse_date(value):
    """Best-effort published date -> ISO-8601. Handles RFC822 (pubDate) and ISO8601
    (updated/published); returns the raw value if neither parses, '' if empty."""
    value = (value or "").strip()
    if not value:
        return ""
    try:
        import email.utils
        dt = email.utils.parsedate_to_datetime(value)
        if dt is not None:
            return dt.isoformat()
    except Exception:
        pass
    try:
        import datetime
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except Exception:
        return value


def normalize(title, url, published, body_html, source, body_md=None, categories=None,
              meta_extra=""):
    """Build an advisories row from raw feed fields. Pure - no DB, no network. Generic across
    vendors: identifiers and scores come from standard patterns in the title/body, and the product
    tag from the feed's <category> tags or its name. `meta_extra` is extra raw text (the feed's
    OTHER text field, e.g. a summary when the full content is the body) scanned for CVE/CVSS/CWE
    but not displayed, so a score that lives in the summary is not lost."""
    body = body_md if body_md is not None else html_to_markdown(body_html)
    haystack = (title or "") + "\n" + body + "\n" + (meta_extra or "")

    cves = sorted(set(c.upper() for c in CVE_RE.findall(haystack)))
    ref = cves[0] if cves else ""

    cvss_score = ""
    loose = CVSS_LOOSE_RE.search(haystack)
    if loose:
        cvss_score = loose.group(1)
    vector = ""
    vm = CVSS_VECTOR_RE.search(haystack)
    if vm:
        vector = vm.group(0)
    level = ""
    sev = SEVERITY_LOOSE_RE.search(haystack)
    if sev:
        level = sev.group(1).lower()
    if cvss_score and not level:
        level = score_band(cvss_score)
    if level == "moderate":
        level = "medium"

    tags = [c.strip() for c in (categories or []) if c and c.strip()]
    product = ", ".join(dict.fromkeys(tags)) if tags else (source or "")

    return {
        "ref": ref, "source": source, "title": (title or "").strip(), "url": url,
        "published": published, "status": "watch", "body": body, "body_html": body_html or "",
        "cve": ",".join(cves), "cwe": parse_cwe(haystack), "cvss": cvss_score,
        "cvss_vector": vector, "severity": level, "product": product, "_target_slug": None,
    }


def _atom_link(entry):
    for l in entry.findall(ATOM_NS + "link"):
        if (l.get("rel") or "alternate") == "alternate" and l.get("href"):
            return l.get("href")
    l = entry.find(ATOM_NS + "link")
    return l.get("href") if l is not None else ""


_XML_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_BARE_AMP = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")


def _parse_xml(xml_bytes):
    """ET.fromstring, but tolerant of the two ways real feeds are malformed: control characters
    that are illegal in XML 1.0, and a bare `&` that was never escaped. Sanitize and retry once."""
    try:
        return ET.fromstring(xml_bytes)
    except ET.ParseError:
        txt = xml_bytes.decode("utf-8", "replace")
        txt = _BARE_AMP.sub("&amp;", _XML_ILLEGAL.sub("", txt))
        return ET.fromstring(txt)


def parse_rss(xml_bytes, source):
    """Parse an RSS 2.0 or Atom 1.0 feed. RSS <item> first; Atom <entry> if none found."""
    root = _parse_xml(xml_bytes)
    out = []
    items = root.findall(".//item")
    if items:
        for item in items:
            link = item.findtext("link") or ""
            if not link:
                continue
            title = item.findtext("title") or ""
            pub = _parse_date(item.findtext("pubDate") or item.findtext(_DC_DATE) or "")
            content = item.findtext(_CONTENT_NS) or ""
            desc = item.findtext("description") or ""
            body = content or desc               # prefer the rich HTML for display
            extra = desc if (content and desc) else ""   # scan the summary for metadata too
            cats = [c.text for c in item.findall("category") if c is not None and c.text]
            out.append(normalize(title, link, pub, body, source, categories=cats, meta_extra=extra))
        return out
    for entry in root.findall(".//" + ATOM_NS + "entry"):
        link = _atom_link(entry)
        if not link:
            continue
        title = entry.findtext(ATOM_NS + "title") or ""
        pub = _parse_date(entry.findtext(ATOM_NS + "updated")
                          or entry.findtext(ATOM_NS + "published") or "")
        content = entry.findtext(ATOM_NS + "content") or ""
        summary = entry.findtext(ATOM_NS + "summary") or ""
        body = content or summary
        extra = summary if (content and summary) else ""
        cats = [c.get("term") for c in entry.findall(ATOM_NS + "category") if c.get("term")]
        out.append(normalize(title, link, pub, body, source, categories=cats, meta_extra=extra))
    return out


def parse_category_json(raw):
    """Return (topics, more) from a Discourse category listing page."""
    d = json.loads(raw)
    tl = d.get("topic_list") or {}
    return tl.get("topics") or [], bool(tl.get("more_topics_url"))


def parse_topic_json(raw):
    """Return (title, created_at, body_html) for a Discourse topic."""
    d = json.loads(raw)
    title = d.get("title") or ""
    created = d.get("created_at") or ""
    body = ""
    posts = ((d.get("post_stream") or {}).get("posts") or [])
    if posts:
        body = posts[0].get("cooked") or ""
    return title, created, body


# ------------------------------------------------------------------ db
def ensure_schema(conn):
    """Additive migration: columns and the uniqueness constraint ingest relies on."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(advisories)").fetchall()}
    # `body_html` is the RAW source. `body` is markdown derived from it, so a change to the
    # converter is a `--reparse` away instead of 266 network round-trips; it is also the only
    # way to recover from a conversion bug, since the conversion is lossy by design.
    for name, decl in (("cve", "TEXT"), ("severity", "TEXT"), ("product", "TEXT"),
                       ("cvss", "TEXT"), ("cvss_vector", "TEXT"), ("fetched_at", "TEXT"),
                       ("body_html", "TEXT"), ("cwe", "TEXT")):
        if name not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN %s %s" % (name, decl))
    # url is the natural key: stable, canonical, and present on every item.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_advisories_url ON advisories(url)")
    conn.commit()


def _target_id(conn, slug):
    if not slug:
        return None
    row = conn.execute("SELECT id FROM targets WHERE slug = ?", (slug,)).fetchone()
    return row["id"] if row else None


def upsert(conn, row):
    """Insert or update one advisory. Returns 'new', 'updated' or 'unchanged'."""
    tid = _target_id(conn, row.pop("_target_slug", None))
    existing = conn.execute(
        "SELECT id, title, body, body_html, published, cve, cwe, cvss, severity, product"
        " FROM advisories WHERE url = ?",
        (row["url"],)).fetchone()
    now = common.now_iso()
    body_html = row.get("body_html") or ""

    if existing is None:
        # first_seen_at is written here and never again. indexed_at below is bumped whenever a
        # vendor edits an advisory, so it cannot answer "is this new to us" - see
        # common.ensure_first_seen().
        conn.execute(
            "INSERT INTO advisories (target_id, ref, source, title, url, published, status,"
            " body, body_html, cve, cwe, cvss, cvss_vector, severity, product, indexed_at,"
            " fetched_at, first_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, row["ref"], row["source"], row["title"], row["url"], row["published"],
             row["status"], row["body"], body_html, row["cve"], row["cwe"], row["cvss"],
             row["cvss_vector"], row["severity"], row["product"], now, now, now))
        conn.commit()
        return "new"

    changed = (existing["title"] != row["title"] or (existing["body"] or "") != row["body"]
               or (existing["cve"] or "") != row["cve"]
               or (existing["cwe"] or "") != row["cwe"]
               or (existing["cvss"] or "") != row["cvss"]
               or (existing["severity"] or "") != row["severity"]
               or (existing["product"] or "") != row["product"]
               # A row stored before body_html existed must be topped up even when nothing
               # else moved, or --reparse can never regenerate its markdown.
               or (body_html and (existing["body_html"] or "") != body_html))
    if changed:
        # Never clobber a human-set status; only refresh the fetched content. body_html is
        # only written when we actually have HTML - an RSS-only refresh must not blank it.
        conn.execute(
            "UPDATE advisories SET title=?, body=?, published=?, cve=?, cwe=?, cvss=?,"
            " cvss_vector=?, severity=?, product=?,"
            " body_html=COALESCE(NULLIF(?,''), body_html),"
            " ref=COALESCE(NULLIF(?,''), ref), target_id=COALESCE(?, target_id),"
            " indexed_at=?, fetched_at=? WHERE id=?",
            (row["title"], row["body"], row["published"], row["cve"], row["cwe"], row["cvss"],
             row["cvss_vector"], row["severity"], row["product"], body_html, row["ref"], tid,
             now, now, existing["id"]))
        conn.commit()
        return "updated"

    conn.execute("UPDATE advisories SET fetched_at=? WHERE id=?", (now, existing["id"]))
    conn.commit()
    return "unchanged"


def index_fts(conn):
    """Refresh the advisory rows in the shared search index."""
    try:
        conn.execute("DELETE FROM search_fts WHERE kind='advisory'")
        rows = conn.execute(
            "SELECT a.id, a.ref, a.title, a.body, t.slug FROM advisories a"
            " LEFT JOIN targets t ON t.id=a.target_id").fetchall()
        for r in rows:
            conn.execute(
                "INSERT INTO search_fts (kind, rowid_ref, ref, title, target, body)"
                " VALUES ('advisory', ?, ?, ?, ?, ?)",
                (str(r["id"]), r["ref"] or "", r["title"] or "", r["slug"] or "", r["body"] or ""))
        conn.commit()
    except Exception as e:
        sys.stderr.write("fts refresh failed: %s\n" % e)


# ------------------------------------------------------------------ sync
def feeds(cfg):
    return cfg.get("advisory_feeds") or DEFAULT_FEEDS


def sync_rss(conn, cfg, verbose=True):
    """Poll the RSS feed. What cron runs."""
    ensure_schema(conn)
    stats = {"new": 0, "updated": 0, "unchanged": 0, "errors": 0}
    for feed in feeds(cfg):
        # Dispatch by type. "rss" and a Discourse category's ".rss" are both parsed by parse_rss
        # (RSS 2.0 or Atom); the deep Discourse API walk lives in backfill(). `url` is the config
        # key; `rss` is accepted for backward compatibility.
        url = feed.get("url") or feed.get("rss")
        if not url:
            continue
        try:
            raw = fetch(url)
            items = parse_rss(raw, feed.get("name", "rss"))
        except Exception as e:
            stats["errors"] += 1
            sys.stderr.write("feed %s failed: %s\n" % (url, e))
            continue
        for item in items:
            try:
                stats[upsert(conn, item)] += 1
            except Exception as e:
                stats["errors"] += 1
                sys.stderr.write("upsert failed for %s: %s\n" % (item.get("url"), e))
    index_fts(conn)
    if verbose:
        print("rss sync: new=%(new)d updated=%(updated)d unchanged=%(unchanged)d errors=%(errors)d"
              % stats)
    return stats


def backfill(conn, cfg, verbose=True, max_pages=PAGE_LIMIT):
    """Walk the whole Discourse category to capture every advisory ever posted."""
    ensure_schema(conn)
    stats = {"new": 0, "updated": 0, "unchanged": 0, "errors": 0, "topics": 0, "pages": 0}
    for feed in feeds(cfg):
        cat = feed.get("category_json")
        topic_tpl = feed.get("topic_json")
        if not (cat and topic_tpl):
            continue
        source = feed.get("name", "discourse")
        seen = set()
        for page in range(max_pages):
            try:
                raw = fetch("%s?page=%d" % (cat, page))
                topics, more = parse_category_json(raw)
            except Exception as e:
                stats["errors"] += 1
                sys.stderr.write("category page %d failed: %s\n" % (page, e))
                break
            if not topics:
                break
            stats["pages"] += 1
            for t in topics:
                tid = t.get("id")
                title = t.get("title") or ""
                if tid in seen:
                    continue
                seen.add(tid)
                # Skip the category's own "About" pinned topic - not an advisory.
                if title.lower().startswith("about the "):
                    continue
                stats["topics"] += 1
                url = "https://discuss.example-vendor.co/t/%s/%s" % (t.get("slug") or "t", tid)
                try:
                    time.sleep(POLITE_DELAY)
                    traw = fetch(topic_tpl.format(id=tid))
                    ttitle, created, body = parse_topic_json(traw)
                    row = normalize(ttitle or title, url,
                                    _iso_from_rfc822(created or t.get("created_at") or ""),
                                    body, source)
                    stats[upsert(conn, row)] += 1
                except Exception as e:
                    stats["errors"] += 1
                    sys.stderr.write("topic %s failed: %s\n" % (tid, e))
            if verbose:
                print("  page %d: %d topics (running new=%d updated=%d)"
                      % (page, len(topics), stats["new"], stats["updated"]))
            if not more:
                break
    index_fts(conn)
    if verbose:
        print("backfill: pages=%(pages)d topics=%(topics)d new=%(new)d updated=%(updated)d "
              "unchanged=%(unchanged)d errors=%(errors)d" % stats)
    return stats


def reparse(conn, verbose=True):
    """Re-derive the markdown body and ref/CVE/CVSS/severity/product from stored data. No network.

    Needed whenever the parsing or formatting rules change: the sources are already on disk, so
    there is no reason to re-hit the feed. Never touches `status` - that is a human decision.

    Where `body_html` is present the markdown body is REGENERATED from it, which is what makes
    converter changes a local operation. Rows stored before that column existed have only the
    converted body; those are passed through untouched (`body_md=`) rather than fed back through
    the HTML converter, which would flatten them.
    """
    ensure_schema(conn)
    rows = conn.execute(
        "SELECT id, title, url, published, body, body_html FROM advisories").fetchall()
    changed = 0
    rebodied = 0
    for r in rows:
        html = r["body_html"] or ""
        if html:
            row = normalize(r["title"], r["url"], r["published"], html, "reparse")
        else:
            row = normalize(r["title"], r["url"], r["published"], "", "reparse",
                            body_md=r["body"] or "")
        tid = _target_id(conn, row.pop("_target_slug", None))
        cur = conn.execute(
            "SELECT ref, cve, cwe, cvss, cvss_vector, severity, product, target_id"
            " FROM advisories WHERE id=?", (r["id"],)).fetchone()
        body_changed = html and row["body"] != (r["body"] or "")
        same = (
            not body_changed
            and (cur["cve"] or "") == row["cve"] and (cur["cwe"] or "") == row["cwe"]
            and (cur["cvss"] or "") == row["cvss"]
            and (cur["severity"] or "") == row["severity"]
            and (cur["product"] or "") == row["product"]
            and (cur["cvss_vector"] or "") == row["cvss_vector"]
            and (cur["ref"] or "") == (row["ref"] or cur["ref"] or "")
            and (cur["target_id"] or None) == (tid if tid is not None else cur["target_id"])
        )
        if same:
            continue
        if body_changed:
            conn.execute("UPDATE advisories SET body=? WHERE id=?", (row["body"], r["id"]))
            rebodied += 1
        conn.execute(
            "UPDATE advisories SET cve=?, cwe=?, cvss=?, cvss_vector=?, severity=?, product=?,"
            " ref=COALESCE(NULLIF(?,''), ref), target_id=COALESCE(?, target_id), indexed_at=?"
            " WHERE id=?",
            (row["cve"], row["cwe"], row["cvss"], row["cvss_vector"], row["severity"],
             row["product"], row["ref"], tid, common.now_iso(), r["id"]))
        changed += 1
    conn.commit()
    index_fts(conn)
    if verbose:
        print("reparse: %d of %d rows updated (%d bodies re-rendered)"
              % (changed, len(rows), rebodied))
    return {"rows": len(rows), "changed": changed, "bodies": rebodied}


def stats(conn):
    ensure_schema(conn)
    total = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
    print("advisories: %d" % total)
    for label, sql in (
        ("by product", "SELECT COALESCE(NULLIF(product,''),'(none)'), COUNT(*) FROM advisories"
                       " GROUP BY 1 ORDER BY 2 DESC"),
        ("by status", "SELECT status, COUNT(*) FROM advisories GROUP BY 1 ORDER BY 2 DESC"),
        ("with CVE", "SELECT CASE WHEN cve IS NOT NULL AND cve<>'' THEN 'yes' ELSE 'no' END,"
                     " COUNT(*) FROM advisories GROUP BY 1"),
    ):
        print(" ", label)
        for r in conn.execute(sql).fetchall():
            print("    %-22s %d" % (r[0], r[1]))
    row = conn.execute("SELECT ref, title, published FROM advisories"
                       " ORDER BY published DESC LIMIT 5").fetchall()
    print("  newest")
    for r in row:
        print("    %-14s %s" % (r["ref"] or "-", (r["title"] or "")[:64]))


def main():
    ap = argparse.ArgumentParser(description="ExampleVendor advisory ingestion")
    ap.add_argument("--sync", action="store_true", help="poll the RSS feed (cron mode)")
    ap.add_argument("--backfill", action="store_true", help="walk the full Discourse history")
    ap.add_argument("--reparse", action="store_true",
                    help="re-derive CVE/CVSS/severity/product from stored bodies (no network)")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--max-pages", type=int, default=PAGE_LIMIT)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    cfg = common.load_config()
    conn = common.connect()
    common.init_db(conn)
    try:
        if args.backfill:
            backfill(conn, cfg, verbose=not args.quiet, max_pages=args.max_pages)
        if args.sync:
            sync_rss(conn, cfg, verbose=not args.quiet)
        if args.reparse:
            reparse(conn, verbose=not args.quiet)
        if args.stats or not (args.sync or args.backfill or args.reparse):
            stats(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
