#!/usr/bin/env python3
"""HackerOne integration. Stdlib only.

Pulls the researcher's own reports from the HackerOne API and makes them the source of truth for
the Tracker, replacing hand-maintained markdown tracker rows.

    python3 h1.py --test        # verify the stored credential authenticates
    python3 h1.py --sync        # pull reports from EVERY program on the account
    python3 h1.py --sync --program example-vendor     # ...or just one
    python3 h1.py --stats

CREDENTIALS live in secrets.json (mode 0600), never in config.json and never in the database.
The token is never returned by any API endpoint - only a masked fingerprint.

SCOPE: every report the account can see is stored, whichever program it belongs to. This used to
discard everything outside `program_handle`, which cost five confirmed awards worth $2000 that
the account had been paid and this database did not know about. Discarding data to keep a view
narrow was the wrong layer: the database holds everything, and the TRACKER narrows to one program
at the view layer (server.py `primary_program()`).

`program_handle` in secrets.json is still meaningful, but it now means the PRIMARY program - the
one reports are submitted to, whose weaknesses and scopes are resolvable, and the one the Tracker
shows by default. It no longer decides what is worth storing.
"""
import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import common

API_ROOT = "https://api.hackerone.com/v1"
USER_AGENT = "quarry-h1-sync/1.0"
HTTP_TIMEOUT = 45
PAGE_SIZE = 100
MAX_PAGES = 100
POLITE_DELAY = 0.35

# The sentinel meaning "no program filter", for the places a scope has to travel as a string and
# cannot carry None: the --program flag, the ?program= query parameter, the stats dicts. It is
# not a legal HackerOne handle, so it cannot collide with a real program.
ALL_PROGRAMS = "all"

# At the instance ROOT (next to config.json), never inside core/. Secrets that live in the code
# directory are wiped by a code redeploy (an rsync of core/ with --delete removes any file the repo
# does not carry, and secrets.json is git-ignored, so it vanishes). The root is on the data volume
# and deploys never reach it.
SECRETS_PATH = os.path.join(common.ROOT_DIR, "secrets.json")
_OLD_SECRETS_PATH = os.path.join(common.APP_DIR, "secrets.json")
try:
    # One-time migration for a build that stored secrets under core/. Idempotent and guarded so it
    # is safe to run from either module regardless of import order.
    if os.path.exists(_OLD_SECRETS_PATH) and not os.path.exists(SECRETS_PATH):
        os.replace(_OLD_SECRETS_PATH, SECRETS_PATH)
except OSError:
    pass

# --------------------------------------------------------------- collaborators
# The hacker API has no `collaborators` relationship (verified against #0000000, which genuinely
# has one). The activities feed DOES name everyone who touched a report - but that includes
# HackerOne triagers and vendor engineers, who are emphatically not collaborators. So:
#
#   * ALLOWLIST  - people we actually co-report with. Only these are ever credited.
#   * DENY rules - belt and braces, so a mistaken allowlist entry still cannot promote a triager.
#
# Both are overridable via secrets.json -> hackerone -> collaborator_allowlist / actor_denylist.
DEFAULT_COLLABORATOR_ALLOWLIST = []
DEFAULT_ACTOR_DENY_PREFIXES = ["h1_", "hackerone"]     # e.g. h1_analyst_*, hackerone-triage
DEFAULT_ACTOR_DENYLIST = []                            # program engineers who comment but never collaborate


def collaborator_rules():
    h1 = load_secrets().get("hackerone") or {}
    return (
        [u.lower() for u in (h1.get("collaborator_allowlist") or DEFAULT_COLLABORATOR_ALLOWLIST)],
        [p.lower() for p in (h1.get("actor_deny_prefixes") or DEFAULT_ACTOR_DENY_PREFIXES)],
        [u.lower() for u in (h1.get("actor_denylist") or DEFAULT_ACTOR_DENYLIST)],
    )


def is_real_collaborator(username, me, allowlist, deny_prefixes, denylist):
    """True only for a human we co-report with. Triagers and vendor staff never qualify."""
    if not username:
        return False
    u = username.lower()
    if me and u == me.lower():
        return False
    if u in denylist:
        return False
    if any(u.startswith(p) for p in deny_prefixes):
        return False
    return u in allowlist


# ------------------------------------------------------------------ secrets
def load_secrets():
    if not os.path.exists(SECRETS_PATH):
        return {}
    try:
        with open(SECRETS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return {}


def save_secrets(data):
    tmp = SECRETS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SECRETS_PATH)
    os.chmod(SECRETS_PATH, 0o600)


def get_credentials():
    """Return (username, token, primary_program_handle) or (None, None, handle).

    The third element is the PRIMARY program - what we submit to and what the Tracker defaults
    to. It is not a sync filter; see the module docstring.
    """
    h1 = load_secrets().get("hackerone") or {}
    return (h1.get("username"), h1.get("api_token"),
            h1.get("program_handle") or "example-vendor")


def set_credentials(username, token, program_handle=None):
    data = load_secrets()
    h1 = data.get("hackerone") or {}
    h1["username"] = username
    h1["api_token"] = token
    if program_handle:
        h1["program_handle"] = program_handle
    h1.setdefault("program_handle", "example-vendor")
    data["hackerone"] = h1
    save_secrets(data)


def fingerprint(token):
    """A non-reversible hint so the UI can show WHICH key is stored without revealing it."""
    if not token:
        return ""
    import hashlib
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def masked(token):
    if not token:
        return ""
    if len(token) <= 8:
        return "*" * len(token)
    return token[:3] + "*" * (len(token) - 7) + token[-4:]


# ------------------------------------------------------------------ http
class H1Error(Exception):
    """An HTTP-shaped failure talking to HackerOne.

    Carries the status code and any Retry-After so a caller can tell a dead credential (401,
    back off hard, alert) from a rate limit (429, sleep and retry) without re-parsing the
    message. str() is unchanged, so existing callers that only print it are unaffected.
    """

    def __init__(self, message, code=None, retry_after=None):
        super().__init__(message)
        self.code = code
        self.retry_after = retry_after


def _retry_after_seconds(headers):
    """Retry-After is either delta-seconds or an HTTP date. Return seconds, or None."""
    if not headers:
        return None
    raw = headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(str(raw).strip()))
    except (TypeError, ValueError):
        pass
    try:
        import email.utils
        when = email.utils.parsedate_to_datetime(str(raw))
        if when is None:
            return None
        return max(0.0, when.timestamp() - time.time())
    except Exception:
        return None


def _request(path, username, token, params=None, method="GET", payload=None):
    url = API_ROOT + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    cred = base64.b64encode(("%s:%s" % (username, token)).encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": "Basic " + cred,
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        retry_after = _retry_after_seconds(getattr(e, "headers", None))
        if e.code == 401:
            # 401 is also what the hacker API returns for an UNKNOWN PATH, so a working
            # credential produces this too. Say both, in that order: on 2026-08-04 this message
            # sent a whole debugging pass at the credential while the real fault was a route that
            # does not exist.
            raise H1Error("HackerOne returned 401 for %s. Either the endpoint does not exist - the "
                          "hacker API answers 401 rather than 404 for an unknown path - or the "
                          "credential is wrong. Check the path first." % path,
                          code=401, retry_after=retry_after)
        if e.code == 429:
            raise H1Error("HackerOne rate limit hit (429). Wait and retry.",
                          code=429, retry_after=retry_after)
        raise H1Error("HackerOne API error %s: %s" % (e.code, body),
                      code=e.code, retry_after=retry_after)
    except urllib.error.URLError as e:
        raise H1Error("Could not reach HackerOne: %s" % e.reason, code=None)


# ------------------------------------------------------------------ submission
# Creating a report is the one irreversible thing this module does. Everything below is built so
# the destructive step is explicit: split_report_markdown and build_report_payload are pure, the
# CLI dry-runs by default, and create_report is only reached with --confirm.

class ReportFormatError(Exception):
    """The markdown does not have the shape a report needs."""


#: The house format from REPORT_STANDARD.md, as refusals rather than as a checklist. Every one of
#: these was already written down and was violated anyway - #0000000 went out hard-wrapped and
#: #0000000 went out with no `**Summary:**`, no `## Preconditions`, no prerequisites table, prose
#: Remediation and a banned `Medium` rating. A report cannot be edited after sending, so a rule
#: that lives only in a document someone is supposed to read is a rule that fails once per report.
SEVERITY_BULLET_RE = re.compile(r"^\* \*\*(Confidentiality|Integrity|Availability):\*\* (\w+)",
                                re.M)


def verify_submission_target(conn, handle, scope, report_path):
    """Cross-check the program a report is about to be filed against. Returns a list of problems.

    Naming `--program` makes the target EXPLICIT; it does not make it right. Two independent
    facts already know which program a report belongs to, and both are stronger than a flag typed
    at 2am: the structured scope id is owned by exactly one program, and the workspace the report
    file lives in maps to one through its target. A submission cannot be undone, so both are
    checked and either one disagreeing is a refusal rather than a warning.

    A dry run once caught a ExampleVendor report about to be filed against ExampleVendor. This is that catch,
    made mechanical.
    """
    problems = []
    if conn is None:
        return problems

    if scope:
        row = conn.execute(
            "SELECT p.slug FROM scopes s JOIN programs p ON p.id = s.program_id"
            " WHERE s.h1_id = ?", (str(scope),)).fetchone()
        if row and row[0] and row[0] != handle:
            problems.append(
                "scope %s belongs to program '%s', not '%s' - the scope id is owned by exactly "
                "one program, so one of the two is wrong" % (scope, row[0], handle))

    ap = os.path.abspath(report_path or "")
    m = re.search(r"/vulns_([A-Za-z0-9_-]+)/", ap)
    if m:
        row = conn.execute(
            "SELECT p.slug FROM targets t JOIN programs p ON p.id = t.program_id"
            " WHERE t.slug = ?", (m.group(1).lower(),)).fetchone()
        if row and row[0] and row[0] != handle:
            problems.append(
                "the report lives in the '%s' workspace, which belongs to program '%s', not "
                "'%s'" % (m.group(1), row[0], handle))
    return problems


def title_target_problems(conn, text, report_path, handle, scope):
    """The report title must NAME the target somewhere - product name or recognised shorthand.

    A triager reads a queue of titles, and one reading "ACL Plugin Never Clears Group Headers"
    names no product at all. Three reports went out that way on 2026-08-03 before this existed.
    Position is a writing decision; presence is not.

    Candidates are drawn from three places rather than one, because none is reliable alone: the
    workspace directory, the program handle, and the words of the structured scope's identifier.
    The ExampleVendor engagement is why - its reports were against `example-app`, which matches neither
    the `vulns_example` workspace nor the `example` handle.

    Returns a list of problems. Unresolvable target names produce NO problem: this refuses a title
    that is demonstrably wrong, never one it merely cannot vouch for.
    """
    first_line = text.split("\n")[0].lstrip("# ").strip()
    if not first_line:
        return []
    candidates = set()
    ws = re.search(r"/vulns_([A-Za-z0-9_-]+)/", os.path.abspath(report_path or ""))
    if ws:
        candidates.add(ws.group(1).lower())
    if handle:
        candidates.update(re.split(r"[^a-z0-9]+", handle.lower()))
    if scope and conn is not None:
        try:
            row = conn.execute("SELECT identifier FROM scopes WHERE h1_id = ?",
                               (str(scope),)).fetchone()
            if row and row[0]:
                ident = re.sub(r"^https?://", "", str(row[0]).lower())
                candidates.update(w for w in re.split(r"[^a-z0-9]+", ident) if len(w) > 2)
        except Exception:
            pass
    candidates.discard("")
    candidates.discard("com")
    candidates.discard("github")
    if not candidates:
        return []
    # ANYWHERE in the title, not only at the front (user correction 2026-08-03). What matters is
    # that a title read on its own names the product; where it sits is a writing decision.
    whole = first_line.lower()
    if any(c in whole for c in candidates):
        return []
    return ["the title must name the target somewhere - %r contains none of %s"
            % (first_line[:52], sorted(candidates))]



def _section_body(text, name):
    """The body of one `## <name>` section, or None when the section is absent."""
    m = re.search(r"(?ms)^## %s\s*$(.*?)(?=^## |\Z)" % re.escape(name), text or "")
    return m.group(1) if m else None

def _report_shape_problems(text):
    """Everything REPORT_STANDARD.md requires that can be checked mechanically."""
    out = []
    head = "\n".join(text.split("\n")[:8])
    if "**Summary:**" not in head:
        out.append("no `**Summary:**` opening the report (REPORT_STANDARD 'THE REPORT SHAPE')")

    # Title length. REPORT_STANDARD gives 12-15 words, one clause. #0000000 went out at 16
    # because the guard checked the colon and the sections and not this, and two hand-trims still
    # landed over - counting is exactly the job a check should be doing rather than a person.
    first = text.split("\n")[0].lstrip("# ").strip()
    words = len([w for w in first.split() if w.strip()])
    if first and not 12 <= words <= 15:
        out.append("title is %d words; the standard is 12-15, one clause" % words)

    # STEPS TO REPRODUCE must be RUNNABLE. #0000000 shipped saying "Two agent policies, two
    # enrolled agents" with no command that creates either, and F51 was drafted with a Setup that
    # could not produce its own transcript on any cluster. A triager who cannot reproduce closes
    # not-applicable, which costs reputation without the finding being judged. Prose said this
    # already and prose did not hold, so it is counted here instead.
    steps = _section_body(text, "Steps To Reproduce")
    if steps is not None:
        # Counted rather than pattern-matched against a list of binaries: #0000000 is a good
        # report whose steps are example-cli and grep, and a curl/docker whitelist called it a
        # failure. What actually distinguishes a runnable Steps section is DENSITY of literal
        # command text - fenced lines plus inline code spans - not which tool it happens to use.
        fenced = sum(1 for ln in re.findall(r"(?ms)^```.*?^```", steps)
                     for ln in ln.split("\n")[1:-1] if ln.strip())
        spans = len(re.findall(r"`[^`\n]{4,}`", steps))
        literal = fenced + spans
        if literal < 10:
            out.append("Steps To Reproduce carries only %d lines of literal command text (%d fenced, "
                       "%d inline). Every artefact the report names - index, role, user, account, "
                       "container - needs the command that creates it, or a triager cannot "
                       "reproduce and closes not-applicable" % (literal, fenced, spans))
        if not re.search(r"\*\*(Setup|Config|Baseline|Step 1|Preconditions)", steps):
            out.append("Steps To Reproduce has no bold lead-in; the standard wants Setup, Baseline "
                       "and numbered Steps, opening with ONE config block of placeholders")

    sections = re.findall(r"^## (.+?)\s*$", text, re.M)
    if "Preconditions" not in sections:
        out.append("no `## Preconditions` section")
    for required in ("Impact", "Remediation"):
        if required not in sections:
            out.append("no `## %s` section" % required)
    if "Impact" in sections and "Remediation" in sections:
        if sections.index("Impact") > sections.index("Remediation"):
            out.append("`## Impact` must come BEFORE `## Remediation`")

    bullets = SEVERITY_BULLET_RE.findall(text)
    if not bullets:
        out.append("no severity bullets under `## Impact` "
                   "(`* **Confidentiality:** High.` and so on)")
    for dim, rating in bullets:
        if rating == "Medium":
            out.append("`%s: Medium` is banned - a dimension is High if it was demonstrated, Low "
                       "if the reach is narrow and the bullet names the constraint, and the "
                       "bullet is DELETED if it was only reasoned about" % dim)
        elif rating not in ("High", "Low"):
            out.append("`%s: %s` is not a rating - only High or Low" % (dim, rating))
        if rating == "None":
            out.append("a dimension that was not impacted is left out entirely, not rated None")

    # The prerequisites-versus-impact table closing the Impact section.
    impact = re.search(r"^## Impact\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    if impact and not re.search(r"^\|.*\|.*\|\s*$", impact.group(1), re.M):
        out.append("no prerequisites-versus-impact table closing `## Impact`")

    # Remediation reads as bullets with bold labels, not prose.
    remed = re.search(r"^## Remediation\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    if remed and not re.search(r"^\* \*\*", remed.group(1), re.M):
        out.append("`## Remediation` must be bullets opening with a bold imperative label, "
                   "not prose")
    return out


def _outside_fences(text):
    """Lines that are NOT inside a fenced code block. Code keeps its own line breaks; prose
    must not, so only prose is measured for hard wrapping."""
    out, fenced = [], False
    for ln in text.split("\n"):
        if ln.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            out.append(ln)
    return out


def split_report_markdown(text):
    """Split a report file into the three fields the HackerOne API takes.

    HackerOne renders the `impact` field AFTER the entire body, which is why the split is where
    it is. Everything before `## Impact` becomes `vulnerability_information`; the Impact section
    AND everything after it become `impact`. So a source file in standard order

        Summary / Code path / Steps To Reproduce / Impact / Remediation

    renders on HackerOne in that same order, with Impact and Remediation together in the impact
    field. Leaving Remediation in the body instead put it BEFORE Impact once rendered, inverting
    the order the report standard asks for. Observed on #0000000, fixed here.

    The `## Impact` heading itself is dropped because HackerOne supplies its own.

    Returns (title, vulnerability_information, impact).
    """
    lines = text.split("\n")
    title = ""
    for i, ln in enumerate(lines):
        if ln.startswith("# "):
            title = ln[2:].strip()
            lines = lines[i + 1:]
            break
    if not title:
        raise ReportFormatError("no '# Title' heading found")

    before, after = [], []
    seen_impact = False
    for ln in lines:
        if ln.startswith("## ") and ln[3:].strip().lower() == "impact":
            seen_impact = True
            continue
        (after if seen_impact else before).append(ln)

    impact_text = "\n".join(after).strip()
    if not impact_text:
        raise ReportFormatError("no '## Impact' section found")
    return title, "\n".join(before).strip(), impact_text


SEVERITY_RATINGS = ("none", "low", "medium", "high", "critical")


def build_report_payload(team_handle, title, vulnerability_information, impact,
                         weakness_id=None, structured_scope_id=None, severity_rating=None):
    """The POST body for /hackers/reports.

    `severity_rating` is REQUIRED by this program: submitting without it returns 422 "Severity
    rating must be set". It is a structured field and is NOT the thing the report standard
    retires - that rule is about editorialising severity in the Impact PROSE ("Estimated severity
    Low, CVSS 3.1 around 4.3"). Set this to our own triage assessment; keep it out of the body.
    """
    if severity_rating and severity_rating not in SEVERITY_RATINGS:
        raise H1Error("severity_rating must be one of %s" % ", ".join(SEVERITY_RATINGS))
    attrs = {
        "team_handle": team_handle,
        "title": title,
        "vulnerability_information": vulnerability_information,
        "impact": impact,
    }
    if severity_rating:
        attrs["severity_rating"] = severity_rating
    if weakness_id:
        attrs["weakness_id"] = int(weakness_id)
    if structured_scope_id:
        attrs["structured_scope_id"] = int(structured_scope_id)
    return {"data": {"type": "report", "attributes": attrs}}


def list_weaknesses(username, token, program_handle):
    """[(id, cwe, name)] for the program, across all pages."""
    out, page = [], 1
    while page <= 10:
        d = _request("/hackers/programs/%s/weaknesses" % program_handle, username, token,
                     {"page[size]": 100, "page[number]": page})
        rows = d.get("data") or []
        if not rows:
            break
        for r in rows:
            a = r.get("attributes") or {}
            out.append((r["id"], (a.get("external_id") or "").lower(), a.get("name") or ""))
        page += 1
        time.sleep(POLITE_DELAY)
    return out


def list_structured_scopes(username, token, program_handle):
    """[(id, asset_identifier, asset_type, eligible_for_bounty)] for the program, all pages.

    Paginated like list_weaknesses. It was a single page[size]=100 request, which silently
    truncated the two largest programs on the account at exactly 100 assets - a scope list that
    stops mid-way is worse than none, because it says an in-scope asset is out of scope.
    """
    out, page, seen = [], 1, set()
    while page <= 10:
        d = _request("/hackers/programs/%s/structured_scopes" % program_handle, username, token,
                     {"page[size]": 100, "page[number]": page})
        rows = d.get("data") or []
        if not rows:
            break
        for r in rows:
            if r["id"] in seen:
                continue          # a program that ignores page[number] would loop forever
            seen.add(r["id"])
            a = r.get("attributes") or {}
            out.append((r["id"], a.get("asset_identifier") or "", a.get("asset_type") or "",
                        bool(a.get("eligible_for_bounty"))))
        if len(rows) < 100:
            break
        page += 1
        time.sleep(POLITE_DELAY)
    return out


def resolve_weakness(username, token, program_handle, wanted):
    """Accept a numeric id or a CWE string like 'cwe-287' and return the numeric id."""
    wanted = str(wanted).strip()
    if wanted.isdigit():
        return wanted
    key = wanted.lower()
    if not key.startswith("cwe-"):
        key = "cwe-" + key
    for wid, cwe, _name in list_weaknesses(username, token, program_handle):
        if cwe == key:
            return wid
    raise H1Error("no weakness matching %r for program %s" % (wanted, program_handle))


def resolve_scope(username, token, program_handle, wanted):
    """Accept a numeric id or an exact asset identifier and return the numeric id."""
    wanted = str(wanted).strip()
    if wanted.isdigit():
        return wanted
    for sid, ident, _type, _bounty in list_structured_scopes(username, token, program_handle):
        if ident.lower() == wanted.lower():
            return sid
    raise H1Error("no in-scope asset matching %r for program %s" % (wanted, program_handle))


def create_report(username, token, payload):
    """POST the report. Returns (h1_id, url, raw). IRREVERSIBLE."""
    d = _request("/hackers/reports", username, token, method="POST", payload=payload)
    node = d.get("data") or {}
    h1_id = node.get("id") or ""
    if not h1_id:
        raise H1Error("HackerOne accepted the request but returned no report id")
    return h1_id, "https://hackerone.com/reports/%s" % h1_id, d


# ------------------------------------------------------------------ report intents (draft + attachments)

def _multipart_upload(path, username, token, files):
    """POST multipart/form-data to `path` with file attachments.

    `files` is a list of (field_name, filename, data_bytes, content_type) tuples.
    Returns the parsed JSON response.
    """
    import uuid
    boundary = uuid.uuid4().hex
    body_parts = []
    for field, fname, fdata, ctype in files:
        body_parts.append(("--%s\r\n" % boundary).encode("ascii"))
        body_parts.append(
            ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (field, fname)
             ).encode("ascii"))
        body_parts.append(("Content-Type: %s\r\n\r\n" % ctype).encode("ascii"))
        body_parts.append(fdata)
        body_parts.append(b"\r\n")
    body_parts.append(("--%s--\r\n" % boundary).encode("ascii"))
    body = b"".join(body_parts)

    url = API_ROOT + path
    cred = base64.b64encode(("%s:%s" % (username, token)).encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": "Basic " + cred,
        "Content-Type": "multipart/form-data; boundary=%s" % boundary,
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT * 2) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise H1Error("attachment upload failed (HTTP %d): %s" % (e.code, err_body), code=e.code)
    except urllib.error.URLError as e:
        raise H1Error("could not reach HackerOne for attachment upload: %s" % e.reason)


def create_report_intent(username, token, team_handle):
    """Create a draft report (report_intent). Returns the intent id.

    Report intents are HackerOne's draft mechanism. Files can be attached to an
    intent before it is submitted as a real report. The intent id is ephemeral
    and only meaningful until submission.

    KNOWN RISK / UNVERIFIED (maintainer note, v1.4.0): the `/hackers/report_intents`
    path and its `/attachments` and `/submit` subresources are not confirmed against a
    live HackerOne hacker REST token, and the hacker API returns 401 (not 404) for a
    route that does not exist, so a wrong path reads as an auth failure. Verify this flow
    end to end against a real token before relying on `--attach`; if report intents live
    only in the GraphQL/web API this path needs reworking. Tracked as a follow-up.
    """
    payload = {"data": {"type": "report-intent",
                        "attributes": {"team_handle": team_handle}}}
    d = _request("/hackers/report_intents", username, token, method="POST", payload=payload)
    node = d.get("data") or {}
    intent_id = node.get("id")
    if not intent_id:
        raise H1Error("HackerOne accepted the intent but returned no id")
    return str(intent_id)


def upload_attachments(username, token, intent_id, file_paths):
    """Upload files to a report intent. Returns a list of attachment metadata dicts.

    Each file is uploaded via multipart POST to /hackers/report_intents/{id}/attachments.
    The `files[]` field name is what the API expects.
    """
    import mimetypes as mt
    results = []
    for fpath in file_paths:
        if not os.path.isfile(fpath):
            continue
        fname = os.path.basename(fpath)
        ctype = mt.guess_type(fname)[0] or "application/octet-stream"
        with open(fpath, "rb") as fh:
            data = fh.read()
        path = "/hackers/report_intents/%s/attachments" % intent_id
        resp = _multipart_upload(path, username, token, [("files[]", fname, data, ctype)])
        # The response wraps attachments in a data array, but a single upload can come back
        # as a bare object. Normalize to a list so we never iterate a dict's keys (which made
        # the later att.get(...) raise AttributeError on a string).
        data_field = resp.get("data") or []
        if isinstance(data_field, dict):
            data_field = [data_field]
        for att in data_field:
            if not isinstance(att, dict):
                continue
            a = att.get("attributes") or att
            results.append({
                "id": att.get("id") or "",
                "file_name": a.get("file_name") or fname,
                "file_size": a.get("file_size") or len(data),
                "content_type": a.get("content_type") or ctype,
            })
    return results


def submit_report_intent(username, token, intent_id, payload):
    """Submit a report intent as a real report. IRREVERSIBLE.

    The payload is the same shape as build_report_payload produces. Returns
    (h1_id, url, raw) just like create_report.
    """
    d = _request("/hackers/report_intents/%s/submit" % intent_id, username, token,
                 method="POST", payload=payload)
    node = d.get("data") or {}
    h1_id = node.get("id") or ""
    if not h1_id:
        raise H1Error("HackerOne accepted the submission but returned no report id")
    return h1_id, "https://hackerone.com/reports/%s" % h1_id, d


def create_report_with_attachments(username, token, payload, file_paths):
    """Create a report with file attachments via the report_intents flow.

    1. Create a draft intent
    2. Upload each file as an attachment
    3. Submit the intent as a real report

    Returns (h1_id, url, raw_response, attachments_uploaded).
    IRREVERSIBLE once step 3 completes.
    """
    handle = payload.get("data", {}).get("attributes", {}).get("team_handle")
    if not handle:
        raise H1Error("payload missing team_handle")

    intent_id = create_report_intent(username, token, handle)
    attachments = []
    if file_paths:
        attachments = upload_attachments(username, token, intent_id, file_paths)

    h1_id, url, raw = submit_report_intent(username, token, intent_id, payload)
    return h1_id, url, raw, attachments


def add_comment(username, token, h1_id, body, internal=False):
    """NOT SUPPORTED. HackerOne's hacker API has no endpoint for commenting on a report.

    This function is kept as a documented dead end so the next person does not spend the evening
    rediscovering it. `POST /hackers/reports/<id>/activities` was the obvious candidate and it
    returns 401 - but so does `/hackers/reports/<id>/definitely-not-a-route`, because the hacker API
    answers 401 for ANY unknown path rather than 404. A 401 there means "no such endpoint", not
    "bad credential", and the same token reads `GET /hackers/reports/<id>` fine.

    Commenting on a filed report is a web-UI action for a hacker. If that changes, the payload shape
    below is the one to try first.
    """
    raise H1Error(
        "HackerOne's hacker API cannot post comments; there is no such endpoint. "
        "Post it in the web UI: https://hackerone.com/reports/%s" % h1_id)


def test_credentials(username, token):
    """Return a small dict proving the credential works, or raise H1Error."""
    d = _request("/hackers/me/reports", username, token, {"page[size]": 1})
    return {"ok": True, "sample_count": len(d.get("data") or [])}


# ------------------------------------------------------------------ fetch
def _attr(node, *names):
    a = (node or {}).get("attributes") or {}
    for n in names:
        if a.get(n) is not None:
            return a[n]
    return None


def _rel(node, key):
    r = ((node or {}).get("relationships") or {}).get(key) or {}
    d = r.get("data")
    if isinstance(d, list):
        d = d[0] if d else None
    return (d or {}).get("attributes") or {}


def fetch_reports(username, token, program_handle=None, max_pages=MAX_PAGES, verbose=False):
    """All of the hacker's reports, optionally narrowed to one program handle."""
    out = []
    params = {"page[size]": PAGE_SIZE}
    path = "/hackers/me/reports"
    pages = 0
    next_url = None
    while pages < max_pages:
        if next_url:
            # follow the server's own pagination link rather than guessing page numbers
            parsed = urllib.parse.urlparse(next_url)
            path = parsed.path.replace("/v1", "", 1)
            params = dict(urllib.parse.parse_qsl(parsed.query))
        d = _request(path, username, token, params)
        rows = d.get("data") or []
        if not rows:
            break
        pages += 1
        for node in rows:
            prog = _rel(node, "program").get("handle")
            if program_handle and prog != program_handle:
                continue
            out.append(normalize_report(node, prog))
        if verbose:
            print("  page %d: %d rows (%d kept)" % (pages, len(rows), len(out)))
        next_url = (d.get("links") or {}).get("next")
        if not next_url:
            break
        time.sleep(POLITE_DELAY)
    return out


def normalize_report(node, program_handle):
    """Map an H1 report object onto our `reports` columns. Pure.

    Works on both the list payload and the richer single-report payload; fields the list form
    does not carry simply come back empty, and get filled in by the detail pass.
    """
    rid = str(node.get("id") or "")
    sev = _rel(node, "severity")
    weakness = _rel(node, "weakness")
    scope = _rel(node, "structured_scope")
    attrs = node.get("attributes") or {}

    state = _attr(node, "state") or ""
    submitted = (_attr(node, "submitted_at") or _attr(node, "created_at") or "")
    closed = (_attr(node, "closed_at") or "")

    # Who actually filed this. On our own reports this is us, but a report we were ADDED to as
    # a collaborator carries someone else here, which is the only reliable ownership signal.
    reporter = ((node.get("relationships") or {}).get("reporter") or {}).get("data") or {}
    reporter_user = (reporter.get("attributes") or {}).get("username") or ""
    reporter_id = str(reporter.get("id") or "")

    # Bounties are a LIST - a report can be topped up more than once AND can be split between
    # people, so sum rather than take the first. `awarded_amount` is what actually landed.
    #
    # COLLABORATORS: derived ONLY from bounties[].awarded_user. Deliberately NOT from the
    # activities feed - that is full of HackerOne triagers (h1_analyst_*) and vendor engineers
    # who comment on a report, none of whom are collaborators. A person who received part of the
    # payout is a real co-reporter; a person who commented is not.
    bounty_total = 0.0
    my_bounty = 0.0
    currency = ""
    split = []
    bl = ((node.get("relationships") or {}).get("bounties") or {}).get("data") or []
    for b in bl:
        ba = b.get("attributes") or {}
        amt = 0.0
        for key in ("awarded_amount", "amount"):
            try:
                amt = float(ba.get(key) or 0)
                break
            except (TypeError, ValueError):
                pass
        try:
            amt += float(ba.get("awarded_bonus_amount") or 0)
        except (TypeError, ValueError):
            pass
        bounty_total += amt
        currency = currency or ba.get("awarded_currency") or ""

        au = ((b.get("relationships") or {}).get("awarded_user") or {}).get("data") or {}
        au_user = (au.get("attributes") or {}).get("username") or ""
        au_id = str(au.get("id") or "")
        if au_user:
            split.append({"username": au_user, "user_id": au_id, "amount": "%.2f" % amt})
        if au_user and reporter_user and au_user == reporter_user:
            my_bounty += amt
        elif not au_user:
            my_bounty += amt

    # Anyone PAID on this report who is not the reporter is a genuine co-reporter.
    collaborators = sorted({
        "%s (id=%s)" % (e["username"], e["user_id"])
        for e in split if e["username"] and e["username"] != reporter_user
    })

    # The hacker API exposes NO `collaborators` relationship - verified against a report that
    # genuinely has one (an invited-collaborator report). So the only
    # reliable signal that we are on someone else's report is that the reporter is not us.
    # `me` is filled in by the caller, which knows the configured account.
    me = globals().get("_ME") or ""
    allowlist, deny_prefixes, denylist = collaborator_rules()

    my_role = ""
    if reporter_user:
        my_role = "reporter" if reporter_user == me else "collaborator"
        if my_role == "collaborator":
            tag = "%s (id=%s)" % (reporter_user, reporter_id)
            if tag not in collaborators:
                collaborators = sorted(collaborators + [tag])

    # Catch the other direction: OUR report, someone else invited onto it. They appear only in
    # the activities feed, so filter it hard through the allowlist.
    acts = ((node.get("relationships") or {}).get("activities") or {}).get("data") or []
    for act in acts:
        actor = ((act.get("relationships") or {}).get("actor") or {}).get("data") or {}
        aa = actor.get("attributes") or {}
        nm = aa.get("username") or ""
        if is_real_collaborator(nm, me, allowlist, deny_prefixes, denylist):
            tag = "%s (id=%s)" % (nm, actor.get("id") or "")
            if tag not in collaborators:
                collaborators = sorted(collaborators + [tag])

    cves = attrs.get("cve_ids") or []
    if isinstance(cves, str):
        cves = [cves]

    # The conversation thread. `activities` carries the whole exchange - triage bot, vendor
    # engineers, our replies - as `activity-<kind>` nodes. Only the detail endpoint populates it;
    # the list endpoint returns an empty relationship, which is why this is two-phase.
    #
    # `internal: true` marks a program-side note. Those are visible to us on the report page, so
    # they are kept, but flagged so the UI can mark them rather than passing them off as replies
    # addressed to us.
    thread = []
    for act in acts:
        aa = act.get("attributes") or {}
        msg = (aa.get("message") or "").strip()
        kind = (act.get("type") or "").replace("activity-", "")
        if not msg and kind in ("comment", ""):
            continue          # empty comment nodes carry no information
        actor = ((act.get("relationships") or {}).get("actor") or {}).get("data") or {}
        thread.append({
            "kind": kind,
            "actor": (actor.get("attributes") or {}).get("username") or "",
            "at": aa.get("created_at") or "",
            "internal": bool(aa.get("internal")),
            "message": msg,
        })
    thread.sort(key=lambda x: x["at"] or "")

    return {
        "h1_id": rid,
        # Normalised at the boundary so it is applied on every sync and refresh, not patched
        # once in the database where the next poll would undo it. See clean_title().
        "title": clean_title(_attr(node, "title")) or ("report %s" % rid),
        "state": state,
        "severity": sev.get("rating") or "",
        "cvss": str(sev.get("score") or "") if sev.get("score") is not None else "",
        "cvss_vector": sev.get("cvss_vector_string") or "",
        "submitted_on": submitted[:10] if submitted else None,
        "resolved_on": closed[:10] if closed else None,
        "url": "https://hackerone.com/reports/%s" % rid,
        "body": _attr(node, "vulnerability_information") or "",
        "program": program_handle or "",
        "weakness": weakness.get("name") or "",
        "cwe": weakness.get("external_id") or "",
        "cve": ",".join(str(c) for c in cves),
        "asset": scope.get("asset_identifier") or "",
        "bounty": ("%.2f" % bounty_total) if bounty_total else "",
        "my_bounty": ("%.2f" % my_bounty) if my_bounty else "",
        "currency": currency,
        "reporter_username": reporter_user,
        "reporter_id": reporter_id,
        "collaborators": ",".join(collaborators),
        "my_role": my_role,
        # Only meaningful when the money actually went to more than one person.
        "payout_split": json.dumps(split) if len(split) > 1 else "",
        "disclosed_at": _attr(node, "disclosed_at") or "",
        "last_activity": _attr(node, "last_activity_at") or _attr(node, "last_program_activity_at") or "",
        # Empty string, not "[]", when the list endpoint gave us nothing: upsert_report must be
        # able to tell "no thread in this payload" from "fetched, and there genuinely are none".
        "thread": json.dumps(thread) if thread else "",
    }


def fetch_report_detail(username, token, report_id, program_handle=None):
    """GET /hackers/reports/{id} - the ONLY place bounty, CVSS score/vector, CWE and CVE appear.

    The list endpoint omits all of them, which is why the sync is two-phase.
    """
    d = _request("/hackers/reports/%s" % report_id, username, token)
    node = d.get("data") or {}
    prog = _rel(node, "program").get("handle") or program_handle
    return normalize_report(node, prog)


# ------------------------------------------------------------------ db
def ensure_schema(conn):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}
    for name, decl in (("source", "TEXT"), ("program", "TEXT"), ("weakness", "TEXT"),
                       ("asset", "TEXT"), ("last_activity", "TEXT"), ("h1_state", "TEXT"),
                       ("synced_at", "TEXT"), ("cvss", "TEXT"), ("cvss_vector", "TEXT"),
                       ("cwe", "TEXT"), ("cve", "TEXT"), ("currency", "TEXT"),
                       ("reporter_username", "TEXT"), ("reporter_id", "TEXT"),
                       ("collaborators", "TEXT"), ("payout_split", "TEXT"),
                       ("my_bounty", "TEXT"), ("my_role", "TEXT"), ("h1_body_path", "TEXT"),
                       ("thread", "TEXT"),
                       # These three were added by hand to the live database and never made it
                       # into any schema definition, so a fresh clone crashed on its first sync:
                       # upsert_report writes them unconditionally.
                       ("expected_bounty", "TEXT"), ("expected_cve", "TEXT"),
                       ("expected_note", "TEXT")):
        if name not in cols:
            conn.execute("ALTER TABLE reports ADD COLUMN %s %s" % (name, decl))
    # `first_seen_at` is NOT in this loop. It is added by common.ensure_first_seen(), which every
    # entry point reaches through init_db, because ingest.py inserts reports too and does not
    # import this module.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_h1id ON reports(h1_id)")
    conn.commit()


_MD_HEADING_RE = re.compile(r"^\s*#{1,6}\s+")


def clean_title(value):
    """Strip a leading markdown heading marker from a report title.

    #0000000 was submitted with its title field set to "# Denial of Service in ...", because the
    markdown heading was pasted along with the text. HackerOne stores and returns that verbatim,
    so every sync would otherwise re-apply it.

    Only the heading FORM is stripped - one to six '#' followed by whitespace. A title that
    legitimately starts with '#' and no space, such as "#1 priority", is left alone.
    """
    return _MD_HEADING_RE.sub("", str(value or "")).strip()


def _clean_amount(value):
    """Only a bare number is a confirmed award. '[amount]', '-', '' and None are not."""
    v = str(value or "").strip()
    return v if re.fullmatch(r"\d+(\.\d+)?", v) else ""


# Bookkeeping, not content. These record when we last LOOKED at a row, so a change in them is
# not a change worth telling Seth about.
BOOKKEEPING_COLS = ("id", "indexed_at", "synced_at")


def content_changed(before, after):
    """Did this write actually alter the row, ignoring sync bookkeeping?

    Deliberately compares every other column rather than an allowlist: a column added later is
    then treated as content by default, which fails toward showing a change rather than hiding
    one.
    """
    if before is None or after is None:
        return True
    # NULL and '' are the same absence to a reader. They differ here because the COALESCE and
    # NULLIF guards in the UPDATE flip between them - `class` goes '' -> NULL on the first
    # re-sync of a row with no class - and that flip is not news.
    def norm(v):
        return "" if v is None else v
    return any(norm(before[k]) != norm(after[k])
               for k in after.keys() if k not in BOOKKEEPING_COLS)


def upsert_report(conn, row, target_hint=None):
    """Insert or update by h1_id. H1 wins on the fields it owns; file-derived fields survive."""
    now = common.now_iso()
    # A report with no local file has no class, because class comes from the directory a note
    # lives in. Derive one from the CWE so the Tracker filter and the dashboard breakdown agree
    # on the same number. NEVER overwrite a class the file already set - that is the
    # researcher's own judgement and expresses things no CWE does, such as DLSFLS.
    derived_class = common.class_for_report(
        {"class": "", "cwe": row.get("cwe") or ""})
    if derived_class == common.UNCLASSED:
        derived_class = ""
    row["bounty"] = _clean_amount(row.get("bounty"))
    row["my_bounty"] = _clean_amount(row.get("my_bounty"))
    # Match order matters. Prefer a row this sync already owns, then a genuine report file.
    # NEVER match an RCA or a follow-up comment: those share the parent's H1 id and would
    # otherwise be overwritten with the report's data and counted as submissions.
    existing = conn.execute(
        "SELECT id, file_path, title, state FROM reports"
        " WHERE h1_id = ? AND kind = 'report'"
        " ORDER BY (source = 'hackerone') DESC, (file_path IS NOT NULL) DESC, id ASC LIMIT 1",
        (row["h1_id"],)).fetchone()

    if existing is None:
        conn.execute(
            "INSERT INTO reports (h1_id, title, state, severity, submitted_on, resolved_on,"
            " url, body, program, weakness, asset, last_activity, h1_state, bounty,"
            " cvss, cvss_vector, cwe, cve, currency, reporter_username, reporter_id,"
            " collaborators, payout_split, my_bounty, my_role, h1_body_path, thread, class, source,"
            " tracker_only, kind, indexed_at, synced_at, first_seen_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'hackerone',0,'report',?,?,?)",
            (row["h1_id"], row["title"], row["state"], row["severity"], row["submitted_on"],
             row["resolved_on"], row["url"], row["body"], row["program"], row["weakness"],
             row["asset"], row["last_activity"], row["state"], row.get("bounty") or "",
             row.get("cvss") or "", row.get("cvss_vector") or "", row.get("cwe") or "",
             row.get("cve") or "", row.get("currency") or "",
             row.get("reporter_username") or "", row.get("reporter_id") or "",
             row.get("collaborators") or "", row.get("payout_split") or "",
             row.get("my_bounty") or "", row.get("my_role") or "",
             row.get("h1_body_path") or "", row.get("thread") or "", derived_class, now, now, now))
        conn.commit()
        return "new"

    # HackerOne owns what a report IS: its title, its text, and the conversation on it. The local
    # markdown file is the researcher's working document and is frequently a DIFFERENT document -
    # #0000000 is filed on disk as an Apache UpstreamLib write-up while HackerOne knows it as
    # "Denial of Service in ExampleProduct Expression Scripts via Deeply Nested Parentheses".
    # Showing the file's text under the H1 title misrepresents what was submitted.
    #
    # body and thread are NULLIF-guarded because the LIST endpoint returns neither: an empty value
    # means "this payload did not carry it", not "it is empty upstream". Only fetch_report_detail
    # populates them, which is what `--refresh` is for.
    # `indexed_at` drives the "new" badge in the sidebar, so it has to mean "this row's content
    # changed", not "a sync touched this row". The nightly `--full` detail pass re-reads all 111
    # reports whether or not anything moved; bumping indexed_at unconditionally made every
    # morning open on a false "+111 new". Snapshot around the UPDATE and only bump on a real
    # diff - comparing after the fact is what keeps this honest through the COALESCE and CASE
    # guards above, which make "what will this write actually change" impossible to predict here.
    before = conn.execute("SELECT * FROM reports WHERE id=?", (existing["id"],)).fetchone()
    conn.execute(
        "UPDATE reports SET title = COALESCE(NULLIF(?,''), title), state=?, severity=?,"
        " body=COALESCE(NULLIF(?,''), body), thread=COALESCE(NULLIF(?,''), thread),"
        " submitted_on=COALESCE(?, submitted_on), resolved_on=COALESCE(?, resolved_on),"
        # program is NULLIF-guarded, unlike the other H1-owned fields: it is what the Tracker's
        # default scope filters on, so a payload that came back without a program relationship
        # would otherwise blank the handle and drop the report out of every program's view.
        " url=?, program=COALESCE(NULLIF(?,''), program), weakness=?, asset=?, last_activity=?,"
        " h1_state=?,"
        # HackerOne OWNS the money. Not COALESCE: if H1 reports no award, any value already on
        # the row came from the markdown tracker and is an EXPECTATION, not a payment. Letting it
        # survive here is what silently turned 20 confirmed awards into 24.
        " bounty=?,"
        # An expectation is a BELIEF about money that has not arrived. The moment HackerOne
        # reports an award, that belief is answered and must go, or the same money is counted
        # twice: once in the confirmed total and once in the anticipated total.
        " expected_bounty=CASE WHEN ?<>'' THEN '' ELSE expected_bounty END,"
        " expected_note=CASE WHEN ?<>'' THEN '' ELSE expected_note END,"
        " cvss=COALESCE(NULLIF(?,''), cvss),"
        " cvss_vector=COALESCE(NULLIF(?,''), cvss_vector), cwe=COALESCE(NULLIF(?,''), cwe),"
        " cve=COALESCE(NULLIF(?,''), cve), currency=COALESCE(NULLIF(?,''), currency),"
        " reporter_username=COALESCE(NULLIF(?,''), reporter_username),"
        " reporter_id=COALESCE(NULLIF(?,''), reporter_id),"
        " collaborators=?, payout_split=?, my_bounty=?,"
        " my_role=COALESCE(NULLIF(?,''), my_role),"
        " h1_body_path=COALESCE(NULLIF(?,''), h1_body_path),"
        " class=COALESCE(NULLIF(class,''), NULLIF(?,'')),"
        " source='hackerone', tracker_only=0, synced_at=?"
        " WHERE id=?",
        (row["title"], row["state"], row["severity"],
         row.get("body") or "", row.get("thread") or "",
         row["submitted_on"], row["resolved_on"],
         row["url"], row["program"], row["weakness"], row["asset"], row["last_activity"],
         row["state"], row.get("bounty") or "",
         row.get("bounty") or "", row.get("bounty") or "",
         row.get("cvss") or "",
         row.get("cvss_vector") or "", row.get("cwe") or "", row.get("cve") or "",
         row.get("currency") or "", row.get("reporter_username") or "",
         row.get("reporter_id") or "", row.get("collaborators") or "",
         row.get("payout_split") or "", row.get("my_bounty") or "",
         row.get("my_role") or "", row.get("h1_body_path") or "", derived_class,
         now, existing["id"]))

    after = conn.execute("SELECT * FROM reports WHERE id=?", (existing["id"],)).fetchone()
    if content_changed(before, after):
        conn.execute("UPDATE reports SET indexed_at=? WHERE id=?", (now, existing["id"]))
    conn.commit()
    changed = (existing["state"] or "") != row["state"]
    return "updated" if changed else "unchanged"


# Programs with no workspace of their own. Deliberately OUTSIDE the vulns_* tree: creating
# vulns_<program>/ to hold API copies would make ingest treat a directory of downloads as a hunt
# workspace and invent a target for it.
H1_STORE_ROOT = os.path.join(common.HUNT_ROOT, "h1_reports")


def report_store_dir(program):
    """Where a program's report copies live.

    A program that has a workspace on disk keeps its reports inside it, which is what puts
    a workspace-backed program's at the path its rows already point to through `h1_body_path`. Everything else
    goes to the shared store, because writing another vendor's reports into vulns_example would
    put them in the middle of the ExampleVendor research the workspace exists to hold.
    """
    # Not common.slugify: that folds '_' to '-', and a handle is a path component here, so
    # acme_bbp and acme-bbp would collide into one directory.
    slug = re.sub(r"[^a-z0-9_.-]+", "-", str(program or "").strip().lower()).strip("-.") or "unknown"
    ws = os.path.join(common.HUNT_ROOT, "vulns_%s" % slug)
    if os.path.isdir(ws):
        return os.path.join(ws, "h1_reports")
    return os.path.join(H1_STORE_ROOT, slug)


def write_report_file(row):
    """Persist the full report to disk as markdown.

    Kept OUT of the indexed workspace tree (see ingest.IGNORE_DIRS) so these do not double-count
    against the HackerOne-sourced rows that already represent them. The point is durability and
    greppability: the report text survives without the API, the database, or this app.
    """
    if not row.get("h1_id"):
        return None
    store = report_store_dir(row.get("program"))
    os.makedirs(store, exist_ok=True)
    slug = common.slugify(row.get("title") or "", 70)
    path = os.path.join(store, "%s-%s.md" % (row["h1_id"], slug))

    meta = [
        "# %s" % (row.get("title") or "(untitled)"),
        "",
        "**HackerOne:** [#%s](%s)" % (row["h1_id"], row.get("url") or ""),
        "**Program:** %s" % (row.get("program") or ""),
        "**State:** %s" % (row.get("state") or ""),
        "**Reporter:** %s%s" % (row.get("reporter_username") or "",
                                " (id=%s)" % row["reporter_id"] if row.get("reporter_id") else ""),
    ]
    if row.get("my_role"):
        meta.append("**My role:** %s" % row["my_role"])
    if row.get("collaborators"):
        meta.append("**Collaborators:** %s" % row["collaborators"])
    if row.get("severity") or row.get("cvss"):
        meta.append("**Severity:** %s%s" % (row.get("severity") or "",
                                            " (CVSS %s)" % row["cvss"] if row.get("cvss") else ""))
    if row.get("cvss_vector"):
        meta.append("**Vector:** `%s`" % row["cvss_vector"])
    if row.get("cwe"):
        meta.append("**CWE:** %s" % row["cwe"])
    if row.get("cve"):
        meta.append("**CVE:** %s" % row["cve"])
    if row.get("bounty"):
        meta.append("**Bounty:** %s %s" % (row["bounty"], row.get("currency") or "USD"))
    if row.get("my_bounty") and row.get("my_bounty") != row.get("bounty"):
        meta.append("**My share:** %s %s" % (row["my_bounty"], row.get("currency") or "USD"))
    if row.get("payout_split") and row["payout_split"] not in ("[]", "null"):
        meta.append("**Payout split:** `%s`" % row["payout_split"])
    if row.get("submitted_on"):
        meta.append("**Submitted:** %s" % row["submitted_on"])
    if row.get("resolved_on"):
        meta.append("**Closed:** %s" % row["resolved_on"])
    meta += ["", "<!-- Synced from the HackerOne API by quarry. Local edits will be overwritten. -->",
             "", "---", ""]

    body = row.get("body") or "_No vulnerability_information returned by the API._"
    common.write_text_atomic(path, "\n".join(meta) + body.replace("\r\n", "\n") + "\n")
    return path


def sync(conn, verbose=True, program_handle=None, progress=None):
    """Full two-phase sync. `program_handle=None` means EVERY program, as it does everywhere else
    in this module; pass a handle to narrow it."""
    username, token, _primary = get_credentials()
    if not (username and token):
        raise H1Error("No HackerOne credential stored. Add one in the Integrations tab.")
    handle = program_handle or None
    globals()["_ME"] = username        # used by normalize_report to decide reporter vs collaborator
    ensure_schema(conn)

    rows = fetch_reports(username, token, handle, verbose=verbose)

    # COLLABORATOR REPORTS ARE NOT ENUMERABLE.
    # Verified 2026-07-30: /hackers/me/reports returns only reports you SUBMITTED. A report you
    # were invited onto (#0000000, submitted by a-collaborator) is absent from every id it returns,
    # yet fetches fine at /hackers/reports/3903396. hacktivity with "collaborator:<user>" returns
    # zero rows, and filter[program] is ignored on the hacker API. There is no discovery path, so
    # collaborator report ids have to be supplied explicitly.
    known = [str(x).strip() for x in (load_secrets().get("hackerone") or {}).get(
        "extra_report_ids", []) if str(x).strip()]
    have = {r["h1_id"] for r in rows}
    for rid in known:
        if rid in have:
            continue
        try:
            time.sleep(POLITE_DELAY)
            extra = fetch_report_detail(username, token, rid, handle)
            if handle and extra.get("program") and extra["program"] != handle:
                if verbose:
                    print("  skipping %s: program is %s, not %s" % (rid, extra["program"], handle))
                continue
            rows.append(extra)
            if verbose:
                print("  + tracked report %s (%s)" % (rid, extra.get("my_role") or "?"))
        except H1Error as e:
            sys.stderr.write("tracked report %s failed: %s\n" % (rid, e))
    stats = {"fetched": len(rows), "new": 0, "updated": 0, "unchanged": 0,
             "enriched": 0, "detail_errors": 0, "written": 0, "program": handle or ALL_PROGRAMS}

    # Phase 2: the list payload has no bounty, no CVSS score/vector, no CWE and no CVE, so each
    # report is fetched individually. That is one request per report and the reason this stays a
    # manual/nightly operation rather than the 15-minute poll (h1_watch.py), which only fetches
    # the details of reports the list says have moved.
    _total = len(rows)
    for _i, r in enumerate(rows):
        # Phase 2 is the slow half (one request per report); report how many are done so a caller
        # can drive a progress bar instead of an indefinite spinner. progress=None for the CLI.
        if progress:
            progress(_i, _total)
        try:
            time.sleep(POLITE_DELAY)
            # The LIST payload's handle is the fallback, not the sync scope: with the sync no
            # longer pinned to one program there is no single handle a detail row can default to.
            detail = fetch_report_detail(username, token, r["h1_id"], r.get("program"))
            for k, v in detail.items():
                if v not in (None, ""):
                    r[k] = v
            stats["enriched"] += 1
            try:
                fp = write_report_file(r)
                if fp:
                    r["h1_body_path"] = fp
                    stats["written"] = stats.get("written", 0) + 1
            except OSError as werr:
                sys.stderr.write("could not write report file for %s: %s\n" % (r["h1_id"], werr))
        except H1Error as e:
            stats["detail_errors"] += 1
            sys.stderr.write("detail fetch failed for %s: %s\n" % (r["h1_id"], e))
        stats[upsert_report(conn, r)] += 1
    stats["expected_filled"] = recover_expected_from_tracker(conn)
    stats["programs_indexed"] = index_programs(conn)
    if verbose:
        print("h1 sync (%s): fetched=%d new=%d updated=%d unchanged=%d programs=+%d"
              % (stats["program"], stats["fetched"], stats["new"], stats["updated"],
                 stats["unchanged"], stats["programs_indexed"]))
    return stats


def program_display_name(handle):
    """'acme-bbp' -> 'Acme Bbp'. A readable placeholder, editable in the Programs tab.

    HackerOne's hacker API does not return a program's display name on a report, only its handle,
    so this is derived rather than fetched. It is only ever used when CREATING a row.
    """
    words = [w for w in re.split(r"[-_.\s]+", str(handle or "").strip()) if w]
    return " ".join(w[:1].upper() + w[1:] for w in words) or str(handle or "")


def index_programs(conn):
    """Ensure every program we hold reports for exists as a `programs` row. Returns rows added.

    INSERT ONLY. ingest.sync_programs owns programs that have a workspace on disk - it is what
    fills scope_md and roe_md from the pasted guidelines - and rewriting those rows from a bare
    report handle would throw that research away. A handle we have never seen before is the only
    thing this creates.
    """
    handles = [r[0] for r in conn.execute(
        "SELECT DISTINCT program FROM reports"
        " WHERE source='hackerone' AND COALESCE(program,'') <> ''").fetchall()]
    added = 0
    for handle in sorted(handles):
        row = conn.execute("SELECT id FROM programs WHERE slug = ?", (handle,)).fetchone()
        if row:
            continue
        conn.execute(
            "INSERT INTO programs (slug, name, platform, url, updated_at) VALUES (?,?,?,?,?)",
            (handle, program_display_name(handle), "hackerone",
             "https://hackerone.com/%s" % handle, common.now_iso()))
        added += 1
    if added:
        conn.commit()
    return added


def fetch_accessible_programs(username, token, max_pages=30):
    """Every program this credential can SEE on HackerOne - public ones and the private/invited
    programs it has been given - from /hackers/programs, the only endpoint that lists them.

    This is the source for the add-program picker. Report-derived discovery (index_programs) cannot
    surface these: a hunter's private or newly-awarded program does not appear in their reports
    until they have filed against it, so onboarding purely from reports leaves exactly the programs
    they most want to track invisible. Returns one dict per handle, sorted by display name:
    {handle, name, state, offers_bounties, submission_state}.
    """
    out, seen = [], set()
    for pg in range(1, max_pages + 1):
        d = _request("/hackers/programs", username, token,
                     params={"page[size]": 100, "page[number]": pg})
        items = (d or {}).get("data") or []
        for it in items:
            a = it.get("attributes") or {}
            h = (a.get("handle") or "").strip()
            if not h or h in seen:
                continue
            seen.add(h)
            out.append({
                "handle": h,
                "name": (a.get("name") or "").strip() or program_display_name(h),
                "state": a.get("state") or "",
                "offers_bounties": bool(a.get("offers_bounties")),
                "submission_state": a.get("submission_state") or "",
            })
        if len(items) < 100:
            break
    out.sort(key=lambda p: (p["name"] or p["handle"]).lower())
    return out


def onboard_program(conn, username, token, handle, attrs=None):
    """Add ONE program to the tracked set and fill its API-sourced columns immediately.

    Idempotent and insert-only for the stub, so it never overwrites a workspace-backed row (the
    same contract as index_programs). After the stub exists it runs the per-program detail sync for
    just this handle, so policy, structured scopes, submission_state and offers_bounties land at
    once rather than waiting for the next full --sync-programs. Returns
    {"created": bool, "program": <row dict>}.
    """
    handle = (handle or "").strip()
    if not handle:
        raise H1Error("a program handle is required")
    ensure_schema(conn)
    existed = conn.execute("SELECT id FROM programs WHERE slug = ?", (handle,)).fetchone()
    if not existed:
        name = (attrs or {}).get("name") or program_display_name(handle)
        conn.execute(
            "INSERT INTO programs (slug, name, platform, url, updated_at) VALUES (?,?,?,?,?)",
            (handle, name, "hackerone", "https://hackerone.com/%s" % handle, common.now_iso()))
        conn.commit()
    try:
        sync_program_details(conn, username, token, handles=[handle], verbose=False)
    except H1Error:
        pass  # the stub is in; details fill on the next --sync-programs if the API hiccuped now
    row = conn.execute("SELECT * FROM programs WHERE slug = ?", (handle,)).fetchone()
    return {"created": not existed, "program": (dict(row) if row else {"slug": handle})}


# ------------------------------------------------------------------ program details / scopes
# One request per program for the policy, one more for the structured scopes. 18 programs is 36
# requests, which is why this is NOT wired into scripts/sync-h1.sh (a 15-minute cron doing 36
# requests to fetch text that changes a few times a year would be rude). It is a manual pass:
#   python3 h1.py --sync-programs

#: The API columns this sync is allowed to write. scope_md and roe_md ARE NOT IN IT and must
#: never be added: they hold guidelines pasted in by hand from each program's workdir program/
#: folder, HackerOne cannot reproduce them, and one clobbering sync would destroy them for good.
#: The API's own copy of the policy lands in policy_md, alongside rather than merged.
PROGRAM_SYNC_COLUMNS = ("policy_md", "submission_state", "offers_bounties", "bounty_earned",
                        "currency", "synced_at")

PROGRAM_PROTECTED_COLUMNS = ("scope_md", "roe_md")


def fetch_program(username, token, handle):
    """The `attributes` object of /hackers/programs/<handle>. `policy` is the full guidelines."""
    d = _request("/hackers/programs/%s" % handle, username, token)
    return (d.get("data") or d).get("attributes") or {}


def _program_sync_values(attrs):
    """API attributes -> the tuple written to PROGRAM_SYNC_COLUMNS, in order."""
    earned = attrs.get("bounty_earned_for_user")
    return (
        (attrs.get("policy") or "").strip() or None,
        attrs.get("submission_state") or None,
        1 if attrs.get("offers_bounties") else 0,
        "" if earned in (None, "") else str(earned),
        attrs.get("currency") or None,
        common.now_iso(),
    )


def sync_program_details(conn, username, token, handles=None, verbose=True):
    """Fill each program's API-sourced columns and rebuild its structured scopes.

    ADDITIVE BY CONSTRUCTION: the UPDATE below names only PROGRAM_SYNC_COLUMNS, so scope_md and
    roe_md are not merely "preserved when set", they are unreachable from here. There is no code
    path in this function that can write them, whatever the API returns.

    Returns {"programs": n, "scopes": n, "errors": [(handle, message)]}.
    """
    common.init_db(conn)
    rows = conn.execute("SELECT id, slug FROM programs ORDER BY slug").fetchall()
    if handles:
        wanted = {str(h).strip().lower() for h in handles}
        rows = [r for r in rows if r["slug"].lower() in wanted]

    assign = ", ".join("%s = ?" % c for c in PROGRAM_SYNC_COLUMNS)
    stats = {"programs": 0, "scopes": 0, "errors": []}
    for row in rows:
        handle, pid = row["slug"], row["id"]
        try:
            attrs = fetch_program(username, token, handle)
        except H1Error as exc:
            # A single dead handle (program left, or access revoked) must not abort the other 17.
            stats["errors"].append((handle, str(exc)))
            if verbose:
                print("  %-28s SKIP %s" % (handle, exc))
            continue
        conn.execute("UPDATE programs SET " + assign + " WHERE id = ?",
                     _program_sync_values(attrs) + (pid,))
        stats["programs"] += 1

        n = 0
        try:
            n = _sync_scopes(conn, username, token, pid, handle)
        except H1Error as exc:
            stats["errors"].append((handle, str(exc)))
        stats["scopes"] += n
        if verbose:
            print("  %-28s policy=%-5s scopes=%d"
                  % (handle, "yes" if attrs.get("policy") else "no", n))
        conn.commit()
        time.sleep(POLITE_DELAY)
    # Program visibility (public vs private) is only on the accessible-programs LIST, not the
    # per-program detail, so fill it in one pass here.
    try:
        stats["states"] = sync_program_states(conn, username, token, verbose=verbose)
    except H1Error as exc:
        stats["errors"].append(("<program list>", str(exc)))
    conn.commit()
    return stats


def sync_program_states(conn, username, token, verbose=True):
    """Set each program's `state` from the accessible-programs list, which is where HackerOne
    exposes visibility (`public_mode` vs `soft_launched` and other private states). One pass over
    the list, matched to the programs we already track by handle. Returns the count updated."""
    handles = {r["slug"] for r in conn.execute("SELECT slug FROM programs").fetchall()}
    if not handles:
        return 0
    updated = 0
    for pg in range(1, 30):
        d = _request("/hackers/programs", username, token,
                     params={"page[size]": 100, "page[number]": pg})
        items = (d or {}).get("data") or []
        for it in items:
            a = it.get("attributes") or {}
            h = a.get("handle")
            if h in handles and a.get("state"):
                conn.execute("UPDATE programs SET state = ? WHERE slug = ?", (a["state"], h))
                updated += 1
        if len(items) < 100:
            break
    conn.commit()
    if verbose:
        print("  program states: %d updated" % updated)
    return updated


def _sync_scopes(conn, username, token, program_id, handle):
    """Replace one program's `scopes` rows with what the API currently says. Returns the count.

    Delete-then-insert rather than upsert because HackerOne removing an asset is meaningful: a
    scope that is gone is out of scope, and leaving a stale row would say the opposite. Scoped to
    this program_id, so it can never reach another program's rows - or any `targets` row.
    """
    scopes = list_structured_scopes(username, token, handle)
    now = common.now_iso()
    conn.execute("DELETE FROM scopes WHERE program_id = ?", (program_id,))
    for sid, ident, atype, bounty in scopes:
        conn.execute(
            "INSERT OR REPLACE INTO scopes (program_id, h1_id, identifier, asset_type,"
            " eligible_for_bounty, synced_at) VALUES (?,?,?,?,?,?)",
            (program_id, str(sid), ident, atype, 1 if bounty else 0, now))
    return len(scopes)


EXPECTED_NOTE = "anticipated: matching advisory published, payment not yet confirmed by HackerOne"


def recover_expected_from_tracker(conn, verbose=False):
    """Fold hand-recorded ANTICIPATED bounties and CVE cross-refs out of the markdown tracker.

    The researcher records an amount and a CVE against a report when a published ExampleVendor advisory
    appears to match it - i.e. payment is expected but HackerOne has not confirmed it. That is a
    BELIEF, not a fact, so it is kept in expected_* columns and never merged into `bounty`.
    Anything HackerOne has actually confirmed always wins and is left untouched.

    Idempotent, and safe to call after every sync. Sources the values from `tracker_row`, which
    is present on whichever row the markdown fold-in attached to - sometimes the report, and
    sometimes its RCA, so every row carrying one is scanned rather than just tracker_only rows.
    """
    ensure_schema(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}
    for col in ("expected_bounty", "expected_cve", "expected_note"):
        if col not in cols:
            conn.execute("ALTER TABLE reports ADD COLUMN %s TEXT" % col)
    conn.commit()

    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
    money_re = re.compile(r"\$\s*([\d,]+(?:\.\d{1,2})?)")
    filled = cleared = 0
    rows = conn.execute(
        "SELECT h1_id, tracker_row FROM reports"
        " WHERE tracker_row IS NOT NULL AND tracker_row <> '' AND h1_id IS NOT NULL").fetchall()
    for r in rows:
        amounts = money_re.findall(r["tracker_row"])
        cves = cve_re.findall(r["tracker_row"])
        amount = ""
        if amounts:
            try:
                val = float(amounts[0].replace(",", ""))
                amount = "%.2f" % val if val > 0 else ""
            except ValueError:
                amount = ""
        cve = cves[0].upper() if cves else ""
        if not (amount or cve):
            continue
        tgt = conn.execute(
            "SELECT id, bounty, expected_bounty FROM reports WHERE h1_id=? AND source='hackerone'",
            (r["h1_id"],)).fetchone()
        if not tgt:
            continue
        confirmed = (tgt["bounty"] or "").strip()

        # A CONFIRMED AWARD ANSWERS THE EXPECTATION, so the expectation has to go.
        #
        # This used to compute expected = "" correctly and then throw it away: the UPDATE guarded
        # every column with COALESCE(NULLIF(?,''), col), which exists so a blank does not wipe a
        # good value - but that also meant the deliberate blank could never clear anything. The
        # stale amount survived, and was then summed a second time into the anticipated total
        # alongside the real one in the confirmed total.
        #
        # expected_cve is kept. It records WHICH advisory the researcher believes this maps to,
        # which stays useful after payment and is not money, so it cannot double-count.
        if confirmed:
            if (tgt["expected_bounty"] or "").strip():
                conn.execute(
                    "UPDATE reports SET expected_bounty='', expected_note='' WHERE id=?",
                    (tgt["id"],))
                cleared += 1
            if cve:
                conn.execute(
                    "UPDATE reports SET expected_cve=COALESCE(NULLIF(?,''), expected_cve)"
                    " WHERE id=?", (cve, tgt["id"]))
            continue

        conn.execute(
            "UPDATE reports SET expected_bounty=COALESCE(NULLIF(?,''), expected_bounty),"
            " expected_cve=COALESCE(NULLIF(?,''), expected_cve),"
            " expected_note=CASE WHEN ?<>'' THEN ? ELSE expected_note END WHERE id=?",
            (amount, cve, amount, EXPECTED_NOTE, tgt["id"]))
        if amount and not (tgt["expected_bounty"] or ""):
            filled += 1
    conn.commit()
    if verbose:
        print("expected-bounty recovery: %d filled, %d cleared by payment" % (filled, cleared))
    return filled


def refresh_details(conn, verbose=True, only_missing=False, program_handle=None):
    """Re-fetch the DETAIL payload for every stored report and rewrite what HackerOne owns.

    The list endpoint used by `sync` returns neither `vulnerability_information` nor the
    `activities` thread, so a synced report can sit with an empty body, or worse, with the body
    of whatever local markdown file the row was adopted from. This is the pass that fixes that.

    One request per report, so it is a manual operation, not a cron job. `only_missing` limits it
    to rows that have no body yet, which is the cheap way to top up after a normal sync.

    `program_handle` narrows WHICH stored rows are refreshed; None means all of them.
    """
    username, token, _primary = get_credentials()
    if not (username and token):
        raise H1Error("No HackerOne credential stored. Add one in the Integrations tab.")
    handle = program_handle or None
    globals()["_ME"] = username
    ensure_schema(conn)

    sql = "SELECT h1_id, program FROM reports WHERE source='hackerone' AND kind='report'"
    args = []
    if only_missing:
        sql += " AND (body IS NULL OR body='')"
    if handle:
        sql += " AND program = ?"
        args.append(handle)
    ids = [(r["h1_id"], r["program"])
           for r in conn.execute(sql + " ORDER BY h1_id", args).fetchall()]

    done = failed = withthread = 0
    for i, (rid, stored_program) in enumerate(ids, 1):
        try:
            # The row's own program is the fallback. There is no single handle to default to
            # once the database holds more than one program's reports.
            row = fetch_report_detail(username, token, rid, stored_program)
        except Exception as exc:
            failed += 1
            if verbose:
                print("  #%s FAILED: %s" % (rid, exc))
            continue
        row["h1_body_path"] = write_report_file(row)
        upsert_report(conn, row)
        done += 1
        if row.get("thread"):
            withthread += 1
        if verbose and i % 10 == 0:
            print("  %d/%d..." % (i, len(ids)))
    index_programs(conn)
    if verbose:
        print("refresh: %d updated, %d with a conversation thread, %d failed"
              % (done, withthread, failed))
    return {"updated": done, "with_thread": withthread, "failed": failed, "total": len(ids)}


def status(conn):
    username, token, handle = get_credentials()
    ensure_schema(conn)
    def one(sql, d=None):
        try:
            r = conn.execute(sql).fetchone()
            return r[0] if r else d
        except Exception:
            return d
    return {
        "configured": bool(username and token),
        "username": username or "",
        "masked_token": masked(token),
        "fingerprint": fingerprint(token),
        "program_handle": handle,
        "reports_from_h1": one("SELECT COUNT(*) FROM reports WHERE source='hackerone'", 0),
        "last_sync": one("SELECT MAX(synced_at) FROM reports WHERE source='hackerone'"),
    }


def _target_slug_from_path(filepath):
    """Extract the target slug from a workspace path like /workspace/vulns_<slug>/..."""
    m = re.search(r"/vulns_([A-Za-z0-9_-]+)/", os.path.abspath(filepath or ""))
    return m.group(1).lower() if m else None


def submit_cli(conn, args):
    """Drive --submit. Dry runs unless --confirm, because a created report cannot be withdrawn."""
    u, t, _stored_handle = get_credentials()
    if not (u and t):
        sys.exit("no credential stored")
    # --program is REQUIRED to submit. It used to fall back to the stored `program_handle`, which
    # meant the target of a submission was ambient state rather than something the command said
    # out loud - and a dry run once caught a ExampleVendor report about to be filed against ExampleVendor on
    # exactly that path. A report cannot be unfiled, so the handle is stated every time.
    if not args.program:
        sys.exit("h1: --program is required to submit. Name the program the report is filed "
                 "against; there is no default.")
    handle = args.program

    with open(args.submit, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        title, vuln, impact = split_report_markdown(text)
    except ReportFormatError as e:
        sys.exit("h1: %s (%s)" % (e, args.submit))

    # These greps are the report standard's pre-flight. Failing them here rather than after
    # submission is the whole point, since a sent report cannot be edited back into shape.
    problems = []
    if "—" in text or "–" in text:
        problems.append("contains em or en dashes")
    if any(ln.startswith("###") for ln in text.split("\n")):
        problems.append("contains ### headings")
    if ":" in title:
        problems.append("title contains a colon")
    if re.search(r"172\.20\.97\.\d+", text):
        problems.append("contains a lab IP address")
    # Hard-wrapped prose. Repo markdown gets wrapped; a REPORT does not, because HackerOne's
    # editor renders the raggedness. #0000000 was filed wrapped at 98 columns on 2026-08-03 with
    # the rule already written in REPORT_STANDARD.md - a report cannot be edited after sending,
    # so the check belongs here where it can still refuse, not in a checklist someone reads.
    prose = [ln for ln in _outside_fences(text) if ln.strip() and not ln.startswith(("#", "|", "-", "*", ">"))]
    if prose and max(len(ln) for ln in prose) < 200:
        problems.append("prose looks hard-wrapped (longest line %d chars, unwrapped runs several "
                        "hundred) - reflow each paragraph onto ONE line"
                        % max(len(ln) for ln in prose))
    problems.extend(_report_shape_problems(text))
    problems.extend(title_target_problems(common.connect(), text, args.submit, handle, args.scope))
    try:
        problems.extend(verify_submission_target(common.connect(), handle, args.scope,
                                                 args.submit))
    except Exception as exc:  # an unreadable index must not block a submission outright
        print("  warning     could not cross-check the program: %s" % exc)
    if problems:
        sys.exit("h1: refusing to submit, %s" % "; ".join(problems))

    weakness_id = resolve_weakness(u, t, handle, args.weakness) if args.weakness else None
    scope_id = resolve_scope(u, t, handle, args.scope) if args.scope else None
    payload = build_report_payload(handle, title, vuln, impact, weakness_id, scope_id,
                                   severity_rating=args.severity)

    # Collect evidence files if --attach was passed.
    evidence_files = []
    if getattr(args, "attach", False):
        try:
            import screenshot as screenshot_mod
            target_slug = _target_slug_from_path(args.submit)
            if target_slug:
                evidence = screenshot_mod.collect_evidence(target_slug)
                evidence_files = [f["path"] for f in evidence]
        except Exception as exc:
            print("  warning     could not collect evidence: %s" % exc)

    print("  file        %s" % args.submit)
    print("  program     %s" % handle)
    print("  title       %s" % title)
    print("  weakness    %s" % (weakness_id or "(none)"))
    print("  scope       %s" % (scope_id or "(none)"))
    print("  severity    %s" % args.severity)
    print("  body        %d chars" % len(vuln))
    print("  impact      %d chars" % len(impact))
    if evidence_files:
        total_size = sum(os.path.getsize(f) for f in evidence_files)
        print("  evidence    %d files (%d bytes)" % (len(evidence_files), total_size))
        for f in evidence_files:
            print("              %s" % os.path.basename(f))

    if not args.confirm:
        print("\nDRY RUN. Nothing was sent. Re-run with --confirm to submit.")
        return

    if evidence_files:
        h1_id, url, _raw, attachments = create_report_with_attachments(
            u, t, payload, evidence_files)
        print("\nSUBMITTED  #%s  %s  (%d attachments)" % (h1_id, url, len(attachments)))
    else:
        h1_id, url, _raw = create_report(u, t, payload)
        print("\nSUBMITTED  #%s  %s" % (h1_id, url))
    common.audit(conn, "cli", "h1_report_created", source="h1-api",
                 detail=json.dumps({"h1_id": h1_id, "title": title, "file": args.submit}))
    closed = close_lead_on_submit(conn, args.submit, h1_id, url,
                                  args.severity, args.weakness, args.scope)
    if closed:
        print("lead updated: %s" % closed)

    # FILING IS COMPLETE AND IRREVERSIBLE AT THIS POINT. Everything below only updates the local
    # tracker, and it takes minutes where the submission took seconds. Say so, so that a caller
    # watching the output knows the report is already on HackerOne and that waiting is optional -
    # and so that killing this process is never mistaken for an unsent report.
    if args.no_sync:
        print("skipping the follow-up sync (--no-sync). Run: python3 h1.py --sync --program %s"
              % handle)
        return
    print("filed. Now syncing the local tracker, which is slow and changes nothing on HackerOne;"
          " the report above is already live and Ctrl-C here is safe.")
    try:
        sync(conn, verbose=False, program_handle=handle)
        refresh_details(conn, verbose=False, only_missing=True, program_handle=handle)
        print("synced into the tracker")
    except H1Error as e:
        print("submitted, but the follow-up sync failed: %s" % e)
    except KeyboardInterrupt:
        print("sync interrupted. The report is filed; run --sync when convenient.")


def comment_cli(conn, args):
    """Post a comment on an existing report. Dry run unless --confirm, exactly like --submit.

    The body is read from a FILE rather than the command line on purpose: a correction worth posting
    is a few paragraphs of prose with code spans in it, and shell quoting mangles exactly the
    characters that matter. It also means the text can be reviewed before it is sent.
    """
    if not args.body_file:
        sys.exit("h1: --comment needs --body-file")
    try:
        with open(args.body_file, encoding="utf-8") as fh:
            body = fh.read().strip()
    except OSError as exc:
        sys.exit("h1: cannot read %s: %s" % (args.body_file, exc))
    if not body:
        sys.exit("h1: %s is empty" % args.body_file)

    row = conn.execute("SELECT title, h1_state FROM reports WHERE h1_id=?",
                       (str(args.comment),)).fetchone()
    print("  report      #%s  %s" % (args.comment, row["title"] if row else "(not in tracker)"))
    print("  state       %s" % (row["h1_state"] if row else "unknown"))
    print("  body        %d chars from %s" % (len(body), args.body_file))
    print("  visibility  %s" % ("internal note" if args.internal else "VISIBLE TO THE PROGRAM"))
    print()
    for line in body.splitlines()[:12]:
        print("  | " + line)
    if len(body.splitlines()) > 12:
        print("  | ... %d more lines" % (len(body.splitlines()) - 12))

    if not args.confirm:
        print("\nDRY RUN. Nothing was sent. Re-run with --confirm to post.")
        return

    u, t, _ = get_credentials()
    add_comment(u, t, str(args.comment), body, internal=args.internal)
    print("\nPOSTED on #%s  https://hackerone.com/reports/%s" % (args.comment, args.comment))
    common.audit(conn, "cli", "h1_comment_posted", source="h1-api",
                 detail=json.dumps({"h1_id": str(args.comment), "chars": len(body),
                                    "internal": bool(args.internal)}))


def close_lead_on_submit(conn, report_path, h1_id, url, severity, weakness, scope):
    """Move the lead that produced this report to `submitted`, in the same action that files it.

    WHY THIS IS HERE. Filing is the moment a lead becomes submitted, and until now nothing wrote
    that down: `--submit` sent the report and left the lead sitting at `confirmed` with its working
    title, to be fixed by hand afterwards. That is a manual step performed under the relief of
    having just shipped, so it gets skipped - it was skipped on #0000000. Seth watches the queue
    while the pipeline runs, and a lead reading `confirmed` after its report is filed is wrong on
    the one screen he is looking at.

    Returns a short description of what changed, or None. Never raises: a report has already been
    filed by the time this runs and nothing here is worth turning a success into a failure.
    """
    try:
        ap = os.path.abspath(report_path)
        ref_m = re.search(r"/([A-Z]{1,3}\d{1,3})[-_.]", "/" + os.path.basename(ap))
        ws_m = re.search(r"(the workspace [A-Za-z0-9_-]+)/", ap)
        if not ref_m or not ws_m:
            return None
        ref, workspace = ref_m.group(1), ws_m.group(1)

        row = conn.execute(
            "SELECT id, file_path, title, status FROM leads"
            " WHERE ref = ? AND file_path LIKE ? ORDER BY id LIMIT 1",
            (ref, workspace + "/%")).fetchone()
        if not row or not row["file_path"] or not os.path.exists(row["file_path"]):
            return None

        with open(ap, "r", encoding="utf-8") as fh:
            report_title = (re.search(r"^#\s+(.+?)\s*$", fh.read(), re.M) or [None, ""])[1].strip()
        with open(row["file_path"], "r", encoding="utf-8") as fh:
            text = fh.read()
        before = text

        # Status marker, wherever it sits - bare line or table cell.
        text = re.sub(r"(^\|?\s*\*\*Status:\*\*\s*\|?\s*)([A-Za-z][^|\n]*?)(\s*\|?\s*$)",
                      lambda m: m.group(1) + "submitted" + m.group(3), text, count=1, flags=re.M)

        # Title takes the report's, keeping the `<REF> - ` join.
        if report_title:
            text = re.sub(r"^#\s+%s\s*-\s*.*$" % re.escape(ref),
                          "# %s - %s" % (ref, report_title), text, count=1, flags=re.M)

        # A Submitted row, if the header table does not already carry one for this id.
        if h1_id not in text:
            # `--weakness 87` is HackerOne's internal weakness id, NOT a CWE number - 87 is
            # their id for CWE-522. Writing "cwe-87" would put a wrong, plausible-looking CWE in
            # the lead. The real CWE arrives from the API on the sync that follows, so the row
            # records what was actually passed and says which namespace it is in.
            wk = None
            if weakness:
                wk = ("weakness %s" % weakness) if str(weakness).isdigit() else str(weakness)
            bits = [b for b in (severity, wk, scope and ("scope %s" % scope)) if b]
            new_row = "| **Submitted** | %s as #%s (%s) |" % (
                time.strftime("%Y-%m-%d"), h1_id, ", ".join(bits) or "filed")
            rows = list(re.finditer(r"^\|\s*\*\*[A-Za-z ]+\*\*\s*\|.*\|\s*$", text, re.M))
            if rows:
                text = text[:rows[-1].end()] + "\n" + new_row + text[rows[-1].end():]

        if text == before:
            return None
        # The marker must survive, and must stay inside the 25 lines ingest reads, or the lead
        # drops out of the queue while looking statused on disk.
        head = "\n".join(text.split("\n")[:25])
        if "**Status:**" not in head:
            return None
        common.write_text_atomic(row["file_path"], text)
        return "%s -> submitted%s" % (ref, ", title synced" if report_title else "")
    except Exception:
        return None


def main():
    # Line-buffer stdout. Python block-buffers when stdout is not a terminal, which it never is
    # when an agent runs this, so every progress line - including the report id printed the instant
    # a submission succeeds - sat in the buffer until the process exited. On 2026-08-04 #0000000 was
    # filed in about two seconds and then invisible for the two minutes its follow-up sync took,
    # with no way to tell a slow success from a hang. Buffering, not the API, was the whole problem.
    sys.stdout.reconfigure(line_buffering=True)

    ap = argparse.ArgumentParser(description="HackerOne integration")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--sync", action="store_true")
    ap.add_argument("--refresh", action="store_true",
                    help="re-fetch the DETAIL payload for every report: full body + thread")
    ap.add_argument("--only-missing", action="store_true",
                    help="with --refresh: only rows that have no body yet")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--program",
                    help="narrow --sync/--refresh to one program handle. Omitted, or '%s',"
                         " means every program on the account" % ALL_PROGRAMS)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--internal", action="store_true",
                    help="with --comment: post as an internal note instead of to the program")
    ap.add_argument("--comment", metavar="REPORT_ID",
                    help="post a comment on an existing report. Needs --body-file. Prints the "
                         "comment and STOPS unless --confirm is also given")
    ap.add_argument("--body-file", metavar="FILE",
                    help="with --comment: markdown file holding the comment body")
    ap.add_argument("--no-sync", action="store_true",
                    help="with --submit: file the report and stop, skipping the follow-up tracker"
                         " sync. Filing takes seconds and the sync takes minutes")
    ap.add_argument("--submit", metavar="FILE",
                    help="submit a report markdown file. Prints the payload and STOPS unless"
                         " --confirm is also given")
    ap.add_argument("--weakness", help="with --submit: weakness id or CWE, e.g. 287 or cwe-287")
    ap.add_argument("--scope", help="with --submit: structured scope id or exact asset identifier")
    ap.add_argument("--severity", default="medium", choices=list(SEVERITY_RATINGS),
                    help="with --submit: our own triage assessment. Required by the program")
    ap.add_argument("--attach", action="store_true",
                    help="with --submit: auto-attach evidence files from the workspace")
    ap.add_argument("--confirm", action="store_true",
                    help="with --submit: actually send it. Creating a report cannot be undone")
    ap.add_argument("--list-weaknesses", action="store_true")
    ap.add_argument("--list-scopes", action="store_true")
    ap.add_argument("--sync-programs", action="store_true",
                    help="fetch each program's guidelines and structured scopes. 2 requests per"
                         " program, so this is a manual pass, not a cron one")
    args = ap.parse_args()
    # 'all' and "not given" are the same scope, so the flag can be written either way.
    if (args.program or "").strip().lower() == ALL_PROGRAMS:
        args.program = None

    conn = common.connect()
    common.init_db(conn)
    try:
        if args.test:
            u, t, _ = get_credentials()
            if not (u and t):
                sys.exit("no credential stored")
            print(test_credentials(u, t))
        if args.sync:
            sync(conn, verbose=not args.quiet, program_handle=args.program)
        if args.refresh:
            refresh_details(conn, verbose=not args.quiet,
                            only_missing=args.only_missing, program_handle=args.program)
        if args.list_weaknesses or args.list_scopes:
            u, t, handle = get_credentials()
            handle = args.program or handle
            if args.list_weaknesses:
                for wid, cwe, name in list_weaknesses(u, t, handle):
                    print("  %-8s %-12s %s" % (wid, cwe, name))
            if args.list_scopes:
                for sid, ident, atype, bounty in list_structured_scopes(u, t, handle):
                    print("  %-9s %-38s %-26s bounty=%s" % (sid, ident[:38], atype, bounty))
        if args.sync_programs:
            u, t, _ = get_credentials()
            if not (u and t):
                sys.exit("no credential stored")
            st = sync_program_details(conn, u, t,
                                      handles=[args.program] if args.program else None,
                                      verbose=not args.quiet)
            print("programs=%d scopes=%d errors=%d"
                  % (st["programs"], st["scopes"], len(st["errors"])))
        if args.submit:
            submit_cli(conn, args)
        if args.comment:
            comment_cli(conn, args)
        if args.stats or not (args.test or args.sync or args.refresh or args.submit
                              or args.list_weaknesses or args.list_scopes
                              or args.sync_programs):
            for k, v in status(conn).items():
                print("  %-18s %s" % (k, v))
    except H1Error as e:
        sys.exit("h1: %s" % e)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
