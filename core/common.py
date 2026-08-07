"""Shared foundation for the app. Stdlib only - no third-party imports anywhere in this app.

SYSTEMS OF RECORD: every entity has one authority and it is never the DB, which is a cache and a
query layer. Leads / RCAs / notes come from markdown under the workspace volume, reports from the
HackerOne API, advisories from the vendor feed. See "Systems of record" in the README - the older
"files are the source of truth" rule is retired and was wrong in two directions.

NAMING: the product name is DATA, not code. It lives in one place - `app_name` in config.json,
defaulting to DEFAULT_APP_NAME below - and everything user-visible derives from it at runtime.
The wire identifiers below (cookie name, CSRF header, env vars, token prefix) are deliberately
name-INDEPENDENT constants so that renaming the product never touches the protocol surface or
invalidates anyone's session. See RENAME.md.
"""
import json
import os
import re
import sqlite3
import time

# --------------------------------------------------------------------- naming
DEFAULT_APP_NAME = "Quarry VRC"

# Name-independent on purpose. Do NOT rebrand these; nothing user-facing reads them.
# Env-overridable so two instances on the SAME host (cookies are scoped by domain, not port) do
# not clobber each other's session. Distinct default from the private build's "app_session" so a
# public instance running beside a private one never collides; set QUARRY_COOKIE_NAME to run two
# public instances side by side.
COOKIE_NAME = os.environ.get("QUARRY_COOKIE_NAME") or "quarry_session"
CSRF_HEADER = "X-App-CSRF"
TOKEN_PREFIX = "tok_"
ENV_CONFIG = "APP_CONFIG"
ENV_DB = "APP_DB"
ENV_UPLOADS = "APP_UPLOADS"

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(APP_DIR)  # repo root: static/, config, data, tls live here
SCHEMA_PATH = os.path.join(APP_DIR, "schema.sql")
STATIC_DIR = os.path.join(ROOT_DIR, "static")
UPLOAD_DIR = os.environ.get(ENV_UPLOADS) or os.path.join(ROOT_DIR, "uploads")

# APP_CONFIG / APP_DB let the test harness point at a throwaway config and database so tests can
# never touch live data. Unset in normal operation.
CONFIG_PATH = os.environ.get(ENV_CONFIG) or os.path.join(ROOT_DIR, "config.json")
_DEFAULT_DB = os.path.join(ROOT_DIR, "index.db")


def db_path(cfg=None):
    """Resolve the database path: env override, then config `db_path`, then the default."""
    env = os.environ.get(ENV_DB)
    if env:
        return env
    if cfg and cfg.get("db_path"):
        p = cfg["db_path"]
        return p if os.path.isabs(p) else os.path.join(ROOT_DIR, p)
    return _DEFAULT_DB


# Back-compat module constant for callers that just want "the" database.
DB_PATH = os.environ.get(ENV_DB) or _DEFAULT_DB


def app_name(cfg=None):
    """The display name. The ONLY place the product name is decided."""
    if cfg is None:
        cfg = load_config()
    return cfg.get("app_name") or DEFAULT_APP_NAME

# Root under which the workspace directories live. In a container this is the mounted workspace
# volume; env-overridable so the same code runs anywhere.
HUNT_ROOT = os.environ.get("QUARRY_WORKSPACE_DIR") or "/workspace"
WORKSPACE_GLOB_PREFIX = os.environ.get("QUARRY_WORKSPACE_PREFIX") or "vulns_"

# Workspaces present on disk but deliberately NOT indexed. Empty by default; a hunter can add
# their own via config if they keep reference trees beside their hunt workspaces.
EXCLUDE_WORKSPACES = set()

# Workspaces that represent a PROGRAM rather than a product under it (they carry program/
# GUIDELINES.md and standards, not a hunt target). Empty by default; bring your own.
PROGRAM_WORKSPACES = set()

# Which program a hunt-target workspace belongs to, where the slug cannot say so on its own. A
# workspace whose slug EQUALS a program slug, or begins with `<program>-`, is matched
# automatically and needs no entry. Bring your own overrides here if a target's name does not
# record its program.
TARGET_PROGRAM = {}


# ------------------------------------------------------------------ CWE -> class
# The hunt workspaces are organised by a short class code (DoS, BAC, SECRETS...) taken from the
# directory a note lives in. Reports pulled straight from the HackerOne API have no local file and
# therefore no class - some fraction of them at any time - but HackerOne almost always assigns a
# CWE. This maps the CWE onto the same house vocabulary so the Tracker and the hunt tree read
# alike.
#
# Names verified against cwe.mitre.org (CWE 4.20). Keys are lowercase "cwe-<n>"; that is the exact
# shape `weakness.external_id` arrives in from the API.
CWE_CLASS = {
    # --- resource exhaustion / availability ------------------------------------ DoS
    "cwe-400": "DoS",       # Uncontrolled Resource Consumption
    "cwe-405": "DoS",       # Asymmetric Resource Consumption (Amplification)
    "cwe-409": "DoS",       # Improper Handling of Highly Compressed Data (Data Amplification)
    "cwe-674": "DoS",       # Uncontrolled Recursion
    "cwe-770": "DoS",       # Allocation of Resources Without Limits or Throttling
    "cwe-776": "DoS",       # XML Entity Expansion
    "cwe-789": "DoS",       # Memory Allocation with Excessive Size Value
    "cwe-834": "DoS",       # Excessive Iteration
    "cwe-1050": "DoS",      # Excessive Platform Resource Consumption within a Loop
    "cwe-1333": "DoS",      # Inefficient Regular Expression Complexity (ReDoS)
    "cwe-401": "DoS",       # Missing Release of Memory after Effective Lifetime
    "cwe-1284": "DoS",      # Improper Validation of Specified Quantity in Input

    # --- authorisation --------------------------------------------------------- BAC
    "cwe-284": "BAC",       # Improper Access Control
    "cwe-285": "BAC",       # Improper Authorization
    "cwe-862": "BAC",       # Missing Authorization
    "cwe-863": "BAC",       # Incorrect Authorization
    "cwe-639": "BAC",       # Authorization Bypass Through User-Controlled Key (IDOR)
    "cwe-566": "BAC",       # Authorization Bypass Through User-Controlled SQL Primary Key
    "cwe-1220": "BAC",      # Insufficient Granularity of Access Control
    "cwe-425": "BAC",       # Direct Request (Forced Browsing)
    "cwe-538": "BAC",       # Insertion of Sensitive Information into Externally-Accessible File

    # --- privilege ------------------------------------------------------------- PRIVESC
    "cwe-269": "PRIVESC",   # Improper Privilege Management
    "cwe-266": "PRIVESC",   # Incorrect Privilege Assignment
    "cwe-268": "PRIVESC",   # Privilege Chaining
    "cwe-250": "PRIVESC",   # Execution with Unnecessary Privileges
    "cwe-272": "PRIVESC",   # Least Privilege Violation

    # --- authentication / session ---------------------------------------------- AUTHN
    "cwe-287": "AUTHN",     # Improper Authentication
    "cwe-290": "AUTHN",     # Authentication Bypass by Spoofing
    "cwe-306": "AUTHN",     # Missing Authentication for Critical Function
    "cwe-307": "AUTHN",     # Improper Restriction of Excessive Authentication Attempts
    "cwe-384": "AUTHN",     # Session Fixation
    "cwe-521": "AUTHN",     # Weak Password Requirements
    "cwe-613": "AUTHN",     # Insufficient Session Expiration
    "cwe-620": "AUTHN",     # Unverified Password Change

    # --- information exposure --------------------------------------------------- SECRETS
    "cwe-200": "SECRETS",   # Exposure of Sensitive Information to an Unauthorized Actor
    "cwe-209": "SECRETS",   # Generation of Error Message Containing Sensitive Information
    "cwe-215": "SECRETS",   # Insertion of Sensitive Information Into Debugging Code
    "cwe-359": "SECRETS",   # Exposure of Private Personal Information
    "cwe-532": "SECRETS",   # Insertion of Sensitive Information into Log File
    "cwe-540": "SECRETS",   # Inclusion of Sensitive Information in Source Code
    "cwe-548": "SECRETS",   # Exposure of Information Through Directory Listing
    "cwe-798": "SECRETS",   # Use of Hard-coded Credentials

    # --- injection -------------------------------------------------------------- INJECTION
    "cwe-77": "INJECTION",  # Command Injection
    "cwe-78": "INJECTION",  # OS Command Injection
    "cwe-88": "INJECTION",  # Argument Injection
    "cwe-89": "INJECTION",  # SQL Injection
    "cwe-90": "INJECTION",  # LDAP Injection
    "cwe-91": "INJECTION",  # XML Injection
    "cwe-93": "INJECTION",  # CRLF Injection
    "cwe-94": "INJECTION",  # Improper Control of Generation of Code
    "cwe-95": "INJECTION",  # Eval Injection
    "cwe-943": "INJECTION",  # Improper Neutralization in Data Query Logic (NoSQL)

    # --- template injection ------------------------------------------------------ SSTI
    "cwe-917": "SSTI",      # Expression Language Injection
    "cwe-1336": "SSTI",     # Improper Neutralization of Special Elements Used in a Template Engine

    # --- the rest, one class each -------------------------------------------------
    "cwe-79": "XSS",        # Cross-site Scripting
    "cwe-80": "XSS",
    "cwe-83": "XSS",
    "cwe-87": "XSS",
    "cwe-918": "SSRF",      # Server-Side Request Forgery
    "cwe-611": "XXE",       # Improper Restriction of XML External Entity Reference
    "cwe-827": "XXE",       # Improper Control of Document Type Definition
    "cwe-502": "DESERIAL",  # Deserialization of Untrusted Data
    "cwe-22": "PATH",       # Path Traversal
    "cwe-23": "PATH",
    "cwe-36": "PATH",
    "cwe-59": "PATH",       # Improper Link Resolution Before File Access
    "cwe-73": "PATH",       # External Control of File Name or Path
    "cwe-434": "UPLOAD",    # Unrestricted Upload of File with Dangerous Type
    "cwe-352": "CSRF",      # Cross-Site Request Forgery
    "cwe-601": "REDIRECT",  # URL Redirection to Untrusted Site
    "cwe-444": "SMUGGLING",  # Inconsistent Interpretation of HTTP Requests
    "cwe-113": "SMUGGLING",  # CRLF Injection in HTTP Headers
    "cwe-1321": "PROTO",    # Improperly Controlled Modification of Object Prototype Attributes
    "cwe-295": "CRYPTO",    # Improper Certificate Validation
    "cwe-311": "CRYPTO",    # Missing Encryption of Sensitive Data
    "cwe-326": "CRYPTO",    # Inadequate Encryption Strength
    "cwe-327": "CRYPTO",    # Use of a Broken or Risky Cryptographic Algorithm
    "cwe-330": "CRYPTO",    # Use of Insufficiently Random Values
    "cwe-338": "CRYPTO",    # Use of Cryptographically Weak PRNG
    "cwe-347": "CRYPTO",    # Improper Verification of Cryptographic Signature
    "cwe-345": "INTEGRITY",  # Insufficient Verification of Data Authenticity
    "cwe-353": "INTEGRITY",  # Missing Support for Integrity Check
    "cwe-494": "INTEGRITY",  # Download of Code Without Integrity Check
    "cwe-565": "INTEGRITY",  # Reliance on Cookies without Validation and Integrity Checking
    "cwe-119": "MEMORY",    # Improper Restriction of Operations within Memory Buffer
    "cwe-120": "MEMORY",
    "cwe-125": "MEMORY",    # Out-of-bounds Read
    "cwe-787": "MEMORY",    # Out-of-bounds Write
    "cwe-415": "MEMORY",    # Double Free
    "cwe-416": "MEMORY",    # Use After Free
    "cwe-476": "MEMORY",    # NULL Pointer Dereference
    "cwe-190": "MEMORY",    # Integer Overflow or Wraparound
    "cwe-191": "MEMORY",    # Integer Underflow
    "cwe-362": "RACE",      # Race Condition
    "cwe-367": "RACE",      # TOCTOU
    "cwe-16": "CONFIG",     # Configuration
    "cwe-276": "CONFIG",    # Incorrect Default Permissions
    "cwe-732": "CONFIG",    # Incorrect Permission Assignment for Critical Resource
    "cwe-1188": "CONFIG",   # Insecure Default Initialization of Resource
    "cwe-20": "VALIDATION",  # Improper Input Validation
    "cwe-840": "BIZLOGIC",  # Business Logic Errors
}

UNCLASSED = "Unclassified"


def class_for_report(row):
    """The class to file a report under.

    The local markdown file wins when there is one: it carries the researcher's own judgement,
    including ExampleVendor-specific classes such as DLSFLS that no CWE expresses. Otherwise derive
    from the CWE, and fall back to UNCLASSED rather than inventing a bucket.

    `row` may be a sqlite3.Row or a plain dict.
    """
    def get(key):
        try:
            return row[key]
        except (KeyError, IndexError, TypeError):
            return None

    local = (get("class") or "").strip()
    if local:
        return local
    cwe = (get("cwe") or "").strip().lower()
    if cwe:
        if not cwe.startswith("cwe-"):
            cwe = "cwe-" + cwe.lstrip("cwe").lstrip("-")
        mapped = CWE_CLASS.get(cwe)
        if mapped:
            return mapped
        return cwe.upper()      # a real CWE we have not mapped: show it rather than hide it
    return UNCLASSED


DEFAULT_CONFIG = {
    # Display name. Change this one value to rebrand the whole app - see RENAME.md.
    "app_name": DEFAULT_APP_NAME,
    # Database filename or absolute path. Relative paths resolve against the app directory.
    "db_path": "index.db",
    "bind_host": "127.0.0.1",
    "bind_port": 8443,
    "tls_cert": os.path.join(ROOT_DIR, "tls", "cert.pem"),
    "tls_key": os.path.join(ROOT_DIR, "tls", "key.pem"),
    # 0 means the session never expires. See auth.NEVER_EXPIRES and the Settings tab; the app
    # binds to loopback and has one operator, so being logged out on a timer bought nothing.
    "session_hours": 0,
    "users": {},  # username -> {"salt": hex, "hash": hex, "iterations": int}
    # Minimum length enforced by --adduser. Lowering this is only reasonable because reaching the
    # login form at all requires being on `allow_remote`, and logins are rate-limited to 5 per
    # 15 min per source address. Note that limiter is in-memory and resets on restart.
    "min_password_length": 12,
    # File browser. browse_roots are the trees exposed in the UI's Files tab.
    "browse_roots": [{"label": "workspace", "path": "/workspace"},
                     {"label": "payloads", "path": "/payloads"}],
    # Deny-list applied to every browse/read/download. ON BY DEFAULT because this UI is
    # network-reachable and the host may hold private key material. Set to [] to expose everything.
    "browse_deny_globs": [
        "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
        "id_rsa*", "id_ecdsa*", "id_ed25519*", "*.gpg", "*.kdbx",
        ".ssh/*", "*/.ssh/*", ".aws/*", "*/.aws/*", "*credentials*",
        ".netrc", "*/.netrc", "*.env", "*/.git/config",
    ],
    "browse_max_bytes": 2_000_000,  # refuse to inline-render files larger than this
    # Reference clone the Payloads tab is built from (see payloads.py). Kept OUTSIDE the workspace
    # so ingest never mistakes a cheatsheet for a lead, and never committed.
    "payloads_root": "/payloads",
    # Client IP allowlist, enforced before auth on EVERY request including /api/health.
    # Accepts bare IPs and CIDRs. Empty list = allow all - the open-by-default posture for a
    # container you run yourself. Set QUARRY_ALLOWLIST (or this list) to lock it down.
    "allow_remote": [],
}

# Which directory name maps to which vulnerability class.
KNOWN_CLASSES = {
    "BAC", "DoS", "SECRETS", "RCE", "API", "INTEGRITY", "SSTI",
    "PRIVESC", "DLSFLS", "FLS_SIDECHANNEL", "other", "codeql", "harness",
}

# Ordered: first match wins. Applied against the file's first line (uppercased).
STATUS_PATTERNS = [
    # FIRST, ahead of `submitted`, and that ordering is the whole reason this list is ordered. A
    # paid lead's header names BOTH events, because the award is written next to the id it was
    # paid against ("SUBMITTED 2026-08-02 as #0000000, AWARDED"). Sniffed the other way round
    # every one of them would resolve to the weaker `submitted` and the terminal state would be
    # unreachable from a header. Deliberately narrow: a match here is also what decides an
    # unmarked note IS a lead, so a hunt log that merely mentions a bounty must not trip it.
    ("awarded", re.compile(r"\bAWARDED\b|\bBOUNTY\s+PAID\b")),
    # Ahead of `submitted` too, though the two do not currently overlap: `\bSHIPPED\b` cannot match
    # the SHIP in "ready to ship", because SHIP and SHIPPED are different words to a boundary. That
    # was verified rather than assumed, and the position is kept anyway - it costs nothing and it
    # is the ordering a reader expects from a lifecycle list. What the position DOES decide today
    # is `ready` against `open`: "OPEN LEAD - READY TO SHIP" matches both, and the later state is
    # the true one. These are also different states from `open`'s READY-TO-FIRE, which meant a PoC
    # that runs, where this means a report that is drafted, reviewed and waiting on the submit call.
    ("ready", re.compile(r"\bREADY[- ]?TO[- ]?SHIP\b")),
    ("submitted", re.compile(r"\bSUBMITTED\b|\bH1\s*#\d+|\bSHIPPED\b")),
    ("killed", re.compile(r"\bKILL(ED)?\b|\bNEGATIVE\b|\bDEAD\b|\bDO NOT RE-?HUNT\b")),
    ("parked", re.compile(r"\bPARKED\b|\bSHELVED\b|\bDEFERRED\b")),
    ("confirmed", re.compile(r"\bCONFIRMED\b")),
    ("open", re.compile(r"\bOPEN LEAD\b|\bOPEN\b|\bREADY-?TO-?FIRE\b")),
]

# 'L2', 'G8', 'F3', 'K1' at the start of a title.
REF_RE = re.compile(r"^#?\s*([A-Z]{1,2}\d{1,3})\b")

# Report filenames like 3899885_G8-synthetics-param-value-edit-route.md
REPORT_FILE_RE = re.compile(r"^(\d{5,9})_([A-Z]{1,2}\d{1,3})?-?(.*)\.md$")


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh))
    return cfg


def save_config(cfg):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


def connect(path=None):
    # Resolved at CALL time, not import time, so config `db_path` and the APP_DB test override
    # both take effect without every caller having to thread the path through.
    if path is None:
        path = db_path(load_config())
    conn = sqlite3.connect(path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _ensure_audit_source(conn)
    _ensure_reports_90d(conn)
    return conn


def _ensure_reports_90d(conn):
    """Add `programs.reports_90d`, the count of reports a program received in the last 90 days.

    MANUALLY SOURCED, and that is not an oversight. The hacker API does not expose it:
    `/hackers/programs/{handle}` returns twenty attributes covering bounty, scope, state and
    triage, and no volume metric at all, and the `statistics`, `metrics` and `stats` sub-paths do
    not exist. The figure is rendered on the program's own page from an endpoint outside the
    documented API, so it is read once during evaluation and written here.

    It is worth the manual step because it measures the thing that has actually cost us reports -
    how many other researchers are filing against this program right now - which the hacktivity
    resolution rate only approximates, and approximates badly for a program that resolves slowly
    while receiving a flood.
    """
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(programs)")}
        if not cols or "reports_90d" in cols:
            return
        conn.execute("ALTER TABLE programs ADD COLUMN reports_90d INTEGER")
        conn.commit()
    except sqlite3.Error:
        pass


def _ensure_audit_source(conn):
    """Add `audit.source` and backfill it. Idempotent, and cheap enough to run on every connect.

    Backfilled rather than left blank, because the whole table resolves exactly - see
    `audit_source`. A column that is empty for everything written before it existed is a column
    nobody trusts, and 'unknown' is that same emptiness wearing a value.
    """
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(audit)")}
        if not cols or "source" in cols:
            return
        conn.execute("ALTER TABLE audit ADD COLUMN source TEXT")
        conn.execute(
            "UPDATE audit SET source = CASE"
            "  WHEN LOWER(TRIM(COALESCE(actor,''))) IN ('cli','cron')"
            "    THEN LOWER(TRIM(actor))"
            "  WHEN TRIM(COALESCE(remote,'')) <> '' THEN 'web'"
            "  ELSE 'cli' END")
        conn.commit()
    except sqlite3.Error:
        # A read-only or half-built database must not make connect() fail.
        pass


def init_db(conn):
    with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
        conn.executescript(fh.read())
    conn.commit()
    ensure_first_seen(conn)
    ensure_program_columns(conn)


#: Columns added to `programs` after the table shipped. schema.sql only CREATEs IF NOT EXISTS, so
#: an existing database never sees a widened definition and has to be ALTERed. Every one of these
#: is written from the HackerOne API; none of them is scope_md or roe_md, which are hand-entered.
PROGRAM_API_COLUMNS = (("policy_md", "TEXT"), ("submission_state", "TEXT"),
                       ("offers_bounties", "INTEGER"), ("bounty_earned", "TEXT"),
                       ("currency", "TEXT"), ("synced_at", "TEXT"), ("state", "TEXT"))


def ensure_program_columns(conn):
    """Widen `programs` with the API-sourced columns. Idempotent, and additive by construction."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(programs)").fetchall()}
    if not cols:
        return                            # table not created yet on a bare database
    added = False
    for name, decl in PROGRAM_API_COLUMNS:
        if name not in cols:
            conn.execute("ALTER TABLE programs ADD COLUMN %s %s" % (name, decl))
            added = True
    if added:
        conn.commit()


#: (table, column the row's own publication date lives in). The backfill prefers that column over
#: indexed_at because indexed_at is exactly what is untrustworthy here, and a row cannot have been
#: first seen before it existed. It UNDERestimates, which is the safe direction: the worst case is
#: an old row that never badges, the opposite of the failure being fixed.
FIRST_SEEN_BACKFILL = (("reports", "submitted_on"), ("advisories", "published"))

#: Leads carry no publication date, and backfilling from `indexed_at` is worse than useless: a
#: lead edited an hour ago would get an hour-old first_seen and read as NEW, which is the exact
#: bug the column exists to fix. Every lead already on disk at migration time has, by definition,
#: already been seen - so they all get the OLDEST timestamp in the table as their floor. Only rows
#: inserted after the migration get a real arrival time, and those are the only genuinely new ones.
FIRST_SEEN_FLOOR_TABLES = ("leads",)


def ensure_first_seen(conn):
    """Add and backfill `first_seen_at` on every table whose badge depends on it.

    Advisories carry the same conflation as reports and for the same reason: advisories.upsert
    bumps `indexed_at` whenever a vendor edits a title, CVSS or CVE list, so a re-published
    advisory from three weeks ago badges as new. All 266 stored rows currently share one sweep
    timestamp (2026-07-30T22:27:58), which is what a bulk reparse leaves behind and is why
    `published` rather than `indexed_at` is the honest backfill source.

    WHY IT IS NOT `indexed_at`: that column means "this row's content changed", by deliberate
    design (see h1.upsert_report - bumping it unconditionally made the nightly detail pass open
    every morning on a false "+111 new"). But the "new" badge reads it as "this row appeared",
    and those are different questions. On 2026-08-01 report #0000000, submitted six weeks earlier
    on 06-27, was triaged; the update bumped indexed_at and the dashboard badged a six-week-old
    report as new.

    This column answers only the second question. It is written once, on INSERT, by both
    h1.upsert_report and ingest.upsert_report, and never updated afterwards.

    It lives here rather than in h1.ensure_schema because ingest.py also inserts reports and does
    not import h1 - one definition, reached by every entry point through init_db.
    """
    now = now_iso()
    for table in FIRST_SEEN_FLOOR_TABLES:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}
        if not cols:
            continue
        if "first_seen_at" not in cols:
            conn.execute("ALTER TABLE %s ADD COLUMN first_seen_at TEXT" % table)
        floor = conn.execute(
            "SELECT MIN(indexed_at) FROM %s WHERE indexed_at IS NOT NULL" % table).fetchone()[0]
        conn.execute(
            "UPDATE %s SET first_seen_at = COALESCE(?, indexed_at, ?)"
            " WHERE first_seen_at IS NULL OR first_seen_at = ''" % table, (floor, now))

    for table, origin in FIRST_SEEN_BACKFILL:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}
        if not cols:
            continue                      # table not created yet on a bare database
        if "first_seen_at" not in cols:
            conn.execute("ALTER TABLE %s ADD COLUMN first_seen_at TEXT" % table)
        conn.execute(
            "UPDATE %s SET first_seen_at = COALESCE(NULLIF(%s, ''), indexed_at, ?)"
            " WHERE first_seen_at IS NULL OR first_seen_at = ''" % (table, origin), (now,))
    conn.commit()


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


#: Where an audited action came from. A closed set, because the column exists to be filtered on
#: and a free-text origin is a column nobody can group by.
AUDIT_SOURCES = ("web", "cron", "cli", "h1-api")


def audit_source(actor, remote, source=None):
    """Which channel an action arrived through. Never blank, and never 'unknown'.

    An explicit `source` from the caller always wins. Otherwise it is DERIVED, and the derivation
    is exact rather than a guess: a request that reached a route carries the client address, and
    nothing that runs headless has one. The two headless callers already name themselves in
    `actor`, because that is the only identity they have.

    Checked against the whole existing table on 2026-08-03: 38 rows with a remote, 23 actor='cli',
    21 actor='cron', 4 test rows with a remote, and ZERO rows with neither - so every historical
    row resolves without inventing anything.
    """
    if source:
        return source if source in AUDIT_SOURCES else "web"
    a = (actor or "").strip().lower()
    if a in ("cli", "cron"):
        return a
    # A client address means an HTTP request reached a route. Headless callers have none.
    return "web" if (remote or "").strip() else "cli"


def audit(conn, actor, action, entity=None, entity_id=None, detail=None, remote=None,
          source=None):
    conn.execute(
        "INSERT INTO audit (ts, actor, action, entity, entity_id, detail, remote, source)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (now_iso(), actor, action, entity, entity_id, detail, remote,
         audit_source(actor, remote, source)),
    )
    conn.commit()


def safe_under(root, candidate):
    """Return the normalised absolute path iff it really sits under root. Else None.

    Used on every filesystem write driven by user input. Rejects traversal and symlink escape.
    """
    root_real = os.path.realpath(root)
    cand_real = os.path.realpath(os.path.abspath(candidate))
    if cand_real == root_real:
        return cand_real
    if cand_real.startswith(root_real + os.sep):
        return cand_real
    return None


def write_text_atomic(path, text):
    """Write a file atomically, creating parent dirs. Returns the path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)
    return path


def slugify(text, maxlen=60):
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "")).strip("-").lower()
    return (s[:maxlen] or "untitled").strip("-")


def client_allowed(remote_ip, allow_list):
    """True if remote_ip is permitted by allow_list (bare IPs and CIDRs). Empty list = allow all."""
    import ipaddress
    if not allow_list:
        return True
    try:
        addr = ipaddress.ip_address(remote_ip)
    except ValueError:
        return False
    for entry in allow_list:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def path_denied(path, deny_globs):
    """True if path matches any deny glob, on the full path or any single component."""
    import fnmatch
    p = os.path.normpath(path)
    name = os.path.basename(p)
    for pat in deny_globs or []:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(p, "*/" + pat):
            return True
    return False
