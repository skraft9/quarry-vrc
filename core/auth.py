"""Authentication. Stdlib only.

Design notes (deliberate, see docs/app/ARCHITECTURE.md "Security model"):
  * Passwords: PBKDF2-HMAC-SHA256, 600_000 iterations, 16-byte per-user salt.
  * Every secret comparison uses hmac.compare_digest. This codebase was written by someone who
    spends their days finding CWE-208 timing bugs; there are no `==` comparisons on secrets here.
  * Session tokens and API tokens are 32 bytes from secrets.token_urlsafe. Only sha256(token)
    is ever persisted, so a database read does not yield usable credentials.
  * Login is rate-limited per remote address.
"""
import hashlib
import hmac
import secrets
import time

import common

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
TOKEN_BYTES = 32
LOGIN_WINDOW_SEC = 900
LOGIN_MAX_ATTEMPTS = 5

_login_attempts = {}  # remote -> [timestamps]


# ------------------------------------------------------------------ passwords
def hash_password(password, salt=None, iterations=PBKDF2_ITERATIONS):
    salt = salt or secrets.token_bytes(SALT_BYTES)
    if isinstance(salt, str):
        salt = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {"salt": salt.hex(), "hash": dk.hex(), "iterations": iterations}


def verify_password(password, record):
    """Constant-time password check against a stored record."""
    if not record:
        # Still burn comparable time so a missing user is not distinguishable by latency.
        hash_password(password, salt=b"\x00" * SALT_BYTES, iterations=PBKDF2_ITERATIONS)
        return False
    try:
        salt = bytes.fromhex(record["salt"])
        iterations = int(record.get("iterations", PBKDF2_ITERATIONS))
        expected = bytes.fromhex(record["hash"])
    except (KeyError, ValueError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expected)


# ------------------------------------------------------------------ rate limit
def login_allowed(remote):
    now = time.time()
    hits = [t for t in _login_attempts.get(remote, []) if now - t < LOGIN_WINDOW_SEC]
    _login_attempts[remote] = hits
    return len(hits) < LOGIN_MAX_ATTEMPTS


def record_login_failure(remote):
    _login_attempts.setdefault(remote, []).append(time.time())


def clear_login_failures(remote):
    _login_attempts.pop(remote, None)


# ------------------------------------------------------------------ sessions
def _sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


#: `session_hours = 0` means the session never expires. Stored as an explicit sentinel rather than
#: a huge timestamp so the intent survives a look at the table, and so no arithmetic can drift it
#: back into the past. Every read of `expires_at` has to test for it BEFORE comparing to now, or
#: "never" reads as "expired in 1970" and logs the operator out on the next request.
NEVER_EXPIRES = 0.0


def session_expiry(hours, now=None):
    """Absolute expiry for a session opened now, or NEVER_EXPIRES when the timeout is off."""
    hours = int(hours or 0)
    if hours <= 0:
        return NEVER_EXPIRES
    return (time.time() if now is None else now) + hours * 3600


def create_session(conn, username, remote, hours=12):
    token = secrets.token_urlsafe(TOKEN_BYTES)
    now = time.time()
    conn.execute(
        "INSERT INTO sessions (token_hash, username, created_at, expires_at, remote)"
        " VALUES (?,?,?,?,?)",
        (_sha256(token), username, now, session_expiry(hours, now), remote),
    )
    conn.commit()
    return token


def lookup_session(conn, token):
    if not token:
        return None
    row = conn.execute(
        "SELECT username, expires_at FROM sessions WHERE token_hash = ?", (_sha256(token),)
    ).fetchone()
    if not row:
        return None
    if row["expires_at"] != NEVER_EXPIRES and row["expires_at"] < time.time():
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_sha256(token),))
        conn.commit()
        return None
    return {"username": row["username"], "scope": "write", "via": "session"}


def destroy_session(conn, token):
    if token:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_sha256(token),))
        conn.commit()


def purge_expired_sessions(conn):
    # The sentinel is 0.0, which is less than every real timestamp, so it has to be excluded
    # explicitly or the housekeeping pass deletes exactly the sessions meant to survive.
    conn.execute("DELETE FROM sessions WHERE expires_at != ? AND expires_at < ?",
                 (NEVER_EXPIRES, time.time()))
    conn.commit()


# ------------------------------------------------------------------ api tokens
def create_api_token(conn, name, scope, created_by):
    raw = common.TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)
    conn.execute(
        "INSERT INTO api_tokens (name, token_hash, prefix, scope, created_at, created_by)"
        " VALUES (?,?,?,?,?,?)",
        (name, _sha256(raw), raw[:len(common.TOKEN_PREFIX) + 8], scope if scope in ("read", "write") else "read",
         common.now_iso(), created_by),
    )
    conn.commit()
    row = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
    return row["id"], raw


def lookup_api_token(conn, raw):
    if not raw:
        return None
    row = conn.execute(
        "SELECT id, name, scope, revoked FROM api_tokens WHERE token_hash = ?", (_sha256(raw),)
    ).fetchone()
    if not row or row["revoked"]:
        return None
    conn.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (common.now_iso(), row["id"]))
    conn.commit()
    return {"username": "token:" + row["name"], "scope": row["scope"], "via": "token"}


def revoke_api_token(conn, token_id):
    conn.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ?", (token_id,))
    conn.commit()
