#!/usr/bin/env bash
# Quarry VRC container entrypoint. First boot: generate config + TLS, create the schema, index the
# workspace, then hand off to the server. Idempotent - safe to run on every container start.
set -euo pipefail

DATA_DIR="${QUARRY_DATA_DIR:-/data}"
WORKSPACE_DIR="${QUARRY_WORKSPACE_DIR:-/workspace}"
PAYLOADS_DIR="${QUARRY_PAYLOADS_DIR:-/payloads}"
PORT="${QUARRY_PORT:-8443}"

# config.json and the database live on the DATA volume, not the ephemeral image layer, so they
# survive an image upgrade. common.py reads these env names.
export APP_CONFIG="$DATA_DIR/config.json"

# The one hard requirement: an admin password bootstraps the first login. Refuse to start without it
# rather than come up blank, precisely because the IP posture is open by default.
if [ -z "${QUARRY_ADMIN_PASSWORD:-}" ]; then
  echo "FATAL: QUARRY_ADMIN_PASSWORD is not set. Put it in your .env and restart." >&2
  exit 1
fi

mkdir -p "$DATA_DIR/tls" "$WORKSPACE_DIR" "$PAYLOADS_DIR"

# 1. Generate config.json once from the environment. After that it is owned by the volume, so an
#    operator can edit it and keep their changes across restarts.
if [ ! -f "$APP_CONFIG" ]; then
  echo "first boot: generating $APP_CONFIG from environment"
  QUARRY_BIND_HOST="${QUARRY_BIND_HOST:-0.0.0.0}" QUARRY_PORT="$PORT" \
  QUARRY_APP_NAME="${QUARRY_APP_NAME:-Quarry VRC}" QUARRY_ALLOWLIST="${QUARRY_ALLOWLIST:-}" \
  QUARRY_MIN_PASSWORD_LENGTH="${QUARRY_MIN_PASSWORD_LENGTH:-12}" \
  DATA_DIR="$DATA_DIR" WORKSPACE_DIR="$WORKSPACE_DIR" PAYLOADS_DIR="$PAYLOADS_DIR" \
  python3 - "$APP_CONFIG" <<'PY'
import json, os, sys
allow = [a.strip() for a in os.environ.get("QUARRY_ALLOWLIST", "").split(",") if a.strip()]
cfg = {
    "app_name": os.environ.get("QUARRY_APP_NAME", "Quarry VRC"),
    "bind_host": os.environ.get("QUARRY_BIND_HOST", "0.0.0.0"),
    "bind_port": int(os.environ.get("QUARRY_PORT", "8443")),
    "db_path": os.path.join(os.environ["DATA_DIR"], "index.db"),
    "session_hours": 0,
    "min_password_length": int(os.environ.get("QUARRY_MIN_PASSWORD_LENGTH", "12")),
    "allow_remote": allow,                       # [] means open, the default for a self-run host
    "browse_roots": [
        {"label": "workspace", "path": os.environ["WORKSPACE_DIR"]},
        {"label": "payloads", "path": os.environ["PAYLOADS_DIR"]},
    ],
    "payloads_root": os.environ["PAYLOADS_DIR"],
    "tls_cert": os.path.join(os.environ["DATA_DIR"], "tls", "cert.pem"),
    "tls_key": os.path.join(os.environ["DATA_DIR"], "tls", "key.pem"),
    "users": {},
}
with open(sys.argv[1], "w") as fh:
    json.dump(cfg, fh, indent=2, sort_keys=True)
os.chmod(sys.argv[1], 0o600)
print("wrote", sys.argv[1])
PY
fi

# 2. Bootstrap / reset the admin login from the env password (idempotent).
printf '%s\n' "$QUARRY_ADMIN_PASSWORD" | python3 /app/core/server.py --adduser "${QUARRY_ADMIN_USER:-admin}" --password-stdin

# 3. TLS: self-signed local CA on first boot unless the operator mounted their own cert.
if [ "${QUARRY_TLS_MODE:-self-signed}" = "self-signed" ] && [ ! -f "$DATA_DIR/tls/cert.pem" ]; then
  echo "first boot: generating self-signed TLS material"
  python3 /app/core/server.py --gencert
fi

# 4. Schema + index whatever markdown is already in the workspace volume.
python3 /app/core/ingest.py --rebuild || true

# 5. Seed the advisory feeds so the Advisories tab is not empty on first load. Backgrounded on
# purpose: the feeds are a network call and must not delay the server binding its port. It creates
# its own schema, is idempotent, and the tab's Refresh re-runs the same sync by hand thereafter.
( python3 /app/core/advisories.py --sync || true ) &

# 6. Seed the payload arsenal in the background so the Payloads tab and its dashboard tally are
# populated on first load. The reference is a large git repo, so the clone must not block the
# server binding its port; the rebuild is idempotent and self-heals on the next start.
( /app/scripts/sync-payloads.sh "$PAYLOADS_DIR" || true ) &

echo "Quarry VRC starting on https://0.0.0.0:${PORT}/ (published)"
exec python3 /app/core/server.py
