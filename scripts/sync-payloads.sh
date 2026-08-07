#!/usr/bin/env bash
# Clone or update the payload reference and rebuild the searchable `payloads` index from it.
#
# Quarry vendors NO payload content: the arsenal is a clone of a public repo (PayloadsAllTheThings
# by default) that this script keeps on disk at `payloads_root`, and payloads.py reads the fenced
# code blocks out of it into the `payloads` table. This is what a fresh install runs so the
# Payloads tab - and its dashboard tally - are populated instead of sitting at zero.
#
# Safe to re-run: it pulls when the clone already exists and rebuilds either way (the rebuild is a
# truncate-and-refill, so it is idempotent).
#
#   scripts/sync-payloads.sh                 # uses QUARRY_PAYLOADS_DIR
#   scripts/sync-payloads.sh /path/to/root   # explicit root
set -euo pipefail

ROOT="${1:-${QUARRY_PAYLOADS_DIR:-}}"
REPO="${QUARRY_PAYLOADS_REPO:-https://github.com/swisskyrepo/PayloadsAllTheThings.git}"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "$ROOT" ]; then
  echo "usage: sync-payloads.sh <payloads_root>   (or set QUARRY_PAYLOADS_DIR)" >&2
  exit 2
fi

mkdir -p "$ROOT"
if [ -d "$ROOT/.git" ]; then
  echo "payloads: updating clone at $ROOT"
  git -C "$ROOT" fetch --depth 1 -q origin HEAD
  git -C "$ROOT" reset --hard -q FETCH_HEAD
else
  # init-in-place rather than `git clone <url> <dir>`, so a non-empty target (for example the
  # lost+found on a freshly created Docker volume) does not block the checkout.
  echo "payloads: cloning $REPO into $ROOT (shallow)"
  git init -q "$ROOT"
  git -C "$ROOT" remote add origin "$REPO" 2>/dev/null || git -C "$ROOT" remote set-url origin "$REPO"
  git -C "$ROOT" fetch --depth 1 -q origin HEAD
  git -C "$ROOT" reset --hard -q FETCH_HEAD
fi

python3 "$APP_DIR/core/payloads.py" --rebuild --root "$ROOT"
