#!/usr/bin/env bash
# Refuse to let operator-private data reach the public repo. Run before every push and release,
# and in CI on every PR. Exits non-zero (and prints the offending lines) if anything matches.
#
# This repo is PUBLIC. It must never carry any operator's home paths, LAN IPs, real HackerOne
# report ids, program handles, collaborator/triager handles, credentials, or personal identity.
#
# Two layers:
#   1. STRUCTURAL checks below - catch whole CLASSES of leak (paths, RFC1918 IPs, report ids,
#      secrets, emails, non-placeholder workspace names) without naming anything private.
#   2. A LITERAL denylist you keep OUTSIDE git: `.private-denylist` (git-ignored), one string per
#      line, holding your live program handles, vendor names and identifiers. The public script
#      cannot enumerate those without leaking them, so they live only on your machine / CI secret.
#
# The scaffold of this repo was forked from a private codebase and shipped several real references
# (an engineer's handle, program handles used as examples, workspace paths). This check exists so
# that can never recur silently.
set -uo pipefail
cd "$(dirname "$0")/.."

FAIL=0
# Only scan tracked files; skip this script, the denylist, and binary/vendored assets.
FILES=$(git ls-files | grep -vE '^scripts/check-no-private-data\.sh$|^\.private-denylist$|\.(png|jpg|jpeg|gif|ico|woff2?)$')

hit() { # name, matches
  if [ -n "$2" ]; then
    echo "LEAK [$1]:"; echo "$2" | sed 's/^/  /'; FAIL=1
  fi
}

# 1. Operator home directories (allow the /home/YOU/ and /home/<...> placeholders).
hit "home path" "$(grep -rnE '/home/[a-z][a-z0-9_-]*/' -- $FILES 2>/dev/null | grep -vE '/home/YOU/|/home/<')"

# 2. RFC1918 / link-local IPs (allow the documented allow-list examples in .env.example).
hit "private IP" "$(grep -rnE '\b(10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|169\.254\.[0-9]+\.[0-9]+)\b' -- $FILES 2>/dev/null | grep -vE '\.env\.example:|e\.g\.|example|CIDR')"

# 3. Real-looking HackerOne report ids (7-8 digits; the placeholder is #0000000). CSS/JS carry
#    hex colours like #17803, so exclude them - a report id belongs in prose, not a style value.
hit "report id" "$(grep -rnoE '#[0-9]{7,}' -- $(echo "$FILES" | grep -vE '\.(css|js)$') 2>/dev/null | grep -v '#0000000')"

# 4. Workspace names that are not the generic placeholder.
hit "workspace name" "$(grep -rnoE 'vulns_[a-z0-9_]+' -- $FILES 2>/dev/null | grep -vE 'vulns_example|vulns_%s|vulns_\*')"

# 5. Secrets / private keys / provider tokens.
hit "secret" "$(grep -rnE 'BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|\btok_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}' -- $FILES 2>/dev/null)"

# 6. Real email addresses (allow example/vendor/noreply placeholders).
hit "email" "$(grep -rnoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' -- $FILES 2>/dev/null | grep -viE 'example|noreply|vendor|your-|user@|admin@|@app_|@app-')"

# 7. Literal denylist (your machine / CI only).
if [ -f .private-denylist ]; then
  while IFS= read -r term; do
    [ -z "$term" ] && continue
    case "$term" in \#*) continue;; esac
    hit "denylist:$term" "$(grep -rinF -- "$term" $FILES 2>/dev/null)"
  done < .private-denylist
fi

if [ "$FAIL" -ne 0 ]; then
  echo; echo "FAIL: private data found. Scrub it before this reaches the public repo."; exit 1
fi
echo "OK: no operator-private data found in tracked files."
