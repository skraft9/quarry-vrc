# Architecture

Quarry VRC is one container. The application code is baked into the image; every piece of mutable,
user-created state lives on a named volume. This is the MISP model, and it is a necessity rather than
a preference: a container's writable layer is ephemeral and is wiped on every image upgrade, so
anything not on a volume would be lost the first time you `docker compose pull`.

```
container: python:3.12-slim  (no pip layer - Python standard library only)
  entrypoint: ThreadingHTTPServer   (server.py runs as the container process)
  reads   config.json               (generated on first boot from env, on the data volume)
  serves  one HTTPS port            (published, default 8443)

named volumes (Docker-managed, survive image upgrades):
  quarry-data       /data        config.json, index.db (+ FTS), TLS certs
  quarry-workspace  /workspace   your leads / reports markdown - the source of truth
  quarry-payloads   /payloads    the payload library (cloned reference + your own)
```

## The stack

| Piece | Role |
|---|---|
| `server.py` | HTTP server, routing, every `/api` route, the CLI entry point. A `ThreadingHTTPServer` over `ssl`. |
| `common.py` | config, paths, the DB connection, the path-safety guard. Reads `QUARRY_*` env on first boot. |
| `auth.py` | password hashing (PBKDF2), sessions, API tokens. |
| `ingest.py` | filesystem scanner: the markdown in your workspace volume becomes rows in the index. |
| `h1.py` | the HackerOne API client: sync programs/reports/bounties/threads, and submit a report. |
| `payloads.py` + `scripts/sync-payloads.sh` | clone a public payload reference and index it into the searchable payload library. |
| `schema.sql` | the SQLite schema. The database is a rebuildable cache; the files and the API are the authorities. |
| `static/` | `index.html` + `app.js` + `app.css` - the entire UI, hand-rolled, no framework, no CDN. |

## Data flow

1. **Leads** are markdown files you (or the app's "New" button) write into the workspace volume.
   `ingest.py` indexes them; a `**Status:**` marker sets the lead's place in the workflow.
2. **Reports** come from the HackerOne API via `h1.py`. They are never file-derived and never
   overwritten by a rebuild - HackerOne is their authority.
3. **Payloads** are a git clone of a public reference on the payloads volume, extracted one row per
   fenced block. Kept out of the workspace so the lead scanner never mistakes a cheatsheet for a lead.
4. **Search** is SQLite FTS5 across leads, reports and payloads, and backs every `[[wikilink]]`.

## Getting files in, two ways

- **Through the UI** (the default): the app writes into the volume, and you never touch a filesystem
  or a compose file.
- **A bind mount** for power users: `-v /my/stuff:/workspace` (or `/payloads`) in compose. Both write
  to the same place the app reads.

## Security model

See the [Security model section of the README](../README.md#-security-model). In short: an IP
allow-list checked before auth, TLS always, PBKDF2 passwords, hashed session/API tokens, write-only
HackerOne credentials, and a strict `default-src 'none'` CSP.
