## Review of PR #6 - request changes

Thanks for a substantial and cleanly written contribution. The screenshot, timeline, proxy-feed and attachment features are well structured, stdlib-only, defensively coded, and they slot into the existing tables and route machinery correctly. The gate `scripts/check-no-private-data.sh` passes and the new source is pure ASCII with no operator data or AI attribution. I am requesting changes rather than approving because the headline attachment flow is built on a HackerOne endpoint this codebase has not verified exists, the `VERSION` bump skips a release number, there is a crash bug in the attachment response parser, and the capture backends do not reach anything in the documented containerized deployment. None of these are hard to fix, and the underlying design is sound.

## Summary of the PR

- **New module** `core/screenshot.py` (946 lines): three capture backends (Caido GraphQL, Burp REST, OS `screencapture`/`scrot`/`import`) plus evidence timeline, scope-filtered proxy feed, and evidence collection, with a full CLI.
- **`core/h1.py`** gains a report-intent draft-and-attach flow (`create_report_intent`, `upload_attachments`, `submit_report_intent`, `create_report_with_attachments`, `_multipart_upload`) wired into `--submit` via a new `--attach` flag.
- **`core/server.py`** adds six routes: `GET /api/screenshot/backends`, `POST /api/screenshot`, `GET /api/evidence/<target>`, `GET|POST /api/evidence/<target>/timeline`, and `POST /api/evidence/<target>/feed`.
- **`VERSION`** moves 1.3.5 to 1.5.0, targeting `dev`.

## What works well

- **Correct reuse of existing infrastructure.** The `uploads` insert matches the `schema.sql` columns exactly, `scopes`/`programs`/`targets` are joined on the real foreign keys, and `common.slugify`/`now_iso`/`audit`/`connect` are all used as intended.
- **Route safety.** Patterns are anchored (`route()` compiles `^...$`), so `GET /api/evidence/<t>` cannot shadow `.../timeline`, and the `(\w[\w-]*)` slug pattern blocks path traversal into the target segment.
- **Defensive server integration.** `import screenshot` is wrapped so a load failure degrades to a 503 instead of taking the server down, and write actions carry the correct `scope="write"`.
- **Stdlib discipline held.** Every import (argparse, hashlib, mimetypes, subprocess, urllib, uuid, ...) is standard library; no pip, npm or CDN is introduced.
- **Thoughtful UX details.** Atomic writes via a `.tmp` rename, sha256 recorded per file, `--attach` is dry-run by default and only fires on `--confirm`, and timeline text is truncated at 8000 chars.

## Issues to address

- **`VERSION` skips a release number.** It jumps 1.3.5 to 1.5.0, but the house rule is increment-by-one with no gaps; a single coherent feature PR should set `VERSION` to 1.4.0. Fix: change `VERSION` to `1.4.0`.
- **The attachment flow targets an unverified HackerOne endpoint.** `create_report_intent` and `_multipart_upload` in `core/h1.py` POST to `/hackers/report_intents` on `api.hackerone.com/v1`, but `report_intents` is not among the documented hacker REST endpoints, and this codebase already notes in `add_comment` that the hacker API returns 401 (not 404) for routes that do not exist, so a bad path silently reads as an auth failure. Fix: confirm `report_intents`, its `/attachments` subresource and `/submit` exist in the REST API against a live token before merge; if they live only in the GraphQL/web API, the whole `--attach` path is non-functional and should be reworked or dropped.
- **`upload_attachments` crashes on a single-object response.** The line `for att in (resp.get("data") or [resp.get("data")] if resp.get("data") else [])` in `core/h1.py` parses so that when `data` is a dict it iterates the dict's keys (strings), and the unguarded `att.get("id")` then raises AttributeError. Fix: normalize explicitly, e.g. `data = resp.get("data") or []; data = [data] if isinstance(data, dict) else data`.
- **The capture backends do not reach anything in the shipped container.** `core/screenshot.py` defaults Caido/Burp to `127.0.0.1:8080`/`1337`, which is the container loopback and cannot see a proxy running on the operator's host, and `_find_os_tool` finds no binary and no display inside the stdlib-only image, so all three backends fail in the documented `docker compose` deployment. Fix: document that Caido/Burp need `host.docker.internal` (or an explicit `CAIDO_URL`/`BURP_URL`) and that OS capture is host-only, and consider defaulting the container to a reachable host address.

## Suggestions

- **Interactive OS mode blocks the API.** `POST /api/screenshot` inherits `mode="interactive"`, so `capture_os` waits up to the 60s subprocess timeout for a region selection; force `fullscreen` on the server path since a web caller cannot interact.
- **Web-initiated captures are audited as "cli".** `_record_upload` defaults `actor="cli"`, so a capture through `r_screenshot` records `uploaded_by="cli"` and then audits a second time with the real user; thread the actor through `capture(...)` and drop the duplicate audit.
- **`GET /api/evidence/<target>` reads and hashes every file.** `collect_evidence` opens each evidence file to compute sha256 on a listing request; split a stat-only listing from the hashing path so the GET stays cheap on large evidence dirs.
- **`proxy_feed_burp` re-fetches the whole history per match.** Each matched item calls `capture_burp`, which GETs `/v0.1/proxy/history` again; fetch the history once and pass the item through to avoid the N+1.
- **User-supplied `caido_url`/`burp_url` are a minor SSRF vector.** The server issues requests to whatever URL the write-scoped body provides and reflects up to 500 chars of the error body; low risk under the single-operator threat model, but worth a note or an allowlist.
- **No tests accompany the new module.** A smoke test that imports `screenshot` and asserts the six routes register would guard against future regressions.
- **Consider splitting the PR.** The capture/timeline/feed work is cohesive and solid; the API-dependent `--attach` flow is the riskiest piece and could ship as its own follow-up so it does not block the rest, in line with the one-PR-per-kind rule.

## House-rule and standards check

- **ASCII punctuation:** pass. New source is clean; the only non-ASCII in `h1.py` is a pre-existing em-dash detector, untouched by this PR.
- **Standard library only:** pass. No third-party import, pip, npm or CDN.
- **No private/operator data:** pass. `scripts/check-no-private-data.sh` exits 0; placeholders (`vulns_<slug>`, loopback IPs) are used throughout.
- **No committed secrets:** pass. Evidence lands only under the runtime workspace volume; nothing sensitive is added to git.
- **No AI attribution:** pass. Commits, PR body and files are clean.
- **PR conventions:** mixed. Targets `dev`, `feat/` branch, `feat:` title, SHA-pinned backticked links in the body, and `VERSION` is bumped (all pass), but the version number gaps to 1.5.0 (fail) and the PR bundles several features (borderline against one-PR-per-kind).

## Verdict

Request changes. Strong, well-engineered contribution that fits the architecture and honors the stdlib and privacy rules. Before merge: verify the `report_intents` endpoint (or rework `--attach`), fix the `upload_attachments` parser, set `VERSION` to 1.4.0, and resolve the container-reachability of the backends. The suggestions are polish and can follow.

## Maintainer action

To keep this moving into the next release, we are taking the small fixes on ourselves rather than sending them back: setting `VERSION` to `1.4.0` and fixing the `upload_attachments` parser so a single-object response no longer crashes. The two larger items - the unverified `report_intents` endpoint behind `--attach`, and the capture backends not reaching a host proxy inside the container - we are accepting as documented follow-ups for now (comments added in the code and noted in the release), so the solid capture/timeline/feed work is not held up. Merging into `dev` for the v1.4.0 batch release. Thanks again for a strong contribution, and please feel free to follow up on the `--attach` verification.
