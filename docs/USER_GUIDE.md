# Quarry VRC User Guide

The complete manual for Quarry VRC: a self-hosted, single-container vulnerability research console
for HackerOne bug bounty hunters. This document covers every feature, how to run it, and how to
drive it from the web console, the CLI and the HTTP API.

This is the reference manual. For a fast first run see [`SETUP.md`](SETUP.md); for the container
model see [`ARCHITECTURE.md`](ARCHITECTURE.md); for driving Quarry with an AI agent see
[`AGENTS.md`](AGENTS.md).

---

## Table of contents

- [1. Overview and philosophy](#1-overview-and-philosophy)
- [2. Install and run](#2-install-and-run)
  - [2.1 Requirements](#21-requirements)
  - [2.2 Quick start](#22-quick-start)
  - [2.3 The `.env` file](#23-the-env-file)
  - [2.4 First boot, step by step](#24-first-boot-step-by-step)
  - [2.5 First login](#25-first-login)
  - [2.6 Trusting the TLS certificate](#26-trusting-the-tls-certificate)
  - [2.7 Updating](#27-updating)
  - [2.8 Bring your own files (bind mounts)](#28-bring-your-own-files-bind-mounts)
  - [2.9 Running the CLI inside the container](#29-running-the-cli-inside-the-container)
- [3. Core concepts](#3-core-concepts)
  - [3.1 One container, three volumes](#31-one-container-three-volumes)
  - [3.2 Systems of record](#32-systems-of-record)
  - [3.3 Workspace layout](#33-workspace-layout)
  - [3.4 Leads, reports, notes and targets](#34-leads-reports-notes-and-targets)
  - [3.5 Read scope vs write scope](#35-read-scope-vs-write-scope)
  - [3.6 Local-first, standard-library-only design](#36-local-first-standard-library-only-design)
- [4. Security model](#4-security-model)
- [5. The web console](#5-the-web-console)
  - [5.1 Layout, navigation and theme](#51-layout-navigation-and-theme)
  - [5.2 Dashboard](#52-dashboard)
  - [5.3 Leads](#53-leads)
  - [5.4 Tracker](#54-tracker)
  - [5.5 Regression](#55-regression)
  - [5.6 Advisories](#56-advisories)
  - [5.7 Programs](#57-programs)
  - [5.8 Targets](#58-targets)
  - [5.9 Payloads](#59-payloads)
  - [5.10 Files](#510-files)
  - [5.11 Tokens](#511-tokens)
  - [5.12 Integrations](#512-integrations)
  - [5.13 Audit log](#513-audit-log)
  - [5.14 Status](#514-status)
  - [5.15 Settings](#515-settings)
  - [5.16 Certificates](#516-certificates)
  - [5.17 Global search](#517-global-search)
- [6. The lead workflow](#6-the-lead-workflow)
- [7. HackerOne integrations](#7-hackerone-integrations)
  - [7.1 The API token (sync and submit)](#71-the-api-token-sync-and-submit)
  - [7.2 The GraphQL session (invitations, collaborations, splits)](#72-the-graphql-session-invitations-collaborations-splits)
  - [7.3 The incremental poller and events](#73-the-incremental-poller-and-events)
- [8. Evidence and screenshot tooling](#8-evidence-and-screenshot-tooling)
  - [8.1 Backends](#81-backends)
  - [8.2 Capturing a screenshot](#82-capturing-a-screenshot)
  - [8.3 The proxy feed](#83-the-proxy-feed)
  - [8.4 The evidence timeline](#84-the-evidence-timeline)
  - [8.5 Attaching evidence to a submission](#85-attaching-evidence-to-a-submission)
  - [8.6 Reaching a proxy from inside the container](#86-reaching-a-proxy-from-inside-the-container)
- [9. Standards](#9-standards)
- [10. CLI reference](#10-cli-reference)
- [11. HTTP API reference](#11-http-api-reference)
- [12. Configuration reference](#12-configuration-reference)
- [13. Troubleshooting and FAQ](#13-troubleshooting-and-faq)

---

## 1. Overview and philosophy

Quarry VRC (Vulnerability Research Console) is a single-operator console that puts your entire
HackerOne hunt on one board: reports, programs, scopes, bounties, triage threads, hunt leads, a
payload library and CVE/CVSS advisory feeds, all searchable in one place.

Design principles:

- **Local-first.** It runs on your own machine or a private host you control, holds your unreported
  findings and a bounty credential, and is not hardened for the public internet.
- **Zero third-party runtime code.** Inside the image Quarry is the Python 3.12 standard library and
  one HTML page: `sqlite3` with FTS5, `ssl`, `http.server`, `hashlib`. No framework, no build step,
  no package manager, nothing to pin or be compromised through.
- **Your research is plain Markdown on disk.** Leads, notes and reports are files in a Docker volume,
  so you (or an AI agent) can read, query, write and refine them directly.
- **The database is a cache, never an authority.** Every entity has exactly one system of record,
  and it is never SQLite (see [3.2](#32-systems-of-record)). The index is rebuildable at any time.
- **HackerOne is the only supported platform today.** Quarry syncs and submits through the HackerOne
  API. Other platforms are not supported yet.

---

## 2. Install and run

### 2.1 Requirements

| Requirement | Needed for |
|---|---|
| **Docker** (with Compose) | Running Quarry. It is the only thing you install. |
| **A HackerOne API token** | Optional, but the point: it populates the Tracker and enables one-click submit. Pasted in the app, never in a config file. |
| **A HackerOne session cookie** | Optional, only for invitations and collaboration management (see [7.2](#72-the-graphql-session-invitations-collaborations-splits)). |
| **Caido or Burp** | Optional, only for proxy-driven evidence capture (see [8](#8-evidence-and-screenshot-tooling)). |

### 2.2 Quick start

```bash
# Clone the repository
git clone https://github.com/skraft9/quarry-vrc.git quarry && cd quarry

# Copy the example environment file, then set QUARRY_ADMIN_PASSWORD (QUARRY_ALLOWLIST is optional)
cp .env.example .env
$EDITOR .env

# Build the image and start the container
docker compose up -d

# Watch the first-boot banner and the URL it prints
docker compose logs -f quarry
```

- Quarry runs as a single container; the code is baked into the image.
- The database, leads and payloads live on Docker-managed volumes, so upgrades never touch your data.
- First boot generates a config, a self-signed TLS certificate and an empty database, then prints
  the URL to open.

### 2.3 The `.env` file

Copy `.env.example` to `.env` and edit it. `.env` is git-ignored. Only the password is required.

| Variable | Required | Meaning |
|---|---|---|
| `QUARRY_ADMIN_PASSWORD` | Yes | Creates the first admin login on first boot. The server refuses to start without it. Must be at least `QUARRY_MIN_PASSWORD_LENGTH` characters. |
| `QUARRY_ADMIN_USER` | No | The first admin's username. Default `admin`. |
| `QUARRY_MIN_PASSWORD_LENGTH` | No | Minimum password length the server enforces. Default `12`. |
| `QUARRY_APP_NAME` | No | Display name in the top-left brand and the page title. Default `Quarry VRC`. |
| `QUARRY_PORT` | No | Host port the HTTPS console is published on. Default `8443`. The container always serves `8443` internally. |
| `QUARRY_ALLOWLIST` | No | Client IP allow-list, checked before auth on every request. Comma-separated bare IPs and/or CIDRs (for example `192.168.1.0/24,10.0.0.5`). Empty means open, which is fine for a host only you can reach. |
| `QUARRY_TLS_MODE` | No | `self-signed` (default) generates a local CA plus cert on first boot; `mounted` uses a cert/key you mount into `/data/tls`. |
| `QUARRY_PAYLOADS_REPO` | No | Git URL of the payload reference to clone. Default is PayloadsAllTheThings. Point it at any repo of markdown with fenced code blocks. |

**Your HackerOne credentials are not set here.** You paste them once in the Integrations tab so they
are stored server-side (in `secrets.json`, mode 0600) and never rendered back into the page.

### 2.4 First boot, step by step

The container entrypoint is idempotent and safe to run on every start. On the first boot it:

1. Generates `config.json` on the `/data` volume from your environment. After that the file is yours
   to edit, and your edits survive restarts.
2. Bootstraps (or resets) the admin login from `QUARRY_ADMIN_PASSWORD`.
3. Generates a self-signed local CA plus TLS certificate, unless `QUARRY_TLS_MODE=mounted`.
4. Creates the database schema and indexes whatever markdown is already in the workspace volume.
5. Seeds the advisory feeds in the background so the Advisories tab is not empty on first load.
6. Seeds the payload library in the background by cloning the reference repo.
7. Prints the URL and starts serving.

Steps 5 and 6 are backgrounded on purpose: they make network calls and must not delay the server
binding its port. Both are idempotent and self-heal on the next start.

### 2.5 First login

- Open the printed `https://<host>:<port>/`.
- Your browser warns about the self-signed certificate. Proceed once, or trust the CA first (see
  [2.6](#26-trusting-the-tls-certificate)).
- Sign in with `QUARRY_ADMIN_USER` / `QUARRY_ADMIN_PASSWORD`.
- The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`. By default the session never
  expires (loopback app, single operator); change this in Settings (see [5.15](#515-settings)).

Login is rate-limited to 5 attempts per 15 minutes per source address. The limiter is in-memory and
resets on restart.

### 2.6 Trusting the TLS certificate

Open the **Certificates** page from the seal icon beside the version in the sidebar footer. It shows
the certificate details and serves the local CA so you can trust it once and stop the browser
warning for good (see [5.16](#516-certificates)).

### 2.7 Updating

```bash
docker compose pull       # fetch the new image
docker compose up -d      # recreate the container on it
```

- Your database, leads, config and credentials live on Docker volumes, so upgrading is a
  pull-and-recreate that never touches your data.
- To pin a release instead of tracking latest, set the image tag in `docker-compose.yml`, for
  example `image: ghcr.io/skraft9/quarry-vrc:v1.4.0`. Every version is tagged on the Releases page.

### 2.8 Bring your own files (bind mounts)

Prefer to keep leads or payloads on your host? Bind-mount them in `docker-compose.yml`:

```yaml
    volumes:
      - /path/to/my/workspace:/workspace
      - /path/to/my/payloads:/payloads
```

They are indexed on the next boot, or by a re-index from the app (Files tab, or `ingest.py --rebuild`).

### 2.9 Running the CLI inside the container

Every CLI operation runs inside the container. The pattern is:

```bash
docker compose exec quarry python3 core/<module>.py <flags>
```

For example `docker compose exec quarry python3 core/h1.py --sync`. See the full
[CLI reference](#10-cli-reference).

---

## 3. Core concepts

### 3.1 One container, three volumes

Quarry is one container. The application code is baked into the image; every piece of mutable state
lives on a named volume that survives image upgrades.

| Volume | Mount | Holds |
|---|---|---|
| `quarry-data` | `/data` | `config.json`, `index.db` (with FTS), TLS certificates, `secrets.json`. |
| `quarry-workspace` | `/workspace` | Your leads and reports markdown: the source of truth for research. |
| `quarry-payloads` | `/payloads` | The payload library (a cloned public reference plus your own). |

The container's writable layer is wiped on every image upgrade, so anything not on a volume would be
lost the first time you `docker compose pull`. That is why all state is on volumes.

### 3.2 Systems of record

Every entity has one authority, and it is never the database. The SQLite index is a cache and a
query layer that can be rebuilt at any time.

| Entity | Authority | Rebuilt from |
|---|---|---|
| Reports, bounties, payout splits | HackerOne API | `h1.py --sync` |
| Program guidelines, structured scopes | HackerOne API | `h1.py --sync-programs` |
| Leads, RCAs, follow-ups | Markdown in your workspace volume | `ingest.py --rebuild` |
| Payloads | A git clone on disk, never vendored | `scripts/sync-payloads.sh` |
| Advisories | The configured RSS/Atom feeds | `advisories.py --sync` |
| Retest verdicts | Your own judgement, in the `regressions` table | Not rebuildable |

Consequences that matter:

- Because HackerOne owns your reports, a rebuild never invents or overwrites them.
- Anticipated money is held separately and never summed into a confirmed total, so a hand-typed
  figure can never turn an expectation into a confirmed award.
- The one row with no upstream is the exception that proves the rule: a retest verdict is an
  opinion ABOUT an entity rather than an entity, and nothing outside your head holds it. The queue
  it annotates is still derived from HackerOne on every read, so dropping the `regressions` table
  loses what you concluded and nothing you own.

### 3.3 Workspace layout

Leads and reports are files under the workspace root (`/workspace`), organized by target and
vulnerability class:

```
/workspace/<target>/<CLASS>/notes/<slug>.md      a LEAD (your working note)
/workspace/<target>/<CLASS>/reports/<slug>.md    a REPORT (what you send to HackerOne)
/workspace/<target>/notes/<slug>.md              a lead with no class
/workspace/<target>/evidence/<file>              screenshots and captures (not indexed as leads)
```

- A **target workspace** directory is named with the `vulns_` prefix by convention (for example
  `vulns_example`); the slug is what appears in the Targets tab and in evidence paths.
- `<CLASS>` is a short code from the directory name: `BAC`, `DoS`, `RCE`, `SECRETS`, `PRIVESC`,
  `AUTHN`, `INJECTION`, `SSRF`, `INTEGRITY`, `API`, and more.
- Files under `evidence/` or `bin/` are ignored by the lead scanner, so PoC scripts and captures do
  not pollute the lead list.

### 3.4 Leads, reports, notes and targets

- **Lead:** a markdown file that carries a `**Status:**` marker within its first 25 lines. Without
  that marker the file is a **note**: still searchable and browsable, but not a queue item.
- **Report:** prose aimed at a triager, filed under a target's `reports/` directory. Reports shown in
  the Tracker are HackerOne-sourced, not file-derived.
- **Target:** an in-scope asset mapped from HackerOne to the local workspace your leads are filed
  against. One workspace can back several HackerOne assets; a lead's `Target` header row records
  which specific asset a finding is against.

The lead status vocabulary, lowest to terminal:

`open` -> `confirmed` -> `ready` -> `submitted` -> `awarded`, plus `parked` (shelved) and `killed`
(dead, do not re-hunt).

See [6. The lead workflow](#6-the-lead-workflow) for how to write and move a lead, and
[9. Standards](#9-standards) for the exact lead and report shapes.

### 3.5 Read scope vs write scope

Access to Quarry has two levels:

- **Read:** view every list and detail (leads, reports, programs, advisories, payloads, files).
- **Write:** create and edit leads/reports/advisories, change status, write files, submit to
  HackerOne, and change settings.

A browser session (from the login form) always has write scope. API tokens are issued as either
`read` or `write` (see [5.11](#511-tokens)). A read token can query everything but cannot mutate
anything.

### 3.6 Local-first, standard-library-only design

- No pip, no npm, no CDN, no build step. `git` and `curl` ship in the image only so the payload
  library can clone its reference and the container can health-check itself; neither is a language
  dependency.
- A strict Content-Security-Policy (`default-src 'none'`) blocks inline handlers, remote scripts and
  remote fonts. The markdown renderer escapes at the boundary.
- The whole corpus is queryable with SQLite FTS5 full-text search across leads, reports and payloads.

---

## 4. Security model

Quarry holds your unpublished findings and a bounty API credential. It is built to run on your own
machine or a private host you control, and is not hardened for the public internet.

| Control | Detail |
|---|---|
| **Zero-dependency runtime** | Python standard library only. No third-party runtime code to audit or be compromised through. |
| **IP allow-list, first** | `QUARRY_ALLOWLIST` / `allow_remote` is checked before authentication and routing on every request, including `/api/health`. An unlisted address gets 403 and nothing else. Empty means open. |
| **TLS always** | Self-signed local CA on first boot, or bring your own by mounting into `/data/tls` with `QUARRY_TLS_MODE=mounted`. TLS 1.2 minimum. |
| **PBKDF2-HMAC-SHA256** | 600,000 iterations, 16-byte per-user salt, constant-time verify. Login failures are rate-limited per source (5 per 15 minutes). |
| **Hashed credentials** | Sessions and API tokens are stored as SHA-256, so a database read yields nothing usable. |
| **Write-only secrets** | Your HackerOne API token and session cookie are stored server-side in `secrets.json` (mode 0600) and never returned by any endpoint, only a masked hint. |
| **CSRF protection** | Cookie-authenticated mutations must carry the `X-App-CSRF: 1` header. Bearer-token requests are CSRF-exempt (no ambient browser credential). |
| **File-browser deny-list** | Every browse/read/download is filtered by `browse_deny_globs`, which blocks key material, dotfiles and databases by default. |
| **Strict CSP** | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`. |

Security headers on every response include `X-Content-Type-Options: nosniff`, `X-Frame-Options:
DENY` and `Referrer-Policy: no-referrer`.

---

## 5. The web console

### 5.1 Layout, navigation and theme

- **Topbar:** brand (links to the Dashboard), a global search box (press `/` to focus), the signed-in
  user chip, a Theme button (cycles auto / light / dark), and Log out.
- **Sidebar:** the primary navigation. The daily research tools are grouped at the top; everything
  you configure sits below an `Admin` divider. The sidebar collapses, and the state is remembered.
- **Sidebar footer:** the running version, and a seal icon that opens the Certificates page.

The navigation entries, in order:

| Group | Tabs |
|---|---|
| Research | Dashboard, Leads, Tracker, Regression, Advisories, Programs, Targets, Payloads |
| Admin | Files, Tokens, Integrations, Audit log, Status, Settings |
| Footer | Certificates (seal icon) |

Global search (`#/search`) has no sidebar entry but is always reachable from the topbar box and from
any `[[wikilink]]` in your markdown.

New-since-you-last-looked badges appear on the Dashboard, Leads, Tracker and Advisories, driven by a
per-browser watermark so a fresh browser never opens on a wall of false badges.

### 5.2 Dashboard

The at-a-glance view of what you earned, what moved, and what is still open.

- **Money tiles:** confirmed total bounty, your share (which differs from the total on a split
  payout), number of awards, number of splits, and how many reports you hold as a collaborator.
  Anticipated money is shown separately and never added to the confirmed total.
- **Counts:** leads, reports, programs, targets, scopes, uploads, payloads, advisories, and
  **retests due** - shipped fixes waiting on a second look, which opens
  [5.5 Regression](#55-regression) already filtered to that bucket. It counts what is DUE rather
  than every resolved report, because the tile is a to-do and a count of every fix you ever earned
  would sit there unchanged forever.
- **Breakdowns:** leads by status and by target; paid reports by class and by target/program;
  reports by state. Each is a link into the filtered list.
- **Hacktivity tile:** the selected program's public activity feed, served from local storage (never
  a live call on page load). A picker chooses which program to watch, and a Refresh button polls
  HackerOne once. The tile shows the age of the stored rows so a stale feed reads honestly rather
  than going blank.
- **New / Updated badges:** counts of newly arrived and recently changed reports, plus money that
  landed since you last looked.

Note: the "reports moved" and "money landed" deltas are driven by the incremental poller's event
history. In a build without the optional poller module those figures read as zero rather than
erroring (see [7.3](#73-the-incremental-poller-and-events)).

### 5.3 Leads

Your hunt queue, indexed from the workspace markdown.

- **Columns:** title, ref, class, status, severity, program, target, modified.
- **Filters:** by target, class and status, plus free-text search across title/ref/body.
- **A lead is a lead** only if it carries a `**Status:**` marker; unmarked notes index as `unknown`
  and are excluded from this list (they remain in Notes, Files and Search).
- **New button:** creates a lead file in the workspace. You must pick a target first, because the
  file has to land in that target's workspace.
- **Detail pane:** the rendered markdown, the header fields, the researcher a lead credits, and the
  lead-working actions (see [6. The lead workflow](#6-the-lead-workflow)).

### 5.4 Tracker

Every HackerOne report the account can see, synced from the API.

- **Columns:** H1 id, program, target, title, state, severity, CWE, privileges-required (PRIV),
  impact, bounty, role, last update, submitted date.
- **PRIV badge:** a compact one-letter badge, `N` / `L` / `H` for None / Low / High privileges
  required, with High shown in red. The full word is in the hover title.
- **Impact cell:** one colored letter per impacted CIA dimension (C red, I amber, A blue), decoded
  from the CVSS vector server-side.
- **Role pill:** whether you are the reporter or a collaborator on the report.
- **Program scope:** the Tracker defaults to showing every program. A picker in the filter bar
  narrows it to one handle; the response says which scope was applied so a filtered view never hides
  rows silently.
- **Sorting:** default is newest submitted first, with the report number as a deterministic
  tiebreak. Money and id columns sort numerically even though they are stored as text.
- **Detail pane:** the report body, the triage thread (the analyst's actual comment on a closed
  report, where the reopen condition usually lives), bounty and split data, and collaborators.

The Tracker is HackerOne-sourced only. Local drafts, RCAs and follow-up comments are deliberately
excluded so the list mirrors HackerOne exactly.

### 5.5 Regression

The Tracker's back half: the fixes shipped for your resolved reports, and what a retest found.

A resolved report is the one piece of attack surface you have an unfair advantage on. The patch is
new code, written under deadline pressure, by someone who saw a single proof of concept and very
often defended against that request rather than against the bug - and you already know the class,
the endpoint, the parameter and the bypass that worked once. This tab is the reminder to go back,
with the evidence attached.

- **The queue is derived, never maintained.** Every HackerOne-sourced report in state `resolved`
  with a close date is a candidate, computed on each read. Nothing to sync, nothing to clean up: a
  report the program reopens leaves the queue on the next `h1.py --sync`.
- **Columns:** report id, program, title, asset, the date the fix closed, when a retest is due, the
  verdict, and what the original earned. The bounty is not decoration - it is the best available
  proxy for how much the program cared, and so for how carefully the fix was written.
- **The window.** A fix reads as due `regression_window_days` after the report closed, 30 by
  default, changeable in [5.15 Settings](#515-settings). It is a prompt, not a deadline: it only
  decides what order the list is read in.
- **Verdicts:** `holds` (retested, the fix stands), `broken` (incomplete or bypassable), `skipped`
  (target retired, access gone). A report nobody has looked at is `pending` and carries no stored
  row at all. Clearing a verdict puts it back in the queue and keeps the note.
- **Snooze** pushes the due date out by 7 or 30 days without recording a verdict, for the fix that
  is known to still be rolling out. It sits below the verdicts and is deliberately quieter.
- **Detail pane:** the original report body and the full triage thread. The thread is the point -
  it is where the program said what it changed, which is the paragraph a retest is planned from.
- **Draft the bypass lead.** On a `broken` verdict only, this writes a pre-filled lead into a
  workspace you pick - the original report id, its close date, asset and CWE, and your retest note,
  in the [`LEAD_STANDARD`](../standards/LEAD_STANDARD.md) header-table shape - then indexes it, so
  it appears in Leads immediately. It is refused on any other verdict, because a lead is a claim
  that something is wrong.

**The `moved` badge is the one to open first.** `resolved_on` records the *first* time a report
closed and is never rewritten, so a report that was reopened and re-resolved carries the close date
of the fix *before* the one you would be re-testing - and that is exactly the population an
incomplete fix produces. So the window is not the only thing that surfaces a report: any row whose
HackerOne activity is newer than the date its verdict was recorded comes back to the top of the
queue marked `moved`, whatever that verdict was. The verdict stays on the row as a record, and the
note and retest count are kept, but it no longer describes the report.

Nothing on this tab contacts HackerOne. It is a query over rows the sync already wrote, so it works
offline, costs no API budget and cannot be rate-limited - and it is only as current as your last
`h1.py --sync`.

### 5.6 Advisories

A cross-referenced feed of published vulnerabilities.

- **Source:** any RSS/Atom feed you configure (CISA and VulDB by default; add your own under
  `advisory_feeds` in `config.json`).
- **Columns:** ref, title, vendor, product, type, CVE, CWE, CVSS, PRIV, level, status, credit,
  published date, target, source.
- **CVSS decoding:** vectors are decoded to words (privileges required, impact) server-side.
- **Sync:** the tab has a Refresh that runs the same poll cron would. Feed health (count, newest
  published, last fetched, how many carry a CVE) is available in Status.
- **Advisory-to-report matching:** an optional scorer can hypothesize which of your reports an
  advisory came from and let you confirm or reject each pairing. This feature depends on an optional
  module; in a build without it the match endpoints return `503 module unavailable` and the matching
  UI is inert. Feed ingestion itself is always available.

### 5.7 Programs

Your programs with their scope and rules of engagement.

- **Per program:** name, platform, guidelines/policy, structured scopes, submission state, whether it
  offers bounties, and the money it has earned you.
- **Computed triplet:** award count, average payout and total earned, which multiply out
  consistently (count times mean equals earned).
- **Editable fields:** name, platform, url, the hand-entered scope markdown and rules-of-engagement
  markdown. Structured scopes themselves are read-only because HackerOne owns them.
- **Sync:** `h1.py --sync-programs` fills each program's guidelines and scopes (two API requests per
  program, so it is a manual pass, not a cron one). New programs are onboarded from Integrations.

### 5.8 Targets

Maps in-scope assets to the local workspaces your leads are filed against.

- **Per target:** name, version, source path, and an optional CodeQL database path.
- A target is what a lead is filed under; the Programs/Targets/Leads joins let the console show which
  program a lead ultimately belongs to.
- Editable fields: name, version, source_path, codeql_db.

### 5.9 Payloads

A searchable payload library.

- **Source:** a shallow git clone of a public reference (PayloadsAllTheThings by default) kept on the
  payloads volume. Nothing is vendored into the image or committed to git.
- **Unit of a row:** one fenced code block, so each payload arrives with its surrounding context
  intact rather than as an anonymous line.
- **Search:** full-text, with an optional category filter. The response carries category and total
  stats so an empty result can tell "no match" apart from "the library was never synced".
- **Populate or refresh:** run `scripts/sync-payloads.sh` inside the container, or
  `payloads.py --rebuild` if the clone is already present. Wordlists (fuzzer input) are deliberately
  excluded from the index but remain reachable in the Files tab.
- The library is kept outside the workspace so the lead scanner never mistakes a cheatsheet for a
  lead.

### 5.10 Files

A file browser over the configured roots (`/workspace` and `/payloads` by default).

- **Tree view** with sizes and modified times; a parent link that stops at the configured roots.
- **Read pane** that inline-renders text files up to `browse_max_bytes` (2 MB by default) and marks
  binaries.
- **Edit and save back** for text files; a save re-indexes the file immediately.
- **Download** for any allowed file.
- **Deny-list:** paths matching `browse_deny_globs` (key material, dotfiles, databases) are shown as
  denied rather than hidden, so you can see the guard is working. The deny-list is on by default
  because this UI is network-reachable.

### 5.11 Tokens

Server-side Bearer tokens for non-browser clients (scripts, agents, CI).

- **Create:** name the token and choose `read` or `write` scope. The raw token is shown exactly once;
  store it then.
- **Use:** send `Authorization: Bearer tok_...`. Bearer requests are CSRF-exempt and are the right
  channel for automation.
- **Revoke:** one click; the token stops working immediately.
- Only `sha256(token)` is stored, so a database read never yields a usable token. The list shows the
  name, prefix, scope, creation and last-used times.

### 5.12 Integrations

Where you connect HackerOne. It has three cards.

1. **HackerOne API credential** (used for sync and submit). Paste your API username and token; they
   are verified against the live API before they are stored, kept server-side, and never rendered
   back. You may also set the primary program handle (what the Tracker defaults to and what
   submissions resolve weaknesses/scopes against). Actions: test the stored credential, run a sync,
   and add a program from the accessible-programs picker.
2. **Invitations and collaborations** (used for private-program invites and report collaboration).
   This card asks for a HackerOne browser session cookie, because the REST API has no invitation
   endpoints (see [7.2](#72-the-graphql-session-invitations-collaborations-splits)). It lists pending
   program invitations and collaboration invitations with accept/reject controls, and provides forms
   to invite a collaborator to a report and set a bounty split.
3. Both cards show only a masked hint of the stored secret, never the value.

If the optional GraphQL module is missing from a build, the invitations card shows "module
unavailable" instead of erroring.

### 5.13 Audit log

An append-only record of what happened: logins, credential changes, syncs, status changes, file
writes, submissions, token creation, and more.

- Each row carries a timestamp, actor, action, entity, detail, remote address and a source channel
  (`web`, `cron`, `cli`, or `h1-api`).
- Read-only in the UI; the newest entries first.

### 5.14 Status

A one-request health dashboard: the running version, the HackerOne integration state, the advisory
feed freshness (count, newest published, last fetched, match count), the index counts (reports,
reports with body, reports with thread, leads), and the money summary.

The poller and hacktivity health blocks are populated by their respective modules; in a build
without the optional poller module the poller block is null rather than an error.

The regression block reports **coverage** rather than job health, because there is no job: no
credential, no request and so no run history to report. It carries the number of resolved reports,
how many have ever been given a verdict, how many never have, how many are due now, and how many
fixes turned out not to hold.

### 5.15 Settings

The small set of operator settings that are safe to change from a form.

- **Session expiry:** off by default (the login cookie stays valid until you log out), because the
  app binds to loopback and holds unreported findings. Set a positive number of hours to enable a
  timeout. A change applies to sessions created from the next login onward, not retroactively.
- **Regression window:** how many days after a report closes its fix reads as due a retest on
  [5.5 Regression](#55-regression). Default 30, clamped to 1-3650. Raising it shortens the queue;
  it never discards a verdict.
- **Job cadence:** poll intervals for the background jobs. This editor depends on the optional
  schedule module; in a build without it the interval endpoints return `503` and the editor is
  absent, while every job keeps running on whatever the crontab already says.

### 5.16 Certificates

Reached from the seal icon by the version in the sidebar footer. It shows:

- The server certificate details: subject, issuer, SAN, validity window, SHA-256 fingerprint, serial.
- Whether the certificate is self-signed and whether a local CA is available.
- A download link for the CA certificate so you can import it into your trust store once. Importing
  the CA (rather than the leaf) means every future certificate re-issue is trusted automatically.

Only public certificate material is ever served. Private keys are never read, parsed or handed out.

### 5.17 Global search

Full-text search over leads, reports and payloads.

- Press `/` anywhere to focus the search box, or open `#/search`.
- Backed by SQLite FTS5 with BM25 ranking and highlighted snippets. An optional `kind` filter
  narrows to one entity type.
- Query characters that are FTS5 operators (`|`, `"`, `(`, `*`, `:`, `-`) are handled gracefully: a
  query that would be a syntax error is retried as a quoted term list, so real hunt terms like
  `ES|QL`, `CWE-639` or `auth:none` never fail.
- Every `[[wikilink]]` in your workspace markdown resolves to a search for that term.

---

## 6. The lead workflow

A lead is the working document a report is drafted from. Write the lead file at discovery, not when
it is proved: the moment you have a hypothesis worth chasing, create the file with `**Status:** open`
and a one-line decision summary. See [`standards/LEAD_STANDARD.md`](../standards/LEAD_STANDARD.md)
for the exact shape.

What makes a file a lead:

- A `**Status:**` marker within the first 25 lines. Without it, the file is a searchable note, not a
  queue item.
- One finding per file, named for the finding.
- A real markdown header table so `Class`, `CWE`, `Privilege`, `Impact` and `Researcher` are read
  into their columns.

Actions available on a lead (from the detail pane, or the API):

- **Change status** without opening the editor. Valid values: `open`, `confirmed`, `ready`,
  `submitted`, `awarded`, `parked`, `killed`. The marker is written into the file and the file is
  re-indexed.
- **Append a worklog entry:** add a timestamped section to the note. Safe to fire mid-test without
  loading the whole document, and it cannot clobber anything already written.
- **Copy report:** fetch the draft report belonging to the lead (resolved from an explicit `Report`
  header row, or by convention from the target's `reports/` directory).
- **Sync title:** rewrite the lead's title to match its drafted report's title, keeping the `<REF> -`
  prefix that joins the lead, its report file and the H1 id. Available once the lead is `confirmed`
  or later. When you change a lead's status to a drafted state, the title is also synced
  automatically if a draft exists.
- **The queue** (`/api/queue`) surfaces open and confirmed leads oldest-touched first, so the lead
  you have not touched in longest is the one least likely to be forgotten.

A good loop:

1. Read the program's scope and rules of engagement (Programs).
2. Hunt; write each finding as a lead with `**Status:** open`.
3. Confirm it, move it to `confirmed`, then `ready` once the report is drafted.
4. Submit it (see [7.1](#71-the-api-token-sync-and-submit)), and let the Tracker follow its fate.
5. On closure, read the triage comment and record what you learned, including the reopen condition on
   a kill.

---

## 7. HackerOne integrations

Quarry talks to HackerOne two ways: the REST API (with an API token) for sync and submit, and the
GraphQL API (with a browser session cookie) for invitations and collaborations. Both secrets live in
`secrets.json` (mode 0600), are verified before they are stored, and are never returned by any
endpoint.

### 7.1 The API token (sync and submit)

Connect the credential in **Integrations**: paste your HackerOne API username and token. They are
verified against the live API before storage. You may also set the primary program handle.

What the credential does:

- **Sync** pulls your programs, scopes, reports, states, bounties, payout splits and triage threads.
  Every report the account can see is stored, whichever program it belongs to; the Tracker narrows to
  one program only as a view choice.
- **Submit** files a finished report to a program straight from the app, with no copy-paste into the
  web form.
- **Read the triage** fetches the analyst's actual comment on a closed report.

Submitting from the CLI (the same operation the app's submit action performs):

```bash
docker compose exec quarry python3 core/h1.py --submit reports/<slug>.md --program <handle> \
  --weakness cwe-79 --scope "<in-scope asset>" --severity high
```

- `--submit` prints the payload and **stops** (a dry run). Add `--confirm` to actually send it,
  because a created report cannot be withdrawn.
- `--program` is required; there is no default target for a submission.
- `--severity` is required by most programs (a missing rating is a 422). Choices are the HackerOne
  severity ratings.
- Before sending, Quarry runs the report standard's pre-flight checks (no em/en dashes, no `###`
  headings, no colon in the title, no hard-wrapped prose, and a cross-check of the title and scope
  against the program) and refuses to submit if any fail.
- `--attach` auto-collects evidence files from the target's workspace and uploads them with the
  report (see [8.5](#85-attaching-evidence-to-a-submission)).
- `--no-sync` files the report and skips the slow follow-up tracker sync.

Other useful token operations: `--sync-programs` (fill guidelines and scopes),
`--list-weaknesses`, `--list-scopes`, `--refresh` (re-fetch report bodies and threads), and
`--comment` (post a comment on an existing report). See the [CLI reference](#10-cli-reference).

### 7.2 The GraphQL session (invitations, collaborations, splits)

The HackerOne REST API has no endpoints for invitations or collaborator management. Those operations
live on the GraphQL API at `hackerone.com/graphql`, which needs a browser session cookie rather than
the API token.

To connect it:

1. Log in to HackerOne in your browser.
2. Open DevTools, go to Application > Cookies > `hackerone.com`, and copy the value of the
   `__Host-session` cookie.
3. Paste it into the **Invitations and Collaborations** card in Integrations and click "Save and
   verify". The cookie is verified (it must return your username) before it is stored, write-only.

The cookie typically lasts several weeks before expiry; when it stops working, grab a fresh one and
paste it again. Once stored, the card lists and lets you act on:

- **Program invitations:** list pending private-program invitations; accept or reject each.
- **Collaboration invitations:** list pending report collaboration invitations; accept each.
- **Invite a collaborator:** add a collaborator to a report you own, by report id and username.
- **Bounty split:** set a collaborator's split percentage (0 to 100) on a report.

The same operations are available on the CLI via `core/h1_graphql.py` (see the
[CLI reference](#10-cli-reference)).

**Documented limitation (v1.4.0):** the invitation, collaboration and bounty-split GraphQL
operations are implemented against HackerOne's GraphQL schema but the exact mutation shapes are not
yet confirmed end to end against a live session in every case. Treat write operations
(accept/reject/invite/split) as needing verification against your own account, and check the result
before relying on them.

### 7.3 The incremental poller and events

Quarry runs an incremental poller that watches HackerOne for changes (state transitions, bounty
awards, severity changes, collaborators) and records them as events. Those events drive the
Tracker's moved badges, the Dashboard's New/Updated badges, and the money-landed deltas, so the
Tracker stays current between full `--sync` runs at a cost of only a few requests per poll. A full
sync is ~150 requests and is the wrong thing to run every few minutes; the poll uses the four change
signals the list endpoint returns for free and detail-fetches only the reports whose signals moved.

- Endpoints: `GET /api/h1/job` (poller health), `GET /api/h1/events` (recent changes),
  `POST /api/h1/events/seen`, `POST /api/h1/poll` (run one poll now, with `force` to skip backoff).
- Run one poll by hand from the **Status** tab's **Poll now** button, or from the CLI:

  ```bash
  docker compose exec quarry python3 core/h1_watch.py --poll
  ```

**It runs automatically.** The container polls on a built-in timer, every **15 minutes** by default,
so the Tracker's live monitoring works out of the box with nothing to set up. Tune or disable it
with an environment variable in your `.env` or compose file:

```env
QUARRY_POLL_MINUTES=15   # interval in minutes; 0 turns the built-in timer off
```

The **Status** tab's Incremental Poll card then reads healthy and shows the last run, the cumulative
request count, and how many changes are unread. Poll activity is recorded in the app and the Audit
log, not in a file, so the `h1-cron.log` it writes stays empty on success (the poll runs `--quiet`).

If you would rather run your own scheduler, set `QUARRY_POLL_MINUTES=0` and add a host cron:

```cron
*/15 * * * * cd /path/to/quarry-vrc && docker compose exec -T quarry python3 core/h1_watch.py --poll --quiet >> h1-cron.log 2>&1
```

---

## 8. Evidence and screenshot tooling

Quarry can capture evidence for a submission from a proxy or the OS, keep it in the target's
`evidence/` directory, build a timeline from it, and attach it to a report. This is driven by
`core/screenshot.py` and the `/api/screenshot` and `/api/evidence/*` endpoints. In this build the
evidence tooling is used through the CLI and the API; there is no dedicated evidence tab in the
sidebar.

### 8.1 Backends

Three capture backends, tried in order of preference:

1. **Caido** - pull request/response renders via its API (default `http://127.0.0.1:8080`).
2. **Burp** - export selected items via its REST API (default `http://127.0.0.1:1337`).
3. **OS** - platform screen capture (`screencapture` on macOS; `scrot`, `gnome-screenshot`, `import`
   or `xfce4-screenshooter` on Linux).

Check what is reachable:

```bash
docker compose exec quarry python3 core/screenshot.py --detect
```

or `GET /api/screenshot/backends`.

### 8.2 Capturing a screenshot

```bash
# OS screenshot, filed to the target's evidence directory
docker compose exec quarry python3 core/screenshot.py --capture --target <slug> --name login-idor

# Pull Caido request #42
docker compose exec quarry python3 core/screenshot.py --caido --request-id 42 --target <slug>

# Pull Burp proxy-history item 7
docker compose exec quarry python3 core/screenshot.py --burp --item-index 7 --target <slug>
```

- `--target <slug>` files the capture to `/workspace/vulns_<slug>/evidence/`.
- `--mode` selects the OS capture mode: `interactive`, `fullscreen` or `window`.
- `--record` (or any evidence subcommand) records the file in the uploads table so the Files tab can
  reference it.
- The API equivalent is `POST /api/screenshot` with a `backend` of `auto`, `caido`, `burp` or `os`.

### 8.3 The proxy feed

Pull recent proxy traffic filtered to a target's in-scope hosts and file each matching request as
evidence:

```bash
docker compose exec quarry python3 core/screenshot.py --feed --target <slug> --limit 20
```

- Hosts default to the target's structured scopes; override with `--hosts host1,host2`.
- Backend is auto (Caido then Burp) unless you pass `--caido` or `--burp`.
- The API equivalent is `POST /api/evidence/<target>/feed`.

### 8.4 The evidence timeline

Collect all evidence for a target into a chronological markdown narrative ready to paste into Steps
To Reproduce:

```bash
docker compose exec quarry python3 core/screenshot.py --timeline --target <slug> --ref F01
```

- Text captures (Caido/Burp) are inlined; binary captures (screenshots) are referenced by name.
- `--ref` sets the timeline heading to a lead reference.
- The API returns the timeline from `GET /api/evidence/<target>/timeline` and exports it to a file
  with `POST /api/evidence/<target>/timeline`.

### 8.5 Attaching evidence to a submission

Gather every evidence file for a target, ready for upload with a report:

```bash
docker compose exec quarry python3 core/screenshot.py --collect --target <slug>
```

To upload them with a submission, add `--attach` to `h1.py --submit` (see
[7.1](#71-the-api-token-sync-and-submit)). Quarry creates a report intent (draft), uploads each file
as an attachment, then submits the intent as a real report.

**Documented limitation (v1.4.0):** the report-intent flow (`/hackers/report_intents` and its
`/attachments` and `/submit` subresources) is not yet confirmed against a live HackerOne hacker REST
token. The hacker API returns 401 (not 404) for a route that does not exist, so a wrong path reads as
an auth failure. Verify `--attach` end to end against your own token before relying on it; a plain
`--submit` without `--attach` uses the standard, confirmed report-create path.

### 8.6 Reaching a proxy from inside the container

The Caido and Burp defaults are loopback addresses. Inside the shipped Docker deployment,
`127.0.0.1` is the container, not your machine, so a proxy running on your host is not reachable at
the default URL. To use Caido or Burp from the container:

- Set `CAIDO_URL` / `BURP_URL` (or pass `--caido-url` / `--burp-url`) to
  `http://host.docker.internal:<port>`, or to your host's LAN IP.
- OS screen capture is host-only: the stdlib-only image has no display or capture binary, so the OS
  backend is meant for running `screenshot.py` on the host, not in the container.

---

## 9. Standards

Two vendor-neutral standards ship under [`standards/`](../standards/). They are the authority for how
you write, and they are readable by an AI agent drafting alongside you.

- [`standards/LEAD_STANDARD.md`](../standards/LEAD_STANDARD.md) - how a lead is written: write it at
  discovery, the header block is a two-column table, move the status as you learn, and a kill records
  the condition that would bring the finding back.
- [`standards/REPORT_STANDARD.md`](../standards/REPORT_STANDARD.md) - how a report to a program is
  written: flat `##` headings only, Impact before Remediation, ASCII punctuation, one long line per
  prose paragraph, no severity rating or CVSS string in the body. Read it before drafting.

Both use placeholders (`ExampleVendor`, `<target>`, `<REF>`, `#0000000`, `<lab-host>`) so you never
paste a real host, credential or lab address into a lead or a report.

---

## 10. CLI reference

Run inside the container: `docker compose exec quarry python3 core/<module>.py <flags>`. Every module
is Python standard library only.

### `core/server.py` (server and admin)

| Flag | Purpose |
|---|---|
| `--adduser USERNAME` | Create or reset a login; prompts for a password. |
| `--password-stdin` | With `--adduser`, read the password from stdin (scripted setup). |
| `--gencert` | Issue the server certificate from a local CA (creates the CA on first run). |
| `--self-signed` | With `--gencert`, issue a bare self-signed leaf instead of a CA-signed cert. |
| `--host` / `--port` | Override the bind host/port. |
| `--no-tls` | HTTP only, for loopback testing. |

### `core/ingest.py` (workspace index)

| Flag | Purpose |
|---|---|
| `--rebuild` | Re-scan the workspace and rebuild the lead/report index. |
| `--hard` | A full rebuild rather than an incremental one. |
| `--reindex PATH` | Re-index a single file. |
| `--stats` | Print index counts. |
| `--quiet` | Suppress progress. |
| `--db PATH` | Use a specific database path. |

### `core/h1.py` (HackerOne REST: sync and submit)

| Flag | Purpose |
|---|---|
| `--test` | Verify the stored credential authenticates. |
| `--sync` | Pull reports from every program on the account. |
| `--program HANDLE` | Narrow `--sync`/`--refresh`/`--submit` to one program (or `all`). |
| `--refresh` | Re-fetch the detail payload (full body plus thread) for every report. |
| `--only-missing` | With `--refresh`, only rows that have no body yet. |
| `--sync-programs` | Fetch each program's guidelines and structured scopes. |
| `--list-weaknesses` / `--list-scopes` | List a program's weaknesses / structured scopes. |
| `--submit FILE` | Submit a report markdown file. Prints the payload and stops unless `--confirm`. |
| `--weakness ID` | With `--submit`, weakness id or CWE (for example `287` or `cwe-287`). |
| `--scope ID` | With `--submit`, structured scope id or exact asset identifier. |
| `--severity RATING` | With `--submit`, your triage assessment (required by the program). |
| `--attach` | With `--submit`, auto-attach evidence files from the workspace (see [8.5](#85-attaching-evidence-to-a-submission)). |
| `--confirm` | With `--submit`, actually send it. Irreversible. |
| `--no-sync` | With `--submit`, file and skip the slow follow-up sync. |
| `--comment REPORT_ID` | Post a comment on an existing report (needs `--body-file`). |
| `--body-file FILE` | With `--comment`, the markdown body. |
| `--internal` | With `--comment`, post as an internal note instead of to the program. |
| `--stats` | Print integration status. |
| `--quiet` | Suppress progress. |

### `core/h1_graphql.py` (HackerOne GraphQL: invitations and collaborations)

| Flag | Purpose |
|---|---|
| `--set-session TOKEN` | Store a `__Host-session` cookie value. |
| `--test` | Verify the session token authenticates. |
| `--invitations` | List pending program invitations. |
| `--collabs` | List pending collaboration invitations. |
| `--accept-invite TOKEN` / `--reject-invite TOKEN` | Accept / reject a program invitation. |
| `--accept-collab TOKEN` | Accept a collaboration invitation. |
| `--add-collab REPORT_ID USERNAME` | Invite a collaborator to a report. |
| `--set-split REPORT_ID USERNAME PERCENT` | Set a collaborator's bounty split. |

### `core/screenshot.py` (evidence capture)

| Flag | Purpose |
|---|---|
| `--detect` | Show available backends and exit. |
| `--capture` | Take an OS screenshot. |
| `--caido` / `--burp` | Pull from the Caido / Burp proxy. |
| `--timeline` | Build an evidence timeline for a target. |
| `--feed` | Pull matching proxy traffic for a target. |
| `--collect` | List all evidence files for a target. |
| `--target SLUG` | Workspace target slug (files to `vulns_<slug>/evidence/`). |
| `--name LABEL` | Label for the screenshot filename. |
| `--ref REF` | Lead reference for the timeline heading. |
| `--request-id ID` | Caido request id to capture. |
| `--item-index N` | Burp proxy-history item index. |
| `--mode MODE` | OS capture mode: `interactive`, `fullscreen`, `window`. |
| `--hosts HOST,HOST` | Filter the proxy feed to these hosts. |
| `--limit N` | Max items for the proxy feed (default 20). |
| `--caido-url` / `--burp-url` | Override the proxy API URL. |
| `--caido-token` | Caido authentication token. |
| `--record` | Record the capture in the uploads table. |

### `core/payloads.py` (payload library)

| Flag | Purpose |
|---|---|
| `--rebuild` | Re-read the clone into the `payloads` table. |
| `--root PATH` | Override the configured `payloads_root`. |
| `--search QUERY` | Run a query and print the hits. |
| `--category NAME` | Restrict to one category. |
| `--limit N` | Max hits (default 20). |
| `--stats` | Row counts and last index time. |

### `core/advisories.py` (advisory feeds)

| Flag | Purpose |
|---|---|
| `--sync` | Poll each feed's RSS/Atom (what cron runs). |
| `--backfill` | Walk a Discourse-type feed's full history (slow; run once). |
| `--reparse` | Re-parse stored rows. |
| `--max-pages N` | Cap the backfill page count. |
| `--stats` | Feed counts. |
| `--quiet` | Suppress progress. |

### `core/hacktivity.py` (program activity feed)

| Flag | Purpose |
|---|---|
| `--refresh` | One poll (cron mode). |
| `--show` | Stored entries, newest first. |
| `--status` | Job health. |
| `--program HANDLE` | Which program to watch. |
| `--limit N` | Number of entries (default 10). |
| `--force` | Ignore the failure backoff window. |
| `--json` | JSON output. |
| `--quiet` | Suppress progress. |

### `core/regression.py` (retest queue for shipped fixes)

| Flag | Purpose |
|---|---|
| `--queue` | List the queue. |
| `--bucket B` | `due` (default), `scheduled`, `holds`, `broken`, `skipped` or `all`. |
| `--program HANDLE` | One program. |
| `--search TEXT` | Substring of title, report id, asset or retest note. |
| `--limit N` | Rows to print (default 50). |
| `--show H1_ID` | One entry as JSON, with the report body and triage thread. |
| `--verdict H1_ID --set V` | Record a verdict: `holds`, `broken`, `skipped` or `pending` to clear. |
| `--note TEXT` | What the retest found (with `--verdict`). |
| `--snooze H1_ID` | Push the due date out. |
| `--days N` / `--due-on DATE` | By N days from today, or to an explicit `YYYY-MM-DD`. |
| `--draft H1_ID` | Print a starting lead for a bypass of that report's fix. |
| `--status` | Coverage and the window in force. |
| `--json` | JSON output. |

```bash
# What is due now, most overdue first
python3 core/regression.py --queue

# Record what a retest found, then draft the lead for a fix that did not hold
python3 core/regression.py --verdict 0000000 --set broken --note "the v2 route is unpatched"
python3 core/regression.py --draft 0000000 > /workspace/vulns_example/BAC/notes/bypass.md
```

Reads only rows `h1.py --sync` already wrote; it makes no HackerOne request.

### Scripts

| Command | Purpose |
|---|---|
| `scripts/sync-payloads.sh [root]` | Clone or update the payload reference and rebuild the index. |
| `scripts/check-no-private-data.sh` | Refuse to let private data reach the repository. Run before every push, PR and release. |

---

## 11. HTTP API reference

All API paths are under `/api/`. Authentication is a cookie session (from the login form) or a Bearer
token (`Authorization: Bearer tok_...`). The IP allow-list is checked before auth. Cookie-authenticated
mutations must carry the `X-App-CSRF: 1` header; Bearer requests are exempt. Routes marked **write**
require write scope. Routes marked **public** need no auth.

Example Bearer usage:

```bash
TOKEN=tok_...
BASE=https://<host>:<port>
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/api/leads?status=ready"
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/api/search?q=idor"
```

### Auth and session

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | public. Version and app name. |
| POST | `/api/login` | public. Sets the session cookie. |
| POST | `/api/logout` | Clears the session. |
| GET | `/api/me` | Current identity, scope and channel. |
| GET | `/api/stats` | Dashboard aggregates. |
| GET | `/api/settings` | Current settings. |
| POST | `/api/settings` | **write**. Update allow-listed settings. |

### Entities

`<entity>` is one of `leads`, `reports`, `rcas`, `advisories`, `programs`, `targets`, `scopes`.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/<entity>` | List, with filters, search, sort, limit/offset. |
| GET | `/api/<entity>/<id>` | One row, normalized. |
| POST | `/api/(leads\|reports\|advisories)` | **write**. Create a file-backed row. |
| PUT | `/api/(leads\|reports\|rcas\|advisories\|programs\|targets)/<id>` | **write**. Update editable fields (or the backing file). |

Common list query parameters: `q` (search), `program`, `target`, `class`, `status`/`state`, `type`,
`paid=1` (reports), `sort` (prefix `-` for descending), `limit`, `offset`.

### Working a lead

| Method | Path | Notes |
|---|---|---|
| POST | `/api/(leads\|reports\|advisories)/<id>/status` | **write**. Change status. |
| POST | `/api/(leads\|reports\|advisories)/<id>/append` | **write**. Append a worklog entry. |
| GET | `/api/leads/<id>/report` | The draft report belonging to a lead. |
| POST | `/api/leads/<id>/sync-title` | **write**. Sync the lead title to its report title. |
| GET | `/api/queue` | Open and confirmed leads, oldest-touched first. |

### Search and payloads

| Method | Path | Notes |
|---|---|---|
| GET | `/api/search` | FTS across leads, reports, payloads. `q`, `kind`, `limit`. |
| GET | `/api/payloads` | Search the payload library. `q`, `category`, `limit`. |

### Files, ingest and uploads

| Method | Path | Notes |
|---|---|---|
| GET | `/api/fs/tree` | Browse a configured root. |
| GET | `/api/fs/read` | Read a file (respecting the deny-list). |
| PUT | `/api/fs/write` | **write**. Write a file and re-index. |
| GET | `/api/fs/download` | Download a file. |
| POST | `/api/reindex` | **write**. Rebuild the index. |
| POST | `/api/upload` | **write**. Multipart upload, optionally filed into the workspace. |
| GET | `/api/notes/tree` | All indexed markdown grouped by folder. |

### Evidence and screenshots

| Method | Path | Notes |
|---|---|---|
| GET | `/api/screenshot/backends` | Which capture backends are reachable. |
| POST | `/api/screenshot` | **write**. Capture via a backend. |
| GET | `/api/evidence/<target>` | List evidence for a target. |
| GET | `/api/evidence/<target>/timeline` | Build the evidence timeline. |
| POST | `/api/evidence/<target>/timeline` | **write**. Export the timeline to a file. |
| POST | `/api/evidence/<target>/feed` | **write**. Pull scope-filtered proxy traffic as evidence. |

### Tokens

| Method | Path | Notes |
|---|---|---|
| GET | `/api/tokens` | List tokens (never the secret). |
| POST | `/api/tokens` | **write**. Create a token (shown once). |
| POST | `/api/tokens/<id>/revoke` | **write**. Revoke a token. |

### Advisories

| Method | Path | Notes |
|---|---|---|
| POST | `/api/advisories/sync` | **write**. Poll the feeds now. |
| GET | `/api/advisories/status` | Feed health. |
| GET | `/api/advisories/matches` | Persisted advisory-to-report matches. Optional module. |
| POST | `/api/advisories/matches/recompute` | **write**. Re-score. Optional module. |
| POST | `/api/advisories/<aid>/match/<rid>` | **write**. Record a human verdict. Optional module. |

### HackerOne REST integration

| Method | Path | Notes |
|---|---|---|
| GET | `/api/integrations/hackerone` | Credential state and sync health (masked). |
| PUT | `/api/integrations/hackerone` | **write**. Store the API credential (verified first). |
| POST | `/api/integrations/hackerone/test` | **write**. Test the stored credential. |
| POST | `/api/integrations/hackerone/sync` | **write**. Run a sync. |
| GET | `/api/integrations/hackerone/programs` | Accessible-programs picker. |
| POST | `/api/integrations/hackerone/programs` | **write**. Onboard a program. |

### HackerOne GraphQL integration

| Method | Path | Notes |
|---|---|---|
| GET | `/api/integrations/hackerone/session` | Session state (masked). |
| PUT | `/api/integrations/hackerone/session` | **write**. Store the session cookie (verified first). |
| GET | `/api/h1/invitations` | Pending program invitations. |
| POST | `/api/h1/invitations/accept` | **write**. |
| POST | `/api/h1/invitations/reject` | **write**. |
| GET | `/api/h1/collabs` | Pending collaboration invitations. |
| POST | `/api/h1/collabs/accept` | **write**. |
| POST | `/api/h1/collabs/invite` | **write**. Invite a collaborator to a report. |
| POST | `/api/h1/collabs/split` | **write**. Set a bounty split percentage. |

### Poller, hacktivity, status, certs, audit

| Method | Path | Notes |
|---|---|---|
| GET | `/api/h1/job` | Poller health. Optional module. |
| GET | `/api/h1/events` | Recent upstream changes. Optional module. |
| POST | `/api/h1/events/seen` | **write**. Mark events read. Optional module. |
| POST | `/api/h1/poll` | **write**. Run one poll now. Optional module. |
| GET | `/api/hacktivity` | The program activity feed from storage. |
| POST | `/api/hacktivity/refresh` | **write**. Poll HackerOne once; can set the watched program. |
| GET | `/api/regression` | The retest queue: `?bucket=` `&program=` `&q=` `&limit=` `&offset=`. |
| GET | `/api/regression/<h1_id>` | One entry with the original report body and triage thread. |
| POST | `/api/regression/<h1_id>/verdict` | **write**. `{verdict, note}`. Verdict is `holds`, `broken`, `skipped` or `pending`. |
| POST | `/api/regression/<h1_id>/snooze` | **write**. `{days}`, `{due_on}` or `{clear: true}`. |
| POST | `/api/regression/<h1_id>/lead` | **write**. `{target, class?}`. Drafts the bypass lead; requires a `broken` verdict. |
| GET | `/api/schedule` | Poll intervals. Optional module. |
| POST | `/api/schedule` | **write**. Set intervals. Optional module. |
| GET | `/api/status` | The Status tab's one-request health payload. |
| GET | `/api/unseen` | New-since counts for the badges. |
| GET | `/api/certs` | TLS material for the Certificates view (public cert data only). |
| GET | `/api/certs/ca` | Download the CA certificate. |
| GET | `/api/audit` | The audit log. |

Endpoints marked "Optional module" depend on modules that may not be present in every build; when a
module is absent the endpoint returns `503` with a "module unavailable" message and the UI degrades
gracefully rather than erroring.

---

## 12. Configuration reference

### Environment variables

The `.env` variables are covered in [2.3](#23-the-env-file). Additional variables the code honors:

| Variable | Meaning |
|---|---|
| `QUARRY_COOKIE_NAME` | Session cookie name. Set it to run two instances side by side on one host. Default `quarry_session`. |
| `QUARRY_WORKSPACE_DIR` | Workspace root. Default `/workspace`. |
| `QUARRY_WORKSPACE_PREFIX` | Directory-name prefix that marks a target workspace. Default `vulns_`. |
| `CAIDO_URL` / `BURP_URL` | Proxy API URLs for evidence capture (see [8.6](#86-reaching-a-proxy-from-inside-the-container)). |
| `APP_CONFIG` / `APP_DB` / `APP_UPLOADS` | Override config, database and uploads paths (used by the container and the test harness). |

### `config.json`

Generated on first boot from the environment and then owned by the `/data` volume, so your edits
survive restarts. See [`config.example.json`](../config.example.json) for a full annotated example.
Keys a user touches:

| Key | Meaning |
|---|---|
| `app_name` | Display name. The single place the product name is decided. |
| `bind_host` / `bind_port` | Where the server listens (the container binds `0.0.0.0:8443`). |
| `allow_remote` | The IP allow-list. Bare IPs and CIDRs. Empty means open. |
| `db_path` | Database filename or absolute path. |
| `session_hours` | Session lifetime; `0` means never expires. |
| `regression_window_days` | Days after a report closes before its fix reads as due a retest. Default `30`. |
| `min_password_length` | Enforced by `--adduser`. |
| `browse_roots` | The trees exposed in the Files tab. |
| `browse_deny_globs` | Paths blocked in the file browser (key material, dotfiles, databases). |
| `browse_max_bytes` | Largest file the browser inline-renders. |
| `payloads_root` | Where the payload clone lives. |
| `tls_cert` / `tls_key` | TLS material paths. |
| `users` | The user table (write hashes with `--adduser`, never by hand). |

Additional keys are written by the app as you use it: `advisory_feeds` (your RSS/Atom feed list),
`hacktivity_program` (the watched program), and `poll_intervals` (job cadence, when the schedule
module is present).

### `secrets.json`

Holds your HackerOne credential and session cookie (mode 0600, never committed, never returned by an
endpoint): `hackerone.username`, `hackerone.api_token`, `hackerone.program_handle`,
`hackerone.session_token`, and optional `collaborator_allowlist` / `actor_denylist`. Manage these
through the Integrations tab, not by hand.

---

## 13. Troubleshooting and FAQ

**The server refuses to start with "QUARRY_ADMIN_PASSWORD is not set".**
Set it in `.env` (at least `QUARRY_MIN_PASSWORD_LENGTH` characters) and restart. The server will not
come up blank because the IP posture is open by default.

**My browser warns about the certificate.**
Expected with the default self-signed cert. Open the Certificates page (seal icon by the version),
download the CA and import it into your trust store once. Or set `QUARRY_TLS_MODE=mounted` and mount
your own cert/key into `/data/tls`.

**I get 403 before I even see the login form.**
Your address is not on `QUARRY_ALLOWLIST` / `allow_remote`. Add your IP or CIDR, or leave the list
empty to open it (only on a host you fully control).

**"Too many login attempts."**
Five failures per 15 minutes per source address trips the limiter. Wait it out, or restart the
container (the limiter is in-memory).

**The Payloads tab is empty.**
The library is a git clone that has to be populated. Run
`docker compose exec quarry bash scripts/sync-payloads.sh /payloads`, or wait for the first-boot
background clone to finish.

**The Tracker is empty.**
Connect your HackerOne API credential in Integrations, then run a sync (the Integrations action, or
`docker compose exec quarry python3 core/h1.py --sync`).

**Invitations or collaborations do not load.**
They need a HackerOne browser session cookie, not the API token. Paste the `__Host-session` cookie in
the Invitations card (see [7.2](#72-the-graphql-session-invitations-collaborations-splits)). If it
was working and stopped, the cookie expired; paste a fresh one.

**Caido or Burp is not detected from inside the container.**
`127.0.0.1` is the container, not your host. Set `CAIDO_URL` / `BURP_URL` (or `--caido-url` /
`--burp-url`) to `http://host.docker.internal:<port>` or your host IP (see
[8.6](#86-reaching-a-proxy-from-inside-the-container)).

**A submission was refused before sending.**
The submit pre-flight enforces the report standard (no em/en dashes, no `###` headings, no colon in
the title, no hard-wrapped prose, and a title/scope cross-check). Fix the report to satisfy the
message and re-run. `--submit` without `--confirm` is always a dry run.

**My leads are not showing up.**
A file is a lead only if it carries a `**Status:**` marker within its first 25 lines. Without it, it
indexes as a note (searchable, not queued). Add the marker, then re-index (Files tab, or
`ingest.py --rebuild`).

**Some Status/Dashboard figures read zero.**
The New/Updated and money-landed deltas, and the poller and advisory-match features, depend on
optional modules. When a module is not present in your build the related endpoints return `503` and
the figures read zero; core sync, submit, search, leads and the Tracker are unaffected.

**Did I lose data on upgrade?**
No. All mutable state lives on the `quarry-data`, `quarry-workspace` and `quarry-payloads` volumes,
which survive `docker compose pull` and recreate. Only the image layer is replaced.
