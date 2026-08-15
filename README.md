<div align="center">

<img src="docs/img/banner.svg" alt="Quarry" width="880">

<br>

[![HackerOne Integration](https://img.shields.io/badge/HackerOne_Integration-494649?logo=hackerone&logoColor=white&style=for-the-badge)](https://api.hackerone.com/)

![Report Tracker](https://img.shields.io/badge/Report-Tracker-6f42c1) &nbsp;
![Advisories](https://img.shields.io/badge/Advisories-CVE_%2F_CVSS_Feeds-1f6feb) &nbsp;
[![Payloads](https://img.shields.io/badge/Payload_Library-PayloadsAllTheThings-2ea043)](https://github.com/swisskyrepo/PayloadsAllTheThings) &nbsp;
![Scope Management](https://img.shields.io/badge/Program-Scope_Management-fd7e14)

[![Created by @skraft9](https://img.shields.io/badge/Created_by-%40skraft9-228B22)](https://github.com/skraft9) &nbsp;
[![Built with Claude Code](https://img.shields.io/badge/Built_with-Claude_Code-D97757?logo=claude&logoColor=white)](https://claude.com/claude-code)

`Python` &nbsp;&middot;&nbsp; `JavaScript` &nbsp;&middot;&nbsp; `CSS` &nbsp;&middot;&nbsp; `Docker` &nbsp;&middot;&nbsp; `SQLite` &nbsp;&middot;&nbsp; `Apache-2.0`

</div>

<img src="docs/img/rule.svg" alt="" width="100%">

---

<img width="3786" height="1726" alt="Screenshot 2026-08-06 233434" src="https://github.com/user-attachments/assets/5f698813-1e33-45b2-beb7-7388010b3877" />

---

<img width="3796" height="1728" alt="Screenshot 2026-08-06 235412" src="https://github.com/user-attachments/assets/1d99fed7-d2c7-496c-baf8-a2cfd0836bfe" />

---

<img width="3800" height="1743" alt="Screenshot 2026-08-06 233713" src="https://github.com/user-attachments/assets/29918b8c-fcb4-469e-a56f-31bd9a0d062d" />

---

## <img src="docs/img/gem-sm.svg" width="18" align="top" alt=""> Supported Bug Bounty Platforms

- **HackerOne**

Quarry syncs and submits through the HackerOne API. Other platforms are not supported yet.

<img src="docs/img/rule.svg" alt="" width="100%">

## <img src="docs/img/gem-sm.svg" width="18" align="top" alt=""> Key Features

- **Your entire hunt on one board.** Sync every report, program, bounty and triage thread from the
  HackerOne API, so the console mirrors your real hunting instead of a spreadsheet you patch by hand.
- **Find it, draft it, submit it.** File a finished report using the HackerOne API, then watch
  its state and bounty flow straight back into the Tracker.
- **Your fixed bugs come back to you.** A resolved report is the surface you have an unfair
  advantage on - the patch is new code, written fast, against one proof of concept you wrote. The
  Regression tab queues every shipped fix for a retest, remembers what each one found, and drafts
  the bypass lead when a fix turns out not to hold.
- **A researcher's arsenal, built in.** Full-text search across every lead, report and payload, a
  payload library cloned from PayloadsAllTheThings, proxy and OS evidence capture wired to Caido and
  Burp, and live CVE/CVSS advisory feeds cross-referenced against your work.
- **Team up on a finding.** Accept private program invitations and report collaborations, invite a
  collaborator and set the bounty split, straight from the console.
- **Native to agentic AI.** Every lead, note and payload is plain Markdown on disk, so Claude Code,
  Cursor or your own agent can read, query and draft your research right alongside you.

<img src="docs/img/rule.svg" alt="" width="100%">

## <img src="docs/img/gem-sm.svg" width="18" align="top" alt=""> Quick Start

```bash
# Clone the repository to your machine
git clone https://github.com/skraft9/quarry-vrc.git quarry && cd quarry

# Copy the example environment file (then set QUARRY_ADMIN_PASSWORD; QUARRY_ALLOWLIST is optional)
cp .env.example .env
$EDITOR .env

# Build the image and start the container
docker compose up -d
```

- Quarry runs as a single container; the code is baked into the image.
- Database, leads and payloads live on Docker-managed volumes, so `docker compose pull`
  upgrades the app without touching your data.
- First boot generates a config, a self-signed TLS certificate and an empty database, then prints
  the URL.
- Open the printed URL, sign in, and connect your HackerOne account in **Integrations**.
- Full walkthrough in [`docs/SETUP.md`](docs/SETUP.md).

### Documentation

- **[`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) is the complete manual** - every feature, every tab,
  the CLI and the HTTP API, in one place. Start here when you want more than the quick start.
- [`docs/SETUP.md`](docs/SETUP.md) - first-run walkthrough.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - the one-container, three-volume model.
- [`docs/AGENTS.md`](docs/AGENTS.md) - driving Quarry with an agentic AI.

### Usage

Most of this happens through the UI, but the same operations run on the CLI inside the container
(`docker compose exec quarry python3 ...`):

```bash
# Sync your reports, bounties, states and triage threads from HackerOne
python3 core/h1.py --sync

# Sync each program's guidelines, scopes and visibility
python3 core/h1.py --sync-programs

# Submit a finished report (prints the payload; add --confirm to actually send it)
python3 core/h1.py --submit reports/<slug>.md --program <handle> \
  --weakness cwe-79 --scope "<in-scope asset>" --severity high

# Which shipped fixes are due a retest, and record what one found
python3 core/regression.py --queue
python3 core/regression.py --verdict <report-id> --set broken --note "the v2 route is unpatched"

# Rebuild the lead and report index from your workspace Markdown
python3 core/ingest.py --rebuild

# Refresh the advisory feeds, and search the payload library
python3 core/advisories.py --sync
python3 core/payloads.py --search "jwt none"
```

### Updating

```bash
docker compose pull       # fetch the new image
docker compose up -d      # recreate the container on it
```

- Your database, leads, config and credentials live on Docker volumes, so upgrading is a
  pull-and-recreate that never touches your data.
- To pin a specific release instead of tracking the latest, set the image tag in
  `docker-compose.yml` (for example `image: ghcr.io/skraft9/quarry-vrc:v1.0.0`); every version is
  tagged on the [Releases](https://github.com/skraft9/quarry-vrc/releases) page.

### Requirements

| Requirement | Needed for |
|---|---|
| **Docker** (with Compose) | Running Quarry. It is the only thing you install. |
| **A HackerOne API token** | Optional, but the point: it populates the Tracker and enables one-click submit. Paste it in the app. |

Inside the image, Quarry is the **Python 3.12 standard library and one HTML page** - `sqlite3` with
FTS5, `ssl`, `http.server`, `hashlib`. It runs without a framework, a build step or a package
manager. That is a deliberate security decision: a console holding your unreported findings and a
bounty credential carries **zero third-party runtime code** to audit, pin, or be compromised
through. (`git` and `curl` ship only so the payload library can clone its reference and the
container can health-check itself; neither is a language dependency.)

### The `.env` File

| Variable | Meaning |
|---|---|
| `QUARRY_ADMIN_PASSWORD` | **Required.** Creates the first admin login on first boot; the server refuses to start without it. |
| `QUARRY_ADMIN_USER` | The first admin's username. Default `admin`. |
| `QUARRY_APP_NAME` | Display name in the top-left brand and the page title. |
| `QUARRY_PORT` | Host port the HTTPS console is published on. Default `8443`. |
| `QUARRY_ALLOWLIST` | **Client IP allow-list**, checked before auth on every request. Comma-separated IPs/CIDRs. Empty = open, which is fine for a host only you can reach. |
| `QUARRY_TLS_MODE` | `self-signed` (default) generates a local CA + cert on first boot; `mounted` uses a cert/key you mount into the data volume. |

<img src="docs/img/rule-triple.svg" alt="" width="100%">

## <img src="docs/img/gem-sm.svg" width="18" align="top" alt=""> Core Capabilities

| Tab | What it does |
|---|---|
| **Dashboard** | Shows what you earned, what moved, and what is still open. |
| **Leads** | Tracks your hunt notes from disk through a status workflow: open, confirmed, ready, submitted, awarded, parked, killed. |
| **Tracker** | Lists every HackerOne report with state, bounty, CWE, impact, program, target and payout split. |
| **Regression** | Queues the fixes shipped for your resolved reports for a retest, records what each retest found, and drafts the bypass lead when a fix does not hold. |
| **Programs** | Holds your programs with their scope and rules of engagement; totals awards, average payout and earned. |
| **Targets** | Maps in-scope assets from HackerOne to the local workspaces your leads are filed against. |
| **Advisories** | Ingests any RSS/Atom vulnerability feed you configure (CISA, VulDB, or a vendor's) and cross-references it. |
| **Payloads** | Searches a payload library (one row per documented block), cloned from a public reference and yours to extend. |
| **Files** | Browses the configured roots with an edit-and-save-back pane; denied paths are shown, not hidden. |
| **Certificates** | How to trust the container's TLS cert. Reached from the seal icon beside the version in the sidebar footer. |
| **Integrations** / **Tokens** | Store your HackerOne credentials write-only; accept program invitations and manage report collaborations and bounty splits; issue Bearer tokens for non-browser clients. |
| **Audit log** / **Status** / **Settings** | Record what happened, report health and the index, and change job cadence. |

### <img src="docs/img/gem-amber.svg" width="16" align="top" alt=""> Built for Agentic AI

Quarry is built to pair with an agentic AI - Claude Code, Cursor, or a custom local agent - working
alongside you at the console:

- **Your research is plain Markdown on disk.** Leads, RCAs and notes are files in your workspace
  volume, so an agent can **inspect, query, write and refine** them directly - summarizing a lead,
  drafting a report into your workspace, or reworking a finding - with no API wrappers and no
  lock-in. The app just indexes what the agent (or you) writes.
- **The whole corpus is queryable.** SQLite FTS5 full-text search spans leads, reports and payloads,
  so an agent can pull exactly the context it needs instead of re-reading everything.
- **Programmatic access is first-class.** Server-side **Bearer tokens** let external scripts and AI
  tools query the console over its API - read the Tracker, fetch a lead, check a program's scope -
  without a browser session.

In summary, Quarry is the memory and context engine, and your agent is the pair. Everything stays on
your box. See [`docs/AGENTS.md`](docs/AGENTS.md) for the full agent guide on how to record a lead the
app will index, query the console over the API, and ship a report to HackerOne.

<img src="docs/img/rule.svg" alt="" width="100%">

## <img src="docs/img/gem-amber.svg" width="18" align="top" alt=""> HackerOne Integration

Quarry talks to the HackerOne API directly, so the console reflects your real hunting instead of a
copy you keep in step by hand.

- **Sync** pulls your programs, scopes, reports, states, bounties, payout splits and triage threads.
- **Submit** files a finished report to a program straight from the app, with no copy-paste into the
  web form; add `--attach` to upload evidence captured from Caido, Burp or the OS with it.
- **Read the triage** fetches the analyst's actual comment on a closed report, where the reopen
  condition usually lives.
- **Invitations and collaborations** accept private program invites and manage report collaborations
  and bounty splits, over HackerOne's GraphQL API with a browser session cookie stored write-only,
  distinct from the REST API token.

Your API username and token are pasted once in **Integrations**, verified against the live API before
they are stored, kept server-side, and never rendered back into the page.

### Systems of Record

Every entity has exactly one authority, and it is never the database. The SQLite index is a cache
and a query layer; it holds no entity it is the authority for.

| Entity | Authority | Rebuilt from |
|---|---|---|
| Reports, bounties, payout splits | **HackerOne API** | `h1.py --sync` |
| Program guidelines, scopes | **HackerOne API** | `h1.py --sync-programs` |
| Leads, RCAs, follow-ups | **Markdown in your workspace volume** | `ingest.py --rebuild` |
| Payloads | **A git clone on disk**, never vendored | `scripts/sync-payloads.sh` |
| Retest verdicts | **Your own judgement**, recorded in the console | not rebuildable - see below |

- Storing leads as Markdown on disk is what lets an AI agent read, summarize and draft reports
  directly in your workspace context.
- The one row above with no upstream is the exception that proves the rule: a retest verdict is an
  OPINION about an entity, not an entity, and no source of truth outside your head holds it. The
  queue it annotates is still derived from HackerOne on every read, so dropping the table loses
  what you concluded and nothing you own.
- Because HackerOne owns your reports, a rebuild never invents or overwrites them.
- Anticipated money is held separately and never summed into the total, so a hand-typed figure can
  never turn an expectation into a confirmed award.
- One container, all mutable state on named volumes; details in
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

<img src="docs/img/rule-triple.svg" alt="" width="100%">

## <img src="docs/img/gem-violet.svg" width="18" align="top" alt=""> Security Model

Quarry holds your unpublished findings and a bounty API credential. It is built to run on **your own
machine or a private host you control**, and is not hardened for the public internet.

| Control | Detail |
|---|---|
| **Zero-dependency runtime** | Python standard library only, so there is zero third-party runtime code to audit or be compromised through. |
| **IP allow-list, first** | `QUARRY_ALLOWLIST` is checked before authentication and routing; an unlisted address gets 403 and nothing else. |
| **TLS always** | Self-signed local CA on first boot, or bring your own. |
| **PBKDF2-HMAC-SHA256** | 600,000 iterations, per-user salt, constant-time verify; login failures are rate-limited per source. |
| **Hashed credentials** | Sessions and API tokens are stored as SHA-256, so a database read yields nothing usable. |
| **Write-only secrets** | Your HackerOne token is stored server-side and never returned by any endpoint. |
| **Strict CSP** | `default-src 'none'` blocks inline handlers, remote scripts and remote fonts. The markdown renderer escapes at the boundary and a test suite attacks it. |

<img src="docs/img/rule.svg" alt="" width="100%">

## <img src="docs/img/gem-sm.svg" width="18" align="top" alt=""> Contributing

Two long-lived branches, and every change goes through a pull request so it stays reviewable and
revertable. The full contributor guide is [`CONTRIBUTING.md`](CONTRIBUTING.md); the essentials:

- **`dev`** is the staging branch - work lands here first.
- **`main`** is what ships; `dev` merges into it as a **release**, cut on the GitHub
  [Releases](https://github.com/skraft9/quarry-vrc/releases) page with a version tag and notes.

```bash
git checkout dev && git pull
git checkout -b fix/short-description
# work, then open a PR into dev (not main):
gh pr create --base dev --fill
```

House rules:

- **One change-type prefix per PR, and the branch carries the same one** so the history reads the
  same for everyone: `feat:` (a feature or behaviour change), `fix:` (a bug fix), `docs:` (docs only),
  `chore:` (tooling or cleanup), `security:` (a fix or hardening that closes a security finding).
  Keep the subject imperative and lower-case - `feat: add the labs tab`.
- **One PR per kind of change** - a feature and a docs change are two PRs, even in one sitting.
- **A structured PR body, not a wall of text** - a one-line summary, then labelled one-line bullets:
  what changed (SHA-pinned backticked links), what it resolves, how it was verified.
- **Bump `VERSION`** in the same PR: a feature moves the minor (`1.x.0`), a fix, docs, chore or
  security pass moves the patch (`1.0.x`). A batch of security fixes released together shares one
  patch bump and ships as one release with a **Security** section in the notes.
- **Link the code you touch** in the PR body as a backticked, SHA-pinned hyperlink, and cite other
  PRs by their number (GitHub renders it as the PR's own title).
- **Run `scripts/check-no-private-data.sh` before every PR**; it gates against committing secrets or
  personal data. When the test suites are present, both green too.
- **Standard library only** - no pip, npm or CDN - and **ASCII punctuation** everywhere. Never commit
  a secret or personal data (`.gitignore` covers the known ones).
- Versions run on the `1.x` line and move up; the official launch opens the `2.0` train.

<img src="docs/img/rule.svg" alt="" width="100%">

<div align="center">

Made for hunters and their agents. <img src="docs/img/gem-sm.svg" width="14" align="top" alt=""> [Apache-2.0](LICENSE)

</div>
