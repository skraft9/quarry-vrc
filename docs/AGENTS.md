# Quarry for AI agents

This guide is for an agentic AI - Claude Code, Cursor, or a custom local agent - working a bug
bounty hunt alongside a human in Quarry. It explains what Quarry is, how to record a lead the app
will index, how to query the console, and how to ship a report to HackerOne.

Quarry is deliberately simple to automate: **your research is plain Markdown on disk**, and the
whole corpus is queryable over an HTTP API. There is no SDK to learn and no lock-in - you read and
write files, and optionally call the API for structured queries.

## The mental model

| Thing | Where it lives | Authority |
|---|---|---|
| **Leads** (your working notes/findings) | Markdown files in the **workspace volume** | the files - you own them |
| **Reports** | pulled from the **HackerOne API** | HackerOne |
| **Programs / scopes / targets** | the **HackerOne API** | HackerOne |
| **Payloads** | a cloned reference library | the clone |
| **Retest verdicts** | the `regressions` table, via the console or `regression.py` | you - it is a judgement, not an entity |

The SQLite database is only a cache and a search index. You never edit it directly: you write a
Markdown file, and Quarry indexes it (immediately in-app, or on the next `ingest.py --rebuild`).

## Workspace layout

Leads and reports are files under the workspace root (mounted at `/workspace` in the container),
organised by target and vulnerability class:

```
/workspace/<target>/<CLASS>/notes/<slug>.md      a LEAD (your working note)
/workspace/<target>/<CLASS>/reports/<slug>.md     a REPORT (what you send to HackerOne)
/workspace/<target>/notes/<slug>.md               a lead with no class
```

`<CLASS>` is a short code taken from the directory name: `BAC`, `DoS`, `RCE`, `SECRETS`, `PRIVESC`,
`AUTHN`, `INJECTION`, `SSRF`, `INTEGRITY`, `API`, ... A file under `evidence/` or `bin/` is ignored,
so put PoC scripts and captures there without polluting the lead list.

## Recording a lead the app will index

A file becomes a **lead** when it carries a `**Status:**` marker **within its first 25 lines**.
Without that marker it is treated as a note (still searchable, but not a queue item). Write leads
to this house format so the app parses every field:

```markdown
# <ref> - <one-line title of the finding>

**Decision summary:** One or two sentences: what you think is wrong and whether it is worth chasing.

| | |
|---|---|
| **Status:** | open |
| **Researcher** | yourhandle |
| **Date** | 2026-01-15 |
| **Target** | SomeProduct 1.2.3 |
| **Version** | 1.2.3 |
| **Class** | BAC / broken access control |
| **CWE** | CWE-284 |
| **Privilege** | low |
| **Impact** | Confidentiality - High |
| **Source** | https://github.com/vendor/product @ tag v1.2.3 |

## Claim
<the mechanism, precisely, with file:line where you can>

## Proof
<how to reproduce; put runnable PoCs under bin/, captures under evidence/>
```

**Status vocabulary** (the lead's place in the workflow), lowest to terminal:

`open` -> `confirmed` -> `ready` -> `submitted` -> `awarded`, plus `parked` (shelved) and `killed`
(dead, do not re-hunt). Move a lead by editing its `**Status:**` value. The **Researcher** row is
what attributes a lead to a collaborator, so fill it in.

**Rules that matter to the parser:**

- The `**Status:**` row is FIRST and within the first 25 lines.
- One finding per file. Name the file for the finding, e.g. `bac-idor-on-order-endpoint.md`.
- Keep the header a real Markdown table so `Class`, `CWE`, `Privilege` and `Impact` are read into
  their columns.

## Querying the console (API + Bearer tokens)

Every list is available over the API, so you can pull exactly the context you need instead of
re-reading the whole workspace. Issue a **Bearer token** in the **Tokens** tab, then:

```bash
TOKEN=tok_...
BASE=https://<host>:<port>

curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/api/leads?status=ready"
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/api/reports?program=<handle>"
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/api/programs"
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/api/search?q=idor"
```

Bearer requests are CSRF-exempt (there is no ambient browser credential), so they are the right
channel for scripts and agents. A read token cannot mutate; ask the operator for a write token only
if you need to create leads through the API rather than by writing files.

## Drafting and shipping a report to HackerOne

When a lead reaches `ready`, turn it into a report and file it. A report is prose aimed at a triager:
lead with the impact, state the broken control in the first line, give exact steps to reproduce
(commands only in code blocks; what a command returns goes in the prose above it), and end with
remediation. Write it to `.../reports/<slug>.md`.

To submit, the human connects their HackerOne credential once in **Integrations** (username + API
token, stored write-only). Then a report is filed straight to the API - from the app's submit action
on the lead/report, or from the CLI:

```bash
# prints the payload and STOPS; add --confirm to actually send
python3 h1.py --submit reports/<slug>.md --program <handle> \
  --weakness cwe-284 --scope "<in-scope asset>" --severity medium
```

`--severity` is required by most programs (a missing rating is a 422). Add `--attach` to upload the
evidence captured for the target with the report (see [Capturing evidence](#capturing-evidence-for-a-report)).
After submission the report appears in the **Tracker**, synced from HackerOne, with its state, bounty
and triage thread. Read the triager's actual comment on a closed report - it usually names the
condition under which the finding would have been accepted - before deciding a class is dead.

## Capturing evidence for a report

Evidence lives in the target's `evidence/` directory and is never indexed as a lead.
`core/screenshot.py` captures it from a proxy or the OS and turns it into report-ready material:

```bash
# list which backends are reachable (Caido, Burp, OS)
python3 screenshot.py --detect

# capture: an OS screenshot, or pull a specific proxy request
python3 screenshot.py --capture --target <slug> --name login-idor
python3 screenshot.py --caido --request-id 42 --target <slug>

# pull recent proxy traffic filtered to the target's in-scope hosts, filing each match
python3 screenshot.py --feed --target <slug> --limit 20

# build a chronological timeline ready to paste into Steps To Reproduce
python3 screenshot.py --timeline --target <slug> --ref F01

# list everything gathered for the target (the set --attach uploads)
python3 screenshot.py --collect --target <slug>
```

Attach it on submission by adding `--attach` to the `h1.py --submit` command above. Inside the
container the Caido/Burp defaults (`127.0.0.1:8080` / `127.0.0.1:1337`) resolve to the container, not
the host, so set `CAIDO_URL` / `BURP_URL` to `http://host.docker.internal:<port>` to reach a proxy
running on the operator's machine.

## Program invitations and collaborations

These operations live on HackerOne's GraphQL API, which authenticates with a browser session cookie
(the `__Host-session` value), distinct from the REST API token and stored write-only. The human
pastes it once in the **Invitations and Collaborations** card in **Integrations**; then
`core/h1_graphql.py` lists and acts on invites, collaborations and splits:

```bash
python3 h1_graphql.py --invitations                 # list pending program invitations
python3 h1_graphql.py --accept-invite TOKEN         # accept one (or --reject-invite TOKEN)
python3 h1_graphql.py --collabs                     # list collaboration invitations
python3 h1_graphql.py --accept-collab TOKEN         # accept a collaboration
python3 h1_graphql.py --add-collab REPORT_ID USER   # invite a collaborator to a report you own
python3 h1_graphql.py --set-split REPORT_ID USER 50 # set that collaborator's bounty split to 50%
```

## Retesting a shipped fix

The highest-yield surface an operator owns is the set of bugs already fixed for them: the patch is
new code, written under deadline pressure, against one proof of concept that is already in the
database. `core/regression.py` is that queue, derived from resolved reports - no HackerOne request,
so it is free to poll.

```bash
python3 regression.py --queue                  # what is due, most overdue first
python3 regression.py --show <report-id>       # the report body and the full triage thread
python3 regression.py --verdict <report-id> --set holds  --note "replayed the PoC, 403"
python3 regression.py --verdict <report-id> --set broken --note "the v2 route is unpatched"
python3 regression.py --draft  <report-id>     # a starting lead for the bypass
```

Read the thread before planning the retest - it is where the program said what it changed, and the
retest is only worth running against the paths that change did not cover. Record a verdict either
way: a `holds` is what stops the same fix being re-checked every month, and a `broken` is what
unlocks the drafted lead.

A row marked `moved` had HackerOne activity after its verdict was recorded, which means the verdict
no longer describes it. Re-read the thread on those first.

## A good agent loop

1. Read the program's scope and rules of engagement (**Programs** / `GET /api/programs`).
2. Hunt; write each finding as a lead with `**Status:** open`.
3. Confirm it, move it to `confirmed`, then `ready` once the report is drafted.
4. File it (submit), and let the Tracker follow its fate.
5. On closure, read the triage comment and record what you learned.
6. When the fix ships, come back to it: `regression.py --queue` is the standing to-do that turns a
   resolved report back into a candidate.

Everything stays on the operator's box. Quarry is the memory and context engine; you are the pair.
