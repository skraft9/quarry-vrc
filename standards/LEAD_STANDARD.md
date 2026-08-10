# Lead Standard

How a lead is written, so that clicking two leads in Quarry shows the same shape twice. A lead is the working document a report is eventually drafted from; it is to the report what a bug ticket is to a patch. This file is the authority for the lead the same way `REPORT_STANDARD.md` is for what you send to the program: when it disagrees with a habit in an older lead, this file wins.

Placeholders in the examples (`ExampleVendor`, `<target>`, `<REF>`, `<your-handle>`, `<lab-host>`, `#0000000`) stand in for your own details. A lead is never submitted anywhere, so a real host in a lead leaks nothing on its own, but the report is drafted FROM the lead, so use the placeholders here too rather than rewriting an address twice and missing one.

## Write the lead file AT DISCOVERY, not when it is proved

**The first thing you do with a new candidate is create its lead file.** Not after reproduction, not after it is confirmed, not at the end of the round. The moment there is a hypothesis and a reason to chase it, write `**Status:** open` and one or two sentences of what you think is wrong.

This is the single most valuable habit in the workflow. A candidate that exists only in an agent's context or in your head is invisible to the app, invisible to a collaborator, and gone entirely if the session crashes or is stopped.

**Killed leads are the point, not the leftovers.** An undocumented kill gets re-hunted months later by someone with no way to know it was already tried, and the same dead surface can burn three separate reports before anyone realises it is the same one. A kill on disk is what stops that.

**Move the status as you learn**, rewriting the decision summary in the same edit:

```
open ---> confirmed ---> ready ---> submitted ---> awarded
  |
  +-----> killed      (with the REOPEN CONDITION, not just the verdict)
  +-----> parked      (with what unparks it)
```

**A kill records what would bring it back.** "Not exploitable" is nearly worthless six months on; "inert only because the current browser refuses `javascript:` in `window.open` - revives if a different browser behaves differently" is a lead someone can pick up. Where a whole surface died for one reason, one lead covering that surface is right; do not write ten files where one says it.

## The header block IS A TABLE

The header is a two-column table. It lines the labels up and is scannable in one pass, where a run of `Label: value` lines renders as a ragged bullet list.

```markdown
# <REF> - Reporting API returns other tenants' records without an ownership check

| | |
|---|---|
| **Status:** | submitted |
| **Researcher** | <your-handle> |
| **Date** | 2026-01-15 |
| **Target** | ExampleVendor API |
| **Version** | 4.7.1 |
| **Tested** | ExampleVendor @ `<lab-host>`, trial license |
| **Class** | BAC / privilege semantics |
| **CWE** | CWE-862 (Missing Authorization) |
| **Privilege** | low |
| **Impact** | Confidentiality - High<br>Integrity - Low |
| **Source** | `example-connector-python` @ tag v4.7.1 (abc123def456) |
| **Submitted** | 2026-01-15 as #0000000 (high, cwe-862) |
| **Report** | `reports/0000000_<REF>-reporting-api-bola.md` |
| **PoC** | `bin/reporting_api_poc.sh` (20 assertions, self-verifying, exit 0) |
```

Rules for it:

- **`**Status:**` is the FIRST row**, and it must fall within the first 25 lines of the file. The app parses the marker from a cell exactly as it does from a bare line, so the surrounding pipes are fine.
- **Header rows use no colon except `Status:`**, which keeps its colon because that is the token the parser and every older lead carry.
- **Order:** Status, Researcher, Date, Target, Version, Tested, Class, CWE, Privilege, Impact, Source, then whatever the lifecycle adds - Submitted, Report, Validated, PoC.
- **A repository asset is named by its REPO, not its URL.** A source-code scope registers something like `https://github.com/exampleorg/example-connector-python`, which is a URL two columns wide. Write `example-connector-python`. The full identifier stays in the tooltip, so the lead, the report and the app read the same.
- **`Target` is the program's ASSET NAME and nothing else** - `Python Connector`, `NodeJS Driver`, `ExampleVendor API`. It is what the report gets filed against, so it has to match the scope list. A row reading `example-connector-python 4.7.1 (PyPI) against a hostile listener on <lab-host>:9443` is a sentence, and it makes the Leads table unreadable and its Target column untrustworthy.
- **`Version` sits directly under `Target` and carries the software version alone** - `4.7.1`, `v2.1.0`. It is the second thing a triager checks after the asset, because a finding against a superseded release is a different conversation. **Write `NA` when a version does not apply**, for a hosted service or an account-level finding. An absent row reads as an oversight; `NA` reads as a decision.
- **`Tested` carries the rest of the conditions**: the package registry, the build, and the lab setup, e.g. `PyPI, against a hostile listener on <lab-host>:9443`. Omit the row when there is nothing beyond the version to say.
- **`Class` is your own shorthand for the kind of bug** and is written for you. It is not interchangeable with `CWE`, which is written for the triager, so a lead needs both.
- **`CWE` sits directly under `Class` and carries the identifier plus MITRE's own name in parentheses** - `CWE-862 (Missing Authorization)`, `CWE-732 (Incorrect Permission Assignment for Critical Resource)`, `CWE-284 (Improper Access Control)`. A number alone is unreadable in the Leads table. Use MITRE's name, not the program's variant of it. **One identifier, not a chain**: where a report names a sequence, take the weakness the finding IS rather than what it leads to. Write `NA` where none fits. **Leave the row out entirely until a CWE has actually been chosen** - it is picked at submission time, and inventing one earlier puts a number in front of a triager that nobody stood behind.
- **`Privilege` sits under `CWE` and carries one word: `none`, `low` or `high`.** It is the privilege the ATTACKER needs, not the one the victim holds. `none` is unauthenticated or anonymous. `low` is any ordinary authenticated account, including one holding a routine feature grant. `high` means the attacker already holds an administrative privilege, which on most programs caps the severity and on some puts the finding out of scope entirely. Writing it in the header forces the question early, rather than at the staging gate where a `high` answer has already cost a lab cycle.
- **`Impact` sits under `Privilege` and names each CIA dimension that was DEMONSTRATED, with its rating**, in the form `<Dimension> - <High|Low>`, one per line inside the single cell separated by `<br>`: `Confidentiality - High<br>Integrity - Low`. A single dimension is one line and no separator. **The rating is the same vocabulary the report uses and carries the same rule: only `High` or `Low`, never `Medium`.** A dimension reasoned about rather than measured is left out of the row entirely, exactly as its bullet would be deleted from the report. **When nothing was demonstrated yet, the cell says so** rather than being left empty or omitted: `none demonstrated - static analysis only, no live run yet`. That is the honest cell for a lead written at discovery and not yet validated, which is most of them.
- **`Source` names the code under test** - the repo and the tag or commit it was read at, `example-connector-python @ tag v4.7.1 (abc123def456)`.
- **Omit a row rather than filling it with a nil.** An absent row reads as absent; `PoC: none` reads as a claim.
- **Title stays a plain `# <REF> - <what it is>` heading above the table.** One line, no colon. Once a report exists, that trailing half is the REPORT's title (see below).
- Prefer `<lab-host>` over a lab IP even here.

**The header requirement covers `open`, `confirmed`, `ready` and `parked`.** A parked lead is live work that has been deferred, not a closed one - it is the state you return to, and it is the state that most needs the rows, because whoever unparks it months later has none of the context. `submitted` and `killed` are exempt: a submitted lead's report carries the real data, and a killed one never established a weakness.

## Once a report exists, the lead carries the REPORT's title

**From `confirmed` onwards, a lead's title is `# <REF> - <the report's title, verbatim>`.** The report title is the authority, because it is the sentence that appears on the program. Two titles for one finding mean the Leads tab and the drafted report disagree about what the finding is.

```markdown
# <REF> - Missing Authorization in ExampleVendor Reporting API Step-Progress Endpoint
```

The `<REF> - ` prefix always survives. It is the join between a lead, its report file and the report id, so a bare report sentence with no ref is not a lead title. Everything after it is the report's own heading, unchanged - a report title is 12-15 words with no colon (`REPORT_STANDARD.md`), which is also what the lead then reads as in the queue.

**The title changes in the SAME EDIT that sets `confirmed`, never later.** A lead whose status says confirmed while its heading still says something else is describing two different findings, and that is exactly when someone is most likely reading the queue rather than the file. If the app offers a "sync title" action, use it; if you edit the markdown by hand, do it yourself in that edit. Working names are still the right thing to write while a lead is `open` or `parked`: there is no report to agree with yet.

**A lead merged into another lead's report** takes the report's title like any other filed lead, with the fold named in a trailing parenthesis, so two rows in the Leads table do not carry the same sentence with nothing saying why:

```markdown
# <REF> - External Control of File Path in ExampleVendor .NET Connector via Server-Supplied Locations (merged into <OTHER-REF>)
```

The parenthesis goes at the END so the title still reads as the report's, and it names the SIBLING lead rather than the report id. Both leads keep their own `Submitted` row with the shared report id, and the merged lead's `Report` row points at the sibling's draft. The decision summary says what each half proved.

## The report draft lives under `reports/`, never in `notes/`

A lead is a `notes/` file. The report drafted from it is a `reports/` file. Keeping the draft in `notes/` makes it look like a second lead and breaks the one-lead-per-file rule below.

- The lead points at its report through a **`Report` row**: `reports/<REF>-<slug>.md`, renamed to `reports/<report-id>_<REF>-<slug>.md` once an id exists.
- If the app resolves the report from the lead automatically, an explicit `Report` row is still the readable record and it never hurts to carry it.
- Dedup happens BEFORE you draft, not after. A `## Dedup` section with a real verdict is a precondition of writing the report, because the cheapest moment to discover a finding is already known is before you have spent an hour writing it up.

## Status values

The app takes the FIRST WORD after the `**Status:**` marker, lowercases it, and keeps it only if it is one of:

```
  open ---> confirmed ---> ready ---------> submitted -------> awarded
   |        (reproduced)   (reviewed and    (has a report id) (a bounty
   |                        cleared, waiting        |          was paid)
   |                        to be sent)             |
   +---> parked ---> (back to open)                 | closed duplicate /
   |                                                | informative /
   +---> killed <-----------------------------------+ not-applicable / spam
         (guarded, documented, already known, or not worth reporting)
```

**Anything else silently becomes `unknown`** and the lead drops out of the Leads queue while still looking statused on disk. Write the status lowercase so the file and the UI agree, and keep any trailing detail short, with the durable facts in their own rows:

```markdown
**Status:** submitted
Submitted: 2026-01-15 as #0000000 (high, cwe-862)
```

The marker must appear within the first **25 lines**. Below that it is not seen at all.

## The lifecycle

A lead moves in one direction along the diagram above, and the status marker is the only thing that says where it is. Nothing else - not the title, not a bracketed prefix, not the folder - is authoritative.

| Status | Means | Required in the header / summary |
|---|---|---|
| `open` | being worked, not yet reproduced | - |
| `confirmed` | REPRODUCED live, not yet drafted or reviewed | what is blocking the draft |
| `ready` | reviewed and cleared, waiting on the submit call | - |
| `submitted` | sent to the program | **`Submitted:` with the report id, date, severity** |
| `awarded` | submitted AND paid a bounty | **`Awarded:` with the date, plus the `Submitted:` row it keeps** |
| `killed` | will not be reported, or came back closed | why, with the evidence, and the reopen condition |
| `parked` | real, waiting on something outside your control | one line on what unparks it |

**`confirmed` is not a resting place.** It means reproduced and NOT yet drafted, so a lead sitting there needs a reason. A lead must never sit at `confirmed` because a technical question is unresolved - an unresolved question is what `confirmed` is FOR, and the answer is what moves it forward.

**On submission**, three things move together: the status becomes `submitted` with a `Submitted:` line carrying the id; the report file is renamed to include the id; and any `## Next` section is replaced by `## Submitted`.

**On a closed-without-action outcome** - duplicate, informative, not-applicable, spam - the lead becomes `killed`, not left `submitted`. A report that comes back duplicate is a lead that will never be reported, which is the definition of `killed`. Record the id and the closing state, rewrite the decision summary to say so, and say plainly that it must not be re-reported. A report that merely RESOLVES is not this case: resolved means fixed, and a fix is not a payment, so the lead stays `submitted`.

**On a bounty landing**, and only then, the lead moves to `awarded`. Keep the `Submitted` row - the report id is still the join. **The `Awarded` row carries a DATE and no figure.** The amount belongs on the report, which the app syncs from the program's API; a number typed into a lead is a hand-recorded expectation, and a hand-recorded expectation promoted to a confirmed award is how a running total goes wrong.

## ONE LEAD PER FILE

**A lead file describes exactly one finding.** A file holding a sweep, a campaign, a queue or a round of results is NOT a lead, however many real findings it contains, and it must never carry a `**Status:**` marker. A sweep marked `killed` silently buries any live lead sitting inside it, and one row then hides several findings.

The rule that follows: **the moment a note describes more than one finding, it stops being a lead and becomes a hunt log.** A finding proven dead still gets its OWN lead file with `**Status:** killed`, because a kill is only useful if it is individually findable when someone asks "have we tried this".

## Hunt logs and session notes

Round logs, sweeps, campaign trackers, queues and dedup analyses go under `notes/` with a dated filename and **no `**Status:**` marker, ever**:

```
<target>/notes/hunt-log/<YYYY-MM-DD>-<slug>.md
```

- **Dated in the filename**, so the sequence of a hunt is readable without opening anything.
- **No status marker** - it is the only thing deciding a file is a lead. Without it the file stays indexed and fully searchable, it simply stops pretending to be one finding.
- **Open with one line saying what it is**, so nobody re-adds a marker later.
- Each finding inside gets its OWN lead file, and the log links to it with `[[lead-name]]`. The log keeps the narrative; the leads carry the status.

## Section order

The decision summary comes first, above the header table (see below). After it, not every lead needs every section. Use these names in this order, and skip what does not apply rather than inventing a synonym - `THE DEFECT`, `Root cause` and `ROOT CAUSE (file:line)` for one idea is what makes two leads look unrelated.

| Section | When | What goes in it |
|---|---|---|
| `## Claim` | always | Two or three sentences. What crosses which boundary, the minimum privilege, and what it does NOT reach. |
| `## Root cause` | once located | `file:line` per point. Quote the missing check. Name the guarded sibling. |
| `## Reproduced live` | once reproduced | The baseline 403 first, then the 200. Exact strings, not paraphrase. A table here when it is a matrix of operations. |
| `## Impact` | before drafting | What the attacker gets. Bound it: say what is NOT affected. |
| `## Dedup` | before drafting | CVE / advisory ids, upstream issues searched, verdict, and whether it is fixed on the main branch. |
| `## Honest weakness` | when one exists | Prose. The argument the vendor will reach for. |
| `## Submitted` | on submission | Id, date, severity, weakness, scope, report path. |
| `## Killed` | on kill | Prose, with the citation. The plain-English reason lives in the decision summary at the top. Never delete a killed lead. |
| `## Next` | while open | Prose or a short list, so the lead is resumable cold. |

Flat `##` only. Sentence case, not ALL CAPS. Prose wraps at 100 columns here, unlike a report.

## EVERY lead opens with a decision summary

**Above the header table**, directly under the title, every lead carries a bolded one-liner saying in plain English **why it is in the status it is in**. It sits above the table because it is the one line that answers "do I care about this right now", and a reader should not have to scroll a twelve-row table to reach it:

```markdown
# <REF> - Reporting API returns other tenants' records without an ownership check

**Decision summary:** An ordinary account reads any tenant's reports by passing a foreign tenantId,
because the endpoint checks authentication but never ownership. Reproduced twice from a clean lab;
the report is being drafted.

| | |
|---|---|
| **Status:** | confirmed |
...

## Claim
```

The status row says WHERE a lead is. The decision summary says WHY, and it is the only part of a lead written for someone who has not read the code: someone who was not on the hunt, has never opened the vendor's source, and wants to know in five seconds whether this lead matters to them right now.

Rules:

- **One or two sentences. Under 40 words.** If it needs three, the reason is being over-explained.
- **Name the state and the reason in the same breath.** "Documented behaviour, so it is not a flaw" beats "this was investigated and found to be by design".
- **No `file:line`, no class or method names, no privilege constants.** Those belong in the prose below. The reader who needs the summary is exactly the reader who does not know what those are.
- **Plain words over jargon.** "another team's data", "the vendor already fixed this", "the API documents this response".
- **Rewrite it whenever the status changes.** A stale summary under a moved status marker is worse than none, because it reads as current. A validation verdict is a status change: the summary carries the verdict, the one reason behind it, and any correction the validation made to the lead's own claim, with a pointer to the detail ("See `## Validation, <date>`").

What it must answer, per status:

| Status | The summary answers | Model |
|---|---|---|
| `open` | What are we chasing, and what is unresolved? | "A caller with only backup-creation rights appears able to destroy another team's backups. Seen once; being re-run from a clean lab to rule out leftover state." |
| `parked` | Why parked, and what would unpark it? | "Real, but it needs a second cluster to demonstrate. Parked until a remote-cluster lab exists." |
| `confirmed` | What was proved, and what holds up the draft? | "Reproduced twice from clean state: an attacker-named pipeline runs against another tenant's writes. The report is being drafted." |
| `submitted` | What was sent, and where does it stand? | "Sent 2026-01-15 as #0000000. Awaiting triage." |
| `awarded` | What was paid, and is anything owed? | "Paid on #0000000. Nothing outstanding; the fix shipped in the next release." |
| `killed` | Why will this never be reported? | See the kill reasons below. |

Almost every kill is one of five reasons:

| Reason | Model summary |
|---|---|
| Documented behaviour | "The documentation for this privilege already describes exactly this reach, so using it this way is the feature working as written." |
| Vendor accepted the risk | "The vendor was asked to restrict this and declined, so a report repeats a decision they have already made." |
| Guarded after all | "The action looked unauthorized, but the check is applied one layer down and the attempt is refused, so the boundary holds." |
| Duplicate | "Already sent as #0000000, and one fix closes both, so this cannot be filed separately." |
| Too small to report | "Real, but bounded to two integers a caller can already infer, so it would close informative and cost more credibility than it earns." |

**A report that shipped with a known gap says so here, in the same edit that moves the status to `submitted`**: "Sent 2026-01-15 as #0000000. The independent re-run was blocked by the lab, so this went on two clean reproductions plus a source audit; if the later check disagrees, comment on the report." A lead without this line is not finished.

## Lead bodies are PROSE

The header is the table. The BODY is prose. Write `## Claim`, `## Root cause`, `## Impact`, `## Honest weakness`, `## Killed` and `## Next` as paragraphs and short bullet lists, with `file:line` citations inline.

A table belongs in the body only where the content is genuinely tabular, which in practice means one place: a matrix of operations against results, where the repetition is the point.

```markdown
| Victim operation as superuser | Result after one squatted view |
|---|---|
| `PUT /vsq-new` | 400 `Invalid name [vsq-new], already exists as a view` |
| `POST /vsq-new/_doc` (auto-create) | 404 `no such index` - the view is never mentioned |
```

Put the refusals first in such a table, so the 403-versus-200 contrast reads in one glance. Verbatim API output stays in fenced code, never squeezed into a cell.

## Rules that carry over from the report standard

- ASCII only. No em dashes, en dashes or smart quotes.
- No `no <noun>` phrasing. Say what IS true, or use "without" / "lacks" / "neither ... nor". Verbatim API output is exempt.
- Do not argue with an imagined triager. State what the system does.
- Prove the ceiling before claiming it. A lead that says "unlimited" without a tested bound is how a report gets self-corrected in public.
- Never hard-wrap the decision summary or any rendered field. One paragraph, one line, exactly as in a report and for the same reason: the app renders it, and a hard wrap comes out ragged.

## Linking

`[[other-lead-name]]` resolves to a search in Quarry, so link related leads freely. A link to a lead that does not exist yet is a marker for work worth doing, not an error.

## Before you call a lead confirmed

- The PoC is self-verifying and exits non-zero on failure.
- **The PoC cleans up after itself completely.** A harness that deletes one object of seven reports phantom failures on a second run that look like the finding collapsing. Run it twice in a row and check it still passes.
- The `## Dedup` section has a verdict, not a to-do.
