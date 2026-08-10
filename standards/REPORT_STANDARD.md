# Report Standard

How a report to a bug bounty program is written. This is the authority: when it disagrees with a habit visible in an older report, this file wins. Read it BEFORE drafting, not after.

A report is read by a triager working a queue, and increasingly by an automated pre-screen before any human sees it (see Automated triage below). Every rule here serves one goal: a triager can reproduce the finding, confirm it is real, and judge its severity without asking you a question. Placeholders in the examples (`ExampleVendor`, `<target>`, `<REF>`, `#0000000`, `<lab-host>`) stand in for your own program details; never paste a real host, credential, or lab address into a report.

## The shape

Flat `##` headings only, in this order. Impact always comes BEFORE Remediation.

```
# <Title>                 12-15 words, one clause, no colon, names the target product

**Summary:** ...          bold inline label, NOT a `## Summary` heading; two paragraphs

**Code path (<product> <version>), `path/to/File.ext`:**    authz/BAC findings especially
* `:35-41`: the disabled or missing check, quoted
* `:73`: the unscoped client / unauthorized execution context
* `:90-104`: where attacker-controlled data lands
* contrast line: name the SIBLING routes in the same file that ARE guarded

## Preconditions
## Steps To Reproduce
## Proof of Impact
## Impact
## Remediation
```

Rules that hold in every report:

- **`##` headings only, and they are FLAT.** Never `###` or deeper. `grep -n '^###' <file>` comes back empty.
- **`---` horizontal rules** separate the major blocks: after the code path, after Proof of Impact.
- **ASCII punctuation only.** No em dashes, no en dashes, no smart quotes.
- **Every prose paragraph is ONE long line.** A report is rendered by the program's editor, which reflows text, so a hard wrap at 80 or 100 columns comes out ragged on screen. Only fenced code and table rows keep their own line breaks. Check with `awk '!/^```/' <file> | awk '{print length}' | sort -rn | head -1`: wrapped prose tops out near 100, unwrapped runs to several hundred.
- **No severity rating and no CVSS vector string in the body.** The self-assigned CIA bullets under `## Impact` are the only severity statement, and they carry no numeric score (see Impact).

## Title

`<Weakness> in <Product> <Component> via <Specific Mechanism>`. Name the weakness class first, the exact component second, the mechanism third. No vague labels.

- Denial of Service in ExampleVendor Query Parser via Unbounded Expansion Parameter
- Missing Authorization in ExampleVendor Reporting API Step-Progress Endpoint
- Improper Access Control in ExampleVendor Monitor Health API via Unvalidated monitorId Parameter

**No colon in the title.** Everything after a colon belongs in the Summary. `grep -n '^# .*:' <file>` must come back empty on line 1.

**12-15 words, one clause. Count it, do not eyeball it.** One clause, full stop.

**The title must NAME the target somewhere in the line.** The product name or a recognised shorthand has to appear, because a triager reading a queue of titles cannot tell what a title is about otherwise, and neither can your own tracker. `Cross-Session Data Exposure in ExampleVendor Cache` is fine; `ACL Plugin Never Clears Group Headers` is not, because it names no product at all. Where the title reads best is a writing decision; that it names the target is not.

## Summary

Bold inline `**Summary:**`, NOT a `## Summary` heading. Two paragraphs, split at a specific seam. They do different jobs, and running them together buries the second.

**Paragraph one is the FINDING.** Exact product version. The component and its registering class with a `file:line`. What is unvalidated, unchecked or derived. What the attacker concretely gets. It ends on the defect itself: the guard that should apply, and the one-line reason it does not. A triager who reads only this paragraph knows what was found and where.

**Paragraph two is the ARGUMENT.** Why the defect is a defect rather than a choice: the sibling code that does it correctly, the documentation that promises the behaviour, the operator who read that documentation and was entitled to rely on it, and the minimum privilege needed stated as a concrete role or privilege name. This is the half that survives "working as intended", and it is the half that gets skimmed past when it is welded to the end of a long first paragraph.

Keep each paragraph to 2-3 sentences. Put a line break wherever the paragraph changes job. For authz findings, always include the sibling-contrast sentence ("Sibling routes in the same file are correctly guarded; this one is the outlier"): it pre-empts "works as designed" better than any argument.

## Steps To Reproduce

Bold lead-ins, not sub-headings: **Preconditions**, **Setup**, **Baseline**, **Step 1 ...**, **Verify Impact**. Open with ONE config block of fill-in placeholders that every later command reuses through shell variables.

Three rules make the section readable rather than merely correct:

1. **Code blocks contain COMMANDS ONLY.** No output, no expected output, no result annotations inline. A block a triager can paste and run, and nothing else in it.
2. **What a command returns goes in the PROSE SENTENCE above its block**, opening with "Expect". "Expect four documents with the restricted field absent from every one." The reader knows what they are looking for before they run anything, and the block stays clean.
3. **Every command carries a `#` comment above it saying WHAT IT DOES AND WHY.** Not what it returns, why it is being run at all. Without this a triager reads a wall of commands and cannot tell setup from evidence.

Formatting:

- **One command per line.** Wrap long ones with a trailing backslash at a sensible break.
- **No shell `for` loops and no inline `python3 -c` one-liners** to compress repeated setup. Write the commands out. A loop saves the author six lines and costs the reader the ability to run any single step on its own.
- **Open with ONE config block of placeholders**, commented `# Fill these in once. Every later command reuses them.`

  ```bash
  # Fill these in once. Every later command reuses them.
  API=https://<target-host>:8443
  ADMIN_PW=<admin-password>
  ATK_PW=<attacker-password>
  ```

- Group under bold lead-ins in the order a person actually works: **Confirm the shape**, **Seed the victim data**, **Write the restriction the administrator intends**, **Create the accounts**, **Baseline**, **Step 1..N**, **Teardown**.
- **Baseline first.** Show the attacker being denied through the legitimate path (a 403), then the same thing succeeding through the flawed path. The denied-versus-allowed contrast IS the proof, and it is usually the single most persuasive element in a report.
- **Include teardown.** A triager who cannot cleanly undo it is slower to try it.

**Every account, index, role and object the Proof of Impact uses must be CREATED here.** Every artefact the report names gets the command that creates it: the container with its image tag and every setting the finding needs, each role with its full definition, each user, the seeded documents with their canaries, and the teardown. A triager must be able to run this section start to finish without asking a question. Naming an end state ("two accounts, one restricted") without the commands that build it is how a reproducible finding closes not-applicable, which costs reputation without the finding ever being judged on merit.

Check it mechanically before shipping: every identifier the transcript references should be one the Setup creates. A quick `diff` of the identifiers named in `## Proof of Impact` against those created in `## Steps To Reproduce` catches an edit that dropped a negative-control account while the transcript still used it.

**Proof of Impact is ONE transcript, not a main block with expansions below it.** If a second mechanism is worth showing, it becomes a numbered beat inside the same block (`[3a]`, `[3b]`), because a reader who stops at the first block has then seen everything the report rests on. If it is not worth a beat, it is not evidence and it comes out.

Never fabricate or reconstruct a transcript from memory or from source reading. If the run was not made, the section is absent. A fabricated transcript is worse than an absent one.

## Proof of Impact

One short annotated transcript of the PoC actually running, placed directly after `## Steps To Reproduce`. The commands tell a triager what to type; this shows them what they should see, which is the difference between a report they have to reconstruct and one they can recognise.

**Structure it as four labelled beats.** A triager reads top to bottom once, so the transcript has to tell a story in that single pass. Label the beats literally, in the block, with a numbered comment. Every beat is one or two commands, never more.

```
# [1] DENIED - the attacker cannot reach the data the legitimate way
$ curl -s -u atk:$ATK_PW "$API/vic-1/_search"
# 403 action [read] is unauthorized for user [atk] ... on [vic-1]

# [2] THE ONE ACTION THE ATTACKER IS ALLOWED
$ curl -s -u atk:$ATK_PW -XPUT "$API/_template/evil" -d '{"patterns":["vic-*"], ...}'
# 200 {"acknowledged":true}          <- its privilege permits exactly this and nothing else

# [3] PAYOFF - the victim's data crosses
$ curl -s -u atk:$ATK_PW "$API/pwn-a/_search"
# 200 {"hits":[{"_index":"vic-1","_source":{"card":"CANARY-4111"}}]}
#     ^ written by a superuser into an index the attacker is refused on

# [4] STILL DENIED - the refusal is unchanged, so the account gained nothing
$ curl -s -u atk:$ATK_PW "$API/vic-1/_search"
# 403 ... unauthorized for user [atk] ... on [vic-1]
```

**Beat 4 is the one most often left out, and it matters most.** Repeating the original refusal AFTER the payoff proves the account never gained a privilege along the way, so the crossing is the defect rather than a misconfigured test role. It costs one line and closes the most common triage question.

**Beat 3 must contain a VALUE, not a status code.** `200 OK` proves nothing crossed. A canary string, a card number, a document the reader can see belongs to the victim: that is the payoff. Use an obvious canary (`CANARY-4111`, `ATTACKER-WROTE-THIS`) so the crossing is self-evident rather than something the reader has to reason about.

**One transcript, one claim.** An incidental disclosure (an error message that enumerates names, a dry-run that leaks) is a SEPARATE observation and goes after the four beats under its own one-line heading, or into Impact. Mixing it into the main block competes with the story and blurs the thing being proven.

**Annotate every line a reader must interpret.** `#` comments carry the reading, and `^` or `<-` points at the specific token that matters. What goes in: real captured output, trimmed. Verbatim status lines and error strings. The one or two field values that prove the boundary was crossed.

What stays out:

- **Lab addresses.** Placeholders only (`<target-host>`, `<lab-host>`, `<admin-password>`). A literal lab IP in a report is a leak, not a detail.
- **Full JSON dumps.** Elide with `...` down to the fields that carry the claim. A forty-line body proves nothing a three-line excerpt does not.
- **Timing, shard counts, version noise** unless the claim depends on it.
- **Anything invented.** See the fabrication rule above.

**Dummy data is expected and fine.** Lab usernames (`atk`, `viewer`), index names, canary values and obviously fake card numbers are not sensitive and make the transcript readable. Keep it under about fifteen lines: this section is a demonstration, not a log. If it needs more, the PoC script belongs in an attachment and this shows its verdict lines only.

## Impact

Open with the broken CONTROL, not with a scenario. The first line after the CWE states which security mechanism stopped working, not who could abuse it or what they would see. A triager reading a queue decides in one line whether this matters, and a narrative pretext makes them reconstruct the control themselves.

The formula:

```
[CWE-ID]. [Trigger or action] silently [bypasses | disables | overrides] [the specific security
boundary], exposing [the sensitive data or control surface].
```

- **BAD:** `CWE-863. An analyst given one feature privilege reads every field an administrator withheld, in every tenant.`
- **GOOD:** `CWE-863. Assigning a standard application privilege silently disables Field-Level Security enforcement on the restricted indices, exposing withheld fields across every tenant.`

Both are true and describe the same defect. The second names the control, so a triager knows immediately what failed. The first makes them infer it from a story.

Then, the rest of the section:

- **Name the CWE** (CWE-862 missing authorization, CWE-863 incorrect authorization, CWE-200 disclosure, CWE-789 uncontrolled allocation). State the privilege the attacker needed and what they got. State whether it reproduces on default configuration.
- **Self-assigned severity as a labelled bullet list**, one bullet per CIA dimension that WAS impacted, each followed by the concrete consequence:

  ```
  * **Confidentiality:** High. An ordinary authenticated account reads restricted records across every tenant.
  * **Integrity:** Low. The same path lets the account overwrite one derived field, bounded to values it can already infer.
  ```

  **The only two values are `High` and `Low`. Never write `Medium`.** `Medium` is the value a draft reaches for when the evidence was not pushed to a conclusion, and it tells a triager nothing they can act on. Decide which it is:

  - The dimension was demonstrated, and the bullet says what was demonstrated -> **High**.
  - It moves but the practical reach is narrow, and the bullet names the constraint -> **Low**.
  - It was not tested, or only reasoned about -> **the bullet is deleted**, not softened.

  **List only the dimensions actually impacted.** Do not write `* **Availability:** None.` A dimension that was not impacted is left out entirely; stating the nils pads the section and reads as hedging. This does not relax the separate rule that you may never IMPLY an impact you did not test for: if there is no crash, say nothing about availability rather than claiming one.

  **A rating is a claim, so it needs the same proof as any other.** Before writing a dimension, name the captured output that shows it. If that output does not exist, run it or delete the bullet. An Integrity rating asserting the attacker controlled ranking, on a validation that only proved text exfiltration, is exactly the failure this rule exists to stop.

- **Close with a Prerequisites-versus-Impact table**, two columns, one row per prerequisite:

  ```markdown
  | Prerequisite | Impact |
  |---|---|
  | An ordinary authenticated account | Reads restricted records across every tenant |
  | Any index privilege | Not required at any step |
  | Non-default configuration | None; reproduces on defaults |
  ```

- **Bound the claim honestly, including what is NOT affected.** If a related mechanism is unaffected, say so. No CVSS vector, no numeric score: the score is the program's to assign.

## Remediation

Last section. 2-4 imperative bullets, each opening with a bold label that names the action in imperative title case, then naming the exact file / class / function to change and what the corrected behaviour is:

```
* **Enforce the check in the shared handler:** move the authorization guard from the per-route
  callers into `RequestHandler.dispatch` so every route inherits it.
* **Validate the parameter before allocation:** bound `expansion` at parse time in `QueryParser`.
```

Add a "defense in depth" bullet where one genuinely applies. Be specific enough that a maintainer could act on it directly.

## Length

Write for a triager with a queue, not for the record. Assume the first draft is 40% too long and cut it before showing it to anyone.

**The test for every sentence:** does a triager need this to reproduce the bug, confirm it is real, or judge its severity? If not, delete it. Not shorten it, delete it.

Things that repeatedly fail that test and must be cut:

- **Restating the finding.** The Summary says it once. The code path, the steps and the Impact section each say it again in different words. Say it once, then show it.
- **Detectability and forensics.** "The operation is visible afterwards, audit logging records it." Nobody triaging asked. Cut unless the claim depends on it.
- **Provenance and metadata observations** that prove nothing about the boundary being crossed.
- **Splitting one observation across several numbered points.**
- **Narrating your own dedup work.** A sentence placing the finding against a sibling report is useful. A paragraph defending why it is not a duplicate is arguing before anyone objected.
- **Repeating a file path in full** after the first mention. Give the full path once, then the short form: `Handler.java:169`.
- **Hedges and framing.** "It is worth noting", "importantly", "as described above".

Always worth their space: exact version, exact privilege names, the verbatim denied and allowed responses, `file:line`, the negative control, and the reproduction commands. Reproduction instructions are never cut to hit a number.

Different programs have different appetites for length. Some triage teams are engineer-to-engineer and want dense `file:line` detail; others want a lean report of a few hundred words. Match the program's culture, but the cutting test above applies either way, and completeness of the reproduction is never traded against length. Measure prose with the whole `## Steps To Reproduce` section and every fenced block excluded:

```bash
awk '/^## Steps To Reproduce/{s=1} /^## Proof of Impact/{s=0} !s' <report> \
  | awk '/^```/{f=!f;next} !f' | wc -w
```

## Voice

State facts about the system. Never argue about your own argument.

Editorialising about your own reasoning ("This is not a complaint about a permissive default", "The comparison that settles it is", "This distinguishes the finding from") reads defensively before anyone has objected to anything. Say what the system does instead, and let the fact carry the argument:

- BAD: "This is not a complaint about a permissive default. The comparison that settles it is..."
- GOOD: "The encryption path is protected and the signature path is not. `decode` maintains a `was_encrypted` flag but no equivalent `was_signed` flag exists."

**No ranking or dramatising language.** "Most seriously", "worse still", "critically", "alarmingly" are all out. If one scenario carries more weight, put it first and let the facts do the ranking. The reader decides what is serious.

- BAD: "Most seriously, a role holding manage and no read at all recovers every document."
- GOOD: "A role holding manage and no read at all recovers every document."

**Avoid the "no <noun>" construction.** Writing a fact as an absence is weak. Say what IS true, or use "without", "lacks", "neither ... nor", "requires none".

- BAD: "and confers no index capability" -> GOOD: "and grants nothing on the index itself"
- BAD: "Unconditional, with no ownership or privilege test." -> GOOD: "Unconditional, without testing ownership or privilege."
- BAD: "Attacker holds no index privilege." -> GOOD: "Attacker lacks every index privilege."

The exception is verbatim API output. `# 404 no such index` is what the server said and is quoted, not written. Never edit a pasted response to satisfy a style rule. Check with `grep -noP '\b(no|No)\s+(?!longer)[a-z]+' <file>` and justify every hit that is left.

## Automated triage

Many programs now run a report through an automated or LLM-assisted pre-screen before a human reads it, and the machine's summary often becomes the primary triage record. Four things follow, and they are rules rather than observations. They cost nothing on a report that does not face automated triage, so apply them by default.

**Keep the PoC small and self-contained.** Automated reproduction commonly runs in a constrained sandbox: little memory, one core, a short timeout, and no internet. A PoC that overruns any of those produces "failed to reproduce", which is indistinguishable from a report that was never true. Carry a minimal reproduction that needs no network step (no package install, no download, no out-of-band callback), separate from any larger measurement your lab ran. State the larger measurement as measured; do not ask the triager to re-run it. An SSRF proven only by an external collaborator hit needs an internal-only proof beside it.

**Answer the exploitability questions in the report, because the pre-screen answers them either way.** Three recur and are usually decisive: who is the realistic attacker, described as a persona rather than a privilege string; does that attacker already hold equivalent access by legitimate means; and does this need non-default configuration. If the report does not answer them, the machine answers them from the source alone, and its answer becomes what the human reads first. Name the persona, say what it already holds, say whether the configuration is default.

**Never state a severity.** A claimed severity gives an anchoring check something to catch and buys scrutiny the report would not otherwise attract. State prerequisites, measurements and the resource; the score is theirs.

**Write nothing that reads as an instruction to an automated reader.** Prompt injection through report text is a named threat for these pipelines, and both the analysis and the review passes look for manipulation. Plain declarative prose about what was measured is what you already write; keep asides, imperatives and anything prompt-shaped out of it.

## Companion analysis doc

Where a finding carries more root-cause detail than belongs in the report, keep a separate analysis document alongside it (`<REF>-<slug>-rca.md`) rather than bloating the report. It is where the depth that would fail the Length test lives: a one-paragraph summary, the feature background, the annotated defect with `file:line`, why the error crosses the boundary, a minimal reproduction, the fix, and the generalisable pattern for your own future hunting. The report stays lean; the analysis doc carries the rest.

## One defect across several scopes is several reports

When the same defect appears in sibling implementations that are separate scopes (per-language SDKs, several client drivers, forks of one library), each gets its own report against its own scope. The first is written from scratch; the rest reuse it as a template.

Reused from the template: the shape, the four-beat transcript structure, the Remediation framing, and the prior-art paragraph where it genuinely covers this instance.

Rewritten every time, without exception:

- **The `file:line` citations and the version string.** They are different code.
- **The mechanism sentence in the Summary.** Two components reaching the same outcome by different routes are two mechanisms, and saying otherwise is the fastest way to look like a copy-paste filing.
- **The ceiling.** Reach differs per instance. One component creating a missing directory tree while its siblings refuse a missing directory is a severity difference, not a wording one.
- **Every claim about a DIFFERENT scope.** This is where family reports fail: a claim that a sibling is patched, inherited rather than checked, when it carries the same defect. If a sentence is about a component this report is not filed against, either prove it here or delete it.

## Before submitting

1. `grep -n '^###' <file>` empty; no em or en dashes; non-ASCII count zero.
2. No real password, no lab IP, no real host in the body or any transcript.
3. Title: no colon, 12-15 words counted, names the target.
4. Summary is two paragraphs (finding, then argument); authz findings carry the sibling-contrast sentence.
5. Steps To Reproduce builds every artefact the Proof of Impact uses, one command per line, no loops or one-liners.
6. Proof of Impact is one real transcript, four beats, a value in beat 3, the refusal repeated in beat 4.
7. Impact opens with the broken control, lists only impacted dimensions as `High` or `Low` bullets, and closes with the Prerequisites-versus-Impact table. No CVSS vector, no numeric score.
8. Impact comes BEFORE Remediation.
9. Dedup was actually performed against the vendor's issue tracker, open PRs, advisory feeds and settings reference. If a documented setting governs it or a closed issue accepts it, KILL the lead instead of reporting.
10. The impact bound is proven to exhaustion, not assumed.
11. A minimal reproduction fits a constrained sandbox and needs no network step. The persona, what it already holds, and whether the configuration is default are all stated.
