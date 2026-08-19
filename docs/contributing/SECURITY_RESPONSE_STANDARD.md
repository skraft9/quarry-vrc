# Security Response Standard

How this project responds to a security finding: how to triage it, how to record the decision so it
survives, and how to fix it inside the existing PR conventions. It is a living standard; extend it as
the process sharpens.

**A finding arrives one of two ways, and the response differs:**

- An **internal scan** - CodeQL code scanning on `main` - surfaces an issue in our own code, in the
  open. This is the default the sections below are written for.
- An **external report** - a researcher using GitHub private vulnerability reporting - arrives
  confidentially. It is handled under embargo until a fix and an advisory ship together. See
  [Externally reported vulnerabilities](#externally-reported-vulnerabilities) for where it differs.

The goal is the same for both: every finding reaches one of exactly two resting states with a written
reason attached: **dismissed** (a false positive or an accepted non-issue) or **fixed** (a real defect
closed by a merged change). No finding is left sitting open with nobody having said why.

## The `security:` change type

Security work is its own change type, alongside `feat:`, `fix:`, `docs:` and `chore:`. Any PR whose
purpose is to harden the product or close a reported weakness uses it:

- **`security:`** - a fix or hardening that closes a security finding or removes a weakness. Branch
  `security/<slug>`, PR title `security: <imperative subject>`, one finding-class per PR.

It follows every other rule in the Delivery workflow and PR conventions unchanged: branch off `dev`,
PR into `dev`, bump `VERSION` (patch for a contained hardening), SHA-pinned backticked links in the
body, `scripts/check-no-private-data.sh` green first. A pure write-up of a security decision with no
code change is still `docs:`, not `security:` - the prefix tracks the code, not the topic.

## Claim an alert before you work it

Assign yourself to the alert before you start, so two people never fix the same one twice. Assignment
is a UI action on the alert (the REST API does not expose code-scanning alert assignees yet, so it
cannot be scripted; set it in the Security tab).

Before picking one up, check who holds it. **If someone else is already assigned, leave it to them** -
unless you have a genuinely different fix worth putting forward. Competing fixes are welcome: propose
yours as its own `security:` PR, say how it differs, and let the reviewers compare them side by side
and keep the winning one. The assignee owns the triage; a second opinion is a proposal, not a
takeover.

## Triage

1. **Pull the alerts from the API, not the screenshot.** The API carries the rule id, the exact
   file and line, the data-flow message, and the severity:

   ```bash
   gh api "/repos/<owner>/<repo>/code-scanning/alerts?state=open&per_page=100" \
     | jq -r '.[] | "#\(.number)\t\(.rule.security_severity_level)\t\(.rule.id)\t\(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"'
   ```

2. **Read the code at the commit that was scanned, not at your checkout.** Each alert names its
   `most_recent_instance.commit_sha` and `ref`. If your working branch has drifted, the line numbers
   will not match. Confirm with `git diff --numstat <scanned-sha>..HEAD -- <path>`; when it is empty
   the lines line up and you can read your working tree directly.

3. **Follow the data flow to the sink before deciding.** For a flow query (injection, XSS,
   clear-text logging) pull the thread flow from the analysis SARIF and read the real source and
   sink, because the reported line is the sink and can sit one branch away from where the value is
   actually rendered:

   ```bash
   AID=$(gh api "/repos/<owner>/<repo>/code-scanning/analyses?ref=refs/heads/main&per_page=30" \
     | jq -r '[.[] | select(.category=="/language:<lang>")][0].id')
   gh api "/repos/<owner>/<repo>/code-scanning/analyses/$AID" -H "Accept: application/sarif+json" \
     | jq -r '.runs[0].results[] | select(.ruleId=="<rule>") | .codeFlows[0].threadFlows[0].locations[].location.physicalLocation.region.startLine'
   ```

4. **Classify each alert as one of:**
   - **Real** - the flow reaches a dangerous sink with no barrier in between. It gets fixed.
   - **False positive** - a barrier the tool does not model sits on the path (a validated
     containment check, a masking or hashing step before a log, an escaping renderer), or the rule's
     premise does not apply to this use. It gets dismissed with the barrier named.
   - **Won't fix / accepted** - real but the risk is accepted by design. Dismissed with the
     rationale, not silently.

   The bar for "false positive" is that you can point at the specific barrier or wrong premise. "It
   feels unlikely" is not a barrier. If you cannot name what stops the flow, treat it as real.

## Record the decision so it survives

A dismissal is not fire-and-forget. Two records are kept:

1. **On the alert.** Dismiss it with a reason and a comment. The comment, the reason, the actor and
   the timestamp attach to the alert timeline and are written to the repository audit log, so the
   decision is retrievable later even though code-scanning alerts have no free-text threaded
   comments.

   ```bash
   gh api --method PATCH "/repos/<owner>/<repo>/code-scanning/alerts/<n>" \
     -f state=dismissed \
     -f dismissed_reason="false positive" \
     -f dismissed_comment="<name the barrier or wrong premise; <=280 chars>"
   ```

   `dismissed_reason` is one of `false positive`, `won't fix`, `used in tests`. The comment is capped
   at **280 characters**, so it states the barrier and the verdict and nothing else.

2. **A retained ledger.** The 280-char comment cannot hold the full reasoning, and a public repo is
   not where operational triage notes belong. Keep an alert-by-alert ledger - number, rule, verdict,
   the reasoning, and the action taken (dismissed, or fixed by which PR) - in the operator's private
   notes, so a full copy survives outside the alert UI. This standard is the process; the ledger is
   the record of each batch.

## Fix the real ones

- Open a **`security:`** PR per finding-class (see above). Fix at the single choke point where you
  can: one `_no_crlf()` helper on the header path closes every response-splitting alert at once,
  rather than patching each call site.
- **Do not dismiss a real bug.** A code-scanning alert for a defect you are fixing stays **open**
  until the fix reaches the scanned branch (`main`) and CodeQL re-runs, at which point code scanning
  resolves it automatically. Dismissing it would hide a live bug. Landing the fix in `dev` alone does
  not close it; the alert clears on the next `dev` -> `main` release and re-scan.
- Reference the alert in the PR body by rule id and alert number in words (for example, "resolves
  the two `py/http-response-splitting` alerts"), not as `#N` - a bare `#N` renders as a pull-request
  or issue link, which is a different namespace from a code-scanning alert.

## The PR body shape

A `security:` PR follows the same body standard as any other PR, and that standard is a structured
body, never a wall of text. Lead with a one-line summary of what changed and why, then short
labelled groups, each group a one-line bullet (no hard wrap, because GitHub reflows):

- **What changed** - the edits, each code reference a backticked, SHA-pinned hyperlink.
- **Resolves** - the finding it closes, named by CWE and code-scanning rule id, alerts cited in
  words (not `#N`).
- **Verification** - the gate (`scripts/check-no-private-data.sh`), the compile or the suites, and
  the `VERSION` it lands.

## Versioning and the release note

- **Security fixes move the patch (subrevision), never the minor or major on their own.** A single
  security fix, or a coherent batch of them released together, ships at exactly one patch above the
  current tag (for example `1.4.0` -> `1.4.1`).
- **A batch shares one patch bump, not one per PR.** When several security PRs ship in the same
  release, the batch moves `VERSION` by a single patch: the first PR in the batch moves it, the rest
  leave it, and one release is cut at that version. This keeps releases incrementing by one with no
  gaps.
- **Security fixes ride a minor or major release only when folded in.** If the next batch release
  also carries development work (a `feat:`), the security fixes travel inside that release rather
  than forcing a separate patch. On their own, they are always a patch.
- **Every release that includes security work carries a `Security` section** in its notes (the
  release-note format already orders it after Fixes), recapping each security PR: `* PR #N - <what it
  hardened>`, the user-facing effect and the CWE, not the diff.

## Externally reported vulnerabilities

Everything above is about a scan of our own code, in the open. A vulnerability someone else finds is
different: it arrives confidentially and is handled under embargo. This section is the structure for
that; it will deepen as we actually field reports.

A researcher reports through GitHub **private vulnerability reporting** (the "Report a vulnerability"
button on the Security tab), which is enabled on this repo and described in the repo's
[`SECURITY.md`](../../SECURITY.md) policy, not as a public issue. From intake to disclosure, nothing
about the report goes in a public issue, PR, branch or commit until the fix and its advisory publish
together.

**Write to them like a person, not a legal department.** This is a solo open-source project, so every reply to a reporter - an acknowledgement, a request for detail, and above all a close - is a maintainer talking to a fellow developer: warm, direct, lightly formal, never a courtroom transcript. Closing something as out of scope or accepted-by-design is where tone matters most: give the real reason plainly, name the boundary and the exact condition that would put it back in scope, credit any hardening their report prompted, and thank them like you mean it. The substance still goes on record (the reason, per the "no finding without a written reason" rule); it is the stiffness that goes. The goal is a researcher who still wants to look at the code next month, not one who feels brushed off.

1. **Acknowledge receipt.** Tell the reporter it is received and being looked at, and keep it
   embargoed: nothing about it goes in a public issue, PR, branch or commit yet.
2. **Triage, validate and dupe-check.** Reproduce it, establish the affected versions, and decide
   real, duplicate or not-a-vulnerability. Score severity with CVSS. Keep the reporter posted and
   agree a disclosure timeline. A not-a-vuln or a duplicate is closed here with a reason to the
   reporter - the same "no finding is left without a written reason" rule as a dismissal - and nothing
   further is opened for it.
3. **Open a draft advisory, once it is confirmed real and not a duplicate.** Only now open a draft
   GitHub Security Advisory (GHSA) as the private workspace: it holds the write-up, the affected
   versions, the severity, and a private fork where the fix is built without exposing the issue in a
   public branch. A report that fails validation never reaches this step.
4. **Fix under embargo.** Build the fix in the advisory's private fork under the normal `security:` PR
   conventions, but do not push the branch or open the PR in the open until disclosure. The fix rides
   a release like any other security fix: a patch, batched if it is part of a coherent set.
5. **Publish, request a CVE, credit.** When the fix is ready, publish the advisory and release the fix
   together. Request a CVE ID through the draft advisory (GitHub is a CNA and issues one), so the
   fixed version carries a referenceable id. Credit the reporter unless they ask otherwise, and link
   the advisory from the release note's Security section.
6. **Decide whether it even needs a CVE.** A confirmed vulnerability in a RELEASED version that a user
   must act on wants a CVE and a published advisory. One fixed before it ever shipped, or that only
   touches the dev process rather than a release, is fixed and noted but needs no CVE. When unsure,
   lean toward publishing the advisory: a CVE is cheap, an unannounced real vulnerability is not.

## What is safe to publish

The triage record is public for internal scan findings and private for external reports until
disclosure. Draw the line by what a reader could DO with what is written:

- **Safe in the public repo:** that a scan alert was a false positive and the barrier that makes it
  so; a fixed issue in our own code after the fix has shipped; a dismissal comment reasoning about our
  own source. quarry-vrc is open source, so describing our own code is not a leak.
- **Never in the public repo:** a working exploit or weaponizable repro for an UNFIXED issue; the
  details of an externally reported vulnerability before its fix and advisory ship; a reporter's
  identity or contact they have not agreed to publish; and anything the no-private-data gate already
  rejects.
- **After disclosure**, the advisory is the public record; the public repo may reference it, while the
  full private triage detail stays in the operator's private notes, not here.

Rule of thumb: nothing that helps someone weaponize an unpatched issue, and nothing personal about a
reporter, goes in a public commit, comment or file.

## Verify

After a batch, the open-alert count should equal only the alerts with a fix in flight. Confirm the
false positives read `dismissed` and the fixes auto-resolve after the release re-scan:

```bash
gh api "/repos/<owner>/<repo>/code-scanning/alerts?state=open&per_page=100" \
  | jq -r '.[] | "#\(.number) \(.rule.id)"'
```

An alert that is neither dismissed with a reason nor tracked by an open fix PR is an unfinished
triage, not an acceptable resting state.
