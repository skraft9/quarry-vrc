# Security Response Standard

How this project responds to a code-scanning alert (CodeQL, on `main`) or any other reported
security finding: how to triage it, how to record the decision so it survives, and how to fix it
inside the existing PR conventions. It is a living standard; extend it as the process sharpens.

The goal is that every alert reaches one of exactly two resting states with a written reason
attached: **dismissed** (a false positive or an accepted non-issue) or **fixed** (a real defect
closed by a merged change). No alert is left sitting open with nobody having said why.

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

## Verify

After a batch, the open-alert count should equal only the alerts with a fix in flight. Confirm the
false positives read `dismissed` and the fixes auto-resolve after the release re-scan:

```bash
gh api "/repos/<owner>/<repo>/code-scanning/alerts?state=open&per_page=100" \
  | jq -r '.[] | "#\(.number) \(.rule.id)"'
```

An alert that is neither dismissed with a reason nor tracked by an open fix PR is an unfinished
triage, not an acceptable resting state.
