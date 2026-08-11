# Working on Quarry VRC (public)

> **This file is build instructions for developers and AI coding agents working ON quarry-vrc. It is
> not a user guide.** If you are running quarry-vrc to hunt, start at the [README](README.md) and
> [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md). Human contributors: the front door is
> [`CONTRIBUTING.md`](CONTRIBUTING.md); this file is the fuller, agent-oriented version of the same
> process.

Instructions for Claude Code and contributor sessions in this repo. Quarry VRC is an open-source,
self-hosted console. Nothing personal or credential-bearing is ever committed, and releases are cut
on the GitHub Releases page.

## Nothing personal ships

This repo is open source. It must never contain anyone's HackerOne username, API credentials, program
handles, reports, leads, payloads or research. Everything is bring-your-own at runtime and lands only
on the (git-ignored) data/workspace/payloads volumes. If you add a file that could hold a credential
or personal data, add it to `.gitignore` in the same commit.

**Use the placeholders.** The code carries `ExampleVendor`, `example-connector-*`, `vulns_example`,
`#0000000` and `<lab-host>` precisely so a real name is an obvious outlier. Keep it that way: never
paste a real program name, handle, path, report id or count into code or a comment - use the
placeholder.

**The gate: [`scripts/check-no-private-data.sh`](scripts/check-no-private-data.sh) MUST pass before
every push, PR and release.** It runs two layers:

1. Structural checks that catch whole classes of leak (operator home paths, RFC1918 IPs, 7+ digit
   report ids, non-placeholder `vulns_*` names, private keys / tokens, real emails) without naming
   anything private.
2. A literal `.private-denylist` you keep OUTSIDE git (it is `.gitignore`d) - one string per line of
   your live program handles, vendor names and identifiers. The committed script cannot enumerate
   those without leaking them, so they live only on your machine and in CI as a secret. Maintain it
   as you take on new programs.

CI runs the structural layer on every PR (`.github/workflows/no-private-data.yml`); the denylist
layer is your local pre-push responsibility. Run `bash scripts/check-no-private-data.sh` yourself
before opening any PR or cutting any release.

## Delivery workflow

Two long-lived branches:

- **`dev`** - staging. Work lands here first.
- **`main`** - what ships. `dev` merges into it as a release.

1. **Branch off `dev`**, never commit directly to `main` or `dev`. Name the branch for its change
   type: `feat/`, `fix/`, `docs/`, `chore/`, `security/` (see **PR and commit conventions** below).
2. **Open a PR into `dev`** (`gh pr create --base dev`). Both suites green first when the app code is
   present (`python3 tests/test_smoke.py`, `node tests/test_render.js`). Prefix the title with the
   change type (`feat:`, `fix:`, `docs:`, `chore:`, `security:`). Bump `VERSION` in the same commit
   (minor for behaviour, patch for a fix/docs/chore/security pass; a security batch shares one patch
   bump, see the Versioning note below).
3. **One PR per KIND of change** - a feature and a docs change never share a PR.
4. **Every code reference in a PR body (and every release note) is a backticked hyperlink pinned to
   the commit SHA.** Write ``[`server.py`](https://github.com/skraft9/quarry-vrc/blob/<40-char-sha>/server.py)``
   - the backticks INSIDE the link so a path still reads as code - never a bare path, and never a
   branch name (branch links 404 because our branch names contain slashes, and die on merge anyway).
   Get the SHA with `git rev-parse HEAD` before opening the PR; add `#L<n>` or `#L<a>-L<b>` to point
   at a line. Do NOT hard-wrap a PR body: one long line per paragraph, because GitHub reflows it.
5. **Cite every PR by its NUMBER** (`#12`) and say what it DID. GitHub renders `#12` as the PR's own
   title, so do not repeat the title - the number and the "what it did" are how a reader later finds
   when a behaviour changed. Release notes list the included PRs this way.

## Releases go on the GitHub Releases page

A `dev` -> `main` merge is a **release**, published through the GitHub Releases feature so users get a
versioned, downloadable artifact and notes:

```bash
gh pr create --base main --head dev --title "v1.1.0 - <what shipped>"
# after merge, from main:
gh release create v1.1.0 --title "v1.1.0 - <what shipped>" --notes "..."
```

**Batch a task list into one release.** Land each change as its own PR into `dev`, then promote to
`main` and cut ONE GitHub Release at the end, rather than releasing after every merge.

**Versioning.** Everything pre-official is BETA on the `1.x` line, starting at **1.0.0** and moving
up. The **official public launch opens the `2.0` train**, and that release is packaged on the
Releases page. **Every version and sub-version gets its own tag and release, incrementing by one
with no gaps** - the next release is exactly one step above the current tag. A gap reads as a lost
release; it usually comes from batching UNRELATED changes into one release (which consumes the
skipped numbers). Batch a coherent task list, never unrelated work.

**Security fixes move the patch, never the minor or major on their own.** A single security fix, or
a coherent batch of them released together, ships at exactly one patch above the current tag (for
example `1.4.0` -> `1.4.1`). A batch shares ONE patch bump, not one per PR: the first security PR in
the batch moves `VERSION`, the rest leave it, and one release is cut at that version. Security fixes
ride a minor or major release only when folded into the next batch release that also carries
development work; on their own they are always a patch. Every release that includes security work
carries a **Security** section in its notes recapping each security PR (see the format below).

The end state after a release is `main`, `dev` and nothing else - sweep merged branches.

### Release-note format (the standard)

A release note is real software release notes, not a one-line summary. Structure:

1. A `## vX.Y.Z - <Headline In Title Case>` title - capitalize the first letter of every word - then
   one paragraph saying what shipped and why it matters.
2. Sections in THIS order, and **print only the sections that have content** (omit an empty one
   entirely): **Features**, **Fixes**, **Security**, **Performance**, **Docs**, **Upgrade notes**, and
   **Contributors** last.
3. A bullet tied to a PR LEADS with `PR #N`, `* PR #N - <what it did>`, and describes the user-facing
   impact, not the diff. Use the `PR ` prefix: a GitHub RELEASE body does not preview a bare `#N` the
   way a PR or issue body does, so `PR #N` is a clear, self-describing reference that still auto-links.
   Do NOT restate the PR's own title: no bold subject repeating it, no re-typing it. A bullet with no
   PR may bold its subject.
4. **Upgrade notes** always says how to update and anything a user must do or know before upgrading.
5. **Contributors** closes the notes whenever an outside contributor shipped in the release: tag each
   by handle and list their PRs, for example `* @handle - PR #6, PR #7`. It is a courtesy, included on
   every release that carries external work.

This is a living standard; extend it deliberately over time rather than letting notes drift back to
one-liners.

## House rules

- **ASCII punctuation.** No em dashes, en dashes or smart quotes in source or prose.
- **Standard library only.** No pip, no npm, no CDN. It is a defining property of the project.
- **Never commit** `.env`, `config.json`, `secrets.json`, `tls/`, `index.db`, or any workspace/payload
  content. `.gitignore` covers the known ones.
- **No AI attribution** in commits, PR bodies or files.

## PR and commit conventions

Uniform history and a readable PR list come from one rule: **every branch, commit and PR title starts
with a change-type prefix, and the branch carries the same prefix.** Pick the one that fits:

- **`feat:`** - a new feature or a change in behaviour. Branch `feat/<slug>`.
- **`fix:`** - a bug fix. Branch `fix/<slug>`.
- **`docs:`** - documentation only, no behaviour change. Branch `docs/<slug>`.
- **`chore:`** - tooling, dependencies, config or cleanup, with no user-facing behaviour change.
  Branch `chore/<slug>`.
- **`security:`** - a fix or hardening that closes a security finding (a code-scanning alert or a
  reported weakness) or removes a security weakness. Branch `security/<slug>`. It is its own kind so
  the history and release notes surface security work. Handling triage, dismissals and fixes end to
  end is [`docs/contributing/SECURITY_RESPONSE_STANDARD.md`](docs/contributing/SECURITY_RESPONSE_STANDARD.md).
- **`refactor:`**, **`perf:`**, **`test:`** - use when one fits better, same branch-matches-prefix rule.

Then the look of the subject and the PR:

- **Imperative, lower-case subject after the prefix:** `feat: add the labs tab`, not
  `feat: Added the Labs Tab`. No trailing period.
- **One prefix per PR.** If the title needs `and` between two prefixes, it is two PRs (see step 3 of
  the Delivery workflow).
- **A structured body, not a wall of text.** Lead with a one-line summary of what changed and why,
  then short labelled groups, each group a one-line bullet (no hard wrap): **What changed** (edits,
  each code reference a SHA-pinned backticked link), **Resolves** (the issue, finding or alert it
  closes), **Verification** (gate, compile, suites, the `VERSION` it lands). A `security:` body also
  names the CWE and the code-scanning rule id, and cites alerts in words, not as `#N`.
- **Match the release-note verb to the prefix.** A `feat:` PR is a Features bullet, a `fix:` a Fixes
  bullet, a `security:` a Security bullet, and so on, so the notes fall out of the history.

The rest of the PR shape - target `dev`, SHA-pinned backticked links, cite PRs by number, bump
`VERSION` - lives in the **Delivery workflow** above; this section is only about the prefix and the
uniform look it buys.
