# Working on Quarry VRC (public)

Instructions for Claude Code / contributor sessions in this repo. This is the PUBLIC, open-source
build. It mirrors the private codebase's discipline, with two deliberate differences: releases are
cut on the GitHub Releases page, and **nothing operator-specific is ever committed**.

## Nothing personal ships

This repo is public (or will be). It must never contain any operator's HackerOne username, API
credentials, program handles, reports, leads, payloads or research. Everything is bring-your-own at
runtime and lands only on the (git-ignored) data/workspace/payloads volumes. If you add a file that
could hold a credential or personal data, add it to `.gitignore` in the same commit.

**This was violated once and it must not recur.** The app code was forked from a private codebase
and shipped real references - an engineer's handle in a denylist, program handles used as code
examples, an operator's home-directory workspace paths, and a whole product-alias table for one
private target. The code carries **placeholders** (`ExampleVendor`, `example-connector-*`,
`vulns_example`, `#0000000`, `<lab-host>`) precisely so a real name is an obvious outlier. Keep it
that way: never paste a real program name, handle, path, report id or count into code or a comment -
use the placeholder.

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

1. **Branch off `dev`**, never commit directly to `main` or `dev`. Names: `fix/`, `feat/`, `docs/`.
2. **Open a PR into `dev`** (`gh pr create --base dev`). Both suites green first when the app code is
   present (`python3 tests/test_smoke.py`, `node tests/test_render.js`). Prefix the title `feat:` or
   `fix:`. Bump `VERSION` in the same commit (minor for behaviour, patch for a fix/docs pass).
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

A `dev` -> `main` merge is a **release**. Unlike the private repo, the public repo publishes each
release through the GitHub Releases feature so users get a versioned, downloadable artifact and notes:

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

The end state after a release is `main`, `dev` and nothing else - sweep merged branches.

### Release-note format (the standard)

The canonical, citable version lives in the private repo at `docs/standards/RELEASE_NOTE_STANDARD.md`;
this is the self-contained copy for the public repo. A release note is real software release notes,
not a one-line summary. Structure:

1. A `## vX.Y.Z - <Headline In Title Case>` title - capitalize the first letter of every word - then
   one paragraph saying what shipped and why it matters.
2. Sections in THIS order, and **print only the sections that have content** (omit an empty one
   entirely): **Features**, **Fixes**, **Security**, **Performance**, **Docs**, **Upgrade notes**, and
   **Contributors** last.
3. A bullet tied to a PR LEADS with the number, `* #N - <what it did>`, and describes the user-facing
   impact, not the diff. GitHub renders `#N` as the PR's own title in a hyperlink, so do NOT restate
   that title: no bold subject repeating it, no re-typing it. A bullet with no PR may bold its subject.
4. **Upgrade notes** always says how to update and anything a user must do or know before upgrading.
5. **Contributors** closes the notes whenever an outside contributor shipped in the release: tag each
   by handle and list their PRs, for example `* @handle - #6, #7`. It is a courtesy, included on every
   release that carries external work.

This is a living standard; extend it deliberately over time rather than letting notes drift back to
one-liners.

## House rules

- **ASCII punctuation.** No em dashes, en dashes or smart quotes in source or prose.
- **Standard library only.** No pip, no npm, no CDN. It is a defining property of the project.
- **Never commit** `.env`, `config.json`, `secrets.json`, `tls/`, `index.db`, or any workspace/payload
  content. `.gitignore` covers the known ones.
- **No AI attribution** in commits, PR bodies or files.
