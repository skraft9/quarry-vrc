# Contributing to Quarry VRC

The one guide for anyone changing quarry-vrc's code or docs, human or AI coding agent. Security work
has its own standard in
[`docs/contributing/SECURITY_RESPONSE_STANDARD.md`](docs/contributing/SECURITY_RESPONSE_STANDARD.md).

If you are here to USE quarry-vrc rather than change it, you want the [README](README.md) and
[`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) instead. This file is for contributors.

## Nothing personal ships

This repo is open source. It must never contain a real HackerOne username, API credential, program
handle, report, lead or payload; all of that is bring-your-own at runtime and lands only on
git-ignored volumes. The code uses placeholders (`ExampleVendor`, `vulns_example`, `#0000000`,
`<lab-host>`) so a real name is an obvious outlier. Keep it that way, and the gate below enforces the
structural half of it.

## Branches

Two long-lived branches, and every change goes through a pull request so it stays reviewable and
revertable.

- **`dev`** - staging. Work lands here first.
- **`main`** - what ships. A `dev` -> `main` merge is a **release**, cut on the GitHub
  [Releases](https://github.com/skraft9/quarry-vrc/releases) page with a version tag and notes.

Never commit directly to `main` or `dev`.

```bash
git checkout dev && git pull
git checkout -b feat/short-description   # branch name carries the change-type prefix
# work, then open a PR into dev (not main):
gh pr create --base dev
```

## The one rule that shapes everything: a change-type prefix

Every branch, commit and PR title starts with the same change-type prefix, and the branch carries
it too. Pick the one that fits:

- **`feat:`** - a new feature or behaviour change. Branch `feat/<slug>`.
- **`fix:`** - a bug fix. Branch `fix/<slug>`.
- **`docs:`** - documentation only, no behaviour change. Branch `docs/<slug>`.
- **`chore:`** - tooling, config or cleanup, no user-facing behaviour change. Branch `chore/<slug>`.
- **`security:`** - a fix or hardening that closes a security finding (a code-scanning alert or a
  reported weakness). Branch `security/<slug>`. See the security response standard linked above.
- **`refactor:`**, **`perf:`**, **`test:`** - when one fits better, same branch-matches-prefix rule.

Keep the subject imperative and lower-case: `feat: add the labs tab`, not `feat: Added The Labs Tab`.

## PR shape

- **One PR per kind of change.** A feature and a docs change are two PRs, even in one sitting. If the
  title needs `and` between two prefixes, it is two PRs.
- **A structured body, not a wall of text.** Lead with a one-line summary of what changed and why,
  then short labelled groups, each a one-line bullet: **What changed** (edits, each code reference a
  backticked hyperlink pinned to the commit SHA), **Resolves** (the issue or finding it closes),
  **Verification** (the gate, the compile, the suites, the `VERSION` it lands).
- **Link the code you touch** as a backticked, SHA-pinned hyperlink, and cite other PRs by their
  number (GitHub renders `#N` as the PR's own title).
- **Bump `VERSION`** in the same PR: a feature moves the minor (`1.x.0`); a fix, docs, chore or
  security pass moves the patch (`1.0.x`).

## Versioning and releases

Versions run on the `1.x` beta line and move up by one with no gaps; the official launch opens the
`2.0` train. **Security fixes move the patch, never the minor or major on their own**, and a batch of
them released together shares ONE patch bump and ships as a single release with a **Security** section
in the notes. A `dev` -> `main` merge is titled with the version and cut on the Releases page.

## Release notes

A release note is real release notes, not a one-liner. Title it `## vX.Y.Z - <Headline In Title Case>`
with a sentence on what shipped, then only the sections that have content, in order: **Features**,
**Fixes**, **Security**, **Performance**, **Docs**, **Upgrade notes**, and **Contributors** last. A
bullet tied to a PR leads with `PR #N` and says what it did for the user, not the diff. Any release
that includes security work carries the **Security** section.

## Before every PR

- **Run [`scripts/check-no-private-data.sh`](scripts/check-no-private-data.sh)**; it gates against
  committing secrets or personal data. When the test suites are present, both green too.
- **Standard library only** - no pip, npm or CDN - and **ASCII punctuation** everywhere. Never commit
  a secret, `.env`, `config.json` or any workspace or payload content (`.gitignore` covers the known
  ones).
- **No AI attribution** in commits, PR bodies or files, and no reviewer-directed notes in them either:
  a PR body reads as authored change notes, not as a message to the maintainer.

## AI coding agents

Claude Code and other agents follow this same guide; there is no separate agent file. Read it, and the
[security response standard](docs/contributing/SECURITY_RESPONSE_STANDARD.md) for security work, before
making changes.
