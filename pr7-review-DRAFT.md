## Review of PR #7 - approve-with-changes

@matty69v Thanks for a substantial and cleanly structured contribution that adds a whole capability the hacker REST API cannot reach. The GraphQL client is stdlib only, the routes are correctly scope-gated and audited, the session token is stored write-only and masked, and the frontend binds every server string through the `textContent` helper so none of it can XSS. I am approving with changes rather than approving outright because one code path crashes on an expired session that GraphQL returns as `me: null`, and because the GraphQL field and mutation names are not verified against a live token, the same unverified-endpoint risk PR #6 carried with `report_intents`. The crash is a one-line fix we are making ourselves; the schema verification is passed back to you as a follow-up and accepted as a documented risk so the batch keeps moving.

## Summary of the PR

- **New module.** [`core/h1_graphql.py`](https://github.com/skraft9/quarry-vrc/blob/ba23ffb5102a59b74660c9e03b4cd4bf6ba3f986/core/h1_graphql.py) (517 lines) is a stdlib GraphQL client for `hackerone.com/graphql` covering program invitations, report collaborations, invite-collaborator and bounty-split, with a matching CLI.
- **Server routes.** Eight routes land in [`core/server.py`](https://github.com/skraft9/quarry-vrc/blob/ba23ffb5102a59b74660c9e03b4cd4bf6ba3f986/core/server.py): session status GET and set PUT, invitations list/accept/reject, and collabs list/accept/invite/split; every mutating route carries `scope="write"` and audits.
- **Frontend.** An Invitations and Collaborations card in [`static/app.js`](https://github.com/skraft9/quarry-vrc/blob/ba23ffb5102a59b74660c9e03b4cd4bf6ba3f986/static/app.js) (218 lines) plus 10 lines of [`static/app.css`](https://github.com/skraft9/quarry-vrc/blob/ba23ffb5102a59b74660c9e03b4cd4bf6ba3f986/static/app.css), wired into the Integrations tab through the `INTEGRATIONS` array.
- **VERSION.** [`VERSION`](https://github.com/skraft9/quarry-vrc/blob/ba23ffb5102a59b74660c9e03b4cd4bf6ba3f986/VERSION) moves 1.3.5 to 1.4.0, which matches the current batch target on `dev`.

## What works well

- **The auth model matches the repo.** The session token is stored write-only in `secrets.json` (mode 0600, atomic temp-and-replace), masked in `status()`, and never returned by any endpoint, exactly the discipline the existing API token already follows.
- **The routes are correctly gated.** Every mutating route carries `scope="write"` and the reads default to read-required; the `route` decorator wraps each pattern in `^...$`, so the new static paths cannot be prefix-matched.
- **Writes are audited.** Each write route calls `common.audit` with the correct positional signature, so session-set, accept, reject, invite and split all leave an audit trail.
- **There is no injection surface.** GraphQL variables are parameterized through `$input`, the endpoint URL is a hardcoded constant so there is no SSRF, and `report_id` and `username` are never interpolated into a query string.
- **The frontend is XSS-safe.** Every server-derived string (`program_name`, `report_title`, `invited_by`) is set through the `el()` `text` binding, which is `textContent`; the new code uses no `html:` binding anywhere.
- **Errors are shaped, not swallowed at the client boundary.** 401 and 403 map to a clear "session expired, grab a fresh cookie" message, `URLError` is caught, and top-level GraphQL `errors` are surfaced as `GQLError`.
- **Input hygiene is good.** The token field is `type=password` with autocomplete off, and the split percentage is validated as an integer 0-100 server-side before it reaches the API.
- **PR hygiene is right.** Base is `dev`, branch is `feat/h1-invitations`, the title is `feat:`, and the body uses SHA-pinned backticked links.

## Issues to address

- **The list endpoints crash on an expired session.** In `core/h1_graphql.py`, `list_program_invitations` ([line 180](https://github.com/skraft9/quarry-vrc/blob/ba23ffb5102a59b74660c9e03b4cd4bf6ba3f986/core/h1_graphql.py#L180)) and `list_collab_invitations` ([line 280](https://github.com/skraft9/quarry-vrc/blob/ba23ffb5102a59b74660c9e03b4cd4bf6ba3f986/core/h1_graphql.py#L280)) read `data.get("me", {}).get(...)`; when HackerOne returns `{"data": {"me": null}}`, the shape an expired-but-stored session returns without a top-level error, `.get("me", {})` yields `None` and the chained `.get` raises `AttributeError`, which is not a `GQLError`, so the route's `except gql.GQLError` misses it and the client gets a 500 instead of a clean "session expired". Fix: `(data.get("me") or {}).get(...)` in both, matching `test_session` which already does `me = data.get("me") or {}` at [line 142](https://github.com/skraft9/quarry-vrc/blob/ba23ffb5102a59b74660c9e03b4cd4bf6ba3f986/core/h1_graphql.py#L142). Maintainer decision: we fix this ourselves, one line each, safe.
- **The GraphQL schema is unverified against a live token.** The query fields and mutation and input names in `core/h1_graphql.py` (`soft_launch_invitations`, `collaboration_invitations`, `acceptInvitation` / `AcceptInvitationInput`, `acceptReportCollaboratorInvitation`, `createReportCollaborator` / `CreateReportCollaboratorInput`, `updateReportCollaboratorSplit` / `UpdateReportCollaboratorSplitInput`, `split_percentage`, `bounty_weight`) are not confirmed against `hackerone.com/graphql`, the same unverified-endpoint risk PR #6 carried, and a wrong name fails only at runtime. Fix: confirm each query and mutation against a live `__Host-session` token before relying on it, or annotate the unverified ones. Maintainer decision: passed back to you and accepted meanwhile as a documented risk, not a hard block, so the batch keeps moving.

## Suggestions

- **Reuse `h1.py`'s secrets helpers.** `core/h1_graphql.py` re-implements `load_secrets`, `save_secrets` and a masking function that `core/h1.py` already provides; importing them keeps the two from drifting, and the mask thresholds already differ (12 versus 8).
- **Do not swallow the list errors to empty.** In `static/app.js`, `loadInvitations` catches a failed `/h1/invitations` or `/h1/collabs` into `{ items: [] }`, so an expired session or a 502 renders as "No pending invitations"; surfacing the error would make the symptom of the crash above visible instead of silent.
- **Give the invite and split form feedback on success.** The invite and split handlers toast but leave the inputs populated and do not reload, where the accept and reject flows reload; clearing or refreshing on success would make the two consistent.

## House-rule and standards check

- **ASCII punctuation:** pass. The new module and the added `app.js`, `app.css` and `server.py` lines are ASCII-clean; the em dashes a grep reports are all pre-existing lines outside this PR.
- **Standard library only:** pass. `urllib`, `json`, `argparse`, `os`, `sys`, `time` plus the in-repo `common`; no pip, npm or CDN.
- **No private data:** pass. `bash scripts/check-no-private-data.sh` exits 0.
- **No committed secrets:** pass. The session token lands only in `secrets.json` (0600, gitignored) and never appears in the diff; `status()` returns a mask only.
- **No AI attribution:** pass. None in the files or the PR body.
- **PR conventions:** pass. Base `dev`, branch `feat/h1-invitations`, title `feat:`, SHA-pinned backticked links in the body.
- **VERSION:** pass. 1.4.0 matches the batch target (`dev` is already at 1.4.0 from #5 and #6), so no release number is skipped.
- **Both suites green:** not exercisable. The public repo has no test suites yet (`tests/` is absent while the app-code migration is in progress), so the "both suites green" gate cannot be run against this PR.
- **Route anchoring:** pass. The `route` decorator wraps every pattern in `^...$`, so the new static paths are fully anchored.

## Verdict

approve-with-changes. Before merge: we apply the `me: null` fix in `list_program_invitations` and `list_collab_invitations` ourselves; you confirm the GraphQL field and mutation names against a live token as a follow-up, accepted in the meantime as a documented risk carried the same way PR #6's was; the three suggestions are optional polish that does not block the merge.
