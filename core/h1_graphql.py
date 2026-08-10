#!/usr/bin/env python3
"""HackerOne GraphQL API client for invitation and collaboration management. Stdlib only.

The hacker REST API (v1) has no endpoints for invitations or collaborator management.
Those operations live on the GraphQL API at hackerone.com/graphql, which requires a
browser session cookie rather than the API token used by h1.py.

AUTH: the `__Host-session` cookie from a logged-in HackerOne browser session. Stored
in secrets.json under hackerone.session_token, write-only like the API token. The user
pastes it once in the Integrations tab; it typically lasts several weeks before expiry.

Operations:
    - List and accept/reject private program invitations
    - List and accept report collaboration invitations
    - Invite a collaborator onto a report you own
    - Set the bounty split percentage on a collaboration

CLI:
    python3 h1_graphql.py --invitations             # list pending program invites
    python3 h1_graphql.py --collabs                  # list pending collab invites
    python3 h1_graphql.py --accept-invite TOKEN      # accept a program invite
    python3 h1_graphql.py --accept-collab TOKEN      # accept a collab invite
    python3 h1_graphql.py --add-collab REPORT_ID USER # invite collaborator to report
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import common

GRAPHQL_URL = "https://hackerone.com/graphql"
USER_AGENT = "quarry-h1-graphql/1.0"
HTTP_TIMEOUT = 30

SECRETS_PATH = os.path.join(common.APP_DIR, "secrets.json")


# ------------------------------------------------------------------ secrets

def load_secrets():
    if not os.path.exists(SECRETS_PATH):
        return {}
    try:
        with open(SECRETS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return {}


def save_secrets(data):
    tmp = SECRETS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SECRETS_PATH)
    os.chmod(SECRETS_PATH, 0o600)


def get_session():
    """Return the stored H1 session token, or None."""
    h1 = load_secrets().get("hackerone") or {}
    return h1.get("session_token") or None


def set_session(token):
    """Store the H1 session token. Write-only, never returned by any endpoint."""
    data = load_secrets()
    h1 = data.setdefault("hackerone", {})
    h1["session_token"] = token
    save_secrets(data)


def session_configured():
    return bool(get_session())


def masked_session():
    s = get_session()
    if not s:
        return ""
    if len(s) <= 12:
        return "*" * len(s)
    return s[:4] + "*" * (len(s) - 8) + s[-4:]


# ------------------------------------------------------------------ http

class GQLError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _graphql(query, variables=None, session_token=None):
    """Execute a GraphQL query against hackerone.com/graphql."""
    token = session_token or get_session()
    if not token:
        raise GQLError("no HackerOne session token stored. Paste one in the Integrations tab.")

    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "Cookie": "__Host-session=%s" % token,
    }

    req = urllib.request.Request(GRAPHQL_URL, data=payload, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            body = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = ""
        try:
            err = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        if e.code == 401 or e.code == 403:
            raise GQLError(
                "HackerOne session expired or invalid (HTTP %d). "
                "Grab a fresh __Host-session cookie from your browser." % e.code, code=e.code)
        raise GQLError("HackerOne GraphQL error (HTTP %d): %s" % (e.code, err), code=e.code)
    except urllib.error.URLError as e:
        raise GQLError("could not reach HackerOne: %s" % e.reason)

    errors = body.get("errors")
    if errors:
        msgs = [e.get("message", "") for e in errors]
        raise GQLError("GraphQL errors: %s" % "; ".join(msgs))

    return body.get("data") or {}


def test_session(session_token=None):
    """Verify the session token works by fetching the authenticated user."""
    data = _graphql("{ me { username } }", session_token=session_token)
    me = data.get("me") or {}
    username = me.get("username")
    if not username:
        raise GQLError("session token did not return a username")
    return {"ok": True, "username": username}


# ------------------------------------------------------------------ program invitations

def list_program_invitations(session_token=None):
    """List pending private program invitations.

    Returns a list of dicts with id, token, program handle, message, and dates.
    """
    query = """
    query {
      me {
        soft_launch_invitations(state: [open], first: 50) {
          total_count
          nodes {
            id
            token
            state
            expires_at
            created_at
            message
            team {
              handle
              name
              offers_bounties
              submission_state
            }
          }
        }
      }
    }
    """
    data = _graphql(query, session_token=session_token)
    invitations = data.get("me", {}).get("soft_launch_invitations", {})
    nodes = invitations.get("nodes") or []
    out = []
    for n in nodes:
        team = n.get("team") or {}
        out.append({
            "id": n.get("id") or "",
            "token": n.get("token") or "",
            "state": n.get("state") or "",
            "program_handle": team.get("handle") or "",
            "program_name": team.get("name") or "",
            "offers_bounties": bool(team.get("offers_bounties")),
            "submission_state": team.get("submission_state") or "",
            "message": n.get("message") or "",
            "expires_at": n.get("expires_at") or "",
            "created_at": n.get("created_at") or "",
        })
    return {"items": out, "total": invitations.get("total_count", len(out))}


def accept_program_invitation(token, session_token=None):
    """Accept a program invitation by its token. Returns success status."""
    mutation = """
    mutation AcceptInvitation($input: AcceptInvitationInput!) {
      acceptInvitation(input: $input) {
        was_successful
        errors(first: 5) {
          nodes {
            message
          }
        }
      }
    }
    """
    data = _graphql(mutation, {"input": {"token": token}}, session_token=session_token)
    result = data.get("acceptInvitation") or {}
    errors = _extract_errors(result)
    if errors:
        raise GQLError("accept failed: %s" % "; ".join(errors))
    return {"ok": result.get("was_successful", False), "token": token}


def reject_program_invitation(token, session_token=None):
    """Reject a program invitation by its token."""
    mutation = """
    mutation RejectInvitation($input: RejectInvitationInput!) {
      rejectInvitation(input: $input) {
        was_successful
        errors(first: 5) {
          nodes {
            message
          }
        }
      }
    }
    """
    data = _graphql(mutation, {"input": {"token": token}}, session_token=session_token)
    result = data.get("rejectInvitation") or {}
    errors = _extract_errors(result)
    if errors:
        raise GQLError("reject failed: %s" % "; ".join(errors))
    return {"ok": result.get("was_successful", False), "token": token}


# ------------------------------------------------------------------ collaboration invitations

def list_collab_invitations(session_token=None):
    """List pending report collaboration invitations.

    Returns a list of dicts with token, report info, inviter, and split percentage.
    """
    query = """
    query {
      me {
        collaboration_invitations(first: 50) {
          total_count
          nodes {
            id
            token
            state
            split_percentage
            bounty_weight
            invited_by {
              username
            }
            report {
              _id
              title
              url
              team {
                handle
                name
              }
            }
          }
        }
      }
    }
    """
    data = _graphql(query, session_token=session_token)
    invitations = data.get("me", {}).get("collaboration_invitations", {})
    nodes = invitations.get("nodes") or []
    out = []
    for n in nodes:
        report = n.get("report") or {}
        team = report.get("team") or {}
        invited_by = n.get("invited_by") or {}
        out.append({
            "id": n.get("id") or "",
            "token": n.get("token") or "",
            "state": n.get("state") or "",
            "report_id": report.get("_id") or "",
            "report_title": report.get("title") or "",
            "report_url": report.get("url") or "",
            "program_handle": team.get("handle") or "",
            "program_name": team.get("name") or "",
            "invited_by": invited_by.get("username") or "",
            "split_percentage": n.get("split_percentage"),
            "bounty_weight": n.get("bounty_weight"),
        })
    return {"items": out, "total": invitations.get("total_count", len(out))}


def accept_collab_invitation(token, session_token=None):
    """Accept a report collaboration invitation by its token."""
    mutation = """
    mutation AcceptCollab($input: AcceptReportCollaboratorInvitationInput!) {
      acceptReportCollaboratorInvitation(input: $input) {
        was_successful
        errors(first: 5) {
          nodes {
            message
          }
        }
      }
    }
    """
    data = _graphql(mutation, {"input": {"token": token}}, session_token=session_token)
    result = data.get("acceptReportCollaboratorInvitation") or {}
    errors = _extract_errors(result)
    if errors:
        raise GQLError("accept collab failed: %s" % "; ".join(errors))
    return {"ok": result.get("was_successful", False), "token": token}


# ------------------------------------------------------------------ invite collaborator to report

def invite_collaborator(report_id, username, session_token=None):
    """Invite a user as collaborator on a report you own.

    The report_id is the HackerOne report number (the one in the URL).
    """
    mutation = """
    mutation InviteCollab($input: CreateReportCollaboratorInput!) {
      createReportCollaborator(input: $input) {
        was_successful
        errors(first: 5) {
          nodes {
            message
          }
        }
      }
    }
    """
    variables = {
        "input": {
            "report_id": str(report_id),
            "username": username,
        }
    }
    data = _graphql(mutation, variables, session_token=session_token)
    result = data.get("createReportCollaborator") or {}
    errors = _extract_errors(result)
    if errors:
        raise GQLError("invite collaborator failed: %s" % "; ".join(errors))
    return {"ok": result.get("was_successful", False),
            "report_id": report_id, "username": username}


# ------------------------------------------------------------------ bounty split

def update_bounty_split(report_id, collaborator_username, percentage, session_token=None):
    """Update the bounty split percentage for a collaborator on a report.

    percentage is an integer 0-100 representing the collaborator's share.
    """
    mutation = """
    mutation UpdateSplit($input: UpdateReportCollaboratorSplitInput!) {
      updateReportCollaboratorSplit(input: $input) {
        was_successful
        errors(first: 5) {
          nodes {
            message
          }
        }
      }
    }
    """
    variables = {
        "input": {
            "report_id": str(report_id),
            "collaborator_username": collaborator_username,
            "split_percentage": float(percentage),
        }
    }
    data = _graphql(mutation, variables, session_token=session_token)
    result = data.get("updateReportCollaboratorSplit") or {}
    errors = _extract_errors(result)
    if errors:
        raise GQLError("update split failed: %s" % "; ".join(errors))
    return {"ok": result.get("was_successful", False),
            "report_id": report_id, "username": collaborator_username,
            "percentage": percentage}


# ------------------------------------------------------------------ status

def status():
    """Session state for the Integrations tab."""
    configured = session_configured()
    return {
        "configured": configured,
        "masked_session": masked_session() if configured else "",
    }


# ------------------------------------------------------------------ helpers

def _extract_errors(result):
    """Pull error messages from a GraphQL mutation response."""
    errors_node = result.get("errors") or {}
    nodes = errors_node.get("nodes") or []
    return [n.get("message", "") for n in nodes if n.get("message")]


# ------------------------------------------------------------------ CLI

def main():
    ap = argparse.ArgumentParser(description="HackerOne GraphQL: invitations and collaborations")
    ap.add_argument("--test", action="store_true",
                    help="verify the session token authenticates")
    ap.add_argument("--set-session", metavar="TOKEN",
                    help="store a session cookie token")
    ap.add_argument("--invitations", action="store_true",
                    help="list pending program invitations")
    ap.add_argument("--collabs", action="store_true",
                    help="list pending collaboration invitations")
    ap.add_argument("--accept-invite", metavar="TOKEN",
                    help="accept a program invitation")
    ap.add_argument("--reject-invite", metavar="TOKEN",
                    help="reject a program invitation")
    ap.add_argument("--accept-collab", metavar="TOKEN",
                    help="accept a collaboration invitation")
    ap.add_argument("--add-collab", nargs=2, metavar=("REPORT_ID", "USERNAME"),
                    help="invite a collaborator to a report")
    ap.add_argument("--set-split", nargs=3, metavar=("REPORT_ID", "USERNAME", "PERCENT"),
                    help="set the bounty split percentage for a collaborator")
    args = ap.parse_args()

    try:
        if args.set_session:
            set_session(args.set_session)
            print("session token stored in secrets.json")
            return

        if args.test:
            result = test_session()
            print("authenticated as: %s" % result["username"])
            return

        if args.invitations:
            result = list_program_invitations()
            if not result["items"]:
                print("no pending program invitations")
                return
            print("%d pending program invitation(s):" % result["total"])
            for inv in result["items"]:
                print("  %-25s %-12s bounty=%-5s expires=%s  token=%s" % (
                    inv["program_name"] or inv["program_handle"],
                    inv["state"],
                    "yes" if inv["offers_bounties"] else "no",
                    (inv["expires_at"] or "")[:10],
                    inv["token"][:12] + "..."))
            return

        if args.collabs:
            result = list_collab_invitations()
            if not result["items"]:
                print("no pending collaboration invitations")
                return
            print("%d pending collaboration invitation(s):" % result["total"])
            for inv in result["items"]:
                print("  #%-10s %-40s from=%-15s split=%s%%  token=%s" % (
                    inv["report_id"],
                    (inv["report_title"] or "")[:40],
                    inv["invited_by"],
                    inv.get("split_percentage") or "?",
                    inv["token"][:12] + "..."))
            return

        if args.accept_invite:
            result = accept_program_invitation(args.accept_invite)
            print("accepted: %s" % result.get("ok"))
            return

        if args.reject_invite:
            result = reject_program_invitation(args.reject_invite)
            print("rejected: %s" % result.get("ok"))
            return

        if args.accept_collab:
            result = accept_collab_invitation(args.accept_collab)
            print("accepted collab: %s" % result.get("ok"))
            return

        if args.add_collab:
            report_id, username = args.add_collab
            result = invite_collaborator(report_id, username)
            print("invited %s to #%s: %s" % (username, report_id, result.get("ok")))
            return

        if args.set_split:
            report_id, username, pct = args.set_split
            result = update_bounty_split(report_id, username, int(pct))
            print("set split for %s on #%s to %s%%: %s" % (
                username, report_id, pct, result.get("ok")))
            return

        # Default: show status
        for k, v in status().items():
            print("  %-20s %s" % (k, v))

    except GQLError as e:
        sys.exit("h1_graphql: %s" % e)


if __name__ == "__main__":
    main()
