# Quarry VRC Threat Model

## How to read this

Quarry VRC is a single-operator, self-hosted tool. This document states the security boundaries the project promises to hold, the assumptions those promises rest on, and the things that are deliberately NOT boundaries, so you know before you spend time on a finding. A report is in scope when it crosses a boundary listed here under the deployment this document assumes. A finding that only holds under a different deployment is a finding against that deployment; say which assumption you broke and it will be read on those terms.

## 1. Deployment assumptions

The whole model rests on these. Change any one and the scope changes with it.

* **Single operator.** One person runs the instance and owns everything in it. A running instance has no untrusted users.
* **Self-hosted on a host the operator controls.** The operator can already read the host's files and make outbound requests from it by other means (a shell, curl, the file manager). The app is not the only path to those.
* **Private network, behind the allow-list.** Bound to loopback or a private address, gated by the client IP allow-list (`QUARRY_ALLOWLIST`), reached over the operator's own network. Not published to the public internet.
* **Configured as intended.** `QUARRY_ADMIN_PASSWORD` set, served over the documented container/TLS setup. A deployment that drops these is misconfigured, not a target.
* **No privileged network position assumed reachable.** No cloud metadata service or internal-only service is assumed reachable from the instance. Where one exists (a cloud VM, a shared network), see Accepted Risks: it changes the outbound-request verdict.

If you are evaluating Quarry VRC as a multi-user, RBAC, or shared-tenant system: it is not one. That is a different application with a different threat model, and this document does not cover it.

## 2. Trust levels

Three, and only three.

* **Unauthenticated.** Reaches the socket, holds no valid token. Trusted with nothing.
* **Authenticated token (read or write scope).** A credential held by the operator. The read/write split is an ergonomic guard rail the operator sets for their own workflow, not a delegation boundary to a less-trusted party. Treat a valid token as "the operator."
* **Operator / host owner.** Full authority over the host, its files, its network, and the app's configuration.

Because a token is the operator, anything a token can do that the operator could already do by other means on their own host is within authority, not a privilege crossing.

## 3. In scope and out of scope

Written as boundaries, not features. In scope is what the project promises to hold: cross it and it is a bug we own.

### In scope

* **Unauthenticated access to any authenticated surface.** Reaching a read or write endpoint, a stored Bearer token, or the HackerOne credential without a valid token.
* **Bypass of the client IP allow-list** (`QUARRY_ALLOWLIST`): an inbound request from a non-allow-listed address being served.
* **Escaping the configured workspace root.** Reading, writing, or listing a path outside the browse root via traversal, symlink, or otherwise. Root confinement is a real boundary.
* **Breaking the Content Security Policy or executing in the operator's browser.** Stored XSS, template injection, or markdown/FTS5 parsing that leads to script execution, arbitrary read/write, or code execution.
* **Elevation from read scope to write scope, or from any token to host code execution, through an app bug.**

### Out of scope

* **Anything an authenticated token does within the operator's own authority on the operator's own host:** reading the operator's own files inside the configured workspace root, making the instance reach a network location the operator's host can already reach, running an action the operator is entitled to run.
* Attacks needing prior root/admin on the host or the Docker daemon.
* Misconfigured deployments: no `QUARRY_ADMIN_PASSWORD`, plain HTTP exposed outside the container setup, the allow-list disabled, or the instance published to the public internet.
* Volumetric denial of service against your own instance.
* Findings that only hold under a deployment this document does not assume (multi-user, shared tenant, public-internet exposure, a reachable cloud metadata service). Worth knowing, but a finding against a threat model Quarry VRC does not yet claim: name the assumption you broke.

## 4. Accepted risks

These are real code behaviours a scanner will flag. They are out of scope under the assumptions above, listed here so you do not have to file one to learn that. Each names the condition under which it WOULD become a real finding.

* **Workspace file-read of the operator's own files.** The `/api/fs` endpoints read files inside the configured workspace root. The default secret-name deny-list (`browse_deny_globs`: `id_rsa*`, `*.pem`, `*.env`, and so on) is a best-effort convenience to avoid surfacing key material by accident, not a confinement boundary. A token is the operator, and the operator owns every file under their own root, so bypassing the deny-list (by file-name casing, for instance) discloses the operator's own files to the operator. Out of scope. Escaping the root is a separate thing and is in scope, above. *Would become real if:* read and write scopes were handed to distinct, less-trusted parties, that is, under a delegation or multi-user model.

* **Outbound request to an operator-configured capture tool.** The screenshot and evidence-capture paths reach a Caido or Burp backend to capture proof, and the backend URL can be supplied by a write-scoped caller. A write-scoped caller is the operator, who can already make their own host issue outbound requests; pointing the instance at a URL is within that authority. Out of scope on the assumed deployment. *Would become real if:* the instance runs where it can reach a privileged network position the operator should not reach through it (a cloud metadata endpoint at `169.254.169.254`, an internal service on a shared network), or a write token is delegated to a less-trusted party.

## Hardening despite acceptance

Some accepted-risk behaviours are still sanded down over time to remove foot-guns and reduce accidental exposure, even though they are out of scope. That work is ordinary robustness, recorded in the changelog, and does not mean the behaviour was a vulnerability. Reports that prompt such hardening are credited there.

## Changing this document

The model changes when the app changes. The day Quarry VRC gains real multi-user accounts, a non-loopback default bind, or shared tenancy, this document is rewritten first, because most of the "out of scope" lines above turn into "in scope" the moment the single-operator assumption ends.
