# Quarry VRC Threat Model

## Summary

Quarry VRC is a single-operator, self-hosted console. This document sets out the security boundaries the project holds, the deployment assumptions those boundaries rest on, and the explicit non-boundaries that are out of scope, so you know before you spend time on a finding.

A report is in scope when it breaks a boundary defined here under the assumed deployment. A finding that only holds by breaking one of the baseline assumptions is evaluated on those terms: say which assumption you broke.

## 1. Deployment assumptions

The whole model rests on these. Change any one and the scope changes with it.

* **Single operator.** One trusted user runs the instance and owns everything in it. A running instance has no untrusted local tenants.
* **Self-hosted on a host the operator controls.** The operator already has filesystem access and outbound network capability on the host by other means (a shell, system utilities, Docker). The app is not the only path to those.
* **Private network, behind the allow-list.** Bound to loopback or a private address, gated by the client IP allow-list (`QUARRY_ALLOWLIST`), reached over the operator's own network. Not hardened for, nor intended for, direct public-internet exposure.
* **Configured as intended.** `QUARRY_ADMIN_PASSWORD` is set and the app runs over its documented container and TLS setup. A deployment with no admin password or plain HTTP is a misconfiguration, not a target.
* **No privileged network position.** The instance is not assumed to sit somewhere with implicit access to a cloud metadata service or an unauthenticated internal service it should not be able to reach through the app.

If you are evaluating Quarry VRC as a multi-user, RBAC, or shared-tenant platform: it is not one. That is a different application with a different threat model, and this document does not cover it.

## 2. Trust levels

* **Unauthenticated.** Anything reaching the socket without a valid session cookie or Bearer token. Trusted with nothing.
* **Read-scoped token.** A Bearer token meant for headless utilities, automation scripts, and agentic AI tools: authorised to read indexed data, query search, and inspect state, but not to change state, dispatch submissions, or modify workspace files. Because it is handed to automation the operator wants kept on a short leash, the read/write split IS a boundary: a bug that lets a read token gain write capability is a real escalation (Section 3), not just an ergonomic slip.
* **Write-scoped token, the operator.** Full read and write authority. A write token represents the operator's direct intent inside the app's own domain; anything it can do that the operator could already do by other means on their own host is within authority, not a privilege crossing.
* **Host owner.** Full root over the host OS, the Docker socket, and the runtime.

## 3. In scope and out of scope

Written as boundaries, not features. In scope is what the project promises to hold: cross it and it is a bug we own.

### In scope

* **Unauthenticated access to any authenticated surface.** Reaching a read or write endpoint, extracting a session credential, or reading a stored secret (the HackerOne token, a stored Bearer token) without a valid token.
* **Bypass of the client IP allow-list** (`QUARRY_ALLOWLIST`): serving an inbound request from a non-allow-listed address.
* **Cross-origin and client-side attack on the local instance.** A remote site reaching the operator's local port through the operator's browser: DNS rebinding, CSRF, or cross-origin API access. This is the main external vector for a loopback tool, and it is in scope.
* **Escaping the configured workspace root.** Reading, writing, or listing a path outside the browse root via traversal (`../`), symlink, or archive-extraction abuse. Root confinement is a real boundary.
* **Breaking the Content Security Policy or executing in the operator's browser.** Stored or DOM-based XSS, or template injection, that breaks the CSP (`default-src 'none'`) and runs script in the operator's session.
* **Second-order injection from ingested upstream data.** A malicious payload arriving through data the app ingests (a HackerOne triage comment, an upstream RSS/Atom advisory, a synced Git repo) that reaches code execution, injects HTML or script into the UI, or corrupts the FTS5 index.
* **Privilege escalation.** From a read-scoped token to write capability, or from any token to command execution in the container or on the host.

### Out of scope

* **Anything an authenticated token does within the operator's own authority on their own host:** reading files inside the configured workspace root, making the instance reach a network location the operator's host can already reach, submitting a report with a valid write token.
* Attacks needing prior root or admin on the host or the Docker daemon.
* Misconfigured deployments: no `QUARRY_ADMIN_PASSWORD`, plain HTTP exposed to an untrusted network, the allow-list disabled, or the instance placed on the public internet.
* Volumetric denial of service against your own instance.
* Findings that only hold under a deployment this document does not assume (multi-user, shared tenant, public-internet exposure, a reachable cloud metadata service). Name the assumption you broke and it will be read on those terms.

## 4. Accepted risks

These are real code behaviours a scanner will flag. They are out of scope under the assumptions above, listed here so you do not have to file one to learn that. Each names the condition under which it would become a real finding.

* **Workspace file-read of the operator's own files.** The `/api/fs` endpoints read files inside the configured workspace root, and an authenticated token may read them. The default secret-name deny-list (`browse_deny_globs`: `id_rsa*`, `*.pem`, `*.env`, and so on) is a best-effort convenience to keep key material from being surfaced in the UI or a screen-share by accident, not a confinement boundary. Reading a file inside the root is exactly what the token is authorised to do, so bypassing the deny-list (by file-name casing, for instance) discloses the operator's own files to a token already permitted to read them. Escaping the root is a separate thing and is in scope, above. *Would become real if:* multi-user isolation or delegated, untrusted workspaces were introduced.
* **Outbound request to an operator-configured capture tool.** The screenshot and evidence-capture paths reach a Caido or Burp backend to capture proof, and the backend is configured by the operator (`CAIDO_URL` / `BURP_URL`). A write-scoped caller is the operator, who can already make their own host issue outbound requests, so pointing the instance at a configured backend is within that authority. *Would become real if:* an unauthenticated caller or a read-scoped token could drive the outbound request, or the instance runs where it can reach a privileged network position it should not (a cloud metadata endpoint, an internal service on a shared network).

## Hardening versus vulnerability

Some accepted-risk behaviours are still sanded down over time to remove foot-guns and improve default safety, recorded as ordinary robustness in the release notes. Refining an accepted risk in code does not reclassify the original behaviour as a vulnerability or warrant a security advisory.

## Changing this document

The model changes when the app changes. If Quarry VRC gains multi-user workflows, unauthenticated public endpoints, a non-loopback default bind, or remote collaboration, this document is revised first, because most of the out-of-scope lines above turn into in-scope the moment the single-operator assumption ends.
