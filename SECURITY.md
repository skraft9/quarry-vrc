# Supported Versions

| Version | Supported |
| ------- | ------------------ |
| 1.4.x   | :white_check_mark: |
| < 1.4.0 | :x:                |

# Reporting a Vulnerability

If you find a security flaw, authentication bypass, or hardening oversight in Quarry VRC, please do not open a public issue.

Submit a disclosure privately via **Security** -> **Report a vulnerability** on this repository.

* This project is solo-maintained.
* Reports are reviewed on a best-effort basis.
* Valid and actionable findings will be patched on `dev` and cut into a future release.

# Threat Model and Scope

Quarry VRC is designed to run on a private host or local environment you control. It uses zero third-party runtime packages to eliminate supply chain attack surface.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full picture: the deployment assumptions this scope rests on, its trust levels, and a named list of accepted risks, each with the condition under which it would become in scope.

### In Scope
* Authentication bypasses, token leaks, or logic flaws in session handling.
* Bypasses of the client IP allow-list (`QUARRY_ALLOWLIST`).
* Script execution in the operator's browser (stored or DOM XSS, or template injection) that breaks the CSP (`default-src 'none'`), where the payload arrives in data the operator did not author: a HackerOne title or triage comment, an RSS/Atom advisory, or a synced Git repo. Injecting into your own note is self-XSS, not a finding.
* Cross-origin or client-side attacks that reach the local instance through the operator's browser (DNS rebinding, CSRF, or cross-origin API access).
* Any unauthenticated path that reads back the stored HackerOne credential or an API token.
* Escaping the configured workspace root (path traversal, symlink, or otherwise), or code execution, in markdown parsing, FTS5 search, or workspace endpoints. Reading files inside the operator's own root is within operator authority, not a boundary; see `THREAT_MODEL.md`.
* Privilege escalation from a read-scoped token to write capability, or from any token to code execution in the container or on the host.

### Out of Scope
* Anything an authenticated token does within the operator's own authority on their own host: reading their own files inside the configured root, or making the instance reach a network location their host can already reach. See the accepted risks in `THREAT_MODEL.md`.
* Attacks requiring prior root/admin access to the underlying host or Docker daemon.
* Deployments running without `QUARRY_ADMIN_PASSWORD` or exposing plain HTTP outside the container setup.
* Volumetric denial-of-service against your own local instance.
* Findings that only hold under a multi-user, shared-tenant, or public-internet deployment that Quarry VRC does not implement. Name the assumption you broke and it will be read on those terms.
