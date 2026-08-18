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

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full picture: the deployment assumptions this scope rests on, the three trust levels, and a named list of accepted risks, each with the condition under which it would become in scope.

### In Scope
* Authentication bypasses, token leaks, or logic flaws in session handling.
* Bypasses of the client IP allow-list (`QUARRY_ALLOWLIST`).
* Stored XSS or injection vulnerabilities that break the Content Security Policy (`default-src 'none'`).
* Cross-origin or client-side attacks that reach the local instance through the operator's browser (DNS rebinding, CSRF, or cross-origin API access).
* Second-order injection from ingested upstream data (a HackerOne triage comment, an RSS/Atom advisory, a synced Git repo) that breaks markdown or FTS5 parsing or injects script into the UI.
* Unauthenticated access to write-only HackerOne credentials or stored Bearer tokens.
* Escaping the configured workspace root (path traversal, symlink, or otherwise), or code execution, in markdown parsing, FTS5 search, or workspace endpoints. Reading files inside the operator's own root is within operator authority, not a boundary; see `THREAT_MODEL.md`.

### Out of Scope
* Anything an authenticated token does within the operator's own authority on their own host: reading their own files inside the configured root, or making the instance reach a network location their host can already reach. See the accepted risks in `THREAT_MODEL.md`.
* Attacks requiring prior root/admin access to the underlying host or Docker daemon.
* Deployments running without `QUARRY_ADMIN_PASSWORD` or exposing plain HTTP outside the container setup.
* Volumetric denial-of-service against your own local instance.
