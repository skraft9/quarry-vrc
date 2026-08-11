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

### In Scope
* Authentication bypasses, token leaks, or logic flaws in session handling.
* Bypasses of the client IP allow-list (`QUARRY_ALLOWLIST`).
* Stored XSS or injection vulnerabilities that break the Content Security Policy (`default-src 'none'`).
* Unauthenticated access to write-only HackerOne credentials or stored Bearer tokens.
* Arbitrary file reads, path traversal, or code execution in markdown parsing, FTS5 search, or workspace endpoints.

### Out of Scope
* Attacks requiring prior root/admin access to the underlying host or Docker daemon.
* Deployments running without `QUARRY_ADMIN_PASSWORD` or exposing plain HTTP outside the container setup.
* Volumetric denial-of-service against your own local instance.
