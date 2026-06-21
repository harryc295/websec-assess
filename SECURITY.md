# Authorisation Policy

websec-assess is a web application security assessment platform built **only** for:

- Authorised penetration tests with a signed scope/engagement letter
- Your own personal lab environments
- CTF competitions
- Bug bounty targets where the program's published scope explicitly permits the
  techniques used

## Do not use this tool against any system you do not own or do not have
explicit, documented permission to test. Running active checks against
third-party systems without authorisation is illegal in most jurisdictions
(e.g. the UK Computer Misuse Act 1990, US CFAA) regardless of intent.

## What this enforces, not just states

- Every scan requires an explicit `--i-have-authorization` flag (or
  `authorized: true` in the scan config) before any network request is made.
  See `core/safety.py`.
- Targets must match an explicit scope/allowlist (`scope.allowed_hosts` in
  config) or the scan refuses to run.
- A token-bucket rate limiter caps requests/second per host (default
  conservative; tune in config, never disabled entirely).
- `--dry-run` plans and prints every action a scan would take without sending
  a single request.
- Every action (target resolved, plugin run, request sent, finding recorded)
  is written to an append-only audit log (`audit.log` by default).
- Injection-indicator plugins that send mutated parameters (XSS/SQLi/CmdI/SSTI/
  path traversal/XXE/open-redirect probes) are **off by default** and require
  `active_injection_probes: true` in config in addition to the scope/allowlist
  match above.

## Reporting a vulnerability in websec-assess itself

Open a private security advisory on the GitHub repository rather than a
public issue.
