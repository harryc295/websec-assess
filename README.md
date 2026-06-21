# websec-assess

A modular web application security assessment platform: reconnaissance,
content discovery, vulnerability assessment, and safe injection-*indicator*
checks, with a plugin architecture, async scan engine, SQLite/PostgreSQL
storage, and JSON/Markdown/HTML reporting.

> ## ⚠ Authorisation required
> Use this **only** against systems you own, your own lab/CTF environments,
> or targets where you hold explicit written authorisation (a signed
> engagement letter, or a bug bounty program's published scope). Every scan
> requires `--i-have-authorization` (or `safety.authorized: true`) and an
> explicit `scope.allowed_hosts`/`allowed_cidrs` entry before a single
> request is sent. See [SECURITY.md](SECURITY.md).

## What it does

| Area | Examples |
|---|---|
| Reconnaissance | DNS enum + AXFR check, subdomain enum (crt.sh + brute-force), HTTP fingerprinting, tech detection, robots/sitemap, endpoint crawling, Wayback Machine history, asset inventory |
| Content discovery | Directory/file brute-force, parameter discovery, API endpoint identification, JS analysis, secret detection |
| Vulnerability assessment | Security headers, TLS/cert analysis, misconfiguration (listing/verbose errors/dangerous methods), auth assessment, session management, CORS, CSP, cookies |
| Injection indicators (opt-in) | XSS, SQLi, command injection, SSTI, path traversal, XXE, open redirect -- detection/evidence only, no destructive exploitation |
| API security | OpenAPI/Swagger parsing, GraphQL introspection probe |
| Cloud/infra | Cloud storage references, CI/CD config exposure, Docker/Kubernetes API exposure |
| Passive intel | Certificate transparency analysis |
| Integrations | nuclei, katana, httpx, subfinder, dnsx, naabu, gau, waybackurls -- auto-detected, no-op if not installed |

Auth/access (IDOR, password policy, privilege boundaries), and
WHOIS/ASN/reputation checks are shipped as **documented extension points**,
not fake implementations -- see [docs/plugin_development.md](docs/plugin_development.md#documented-extension-points-not-registered)
for exactly what each needs and how to wire it up.

Every finding carries title, description, severity, confidence, evidence,
affected URL, remediation, references, CWE, and OWASP mapping. See
[examples/reports](examples/reports) for a sample report in all three
formats.

## Quickstart

```bash
pip install -e ".[dev]"      # or: pipx install -e .   (puts websec-assess on PATH)
websec-assess                # no arguments -> interactive menu
websec-assess scan           # no target -> interactive wizard (target, depth, tools, auth)
```

Prefer flags/scripting over prompts:

```bash
websec-assess init --target your-target.example
# edit websec-assess.yaml: confirm scope.allowed_hosts and safety.authorized
websec-assess scan https://your-target.example --i-have-authorization --profile quick
websec-assess list
```

Full per-OS instructions (Windows/Ubuntu/Kali/Mint/Docker): [docs/installation.md](docs/installation.md).

## CLI

```
websec-assess              interactive menu (same as running with no arguments)
websec-assess scan         [TARGET] [--i-have-authorization] [--profile quick|standard|deep]
                            [--plugins a,b,c] [--format json,markdown,html] [--dry-run] [--open]
                            (omit TARGET to be prompted instead)
websec-assess init         --target HOST [--output FILE]
websec-assess resume       SCAN_ID
websec-assess report       SCAN_ID [--format html] [--output-dir DIR] [--open]
websec-assess plugins      [--category recon|content_discovery|...]
websec-assess list
websec-assess guide        explains scan depth, politeness, and injection probes
websec-assess help         full command/flag reference
```

## Architecture

See [docs/architecture.md](docs/architecture.md) (pipeline + phase diagram)
and [docs/database_schema.md](docs/database_schema.md). Writing a new
plugin: [docs/plugin_development.md](docs/plugin_development.md).

## Scan profiles

`quick` / `standard` / `deep` scale wordlist sizes, crawl depth, and which
optional tool-integration plugins run (port scanning and nuclei templates
are `standard`/`deep` only). Injection-indicator plugins never run unless
`active_injection_probes: true` is set, regardless of profile.

## Safety, concretely

- Authorization banner + explicit `--i-have-authorization` gate before any request.
- `scope.allowed_hosts` / `allowed_cidrs` allowlist, enforced on every HTTP
  request, DNS query, and raw-socket probe -- not just a config field nobody checks.
- Per-host token-bucket rate limiting (`rate_limit.requests_per_second`).
- `--dry-run` plans the scan and logs every action without sending a request.
- Append-only JSONL audit log (`audit.log`) of every action taken.
- Injection-indicator plugins are off by default and gated separately.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
mypy src --ignore-missing-imports
pytest -v
```

CI (`.github/workflows/ci.yml`) runs lint + type-check + tests on Ubuntu,
Windows, and macOS, plus a Docker build.

## License

MIT, see [LICENSE](LICENSE). This license covers the software only -- it
does not authorise testing any system without permission; see
[SECURITY.md](SECURITY.md).
