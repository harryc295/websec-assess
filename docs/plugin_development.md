# Writing a plugin

A plugin is a class implementing `async def run(self, ctx) -> PluginResult`,
registered with `@PluginRegistry.register`. `PluginRegistry.discover()`
imports every module under `websec_assess.plugins` so the decorator runs --
there's no separate manifest/entry-point file to update.

```python
from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity


@PluginRegistry.register
class MyCheckPlugin(Plugin):
    name = "vuln_assessment.my_check"      # unique; convention is "<category>.<short_name>"
    category = "vuln_assessment"            # determines which scan phase it runs in
    description = "One line shown in `websec-assess plugins`."
    # profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})  # default: all three
    # requires_active_probes = True          # only runs if safety.active_injection_probes

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url)   # scope/rate-limit/audit handled for you
        if resp is None:
            result.errors.append("No response from target")
            return result

        if "x-my-header" not in resp.headers:
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="Missing X-My-Header",
                    description="...",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    remediation="...",
                    cwe="CWE-...",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
```

## What `ctx` gives you

- `ctx.http` -- a `SafeHttpClient`. Every call goes through scope checking,
  the per-host rate limiter, the audit log, and is skipped entirely in
  dry-run mode. Pass `osint=True` only for fixed, known-safe public lookups
  against a service that *isn't* the target (crt.sh, web.archive.org).
- `ctx.state` -- the `ScanState` for this scan run: `subdomains`, `urls`,
  `js_files`, `parameters`, `forms`, `technologies`, `cookies`,
  `response_cache`. Read what earlier phases found; add what you find so
  later phases can use it.
- `ctx.finding(...)` / `ctx.asset(...)` -- build a `Finding`/`Asset` with
  `scan_id`/`plugin` already filled in.
- `ctx.audit` / `ctx.rate_limiter` -- use these directly if your plugin does
  non-HTTP I/O (DNS resolution, raw sockets, subprocess) so it stays
  dry-run-safe and rate-limited too. See `plugins/recon/dns_enum.py` or
  `plugins/vuln_assessment/tls_analysis.py` for examples.
- `ctx.profile` -- scale how much work you do (`ScanProfile.QUICK` /
  `STANDARD` / `DEEP`). Most plugins keep a small `BUDGET = {"quick": N, ...}`
  dict at module level.

## Phase order

Your plugin's `category` determines which phase it runs in (see
`core/queue.py:PHASE_ORDER`). Plugins in the same phase run concurrently via
`asyncio.gather`; phases run strictly in order. If your check needs data
from another category, put it in a later phase rather than reaching across
phases at runtime.

## Documented extension points (not registered)

These exist as `Plugin` subclasses with a detailed module docstring
explaining exactly what's needed, but no `@PluginRegistry.register` --
they're deliberately not wired into scans because they need either
engagement-specific credentials or an account-mutating action a default,
non-destructive, unauthenticated scan shouldn't assume:

| File | What it needs |
|---|---|
| `plugins/api_security/_extension_points.py::ApiAuthReview` | test credentials to compare authenticated vs. unauthenticated responses |
| `plugins/auth_access/_extension_points.py::PasswordPolicyReview` | submitting candidate passwords to a real form (account-mutating) |
| `plugins/auth_access/_extension_points.py::IdorIndicators` | two credentialed sessions at different privilege levels |
| `plugins/auth_access/_extension_points.py::AuthorizationBoundaryCheck` | role-scoped credentials |
| `plugins/passive_intel/_extension_points.py::WhoisLookup` | a `whois` binary (not on Windows by default) or a third-party lib |
| `plugins/passive_intel/_extension_points.py::AsnLookup` | a BGP/IP-to-ASN data source |
| `plugins/passive_intel/_extension_points.py::ReputationChecks` | a third-party reputation API key |

To implement one: fill in `run()`, add `@PluginRegistry.register` above the
class, and (if it needs credentials) add fields to `AppConfig` for them.

## Testing a plugin

`tests/conftest.py` provides a `local_server` fixture (a stdlib
`http.server` instance) and a `make_ctx()` helper so you can unit-test a
single plugin without touching the network. See
`tests/test_vuln_assessment_plugins.py` for the pattern, and
`tests/integration/test_scan_against_local_server.py` for a full
`Scheduler.run_scan()` exercising every registered plugin at once.
