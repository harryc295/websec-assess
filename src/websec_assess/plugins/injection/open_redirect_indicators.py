"""Open redirect indicator: sets redirect-shaped parameters to an external
test domain and checks whether the server issues a redirect straight to it.
Fully passive in effect -- no payload can do anything harmful here, it's
just an HTTP Location header check."""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.plugins.injection._common import build_url, budget_for, candidate_params

REDIRECT_PARAM_NAMES = (
    "redirect", "redirect_uri", "redirecturl", "url", "next", "return",
    "returnurl", "return_url", "dest", "destination", "target", "continue", "go",
)
TEST_TARGET = "https://websec-assess-redirect-probe.invalid/"


@PluginRegistry.register
class OpenRedirectIndicatorsPlugin(Plugin):
    name = "injection.open_redirect_indicators"
    category = "injection"
    description = "Sets redirect-shaped parameters to an external test domain and checks whether the server redirects there."
    requires_active_probes = True

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        budget = budget_for(ctx)
        all_candidates = candidate_params(ctx, budget * 4)
        prioritised = [c for c in all_candidates if c[1].lower() in REDIRECT_PARAM_NAMES]
        rest = [c for c in all_candidates if c not in prioritised]
        to_test = (prioritised + rest)[:budget]

        for base, name, _, params in to_test:
            test_url = build_url(base, params, name, TEST_TARGET)
            resp = await ctx.http.get(test_url)
            if resp is None or not (300 <= resp.status_code < 400):
                continue
            location = resp.headers.get("location", "")
            if location.startswith(TEST_TARGET.rstrip("/")):
                result.findings.append(
                    ctx.finding(
                        category="injection",
                        title=f"Open redirect via parameter '{name}'",
                        description=f"Setting '{name}' to an external URL caused the server to issue a {resp.status_code} redirect directly to it.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        affected_url=test_url,
                        evidence=[Evidence(description="Location header", matched_value=location)],
                        remediation="Validate redirect targets against an allowlist of in-application paths; never redirect to a raw user-supplied URL.",
                        references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"],
                        cwe="CWE-601",
                        owasp="A01:2021-Broken Access Control",
                    )
                )
        return result
