"""Catalogues every response header on the base URL as evidence for the
report/timeline. Judging which headers are *missing* and how severe that is
belongs to plugins.vuln_assessment.security_headers -- this plugin only
records what's actually there.
"""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity


@PluginRegistry.register
class HeaderAnalysisPlugin(Plugin):
    name = "recon.header_analysis"
    category = "recon"
    description = "Records the full set of HTTP response headers returned by the target as evidence."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url)
        if resp is None:
            result.errors.append("No response from target")
            return result

        headers = dict(resp.headers)
        ctx.state.response_cache["base_headers"] = headers
        result.findings.append(
            ctx.finding(
                category="recon",
                title="Response headers captured",
                description=f"Captured {len(headers)} response header(s) on the base URL for evidence/timeline purposes.",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_url=ctx.target.base_url,
                evidence=[Evidence(description=f"{k}: {v}") for k, v in headers.items()],
                extra={"headers": headers},
            )
        )
        return result
