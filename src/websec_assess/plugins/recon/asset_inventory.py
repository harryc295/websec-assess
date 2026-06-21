"""Summarises everything recon discovered this run. Runs in its own
'inventory' phase (after 'recon') so every recon plugin has already
populated ctx.state by the time this reads it -- recon plugins themselves
run concurrently within their phase, so this can't be one of them."""
from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity


@PluginRegistry.register
class AssetInventoryPlugin(Plugin):
    name = "recon.asset_inventory"
    category = "inventory"
    description = "Summarises subdomains, URLs, JS files, forms, and technologies discovered by recon plugins."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        state = ctx.state
        summary = {
            "subdomains": len(state.subdomains),
            "urls": len(state.urls),
            "js_files": len(state.js_files),
            "forms": len(state.forms),
            "technologies": len(state.technologies),
        }
        result.findings.append(
            ctx.finding(
                category="recon",
                title="Asset inventory summary",
                description=(
                    f"{summary['subdomains']} subdomain(s), {summary['urls']} URL(s), "
                    f"{summary['js_files']} JS file(s), {summary['forms']} form(s), "
                    f"{summary['technologies']} technology marker(s) discovered so far."
                ),
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_url=ctx.target.base_url,
                extra=summary,
            )
        )
        return result
