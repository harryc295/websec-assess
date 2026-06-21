from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.integrations.waybackurls import WaybackurlsAdapter
from websec_assess.integrations.normalize import normalize_waybackurls


@PluginRegistry.register
class WaybackurlsPlugin(Plugin):
    name = "integrations.waybackurls"
    category = "integrations"
    description = "Runs `waybackurls` against the target if installed; complements recon.historical_urls's built-in CDX lookup."

    async def run(self, ctx: PluginContext) -> PluginResult:
        adapter = WaybackurlsAdapter()
        if not adapter.is_installed(ctx.config):
            ctx.audit.record("tool_not_installed", scan_id=ctx.scan_id, tool="waybackurls")
            return PluginResult(plugin=self.name)
        records = await adapter.run_and_parse(ctx)
        return normalize_waybackurls(ctx, records)
