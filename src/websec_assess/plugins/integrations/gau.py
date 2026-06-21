from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.integrations.gau import GauAdapter
from websec_assess.integrations.normalize import normalize_gau


@PluginRegistry.register
class GauPlugin(Plugin):
    name = "integrations.gau"
    category = "integrations"
    description = "Runs `gau` (GetAllUrls) against the target if installed; ingests historical URLs."

    async def run(self, ctx: PluginContext) -> PluginResult:
        adapter = GauAdapter()
        if not adapter.is_installed(ctx.config):
            ctx.audit.record("tool_not_installed", scan_id=ctx.scan_id, tool="gau")
            return PluginResult(plugin=self.name)
        records = await adapter.run_and_parse(ctx)
        return normalize_gau(ctx, records)
