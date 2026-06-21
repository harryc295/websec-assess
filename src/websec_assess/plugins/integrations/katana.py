from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.integrations.katana import KatanaAdapter
from websec_assess.integrations.normalize import normalize_katana


@PluginRegistry.register
class KatanaPlugin(Plugin):
    name = "integrations.katana"
    category = "integrations"
    description = "Runs `katana` against the target if installed; ingests crawled endpoints as URL assets."

    async def run(self, ctx: PluginContext) -> PluginResult:
        adapter = KatanaAdapter()
        if not adapter.is_installed(ctx.config):
            ctx.audit.record("tool_not_installed", scan_id=ctx.scan_id, tool="katana")
            return PluginResult(plugin=self.name)
        records = await adapter.run_and_parse(ctx)
        return normalize_katana(ctx, records)
