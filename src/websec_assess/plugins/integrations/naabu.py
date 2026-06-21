from __future__ import annotations

from websec_assess.core.models import PluginResult, ScanProfile
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.integrations.naabu import NaabuAdapter
from websec_assess.integrations.normalize import normalize_naabu


@PluginRegistry.register
class NaabuPlugin(Plugin):
    name = "integrations.naabu"
    category = "integrations"
    description = "Runs `naabu` port scan against the target host if installed; flags sensitive open ports."
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})

    async def run(self, ctx: PluginContext) -> PluginResult:
        adapter = NaabuAdapter()
        if not adapter.is_installed(ctx.config):
            ctx.audit.record("tool_not_installed", scan_id=ctx.scan_id, tool="naabu")
            return PluginResult(plugin=self.name)
        records = await adapter.run_and_parse(ctx)
        return normalize_naabu(ctx, records)
