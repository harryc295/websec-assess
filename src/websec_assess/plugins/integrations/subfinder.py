from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.integrations.subfinder import SubfinderAdapter
from websec_assess.integrations.normalize import normalize_subfinder


@PluginRegistry.register
class SubfinderPlugin(Plugin):
    name = "integrations.subfinder"
    category = "integrations"
    description = "Runs `subfinder` against the target if installed; complements recon.subdomain_enum's built-in passive lookup."

    async def run(self, ctx: PluginContext) -> PluginResult:
        adapter = SubfinderAdapter()
        if not adapter.is_installed(ctx.config):
            ctx.audit.record("tool_not_installed", scan_id=ctx.scan_id, tool="subfinder")
            return PluginResult(plugin=self.name)
        records = await adapter.run_and_parse(ctx)
        return normalize_subfinder(ctx, records)
