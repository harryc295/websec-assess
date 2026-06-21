from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.integrations.httpx_tool import HttpxToolAdapter
from websec_assess.integrations.normalize import normalize_httpx


@PluginRegistry.register
class HttpxToolPlugin(Plugin):
    name = "integrations.httpx"
    category = "integrations"
    description = "Runs ProjectDiscovery's `httpx` against the target if installed; ingests probe results/tech."

    async def run(self, ctx: PluginContext) -> PluginResult:
        adapter = HttpxToolAdapter()
        if not adapter.is_installed(ctx.config):
            ctx.audit.record("tool_not_installed", scan_id=ctx.scan_id, tool="httpx")
            return PluginResult(plugin=self.name)
        records = await adapter.run_and_parse(ctx)
        return normalize_httpx(ctx, records)
