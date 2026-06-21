from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.integrations.dnsx import DnsxAdapter
from websec_assess.integrations.normalize import normalize_dnsx


@PluginRegistry.register
class DnsxPlugin(Plugin):
    name = "integrations.dnsx"
    category = "integrations"
    description = "Runs `dnsx` against the target host + discovered subdomains if installed; ingests DNS records."

    async def run(self, ctx: PluginContext) -> PluginResult:
        adapter = DnsxAdapter()
        if not adapter.is_installed(ctx.config):
            ctx.audit.record("tool_not_installed", scan_id=ctx.scan_id, tool="dnsx")
            return PluginResult(plugin=self.name)
        records = await adapter.run_and_parse(ctx)
        return normalize_dnsx(ctx, records)
