"""Optional: only runs if the `nuclei` binary is on PATH. See SECURITY.md --
detection only is in scope; nuclei's own active templates are the user's
responsibility to vet against the authorisation they hold."""
from __future__ import annotations

from websec_assess.core.models import PluginResult, ScanProfile
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.integrations.nuclei import NucleiAdapter
from websec_assess.integrations.normalize import normalize_nuclei


@PluginRegistry.register
class NucleiPlugin(Plugin):
    name = "integrations.nuclei"
    category = "integrations"
    description = "Runs `nuclei` against the target if installed; normalises template matches into findings."
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})

    async def run(self, ctx: PluginContext) -> PluginResult:
        adapter = NucleiAdapter()
        if not adapter.is_installed(ctx.config):
            ctx.audit.record("tool_not_installed", scan_id=ctx.scan_id, tool="nuclei")
            return PluginResult(plugin=self.name)
        records = await adapter.run_and_parse(ctx)
        return normalize_nuclei(ctx, records)
