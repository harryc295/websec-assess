"""Harvests parameter names from URLs and forms already discovered by recon
-- no need to actively fuzz when the query strings and form fields already
on hand give a real parameter surface."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity


@PluginRegistry.register
class ParameterDiscoveryPlugin(Plugin):
    name = "content_discovery.parameter_discovery"
    category = "content_discovery"
    description = "Extracts parameter names from discovered URL query strings and form inputs."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        params: set[str] = set()

        for url in ctx.state.urls:
            query = urlsplit(url).query
            for key, _ in parse_qsl(query):
                params.add(key)

        for form in ctx.state.forms:
            for field in form.get("inputs", []):
                name = field.get("name")
                if name:
                    params.add(name)

        new_params = params - ctx.state.parameters
        ctx.state.parameters |= params
        for p in new_params:
            result.assets.append(ctx.asset(asset_type="parameter", value=p, metadata={}))

        if new_params:
            result.findings.append(
                ctx.finding(
                    category="content_discovery",
                    title="Parameters identified",
                    description=f"Identified {len(new_params)} unique parameter name(s) from URL query strings and form inputs.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    extra={"parameters": sorted(new_params)},
                )
            )
        return result
