"""Historical URL collection via the Wayback Machine CDX API -- the same
public data source the `waybackurls` tool uses, fetched directly here so
this works even without the Go binary installed (see integrations.waybackurls
for the adapter that wraps the binary instead, when available)."""
from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

CDX_URL = "https://web.archive.org/cdx/search/cdx"


@PluginRegistry.register
class HistoricalUrlsPlugin(Plugin):
    name = "recon.historical_urls"
    category = "recon"
    description = "Queries the Wayback Machine CDX API for previously archived URLs under the target host."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        host = ctx.target.host
        limit = {"quick": 100, "standard": 500, "deep": 2000}.get(ctx.profile.value, 500)
        params = {
            "url": f"{host}/*",
            "output": "json",
            "collapse": "urlkey",
            "fl": "original",
            "limit": str(limit),
        }
        resp = await ctx.http.get(CDX_URL, params=params, osint=True)
        if resp is None or resp.status_code != 200:
            return result

        try:
            rows = resp.json()
        except ValueError:
            return result

        new_count = 0
        for row in rows[1:] if rows else []:  # first row is the header
            url = row[0] if isinstance(row, list) else None
            if url and url not in ctx.state.urls:
                ctx.state.urls.add(url)
                result.assets.append(ctx.asset(asset_type="url", value=url, metadata={"source": "wayback"}))
                new_count += 1

        if new_count:
            result.findings.append(
                ctx.finding(
                    category="recon",
                    title="Historical URLs collected from the Wayback Machine",
                    description=f"Found {new_count} previously archived URL(s) under this host, which may reveal retired or undocumented endpoints.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    extra={"count": new_count},
                )
            )
        return result
