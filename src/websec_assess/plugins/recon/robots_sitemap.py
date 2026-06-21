"""robots.txt + sitemap.xml: cheap, always-public sources of path disclosure
and URL inventory."""
from __future__ import annotations

from urllib.parse import urljoin
from xml.etree import ElementTree

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


@PluginRegistry.register
class RobotsSitemapPlugin(Plugin):
    name = "recon.robots_sitemap"
    category = "recon"
    description = "Parses robots.txt for disallowed paths and sitemap references, then ingests any sitemap URLs."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        base = ctx.target.base_url
        disallowed: list[str] = []
        sitemap_urls: list[str] = [urljoin(base, "/sitemap.xml")]

        resp = await ctx.http.get(urljoin(base, "/robots.txt"))
        if resp is not None and resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        disallowed.append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_urls.append(line.split(":", 1)[1].strip())

        for path in disallowed:
            result.assets.append(ctx.asset(asset_type="disclosed_path", value=path, metadata={"source": "robots.txt"}))

        if disallowed:
            result.findings.append(
                ctx.finding(
                    category="recon",
                    title="robots.txt discloses paths of interest",
                    description="robots.txt lists paths that are excluded from search-engine crawling, which often hints at admin, staging, or internal functionality.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_url=urljoin(base, "/robots.txt"),
                    evidence=[Evidence(description="Disallowed paths", matched_value=", ".join(disallowed[:30]))],
                )
            )

        seen_sitemaps: set[str] = set()
        url_count = 0
        for sitemap_url in sitemap_urls:
            if sitemap_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sitemap_url)
            sm_resp = await ctx.http.get(sitemap_url)
            if sm_resp is None or sm_resp.status_code != 200:
                continue
            try:
                root = ElementTree.fromstring(sm_resp.content)
            except ElementTree.ParseError:
                continue
            for loc in root.iter(f"{SITEMAP_NS}loc"):
                if loc.text:
                    ctx.state.urls.add(loc.text.strip())
                    result.assets.append(ctx.asset(asset_type="url", value=loc.text.strip(), metadata={"source": "sitemap"}))
                    url_count += 1

        if url_count:
            result.findings.append(
                ctx.finding(
                    category="recon",
                    title="Sitemap URLs ingested",
                    description=f"Collected {url_count} URL(s) from sitemap.xml for use by later assessment phases.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_url=urljoin(base, "/sitemap.xml"),
                )
            )
        return result
