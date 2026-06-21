"""Bounded same-host crawl to discover endpoints/forms beyond robots/sitemap.
Depth and page budget scale with scan profile so 'quick' stays quick."""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from websec_assess.core.html_extract import extract
from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

DEPTH_BUDGET = {"quick": 1, "standard": 2, "deep": 3}
PAGE_BUDGET = {"quick": 20, "standard": 60, "deep": 150}


@PluginRegistry.register
class EndpointDiscoveryPlugin(Plugin):
    name = "recon.endpoint_discovery"
    category = "recon"
    description = "Crawls same-host links/forms from the base URL up to a profile-scaled depth/page budget."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        max_depth = DEPTH_BUDGET.get(ctx.profile.value, 1)
        max_pages = PAGE_BUDGET.get(ctx.profile.value, 20)
        host = ctx.target.host

        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(ctx.target.base_url, 0)]
        new_urls = 0
        new_forms = 0

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            resp = await ctx.http.get(url)
            if resp is None or "text/html" not in resp.headers.get("content-type", ""):
                continue

            page = extract(resp.text[:300_000])
            for href in page.hrefs:
                absolute = urljoin(url, href)
                parsed = urlsplit(absolute)
                if parsed.scheme not in ("http", "https") or parsed.hostname != host:
                    continue
                clean = absolute.split("#")[0]
                if clean not in ctx.state.urls:
                    ctx.state.urls.add(clean)
                    result.assets.append(ctx.asset(asset_type="url", value=clean, metadata={"depth": depth + 1}))
                    new_urls += 1
                if depth + 1 <= max_depth and clean not in visited:
                    queue.append((clean, depth + 1))

            for src in page.srcs:
                absolute = urljoin(url, src)
                if absolute.endswith(".js"):
                    ctx.state.js_files.add(absolute)

            for form in page.forms:
                action = urljoin(url, form["action"]) if form["action"] else url
                ctx.state.forms.append({**form, "action": action, "page": url})
                new_forms += 1

        if new_urls or new_forms:
            result.findings.append(
                ctx.finding(
                    category="recon",
                    title="Endpoint discovery summary",
                    description=(
                        f"Crawled {len(visited)} page(s) (depth<={max_depth}), discovering "
                        f"{new_urls} new in-scope URL(s) and {new_forms} form(s)."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    extra={"pages_crawled": len(visited), "new_urls": new_urls, "new_forms": new_forms},
                )
            )
        return result
