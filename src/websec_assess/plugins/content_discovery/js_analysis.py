"""Fetches discovered JS files and regex-extracts endpoint-like strings."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

PATH_PATTERN = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{2,100})["']""")
URL_PATTERN = re.compile(r"""https?://[^\s"'<>\\]+""")
BUDGET = {"quick": 10, "standard": 30, "deep": 100}


@PluginRegistry.register
class JsAnalysisPlugin(Plugin):
    name = "content_discovery.js_analysis"
    category = "content_discovery"
    description = "Fetches discovered JavaScript files and extracts endpoint-like paths/URLs referenced in them."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        budget = BUDGET.get(ctx.profile.value, 10)
        host = ctx.target.host
        js_files = list(ctx.state.js_files)[:budget]
        new_paths: set[str] = set()

        for js_url in js_files:
            resp = await ctx.http.get(js_url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text[:500_000] if resp.text else ""
            for match in PATH_PATTERN.findall(body):
                if any(match.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2")):
                    continue
                new_paths.add(urljoin(js_url, match))
            for match in URL_PATTERN.findall(body):
                if urlsplit(match).hostname == host:
                    new_paths.add(match)

        added = 0
        for path in new_paths:
            if path not in ctx.state.urls:
                ctx.state.urls.add(path)
                result.assets.append(ctx.asset(asset_type="url", value=path))
                added += 1

        if js_files or added:
            result.findings.append(
                ctx.finding(
                    category="content_discovery",
                    title="JavaScript file analysis",
                    description=f"Analysed {len(js_files)} JS file(s) and extracted {added} new endpoint reference(s).",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    affected_url=ctx.target.base_url,
                    extra={"js_files_analysed": len(js_files), "new_endpoints": added},
                )
            )
        return result
