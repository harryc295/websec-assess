"""Flags API-shaped URLs already discovered and probes well-known
OpenAPI/Swagger definition paths. The actual spec parsing lives in
plugins.api_security.openapi_parser; this just locates candidates."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

API_PATTERN = re.compile(r"/(api|rest|graphql|v[0-9]+)(/|$)", re.IGNORECASE)
SPEC_PATHS = ["/swagger.json", "/swagger.yaml", "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs"]


@PluginRegistry.register
class ApiEndpointIdPlugin(Plugin):
    name = "content_discovery.api_endpoint_id"
    category = "content_discovery"
    description = "Identifies API-shaped URLs and probes common OpenAPI/Swagger definition paths."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        api_urls = {u for u in ctx.state.urls if API_PATTERN.search(urljoin(u, ""))}
        for url in api_urls:
            result.assets.append(ctx.asset(asset_type="api_endpoint", value=url, metadata={}))

        spec_urls: list[str] = []
        for path in SPEC_PATHS:
            url = urljoin(ctx.target.base_url + "/", path.lstrip("/"))
            resp = await ctx.http.get(url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if '"swagger"' in body or '"openapi"' in body or "swagger" in resp.headers.get("content-type", "").lower():
                spec_urls.append(url)
                result.assets.append(ctx.asset(asset_type="api_spec", value=url, metadata={}))

        ctx.state.response_cache.setdefault("openapi_urls", [])
        ctx.state.response_cache["openapi_urls"].extend(spec_urls)

        if api_urls:
            result.findings.append(
                ctx.finding(
                    category="content_discovery",
                    title="API endpoints identified",
                    description=f"Identified {len(api_urls)} URL(s) matching common API path conventions (/api/, /rest/, /graphql, /v1/...).",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    affected_url=ctx.target.base_url,
                    extra={"count": len(api_urls)},
                )
            )
        for url in spec_urls:
            result.findings.append(
                ctx.finding(
                    category="content_discovery",
                    title="OpenAPI/Swagger definition exposed",
                    description="A machine-readable API definition is publicly accessible, which fully documents the API's surface for an attacker.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_url=url,
                    remediation="Restrict access to API documentation endpoints in production, or ensure they don't expose internal-only routes.",
                    cwe="CWE-200",
                    owasp="API8:2023-Security Misconfiguration",
                )
            )
        return result
