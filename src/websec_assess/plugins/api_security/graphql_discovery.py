"""Probes common GraphQL paths with a harmless introspection query
(read-only schema enumeration, not a mutation) and flags introspection if
the server answers."""
from __future__ import annotations

from urllib.parse import urljoin

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

CANDIDATE_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console"]
INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}


@PluginRegistry.register
class GraphqlDiscoveryPlugin(Plugin):
    name = "api_security.graphql_discovery"
    category = "api_security"
    description = "Probes common GraphQL paths with a read-only introspection query and flags introspection if enabled."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        candidates = {urljoin(ctx.target.base_url, p) for p in CANDIDATE_PATHS}
        candidates |= {u for u in ctx.state.urls if u.rstrip("/").endswith("graphql")}

        for url in candidates:
            resp = await ctx.http.post(url, json=INTROSPECTION_QUERY, headers={"Content-Type": "application/json"})
            if resp is None or resp.status_code >= 400 or not resp.text:
                continue

            result.assets.append(ctx.asset(asset_type="api_endpoint", value=url, metadata={"type": "graphql"}))

            if "__schema" in resp.text and "queryType" in resp.text:
                result.findings.append(
                    ctx.finding(
                        category="api_security",
                        title="GraphQL introspection enabled",
                        description=f"The GraphQL endpoint at {url} answers introspection queries, fully disclosing its schema (types, fields, mutations) to any caller.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        affected_url=url,
                        evidence=[Evidence(description="Introspection query response", response_summary=resp.text[:300])],
                        remediation="Disable introspection in production, or require authentication for it.",
                        references=["https://owasp.org/www-project-api-security/"],
                        cwe="CWE-200",
                        owasp="API8:2023-Security Misconfiguration",
                    )
                )
            else:
                result.findings.append(
                    ctx.finding(
                        category="api_security",
                        title="GraphQL endpoint discovered",
                        description=f"Found a responsive GraphQL endpoint at {url} (introspection appears disabled).",
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        affected_url=url,
                    )
                )
        return result
