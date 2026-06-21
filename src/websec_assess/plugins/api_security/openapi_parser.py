"""Parses OpenAPI/Swagger documents found by content_discovery.api_endpoint_id:
enumerates operations as assets and flags ones with no security requirement."""
from __future__ import annotations

import json

import yaml

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}
SENSITIVE_MARKERS = ("internal", "admin", "debug", "private")


def _load_spec(text: str) -> dict | None:
    try:
        parsed = json.loads(text)
    except ValueError:
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    return parsed if isinstance(parsed, dict) else None


@PluginRegistry.register
class OpenApiParserPlugin(Plugin):
    name = "api_security.openapi_parser"
    category = "api_security"
    description = "Parses discovered OpenAPI/Swagger specs and flags operations with no security requirement defined."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        spec_urls = ctx.state.response_cache.get("openapi_urls", [])

        for spec_url in spec_urls:
            resp = await ctx.http.get(spec_url)
            if resp is None or not resp.text:
                continue
            spec = _load_spec(resp.text)
            if not spec or "paths" not in spec:
                continue

            global_security = spec.get("security")
            has_schemes = bool((spec.get("components") or {}).get("securitySchemes") or spec.get("securityDefinitions"))
            unauthenticated_ops: list[str] = []
            sensitive_ops: list[str] = []

            for path, methods in (spec.get("paths") or {}).items():
                if not isinstance(methods, dict):
                    continue
                for method, op in methods.items():
                    if method.lower() not in HTTP_METHODS:
                        continue
                    op = op or {}
                    op_id = f"{method.upper()} {path}"
                    result.assets.append(ctx.asset(asset_type="api_endpoint", value=op_id, metadata={"source": "openapi", "spec": spec_url}))
                    op_security = op.get("security", global_security)
                    if not op_security and not has_schemes:
                        unauthenticated_ops.append(op_id)
                    if any(marker in path.lower() for marker in SENSITIVE_MARKERS):
                        sensitive_ops.append(op_id)

            result.findings.append(
                ctx.finding(
                    category="api_security",
                    title="OpenAPI specification parsed",
                    description=f"Parsed {spec_url}, enumerating {sum(len(m) for m in (spec.get('paths') or {}).values() if isinstance(m, dict))} operation(s).",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_url=spec_url,
                )
            )

            if unauthenticated_ops:
                result.findings.append(
                    ctx.finding(
                        category="api_security",
                        title="API operations with no security requirement defined in the spec",
                        description=(
                            "The following operations have no 'security' requirement (and the spec defines no "
                            "securitySchemes at all), which either means they're intentionally public or that "
                            "auth is enforced out-of-band and undocumented:\n" + "\n".join(unauthenticated_ops[:20])
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        affected_url=spec_url,
                        remediation="Document security requirements per-operation in the spec, and confirm each one matches what's actually enforced server-side.",
                        cwe="CWE-862",
                        owasp="A01:2021-Broken Access Control",
                    )
                )

            if sensitive_ops:
                result.findings.append(
                    ctx.finding(
                        category="api_security",
                        title="Internal-looking operations documented in a public API spec",
                        description="The following operations look internal/administrative but are documented in a spec reachable without authentication:\n" + "\n".join(sensitive_ops[:20]),
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        affected_url=spec_url,
                        remediation="Avoid publishing internal-only operations in a public API spec; serve a restricted spec externally.",
                        cwe="CWE-200",
                    )
                )
        return result
