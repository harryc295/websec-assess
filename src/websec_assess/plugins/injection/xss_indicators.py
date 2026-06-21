"""Reflected-XSS *indicator*: plants a unique, harmless marker (no real
script execution attempted) and checks whether it comes back unescaped.
Active param mutation -- requires safety.active_injection_probes=true."""
from __future__ import annotations

import uuid

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.plugins.injection._common import build_url, budget_for, candidate_params


@PluginRegistry.register
class XssIndicatorsPlugin(Plugin):
    name = "injection.xss_indicators"
    category = "injection"
    description = "Plants a unique marker in each parameter and checks whether it's reflected unescaped in the response."
    requires_active_probes = True

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        token = uuid.uuid4().hex[:8]
        payload = f"\"'><wsaxss{token}>"

        for base, name, _, params in candidate_params(ctx, budget_for(ctx)):
            test_url = build_url(base, params, name, payload)
            resp = await ctx.http.get(test_url)
            if resp is None or not resp.text:
                continue
            if payload in resp.text:
                result.findings.append(
                    ctx.finding(
                        category="injection",
                        title=f"Reflected XSS indicator on parameter '{name}'",
                        description=(
                            f"A harmless marker containing HTML metacharacters was reflected unescaped in the "
                            f"response when sent via the '{name}' parameter. This indicates a likely reflected XSS; "
                            "manual confirmation with a real payload (under authorisation) is recommended."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        affected_url=test_url,
                        evidence=[Evidence(description="Marker reflected unescaped", matched_value=payload)],
                        remediation="Context-appropriately encode/escape all user input before reflecting it into HTML responses; adopt a CSP as defence-in-depth.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                        cwe="CWE-79",
                        owasp="A03:2021-Injection",
                    )
                )
        return result
