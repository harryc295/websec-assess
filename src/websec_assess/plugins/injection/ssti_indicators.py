"""Server-Side Template Injection *indicator*: submits harmless arithmetic
template expressions for the common engines and checks whether the
evaluated result (49) appears where the literal payload doesn't."""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.plugins.injection._common import build_url, budget_for, candidate_params

PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]
EXPECTED = "49"


@PluginRegistry.register
class SstiIndicatorsPlugin(Plugin):
    name = "injection.ssti_indicators"
    category = "injection"
    description = "Submits harmless template arithmetic ({{7*7}} etc.) and checks whether the evaluated result appears in the response."
    requires_active_probes = True

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)

        for base, name, original, params in candidate_params(ctx, budget_for(ctx)):
            for payload in PAYLOADS:
                test_url = build_url(base, params, name, original + payload)
                resp = await ctx.http.get(test_url)
                if resp is None or not resp.text:
                    continue
                if EXPECTED in resp.text and payload not in resp.text:
                    result.findings.append(
                        ctx.finding(
                            category="injection",
                            title=f"SSTI indicator on parameter '{name}'",
                            description=(
                                f"Submitting the template expression '{payload}' via '{name}' produced '{EXPECTED}' "
                                "in the response (the evaluated result) instead of the literal payload, suggesting "
                                "server-side template evaluation of user input."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.MEDIUM,
                            affected_url=test_url,
                            evidence=[Evidence(description="Template expression evaluated", matched_value=f"{payload} -> {EXPECTED}")],
                            remediation="Never render user input as a template string. Treat all user input as data, not template source.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection"],
                            cwe="CWE-1336",
                            owasp="A03:2021-Injection",
                        )
                    )
                    break
        return result
