"""CORS probe: send a harmless, clearly-fake Origin header and see whether
the server reflects it or allows wildcard + credentials. Just an HTTP header
round-trip, nothing destructive."""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

TEST_ORIGIN = "https://websec-assess-cors-probe.invalid"


@PluginRegistry.register
class CorsAnalysisPlugin(Plugin):
    name = "vuln_assessment.cors_analysis"
    category = "vuln_assessment"
    description = "Probes CORS behaviour with a fake Origin header to detect reflection or unsafe wildcard+credentials."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url, headers={"Origin": TEST_ORIGIN})
        if resp is None:
            result.errors.append("No response from target")
            return result

        acao = resp.headers.get("access-control-allow-origin")
        acac = (resp.headers.get("access-control-allow-credentials") or "").lower() == "true"
        if not acao:
            return result

        if acao == TEST_ORIGIN:
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="CORS reflects arbitrary Origin" + (" with credentials allowed" if acac else ""),
                    description="The server echoes back any Origin header in Access-Control-Allow-Origin" + (
                        ", and Access-Control-Allow-Credentials is true, so any website can read authenticated responses on behalf of a visiting user."
                        if acac else ", allowing any website to read unauthenticated responses cross-origin."
                    ),
                    severity=Severity.CRITICAL if acac else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    evidence=[Evidence(description="Reflected Origin", request_summary=f"Origin: {TEST_ORIGIN}", response_summary=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}")],
                    remediation="Validate Origin against an explicit allowlist server-side; never reflect arbitrary Origins, especially with credentials enabled.",
                    cwe="CWE-942",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        elif acao == "*":
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="Wildcard CORS policy (Access-Control-Allow-Origin: *)",
                    description="Any website can make cross-origin requests and read unauthenticated responses from this endpoint.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    remediation="Restrict Access-Control-Allow-Origin to specific trusted origins if the endpoint returns sensitive data.",
                    cwe="CWE-942",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
