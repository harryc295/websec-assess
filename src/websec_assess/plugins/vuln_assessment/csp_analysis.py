"""Parses an existing Content-Security-Policy and flags weak directives.
Whether CSP is present at all is security_headers.py's job; this looks at
content once one exists."""
from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

RISKY_SOURCES = ("'unsafe-inline'", "'unsafe-eval'", "data:", "*")
IMPORTANT_DIRECTIVES = ("default-src", "script-src", "object-src", "frame-ancestors", "base-uri")


def _parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = tokens[1:]
    return directives


@PluginRegistry.register
class CspAnalysisPlugin(Plugin):
    name = "vuln_assessment.csp_analysis"
    category = "vuln_assessment"
    description = "Parses an existing Content-Security-Policy header and flags unsafe sources or missing key directives."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url)
        if resp is None:
            result.errors.append("No response from target")
            return result

        csp = resp.headers.get("content-security-policy")
        if not csp:
            return result  # absence is security_headers.py's concern

        directives = _parse_csp(csp)

        for directive in ("script-src", "default-src"):
            sources = directives.get(directive)
            if not sources:
                continue
            risky = [s for s in sources if s in RISKY_SOURCES]
            if risky:
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"CSP {directive} allows risky source(s): {', '.join(risky)}",
                        description=f"The '{directive}' directive includes {', '.join(risky)}, which significantly weakens CSP's ability to stop script injection.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        affected_url=ctx.target.base_url,
                        remediation="Remove 'unsafe-inline'/'unsafe-eval'/wildcard sources; use nonces or hashes for inline scripts instead.",
                        cwe="CWE-1021",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                )

        missing = [d for d in IMPORTANT_DIRECTIVES if d not in directives and "default-src" not in directives]
        if missing:
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title=f"CSP missing directive(s): {', '.join(missing)}",
                    description="No default-src fallback is set and these specific directives are absent, leaving those resource types unrestricted.",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    affected_url=ctx.target.base_url,
                    remediation="Set an explicit default-src, or define each missing directive individually.",
                    cwe="CWE-1021",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
