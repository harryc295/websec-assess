"""Session-cookie-specific checks: persistence beyond the browser session,
short/low-entropy identifiers, and session IDs leaking into the URL."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from websec_assess.core.cookies import looks_like_session, parse_all
from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

MIN_SESSION_ID_LENGTH = 16


@PluginRegistry.register
class SessionManagementPlugin(Plugin):
    name = "vuln_assessment.session_management"
    category = "vuln_assessment"
    description = "Reviews session-identifier cookies for persistence, identifier length, and URL exposure."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url)
        if resp is None:
            result.errors.append("No response from target")
            return result

        cookies = [c for c in parse_all(resp.headers.get_list("set-cookie")) if looks_like_session(c.name)]
        url = ctx.target.base_url

        query_keys = [k for k, _ in parse_qsl(urlsplit(str(resp.url)).query)]
        if any(looks_like_session(k) for k in query_keys):
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="Session identifier exposed in URL",
                    description="A session-like parameter appears in the URL query string, where it can leak via browser history, Referer headers, and server logs.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_url=str(resp.url),
                    remediation="Carry session identifiers in cookies only, never in URLs.",
                    cwe="CWE-598",
                    owasp="A07:2021-Identification and Authentication Failures",
                )
            )

        for cookie in cookies:
            if cookie.expires or cookie.flags.get("max-age"):
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"Session cookie '{cookie.name}' persists beyond the browser session",
                        description="The cookie has an Expires/Max-Age attribute, so it survives browser close -- confirm this is intentional (e.g. 'remember me') rather than the primary session token.",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        affected_url=url,
                        remediation="Use a non-persistent session cookie for authentication state unless 'remember me' is explicitly requested.",
                        cwe="CWE-613",
                    )
                )
            if len(cookie.value) < MIN_SESSION_ID_LENGTH:
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"Session identifier '{cookie.name}' looks short",
                        description=f"Value is {len(cookie.value)} characters, which may indicate low entropy. This is a length heuristic, not an entropy measurement -- verify the generation method.",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        affected_url=url,
                        remediation="Generate session identifiers with a CSPRNG and at least 128 bits of entropy.",
                        cwe="CWE-330",
                    )
                )
        return result
