"""Checks Set-Cookie attributes (Secure/HttpOnly/SameSite/Domain) on the base
URL response. Session-specific properties (entropy, persistence, URL
exposure) are covered by plugins.vuln_assessment.session_management."""
from __future__ import annotations

from urllib.parse import urlsplit

from websec_assess.core.cookies import looks_like_session, parse_all
from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity


@PluginRegistry.register
class CookieAnalysisPlugin(Plugin):
    name = "vuln_assessment.cookie_analysis"
    category = "vuln_assessment"
    description = "Checks Set-Cookie Secure/HttpOnly/SameSite/Domain attributes on the base URL."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url)
        if resp is None:
            result.errors.append("No response from target")
            return result

        is_https = urlsplit(ctx.target.base_url).scheme == "https"
        cookies = parse_all(resp.headers.get_list("set-cookie"))
        ctx.state.cookies.update({c.name: {"secure": c.secure, "httponly": c.httponly, "samesite": c.samesite} for c in cookies})

        for cookie in cookies:
            sensitive = looks_like_session(cookie.name)
            url = ctx.target.base_url

            if is_https and not cookie.secure:
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"Cookie '{cookie.name}' missing Secure flag",
                        description="Cookie can be sent over plain HTTP, exposing it to network interception.",
                        severity=Severity.MEDIUM if sensitive else Severity.LOW,
                        confidence=Confidence.HIGH,
                        affected_url=url,
                        remediation="Set the Secure attribute on all cookies served over HTTPS.",
                        cwe="CWE-614",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                )

            if not cookie.httponly:
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"Cookie '{cookie.name}' missing HttpOnly flag",
                        description="Cookie is readable from JavaScript, increasing impact if an XSS is found elsewhere.",
                        severity=Severity.MEDIUM if sensitive else Severity.LOW,
                        confidence=Confidence.HIGH,
                        affected_url=url,
                        remediation="Set the HttpOnly attribute unless client-side JS genuinely needs to read this cookie.",
                        cwe="CWE-1004",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                )

            samesite = (cookie.samesite or "").lower()
            if samesite not in ("strict", "lax"):
                if samesite == "none" and not cookie.secure:
                    severity = Severity.HIGH
                else:
                    severity = Severity.LOW
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"Cookie '{cookie.name}' has weak or missing SameSite attribute",
                        description=f"SameSite is '{cookie.samesite or 'not set'}', offering limited/no CSRF defence from the cookie itself.",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        affected_url=url,
                        remediation="Set SameSite=Lax (or Strict where feasible); SameSite=None requires Secure.",
                        cwe="CWE-352",
                        owasp="A01:2021-Broken Access Control",
                    )
                )

            if cookie.domain and cookie.domain.startswith("."):
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"Cookie '{cookie.name}' scoped to a broad parent domain",
                        description=f"Domain attribute '{cookie.domain}' makes this cookie available to every subdomain of that domain.",
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        affected_url=url,
                        remediation="Scope cookies to the most specific domain/host that needs them.",
                        cwe="CWE-1275",
                    )
                )
        return result
