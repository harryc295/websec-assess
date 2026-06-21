"""Scores the presence/absence of standard security response headers.
Recon.header_analysis records what's there; this judges what's missing."""
from __future__ import annotations

from urllib.parse import urlsplit

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

# (header, severity-if-missing, description, remediation, cwe, https_only)
CHECKS: list[tuple[str, Severity, str, str, str, bool]] = [
    (
        "strict-transport-security", Severity.MEDIUM,
        "HSTS is not set, so browsers may be downgraded to plain HTTP by a network attacker.",
        "Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' on all HTTPS responses.",
        "CWE-319", True,
    ),
    (
        "content-security-policy", Severity.MEDIUM,
        "No Content-Security-Policy header, so the browser has no defence-in-depth against injected scripts.",
        "Define a restrictive CSP (see plugins.vuln_assessment.csp_analysis for content-level checks once present).",
        "CWE-1021", False,
    ),
    (
        "x-content-type-options", Severity.LOW,
        "X-Content-Type-Options is missing, allowing browsers to MIME-sniff responses.",
        "Set 'X-Content-Type-Options: nosniff'.",
        "CWE-693", False,
    ),
    (
        "x-frame-options", Severity.MEDIUM,
        "X-Frame-Options is missing, which (absent an equivalent CSP frame-ancestors) leaves the site framable for clickjacking.",
        "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
        "CWE-1021", False,
    ),
    (
        "referrer-policy", Severity.INFO,
        "Referrer-Policy is not set, so the default browser behaviour governs how much of the URL leaks to third parties.",
        "Set an explicit 'Referrer-Policy' (e.g. 'strict-origin-when-cross-origin').",
        "CWE-200", False,
    ),
    (
        "permissions-policy", Severity.INFO,
        "Permissions-Policy is not set, leaving browser feature access (camera, geolocation, etc.) at default.",
        "Set a 'Permissions-Policy' that disables features the site doesn't use.",
        "CWE-693", False,
    ),
]


@PluginRegistry.register
class SecurityHeadersPlugin(Plugin):
    name = "vuln_assessment.security_headers"
    category = "vuln_assessment"
    description = "Checks the base URL for missing standard security response headers."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url)
        if resp is None:
            result.errors.append("No response from target")
            return result

        is_https = urlsplit(ctx.target.base_url).scheme == "https"
        present = {k.lower() for k in resp.headers.keys()}

        for header, severity, description, remediation, cwe, https_only in CHECKS:
            if https_only and not is_https:
                continue
            if header in present:
                continue
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title=f"Missing security header: {header}",
                    description=description,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    remediation=remediation,
                    references=["https://owasp.org/www-project-secure-headers/"],
                    cwe=cwe,
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
