"""Common server misconfigurations: directory listing, verbose error pages,
dangerous HTTP methods (PUT/DELETE/TRACE)."""
from __future__ import annotations

import uuid
from urllib.parse import urljoin

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

LISTING_PATHS = ["/images/", "/assets/", "/uploads/", "/static/", "/files/", "/backup/"]
LISTING_MARKERS = ("Index of /", "<title>Directory listing for", "Parent Directory</a>")
ERROR_MARKERS = (
    "Traceback (most recent call last)",
    "Fatal error:",
    "Warning: ",
    "ORA-",
    "Exception in thread",
    "System.NullReferenceException",
    "at java.",
    "Microsoft OLE DB Provider",
)
DANGEROUS_METHODS = {"PUT", "DELETE"}


@PluginRegistry.register
class MisconfigurationPlugin(Plugin):
    name = "vuln_assessment.misconfiguration"
    category = "vuln_assessment"
    description = "Checks for directory listing, verbose error disclosure, and dangerous HTTP methods."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        base = ctx.target.base_url

        for path in LISTING_PATHS:
            url = urljoin(base, path)
            resp = await ctx.http.get(url)
            if resp is None or resp.status_code != 200 or not resp.text:
                continue
            if any(marker in resp.text for marker in LISTING_MARKERS):
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"Directory listing enabled: {path}",
                        description="The web server returns a directory listing instead of a 403/404, disclosing the contents of this directory.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        affected_url=url,
                        remediation="Disable autoindex/directory browsing on the web server for this path.",
                        cwe="CWE-548",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                )

        probe_path = urljoin(base, f"/__wsa_err_{uuid.uuid4().hex[:8]}__/'%00\"<>")
        resp = await ctx.http.get(probe_path)
        if resp is not None and resp.text and any(marker in resp.text for marker in ERROR_MARKERS):
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="Verbose error message / stack trace disclosure",
                    description="An unusual request triggered a verbose error response containing stack trace or platform internals.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_url=probe_path,
                    evidence=[Evidence(description="Matched error marker in response body", response_summary=resp.text[:1000])],
                    remediation="Disable debug/verbose error pages in production; return generic error pages instead.",
                    cwe="CWE-209",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )

        resp = await ctx.http.options(base)
        if resp is not None:
            allow = {m.strip().upper() for m in resp.headers.get("allow", "").split(",") if m.strip()}
            exposed = allow & DANGEROUS_METHODS
            if exposed:
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title=f"Potentially dangerous HTTP methods allowed: {', '.join(sorted(exposed))}",
                        description=f"The Allow header on an OPTIONS response advertises: {', '.join(sorted(allow))}.",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        affected_url=base,
                        remediation="Restrict the web server/application to only the HTTP methods it actually needs.",
                        cwe="CWE-650",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                )

        marker = uuid.uuid4().hex
        trace_resp = await ctx.http.request("TRACE", base, headers={"X-Wsa-Trace-Test": marker})
        if trace_resp is not None and trace_resp.status_code < 400 and marker in (trace_resp.text or ""):
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="HTTP TRACE method enabled (possible Cross-Site Tracing)",
                    description="The server echoes the request back on a TRACE request, which can be combined with XSS to bypass HttpOnly cookie protections.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_url=base,
                    remediation="Disable the HTTP TRACE method at the web server level.",
                    cwe="CWE-693",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
