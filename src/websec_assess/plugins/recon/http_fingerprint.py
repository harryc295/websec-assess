"""Base-URL fingerprint: status code, redirect chain, server banner."""
from __future__ import annotations

import re

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

VERSION_PATTERN = re.compile(r"[\d]+\.[\d]+(\.[\d]+)?")


@PluginRegistry.register
class HttpFingerprintPlugin(Plugin):
    name = "recon.http_fingerprint"
    category = "recon"
    description = "Fetches the base URL, follows redirects, and flags version-disclosing server banners."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        url = ctx.target.base_url
        chain: list[str] = []
        final_resp = None
        for _ in range(5):
            resp = await ctx.http.get(url)
            if resp is None:
                break
            chain.append(f"{resp.status_code} {url}")
            final_resp = resp
            if resp.is_redirect and "location" in resp.headers:
                url = str(resp.headers["location"])
                continue
            break

        if final_resp is None:
            result.errors.append("No response from target base URL")
            return result

        ctx.state.urls.add(ctx.target.base_url)
        result.assets.append(ctx.asset(asset_type="url", value=ctx.target.base_url, metadata={"status": final_resp.status_code}))

        result.findings.append(
            ctx.finding(
                category="recon",
                title="HTTP fingerprint",
                description=f"Final response: {final_resp.status_code}. Redirect chain length: {len(chain)}.",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_url=ctx.target.base_url,
                evidence=[Evidence(description="Redirect chain", matched_value=" -> ".join(chain))],
            )
        )

        for header_name in ("server", "x-powered-by"):
            value = final_resp.headers.get(header_name)
            if value:
                ctx.state.technologies.add(value)
                if VERSION_PATTERN.search(value):
                    result.findings.append(
                        ctx.finding(
                            category="recon",
                            title=f"Version disclosure via {header_name} header",
                            description=f"The '{header_name}' response header discloses specific software version information, which helps an attacker target known vulnerabilities.",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            affected_url=ctx.target.base_url,
                            evidence=[Evidence(description=f"{header_name}: {value}", matched_value=value)],
                            remediation="Suppress or genericise version information in server response headers.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                            cwe="CWE-200",
                            owasp="A05:2021-Security Misconfiguration",
                        )
                    )
        return result
