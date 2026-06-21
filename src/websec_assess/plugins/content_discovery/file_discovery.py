"""Brute-forces known sensitive filenames (.env, .git/config, backups, etc.)."""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.core.probing import probe_paths
from websec_assess.core.wordlist import load_wordlist

BUDGET = {"quick": 20, "standard": 60, "deep": 60}


@PluginRegistry.register
class FileDiscoveryPlugin(Plugin):
    name = "content_discovery.file_discovery"
    category = "content_discovery"
    description = "Brute-forces a built-in wordlist of sensitive filenames (.env, backups, VCS metadata, etc.)."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        budget = BUDGET.get(ctx.profile.value, 20)
        files = load_wordlist("files_small.txt")[:budget]
        found = await probe_paths(ctx, list(files), concurrency=ctx.config.rate_limit.concurrency)

        for path, resp in found:
            url = str(resp.url)
            ctx.state.urls.add(url)
            result.assets.append(ctx.asset(asset_type="url", value=url, metadata={"status": resp.status_code}))
            result.findings.append(
                ctx.finding(
                    category="content_discovery",
                    title=f"Sensitive file exposed: {path}",
                    description=f"A request for '{path}' responded {resp.status_code} (differs from baseline 404), suggesting this sensitive file is accessible.",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    affected_url=url,
                    evidence=[Evidence(description=f"HTTP {resp.status_code}", matched_value=path, response_summary=resp.text[:500] if resp.text else None)],
                    remediation="Remove the file from the web root or restrict access to it at the web server/proxy level.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"],
                    cwe="CWE-538",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
