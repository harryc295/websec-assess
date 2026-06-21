"""Brute-forces common directory/admin-panel paths against the base URL."""
from __future__ import annotations

import re

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.core.probing import probe_paths
from websec_assess.core.wordlist import load_wordlist

BUDGET = {"quick": 40, "standard": 150, "deep": 150}
SENSITIVE = re.compile(r"\.git|\.svn|\.env|wp-admin|phpmyadmin|adminer|actuator|\.well-known/security")


@PluginRegistry.register
class DirectoryDiscoveryPlugin(Plugin):
    name = "content_discovery.directory_discovery"
    category = "content_discovery"
    description = "Brute-forces a built-in wordlist of common directories/admin paths, filtering soft-404s."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        budget = BUDGET.get(ctx.profile.value, 40)
        paths = load_wordlist("directories_small.txt")[:budget]
        found = await probe_paths(ctx, list(paths), concurrency=ctx.config.rate_limit.concurrency)

        for path, resp in found:
            url = str(resp.url)
            ctx.state.urls.add(url)
            result.assets.append(ctx.asset(asset_type="url", value=url, metadata={"status": resp.status_code}))
            severity = Severity.MEDIUM if SENSITIVE.search(path) else Severity.INFO
            result.findings.append(
                ctx.finding(
                    category="content_discovery",
                    title=f"Discovered path: /{path.lstrip('/')}",
                    description=f"Responded {resp.status_code} (differs from the baseline 404 response), indicating this path exists.",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    affected_url=url,
                    evidence=[Evidence(description=f"HTTP {resp.status_code}", matched_value=path)],
                    remediation="Ensure sensitive admin/management paths require authentication and are not unnecessarily exposed.",
                    cwe="CWE-538" if severity != Severity.INFO else None,
                    owasp="A05:2021-Security Misconfiguration" if severity != Severity.INFO else None,
                )
            )
        return result
