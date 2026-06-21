"""Finds cloud storage URLs (S3/Azure Blob/GCS) referenced in the target's
own page content. Deliberately passive: it reports the reference for manual
follow-up rather than probing the bucket/container itself, which usually
sits on infrastructure/an account outside the scanned host and therefore
outside this scan's authorised scope."""
from __future__ import annotations

import re

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

STORAGE_PATTERN = re.compile(
    r"https?://(?:[a-z0-9.\-]+\.s3[.-][a-z0-9\-]*\.amazonaws\.com|"
    r"[a-z0-9.\-]+\.s3\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.\-]+|"
    r"[a-z0-9\-]+\.blob\.core\.windows\.net|"
    r"storage\.googleapis\.com/[a-z0-9.\-_]+|[a-z0-9\-]+\.storage\.googleapis\.com)"
    r"[^\s\"'<>]*",
    re.IGNORECASE,
)


@PluginRegistry.register
class ExposedStorageDiscoveryPlugin(Plugin):
    name = "cloud_infra.exposed_storage_discovery"
    category = "cloud_infra"
    description = "Scans the homepage for referenced S3/Azure Blob/GCS storage URLs (reported, not probed)."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url)
        if resp is None or not resp.text:
            return result

        matches = sorted({m.group(0) for m in STORAGE_PATTERN.finditer(resp.text)})

        for url in matches:
            result.assets.append(ctx.asset(asset_type="cloud_storage_reference", value=url, metadata={}))
            result.findings.append(
                ctx.finding(
                    category="cloud_infra",
                    title="Cloud storage URL referenced in page content",
                    description=(
                        "The page references a cloud storage URL (S3/Azure Blob/GCS). This is not actively "
                        "probed by this scan -- if the bucket/container is in your authorised scope, manually "
                        "verify it isn't publicly listable/writable and doesn't expose sensitive objects."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    affected_url=ctx.target.base_url,
                    evidence=[Evidence(description="Referenced storage URL", matched_value=url)],
                    remediation="Review bucket/container ACLs; disable public listing; use signed URLs for any non-public objects.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/"],
                    cwe="CWE-200",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
