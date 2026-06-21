"""Probes for accidentally-published CI/CD and cloud config files
(workflow definitions, Terraform state, kube/AWS config) using the same
baseline-404 heuristic as content_discovery's file brute-force, against a
CI/CD-specific wordlist."""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.probing import probe_paths
from websec_assess.core.severity import Confidence, Severity
from websec_assess.core.wordlist import load_wordlist

BUDGET = {"quick": 10, "standard": 25, "deep": 25}


@PluginRegistry.register
class CicdExposurePlugin(Plugin):
    name = "cloud_infra.cicd_exposure"
    category = "cloud_infra"
    description = "Brute-forces common CI/CD and cloud config filenames (workflow files, tfstate, kube/AWS config)."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        budget = BUDGET.get(ctx.profile.value, 10)
        paths = load_wordlist("cloud_cicd_paths.txt")[:budget]
        found = await probe_paths(ctx, list(paths), concurrency=ctx.config.rate_limit.concurrency)

        for path, resp in found:
            url = str(resp.url)
            result.assets.append(ctx.asset(asset_type="url", value=url, metadata={"status": resp.status_code}))
            result.findings.append(
                ctx.finding(
                    category="cloud_infra",
                    title=f"CI/CD or cloud config file exposed: {path}",
                    description=f"A request for '{path}' responded {resp.status_code} (differs from baseline 404), suggesting this CI/CD or cloud configuration file is publicly accessible. Such files often contain credentials, internal hostnames, or deployment details.",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    affected_url=url,
                    evidence=[Evidence(description=f"HTTP {resp.status_code}", matched_value=path)],
                    remediation="Remove CI/CD and IaC state/config files from the web root; keep them in the CI system or a private artifact store only.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    cwe="CWE-538",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
