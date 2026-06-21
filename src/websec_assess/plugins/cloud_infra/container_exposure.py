"""Checks for an unauthenticated Docker daemon API or Kubernetes API server
exposed on the target host's non-standard ports. Note: the Kubernetes check
goes through the same TLS-verifying client as everything else, so a cluster
with a self-signed API server certificate will read as 'not reachable'
rather than 'exposed' -- a false negative, not a false positive."""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

PROBE_TIMEOUT = 5.0


@PluginRegistry.register
class ContainerExposurePlugin(Plugin):
    name = "cloud_infra.container_exposure"
    category = "cloud_infra"
    description = "Checks for an unauthenticated Docker daemon API (2375) or Kubernetes API server (6443) on the target host."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        host = ctx.target.host

        docker_url = f"http://{host}:2375/version"
        resp = await ctx.http.get(docker_url, timeout=PROBE_TIMEOUT)
        if resp is not None and resp.status_code == 200 and '"ApiVersion"' in (resp.text or ""):
            result.findings.append(
                ctx.finding(
                    category="cloud_infra",
                    title="Unauthenticated Docker daemon API exposed",
                    description="The Docker Engine API on port 2375 responds without authentication, which allows full control of the host's containers (equivalent to root on the host).",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    affected_url=docker_url,
                    evidence=[Evidence(description="Docker /version response", response_summary=resp.text[:300])],
                    remediation="Never expose the Docker daemon socket over plain TCP without TLS client-cert auth; bind it to localhost or a Unix socket and use an authenticated proxy if remote access is needed.",
                    references=["https://docs.docker.com/engine/security/protect-access/"],
                    cwe="CWE-306",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )

        k8s_url = f"https://{host}:6443/version"
        resp = await ctx.http.get(k8s_url, timeout=PROBE_TIMEOUT)
        if resp is not None and resp.status_code == 200 and "gitVersion" in (resp.text or ""):
            result.findings.append(
                ctx.finding(
                    category="cloud_infra",
                    title="Kubernetes API server reachable and unauthenticated for /version",
                    description="The Kubernetes API server on port 6443 returned version information without authentication. This endpoint alone is low-sensitivity, but its reachability means the API server is internet-facing -- confirm RBAC and network policy restrict everything else.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_url=k8s_url,
                    evidence=[Evidence(description="Kubernetes /version response", response_summary=resp.text[:300])],
                    remediation="Restrict the API server to a private network/VPN/bastion; never expose it directly to the internet.",
                    cwe="CWE-306",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
        return result
