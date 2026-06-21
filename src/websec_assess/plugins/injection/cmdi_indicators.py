"""Command injection *indicator*: injects shell metacharacters around a
harmless 'echo <marker>' and checks whether the marker comes back in the
response -- proves command execution without running anything destructive."""
from __future__ import annotations

import uuid

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.plugins.injection._common import build_url, budget_for, candidate_params


def _payloads(marker: str) -> list[str]:
    echo = f"echo {marker}"
    return [f";{echo};", f"|{echo}", f"`{echo}`", f"$({echo})", f"&&{echo}"]


@PluginRegistry.register
class CmdiIndicatorsPlugin(Plugin):
    name = "injection.cmdi_indicators"
    category = "injection"
    description = "Injects shell metacharacters wrapping a harmless 'echo <marker>' and checks for the marker in the response."
    requires_active_probes = True

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        marker = f"wsacmdi{uuid.uuid4().hex[:8]}"

        for base, name, original, params in candidate_params(ctx, budget_for(ctx)):
            for payload in _payloads(marker):
                test_url = build_url(base, params, name, original + payload)
                resp = await ctx.http.get(test_url)
                if resp is not None and resp.text and marker in resp.text:
                    result.findings.append(
                        ctx.finding(
                            category="injection",
                            title=f"Command injection indicator on parameter '{name}'",
                            description=(
                                f"A shell metacharacter payload wrapping a harmless 'echo {marker}' on parameter "
                                f"'{name}' caused the marker to appear in the response, indicating the input reaches "
                                "a shell command."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.MEDIUM,
                            affected_url=test_url,
                            evidence=[Evidence(description="Echoed marker from injected command", matched_value=marker)],
                            remediation="Never pass user input to a shell. Use language APIs that avoid the shell entirely, and allowlist input strictly if a shell call is unavoidable.",
                            references=["https://owasp.org/www-community/attacks/Command_Injection"],
                            cwe="CWE-78",
                            owasp="A03:2021-Injection",
                        )
                    )
                    break
        return result
