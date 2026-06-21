"""Path traversal *indicator*: requests a well-known benign file via '../'
sequences and checks for that file's known signature. Evidence is capped to
a short snippet -- enough to prove the read, not a bulk file dump."""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.plugins.injection._common import build_url, budget_for, candidate_params

PAYLOADS = [
    ("../" * n + "etc/passwd", "root:x:0:0:")
    for n in (3, 5, 8)
] + [
    ("..\\" * n + "windows\\win.ini", "[fonts]")
    for n in (3, 5, 8)
]
EVIDENCE_SNIPPET_LIMIT = 300


@PluginRegistry.register
class PathTraversalIndicatorsPlugin(Plugin):
    name = "injection.path_traversal_indicators"
    category = "injection"
    description = "Requests well-known benign files via '../' traversal sequences and checks for their known signature."
    requires_active_probes = True

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)

        for base, name, original, params in candidate_params(ctx, budget_for(ctx)):
            for payload, signature in PAYLOADS:
                test_url = build_url(base, params, name, payload)
                resp = await ctx.http.get(test_url)
                if resp is not None and resp.text and signature in resp.text:
                    idx = resp.text.find(signature)
                    snippet = resp.text[max(0, idx - 20) : idx + EVIDENCE_SNIPPET_LIMIT]
                    result.findings.append(
                        ctx.finding(
                            category="injection",
                            title=f"Path traversal indicator on parameter '{name}'",
                            description=(
                                f"Requesting '{payload}' via parameter '{name}' returned content matching a known "
                                f"signature of a system file ('{signature}'), indicating path traversal."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            affected_url=test_url,
                            evidence=[Evidence(description="Matched known file signature", matched_value=signature, response_summary=snippet)],
                            remediation="Resolve file paths against an allowlist of permitted files/directories; never build filesystem paths directly from user input.",
                            references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                            cwe="CWE-22",
                            owasp="A01:2021-Broken Access Control",
                        )
                    )
                    break
        return result
