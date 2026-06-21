"""XXE *indicator*: POSTs a DOCTYPE/external-entity payload that resolves a
single, non-sensitive file (/etc/hostname) and compares against a baseline
XML POST with no DOCTYPE. Deliberately conservative -- no entity expansion
('billion laughs'), no attempt at sensitive files; this is in-band/error-
based detection only, not a blind/OOB XXE technique."""
from __future__ import annotations

import re

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.plugins.injection._common import budget_for

API_PATTERN = re.compile(r"/(api|rest|graphql|v[0-9]+)(/|$)", re.IGNORECASE)
HOSTNAME_LIKE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}$")
ERROR_MARKERS = ("doctype is disallowed", "external entity", "saxparseexception", "xmlsyntaxerror", "entity")
BASELINE_BODY = "<r>wsaxxebaseline</r>"
XXE_BODY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
    "<r>&x;</r>"
)


@PluginRegistry.register
class XxeIndicatorsPlugin(Plugin):
    name = "injection.xxe_indicators"
    category = "injection"
    description = "POSTs an external-entity XML payload resolving a non-sensitive file and compares against a baseline XML POST."
    requires_active_probes = True

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        candidates: set[str] = set()
        for form in ctx.state.forms:
            if form.get("method") == "post":
                candidates.add(form["action"])
        for url in ctx.state.urls:
            if API_PATTERN.search(url):
                candidates.add(url)

        headers = {"Content-Type": "application/xml"}
        for url in list(candidates)[: budget_for(ctx)]:
            baseline = await ctx.http.post(url, content=BASELINE_BODY, headers=headers)
            probe = await ctx.http.post(url, content=XXE_BODY, headers=headers)
            if baseline is None or probe is None:
                continue
            baseline_text = (baseline.text or "").strip()
            probe_text = (probe.text or "").strip()

            if probe_text and probe_text != baseline_text and HOSTNAME_LIKE.match(probe_text) and len(probe_text) < 64:
                result.findings.append(
                    ctx.finding(
                        category="injection",
                        title="XXE indicator: external entity content reflected",
                        description=(
                            "Posting an XML document declaring an external entity pointing at /etc/hostname produced "
                            "a short, hostname-shaped response body that differs from the baseline XML POST, "
                            "suggesting the parser resolved the external entity."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        affected_url=url,
                        evidence=[Evidence(description="Response differs from baseline and matches hostname shape", response_summary=probe_text[:200])],
                        remediation="Disable DTD processing and external entity resolution in the XML parser (e.g. defusedxml, or the parser's own secure-processing flag).",
                        references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                        cwe="CWE-611",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                )
                continue

            lowered = probe_text.lower()
            baseline_lower = baseline_text.lower()
            new_markers = [m for m in ERROR_MARKERS if m in lowered and m not in baseline_lower]
            if new_markers:
                result.findings.append(
                    ctx.finding(
                        category="injection",
                        title="XXE indicator: parser error referencing external entities/DOCTYPE",
                        description=(
                            "The XML parser's error response specifically mentions DOCTYPE/external entity handling "
                            "for the entity payload but not for the baseline, suggesting DTD processing is enabled. "
                            "This is a weak indicator -- manual confirmation is recommended."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        affected_url=url,
                        evidence=[Evidence(description="New error marker vs. baseline", matched_value=new_markers[0])],
                        remediation="Disable DTD processing and external entity resolution in the XML parser.",
                        cwe="CWE-611",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                )
        return result
