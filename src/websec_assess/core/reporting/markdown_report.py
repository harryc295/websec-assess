from __future__ import annotations

from websec_assess.core.models import Asset, Finding, ScanRun
from websec_assess.core.reporting.common import build_report_context


def render_markdown(scan: ScanRun, findings: list[Finding], assets: list[Asset]) -> str:
    ctx = build_report_context(scan, findings, assets)
    lines: list[str] = []
    lines.append(f"# Security Assessment Report: {scan.target.host}")
    lines.append("")
    lines.append(f"- **Target:** {scan.target.base_url}")
    lines.append(f"- **Profile:** {scan.profile.value}")
    lines.append(f"- **Status:** {scan.status.value}")
    lines.append(f"- **Started:** {scan.started_at}")
    lines.append(f"- **Finished:** {scan.finished_at}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev, count in ctx["severity_counts"].items():
        lines.append(f"| {sev.upper()} | {count} |")
    lines.append("")
    lines.append(f"Total findings: **{ctx['total_findings']}** &nbsp;&nbsp; Total assets discovered: **{ctx['total_assets']}**")
    lines.append("")
    lines.append("## Findings")
    for f in ctx["findings"]:
        lines.append("")
        lines.append(f"### [{f.severity.value.upper()}] {f.title}")
        lines.append(f"- **Plugin:** {f.plugin} ({f.category})")
        lines.append(f"- **Confidence:** {f.confidence.value}")
        lines.append(f"- **Affected URL:** `{f.affected_url}`")
        if f.cwe:
            lines.append(f"- **CWE:** {f.cwe}")
        if f.owasp:
            lines.append(f"- **OWASP:** {f.owasp}")
        lines.append("")
        lines.append(f.description)
        if f.evidence:
            lines.append("")
            lines.append("**Evidence:**")
            for ev in f.evidence:
                lines.append(f"- {ev.description}")
                if ev.matched_value:
                    lines.append(f"  - matched: `{ev.matched_value}`")
        if f.remediation:
            lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
        if f.references:
            lines.append("")
            lines.append("**References:**")
            for ref in f.references:
                lines.append(f"- {ref}")
    lines.append("")
    lines.append("## Asset Inventory")
    for asset_type, items in ctx["assets_by_type"].items():
        lines.append("")
        lines.append(f"### {asset_type} ({len(items)})")
        for item in items:
            lines.append(f"- {item.value}  _(via {item.source_plugin})_")
    return "\n".join(lines) + "\n"
