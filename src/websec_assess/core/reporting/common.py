from __future__ import annotations

from collections import Counter
from typing import Any

from websec_assess.core.models import Asset, Finding, ScanRun
from websec_assess.core.severity import Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def build_report_context(scan: ScanRun, findings: list[Finding], assets: list[Asset]) -> dict[str, Any]:
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    severity_counts = Counter(f.severity.value for f in findings)
    assets_by_type: dict[str, list[Asset]] = {}
    for asset in assets:
        assets_by_type.setdefault(asset.asset_type, []).append(asset)
    return {
        "scan": scan,
        "findings": findings_sorted,
        "severity_counts": {s.value: severity_counts.get(s.value, 0) for s in SEVERITY_ORDER},
        "total_findings": len(findings),
        "assets_by_type": assets_by_type,
        "total_assets": len(assets),
    }
