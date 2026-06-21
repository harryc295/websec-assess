from __future__ import annotations

import json

from websec_assess.core.models import Asset, Finding, ScanRun
from websec_assess.core.reporting.common import build_report_context


def render_json(scan: ScanRun, findings: list[Finding], assets: list[Asset]) -> str:
    ctx = build_report_context(scan, findings, assets)
    payload = {
        "scan": json.loads(scan.model_dump_json()),
        "summary": {
            "total_findings": ctx["total_findings"],
            "severity_counts": ctx["severity_counts"],
            "total_assets": ctx["total_assets"],
        },
        "findings": [json.loads(f.model_dump_json()) for f in ctx["findings"]],
        "assets": [json.loads(a.model_dump_json()) for a in assets],
    }
    return json.dumps(payload, indent=2, default=str)
