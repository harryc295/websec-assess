from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from websec_assess.core.models import Asset, Finding, ScanRun
from websec_assess.core.reporting.common import build_report_context

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html"]),
)


def render_html(scan: ScanRun, findings: list[Finding], assets: list[Asset]) -> str:
    ctx = build_report_context(scan, findings, assets)
    template = _env.get_template("report.html.j2")
    return template.render(**ctx)
