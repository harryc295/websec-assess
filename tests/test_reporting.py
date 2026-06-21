from websec_assess.core.models import Asset, Finding, ScanProfile, ScanRun, ScanStatus, Target
from websec_assess.core.reporting import render_html, render_json, render_markdown
from websec_assess.core.severity import Confidence, Severity


def _sample_scan_and_data():
    scan = ScanRun(
        target=Target(base_url="https://example.com", host="example.com"),
        profile=ScanProfile.QUICK,
        status=ScanStatus.COMPLETED,
        plugins_planned=["a"],
        plugins_completed=["a"],
    )
    findings = [
        Finding(
            scan_id=scan.id,
            plugin="vuln_assessment.security_headers",
            category="vuln_assessment",
            title="Missing security header: x-frame-options",
            description="No clickjacking protection.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_url="https://example.com",
            cwe="CWE-1021",
            owasp="A05:2021-Security Misconfiguration",
        )
    ]
    assets = [Asset(scan_id=scan.id, asset_type="url", value="https://example.com/admin", source_plugin="recon.endpoint_discovery")]
    return scan, findings, assets


def test_render_json_round_trips_counts():
    import json

    scan, findings, assets = _sample_scan_and_data()
    payload = json.loads(render_json(scan, findings, assets))
    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["severity_counts"]["medium"] == 1
    assert payload["findings"][0]["title"].startswith("Missing security header")


def test_render_markdown_contains_finding_and_asset():
    scan, findings, assets = _sample_scan_and_data()
    md = render_markdown(scan, findings, assets)
    assert "Missing security header" in md
    assert "CWE-1021" in md
    assert "https://example.com/admin" in md


def test_render_html_escapes_and_contains_finding():
    scan, findings, assets = _sample_scan_and_data()
    html = render_html(scan, findings, assets)
    assert "Missing security header" in html
    assert "<html" in html.lower()
