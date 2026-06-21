from websec_assess.core.models import Evidence, Finding, ScanProfile, ScanRun, ScanStatus, Target
from websec_assess.core.severity import Confidence, Severity


def test_finding_requires_core_fields():
    finding = Finding(
        scan_id="abc",
        plugin="test.plugin",
        category="recon",
        title="Example finding",
        description="desc",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        affected_url="https://example.com",
    )
    assert finding.id
    assert finding.severity == Severity.HIGH
    assert finding.evidence == []


def test_evidence_truncated_caps_length():
    ev = Evidence(description="x", response_summary="a" * 5000)
    truncated = ev.truncated(limit=100)
    assert len(truncated.response_summary) < 200
    assert "truncated" in truncated.response_summary


def test_evidence_truncated_handles_none():
    ev = Evidence(description="x")
    truncated = ev.truncated()
    assert truncated.response_summary is None
    assert truncated.matched_value is None


def test_scan_run_is_resumable_when_plugins_incomplete():
    scan = ScanRun(
        target=Target(base_url="https://example.com", host="example.com"),
        profile=ScanProfile.QUICK,
        status=ScanStatus.RUNNING,
        plugins_planned=["a", "b"],
        plugins_completed=["a"],
    )
    assert scan.is_resumable() is True


def test_scan_run_not_resumable_when_complete():
    scan = ScanRun(
        target=Target(base_url="https://example.com", host="example.com"),
        profile=ScanProfile.QUICK,
        status=ScanStatus.COMPLETED,
        plugins_planned=["a"],
        plugins_completed=["a"],
    )
    assert scan.is_resumable() is False
