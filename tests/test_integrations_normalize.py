import pytest

from websec_assess.core.models import ScanProfile, Target
from websec_assess.core.plugin import PluginContext, ScanState
from websec_assess.core.safety import AuditLog, RateLimiter
from websec_assess.integrations.normalize import (
    normalize_dnsx,
    normalize_naabu,
    normalize_nuclei,
    normalize_subfinder,
)


@pytest.fixture
def ctx(tmp_path):
    return PluginContext(
        target=Target(base_url="https://example.com", host="example.com"),
        scan_id="scan-1",
        config=None,
        http=None,
        profile=ScanProfile.QUICK,
        state=ScanState(),
        audit=AuditLog(tmp_path / "audit.log"),
        rate_limiter=RateLimiter(100, 100),
        plugin_name="integrations.test",
    )


def test_normalize_nuclei_maps_severity_and_cwe(ctx):
    records = [
        {
            "template-id": "exposed-panel",
            "info": {
                "name": "Exposed Admin Panel",
                "severity": "high",
                "description": "Found an exposed admin panel.",
                "reference": "https://example.com/ref",
                "classification": {"cwe-id": ["CWE-200"]},
            },
            "matched-at": "https://example.com/admin",
        }
    ]
    result = normalize_nuclei(ctx, records)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity.value == "high"
    assert finding.cwe == "CWE-200"
    assert finding.affected_url == "https://example.com/admin"


def test_normalize_subfinder_adds_subdomain_assets(ctx):
    records = [{"host": "api.example.com"}, {"host": "www.example.com"}]
    result = normalize_subfinder(ctx, records)
    values = {a.value for a in result.assets}
    assert values == {"api.example.com", "www.example.com"}
    assert "api.example.com" in ctx.state.subdomains


def test_normalize_dnsx_expands_record_types(ctx):
    records = [{"host": "example.com", "a": ["1.2.3.4"], "cname": ["alias.example.com"]}]
    result = normalize_dnsx(ctx, records)
    values = {a.value for a in result.assets}
    assert "A 1.2.3.4" in values
    assert "CNAME alias.example.com" in values


def test_normalize_naabu_flags_sensitive_ports(ctx):
    records = [{"host": "example.com", "port": 3306}, {"host": "example.com", "port": 80}]
    result = normalize_naabu(ctx, records)
    assert len(result.assets) == 2
    assert len(result.findings) == 1
    assert "3306" in result.findings[0].title
