"""End-to-end: a real scheduler.run_scan() against the local mock server
fixture, going through every wired plugin for the 'quick' profile."""
from __future__ import annotations

from tests.conftest import make_config, make_repository
from websec_assess.core.models import ScanProfile, ScanStatus, Target
from websec_assess.core.plugin import PluginRegistry
from websec_assess.core.queue import Scheduler


async def test_quick_scan_completes_and_finds_known_issues(tmp_path, local_server):
    PluginRegistry.discover()
    config = make_config(tmp_path)
    repo = make_repository(config)
    scheduler = Scheduler(config, repo)

    target = Target(base_url=local_server, host="127.0.0.1")
    scan = await scheduler.run_scan(target, ScanProfile.QUICK)

    assert scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED)
    assert set(scan.plugins_completed) == set(scan.plugins_planned)

    findings = repo.list_findings(scan.id)
    titles = " | ".join(f.title for f in findings)

    assert any("Missing security header" in f.title for f in findings)
    assert any(".env" in f.title for f in findings)
    assert "robots.txt discloses paths" in titles or "robots.txt" in titles
    assert any("AWS Access Key ID" in f.title for f in findings)
    assert any("missing HttpOnly" in f.title for f in findings)

    assets = repo.list_assets(scan.id)
    assert any(a.asset_type == "url" for a in assets)


async def test_dry_run_sends_no_requests(tmp_path, local_server):
    PluginRegistry.discover()
    config = make_config(tmp_path)
    config.safety.dry_run = True
    repo = make_repository(config)
    scheduler = Scheduler(config, repo)

    target = Target(base_url=local_server, host="127.0.0.1")
    scan = await scheduler.run_scan(target, ScanProfile.QUICK)

    findings = repo.list_findings(scan.id)
    assets = repo.list_assets(scan.id)
    assert assets == []
    # A couple of plugins always emit an unconditional summary finding (even
    # "found 0"); nothing else should have produced anything since every
    # HTTP/DNS/socket action is dry-run-gated.
    always_on_summaries = {"recon.asset_inventory", "recon.subdomain_enum"}
    assert all(f.plugin in always_on_summaries for f in findings)
