from websec_assess.core.models import ScanProfile
from websec_assess.core.plugin import Plugin, PluginRegistry


def test_discover_registers_expected_plugin_count():
    PluginRegistry.discover()
    names = {p.name for p in PluginRegistry.all()}
    assert "recon.dns_enum" in names
    assert "vuln_assessment.security_headers" in names
    assert "injection.xss_indicators" in names
    # extension-point stubs must NOT be auto-registered
    assert "auth_access.idor_indicators" not in names
    assert "passive_intel.whois_lookup" not in names


def test_for_profile_excludes_active_probes_by_default():
    PluginRegistry.discover()
    plugins = PluginRegistry.for_profile(ScanProfile.STANDARD, active_probes_enabled=False)
    assert all(not p.requires_active_probes for p in plugins)


def test_for_profile_includes_active_probes_when_enabled():
    PluginRegistry.discover()
    plugins = PluginRegistry.for_profile(ScanProfile.STANDARD, active_probes_enabled=True)
    names = {p.name for p in plugins}
    assert "injection.xss_indicators" in names


def test_by_category_filters_correctly():
    PluginRegistry.discover()
    recon_plugins = PluginRegistry.by_category("recon")
    assert all(p.category == "recon" for p in recon_plugins)
    assert len(recon_plugins) >= 8


def test_plugin_is_abstract():
    import pytest

    with pytest.raises(TypeError):
        Plugin()  # abstract -- can't instantiate directly
