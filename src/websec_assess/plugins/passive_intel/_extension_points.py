"""Documented extension points, not wired up (no @PluginRegistry.register):

- WhoisLookup: stdlib has no WHOIS client, and most WHOIS registries don't
  offer an HTTP API -- real implementations shell out to a `whois` binary
  (present by default on Ubuntu/Kali/Debian, NOT on Windows) or pull in a
  third-party library. Skipped here to avoid an inconsistent cross-platform
  experience and an extra dependency for a single field; wire it up with
  shutil.which("whois") + asyncio.create_subprocess_exec the same way
  integrations.base.ToolAdapter does, and document the Windows gap.
- AsnLookup: needs a BGP/IP-to-ASN data source (e.g. Team Cymru's
  whois/DNS service, ipinfo.io, BGPView). Any of those works the same way
  recon.subdomain_enum calls crt.sh via ctx.http.get(url, osint=True) --
  wire one up and register it.
- ReputationChecks: needs an API key for any real reputation source
  (VirusTotal, AbuseIPDB, etc.), which isn't something this platform should
  assume a user has configured by default.
"""
from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext


class WhoisLookup(Plugin):
    name = "passive_intel.whois_lookup"
    category = "passive_intel"
    description = "STUB - needs a `whois` binary or third-party lib; not registered. See module docstring."

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError("Not registered -- see module docstring.")


class AsnLookup(Plugin):
    name = "passive_intel.asn_lookup"
    category = "passive_intel"
    description = "STUB - needs a BGP/IP-to-ASN data source; not registered. See module docstring."

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError("Not registered -- see module docstring.")


class ReputationChecks(Plugin):
    name = "passive_intel.reputation_checks"
    category = "passive_intel"
    description = "STUB - needs a third-party reputation API key; not registered. See module docstring."

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError("Not registered -- see module docstring.")
