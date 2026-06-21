"""DNS record enumeration + zone-transfer (AXFR) check.

AXFR is a single DNS query, not an exploit -- if the nameserver refuses it
(the overwhelming majority do), this is a no-op. If it succeeds, that's
itself the finding: the zone should not be transferable by anyone who asks.
"""
from __future__ import annotations

import asyncio

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def _resolve(host: str, rtype: str) -> list[str]:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        answer = resolver.resolve(host, rtype)
    except Exception:
        return []
    return [r.to_text() for r in answer]


def _attempt_axfr(ns_host: str, zone: str) -> list[str] | None:
    import dns.query
    import dns.zone

    try:
        xfr = dns.query.xfr(ns_host, zone, timeout=5, lifetime=10)
        zone_obj = dns.zone.from_xfr(xfr)
    except Exception:
        return None
    return [str(n) for n in zone_obj.nodes.keys()]


@PluginRegistry.register
class DnsEnumPlugin(Plugin):
    name = "recon.dns_enum"
    category = "recon"
    description = "Resolves common DNS record types; checks for unauthenticated AXFR zone transfer."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        host = ctx.target.host

        if ctx.http.dry_run:
            ctx.audit.record("dns_enum_skipped_dry_run", scan_id=ctx.scan_id, host=host)
            return result

        await ctx.rate_limiter.acquire(host)
        ctx.audit.record("dns_enum_start", scan_id=ctx.scan_id, host=host)

        records: dict[str, list[str]] = {}
        for rtype in RECORD_TYPES:
            values = await asyncio.to_thread(_resolve, host, rtype)
            if values:
                records[rtype] = values

        for rtype, values in records.items():
            for value in values:
                result.assets.append(
                    ctx.asset(asset_type="dns_record", value=f"{rtype} {value}", metadata={"record_type": rtype})
                )

        if records:
            result.findings.append(
                ctx.finding(
                    category="recon",
                    title="DNS records enumerated",
                    description="Resolved standard DNS record types for the target host.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    evidence=[Evidence(description=f"{rtype}: {', '.join(v)}") for rtype, v in records.items()],
                )
            )

        for ns in records.get("NS", []):
            ns_host = ns.rstrip(".")
            zone_names = await asyncio.to_thread(_attempt_axfr, ns_host, host)
            ctx.audit.record("axfr_attempt", scan_id=ctx.scan_id, nameserver=ns_host, succeeded=bool(zone_names))
            if zone_names:
                result.findings.append(
                    ctx.finding(
                        category="recon",
                        title=f"DNS zone transfer (AXFR) allowed on {ns_host}",
                        description=(
                            "The authoritative nameserver permitted an unauthenticated AXFR zone "
                            "transfer, disclosing the full contents of the DNS zone."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        affected_url=ns_host,
                        evidence=[Evidence(description="Records returned by AXFR", matched_value=", ".join(zone_names[:25]))],
                        remediation="Restrict AXFR to authorised secondary nameservers via an allow-transfer ACL.",
                        references=["https://www.cloudflare.com/learning/dns/dns-zone-transfer-axfr/"],
                        cwe="CWE-200",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                )
                for n in zone_names:
                    result.assets.append(ctx.asset(asset_type="subdomain", value=n, metadata={"via": "axfr"}))
        return result
