"""Subdomain enumeration: passive (certificate transparency via crt.sh) plus
a small active DNS brute-force, scaled by scan profile so 'quick' stays fast.
"""
from __future__ import annotations

import asyncio

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.core.wordlist import load_wordlist

BRUTE_FORCE_BUDGET = {"quick": 0, "standard": 60, "deep": 1000}


def _resolves(name: str) -> bool:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        resolver.resolve(name, "A")
        return True
    except Exception:
        try:
            resolver.resolve(name, "AAAA")
            return True
        except Exception:
            return False


@PluginRegistry.register
class SubdomainEnumPlugin(Plugin):
    name = "recon.subdomain_enum"
    category = "recon"
    description = "Passive subdomain discovery via certificate transparency logs, plus a bounded active DNS brute-force."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        host = ctx.target.host
        found: set[str] = set()

        resp = await ctx.http.get(f"https://crt.sh/?q=%25.{host}&output=json", osint=True)
        if resp is not None and resp.status_code == 200:
            try:
                entries = resp.json()
            except ValueError:
                entries = []
            for entry in entries:
                for line in str(entry.get("name_value", "")).splitlines():
                    name = line.strip().lstrip("*.").lower()
                    if name.endswith(host) and name != host:
                        found.add(name)

        budget = 0 if ctx.http.dry_run else BRUTE_FORCE_BUDGET.get(ctx.profile.value, 60)
        if budget:
            words = load_wordlist("subdomains_small.txt")[:budget]
            candidates = [f"{w}.{host}" for w in words]
            semaphore = asyncio.Semaphore(20)

            async def check(name: str) -> None:
                async with semaphore:
                    await ctx.rate_limiter.acquire(host)
                    if await asyncio.to_thread(_resolves, name):
                        found.add(name)

            await asyncio.gather(*(check(c) for c in candidates))

        for name in found:
            ctx.state.subdomains.add(name)
            result.assets.append(ctx.asset(asset_type="subdomain", value=name, metadata={}))

        result.findings.append(
            ctx.finding(
                category="recon",
                title="Subdomain enumeration summary",
                description=f"Discovered {len(found)} candidate subdomain(s) via certificate transparency and DNS brute-force.",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_url=ctx.target.base_url,
                extra={"count": len(found)},
            )
        )
        return result
