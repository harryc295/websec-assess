"""Certificate Transparency analysis via crt.sh: issuance volume, distinct
issuers, and wildcard certs. recon.subdomain_enum also queries crt.sh, but
only to harvest hostnames -- this looks at the certificate metadata itself."""
from __future__ import annotations

from collections import Counter

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity


@PluginRegistry.register
class CertificateTransparencyPlugin(Plugin):
    name = "passive_intel.certificate_transparency"
    category = "passive_intel"
    description = "Analyses crt.sh certificate transparency log entries for issuer diversity and wildcard certificates."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        host = ctx.target.host
        resp = await ctx.http.get(f"https://crt.sh/?q=%25.{host}&output=json", osint=True)
        if resp is None or resp.status_code != 200:
            return result

        try:
            entries = resp.json()
        except ValueError:
            return result
        if not entries:
            return result

        issuers = Counter(e.get("issuer_name", "unknown") for e in entries)
        wildcard_count = sum(1 for e in entries if "*." in str(e.get("name_value", "")))
        cert_ids = {e.get("id") for e in entries if e.get("id")}

        for cert_id in list(cert_ids)[:200]:
            result.assets.append(ctx.asset(asset_type="tls_certificate", value=str(cert_id), metadata={}))

        result.findings.append(
            ctx.finding(
                category="passive_intel",
                title="Certificate Transparency summary",
                description=(
                    f"{len(cert_ids)} certificate(s) logged across {len(issuers)} distinct issuer(s); "
                    f"{wildcard_count} wildcard certificate entr(y/ies)."
                ),
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_url=ctx.target.base_url,
                extra={"issuers": dict(issuers.most_common(10)), "wildcard_count": wildcard_count, "total_certs": len(cert_ids)},
            )
        )

        if wildcard_count:
            result.findings.append(
                ctx.finding(
                    category="passive_intel",
                    title="Wildcard certificate(s) issued for this domain",
                    description=f"{wildcard_count} certificate transparency entr(y/ies) cover a wildcard (*.{host}) name. A compromise of the wildcard cert's key affects every subdomain.",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    affected_url=ctx.target.base_url,
                    remediation="Prefer per-subdomain certificates (e.g. via ACME automation) over a single wildcard where practical.",
                    cwe="CWE-295",
                )
            )
        return result
