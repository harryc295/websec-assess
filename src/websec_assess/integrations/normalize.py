"""Maps each tool's native record shape onto the shared Finding/Asset
schema. One function per tool -- the schemas genuinely differ enough
(JSON vs. plain lines, nested vs. flat) that a single generic mapper would
just be a pile of if/else branches pretending to be one function."""
from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import PluginContext
from websec_assess.core.severity import Confidence, Severity

SENSITIVE_PORTS = {21, 23, 3306, 3389, 5432, 6379, 9200, 11211, 27017, 5900, 1433}


def _severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.INFO


def normalize_nuclei(ctx: PluginContext, records: list[dict]) -> PluginResult:
    result = PluginResult(plugin=ctx.plugin_name)
    for rec in records:
        info = rec.get("info", {}) or {}
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        classification = info.get("classification") or {}
        cwe_ids = classification.get("cwe-id") or []
        result.findings.append(
            ctx.finding(
                category="integrations",
                title=info.get("name", rec.get("template-id", "Nuclei match")),
                description=info.get("description", "") or f"Matched nuclei template '{rec.get('template-id')}'.",
                severity=_severity(info.get("severity", "info")),
                confidence=Confidence.HIGH,
                affected_url=rec.get("matched-at") or rec.get("host", ctx.target.base_url),
                references=refs,
                cwe=cwe_ids[0] if cwe_ids else None,  # nuclei templates already prefix e.g. "CWE-200"
                extra={"template_id": rec.get("template-id"), "tags": info.get("tags")},
            )
        )
    return result


def normalize_httpx(ctx: PluginContext, records: list[dict]) -> PluginResult:
    result = PluginResult(plugin=ctx.plugin_name)
    for rec in records:
        url = rec.get("url")
        if not url:
            continue
        result.assets.append(ctx.asset(asset_type="url", value=url, metadata={"status_code": rec.get("status_code")}))
        for tech in rec.get("tech", []) or []:
            result.assets.append(ctx.asset(asset_type="technology", value=tech, metadata={"source": "httpx"}))
    if records:
        result.findings.append(
            ctx.finding(
                category="integrations",
                title="httpx probe results",
                description=f"httpx probed {len(records)} URL(s).",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_url=ctx.target.base_url,
                extra={"count": len(records)},
            )
        )
    return result


def normalize_subfinder(ctx: PluginContext, records: list[dict]) -> PluginResult:
    result = PluginResult(plugin=ctx.plugin_name)
    for rec in records:
        host = rec.get("host")
        if host:
            ctx.state.subdomains.add(host)
            result.assets.append(ctx.asset(asset_type="subdomain", value=host, metadata={"source": "subfinder"}))
    return result


def normalize_dnsx(ctx: PluginContext, records: list[dict]) -> PluginResult:
    result = PluginResult(plugin=ctx.plugin_name)
    for rec in records:
        host = rec.get("host", ctx.target.host)
        for key in ("a", "aaaa", "cname", "ns", "mx", "txt"):
            for value in rec.get(key, []) or []:
                result.assets.append(
                    ctx.asset(asset_type="dns_record", value=f"{key.upper()} {value}", metadata={"host": host, "source": "dnsx"})
                )
    return result


def normalize_naabu(ctx: PluginContext, records: list[dict]) -> PluginResult:
    result = PluginResult(plugin=ctx.plugin_name)
    for rec in records:
        host = rec.get("host") or rec.get("ip", ctx.target.host)
        port = rec.get("port")
        if port is None:
            continue
        result.assets.append(ctx.asset(asset_type="open_port", value=f"{host}:{port}", metadata={"source": "naabu"}))
        if int(port) in SENSITIVE_PORTS:
            result.findings.append(
                ctx.finding(
                    category="integrations",
                    title=f"Potentially sensitive service exposed on port {port}",
                    description=f"naabu found port {port} open on {host}, which commonly hosts a database or admin service that shouldn't be internet-facing.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_url=f"{host}:{port}",
                    remediation="Restrict access to this port via firewall/security group rules; expose only through a VPN or bastion.",
                    cwe="CWE-200",
                    owasp="A05:2021-Security Misconfiguration",
                )
            )
    return result


def normalize_katana(ctx: PluginContext, records: list[dict]) -> PluginResult:
    result = PluginResult(plugin=ctx.plugin_name)
    for rec in records:
        url = (rec.get("request") or {}).get("endpoint") or rec.get("endpoint") or rec.get("url")
        if url and url not in ctx.state.urls:
            ctx.state.urls.add(url)
            result.assets.append(ctx.asset(asset_type="url", value=url, metadata={"source": "katana"}))
    return result


def _normalize_url_list(ctx: PluginContext, records: list[dict], source: str) -> PluginResult:
    result = PluginResult(plugin=ctx.plugin_name)
    new_count = 0
    for rec in records:
        url = rec.get("url")
        if url and url not in ctx.state.urls:
            ctx.state.urls.add(url)
            result.assets.append(ctx.asset(asset_type="url", value=url, metadata={"source": source}))
            new_count += 1
    if new_count:
        result.findings.append(
            ctx.finding(
                category="integrations",
                title=f"Historical URLs collected via {source}",
                description=f"{source} returned {new_count} new URL(s) for this host.",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_url=ctx.target.base_url,
                extra={"count": new_count},
            )
        )
    return result


def normalize_gau(ctx: PluginContext, records: list[dict]) -> PluginResult:
    return _normalize_url_list(ctx, records, "gau")


def normalize_waybackurls(ctx: PluginContext, records: list[dict]) -> PluginResult:
    return _normalize_url_list(ctx, records, "waybackurls")
