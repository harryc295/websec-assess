"""TLS/SSL inspection via stdlib ssl+socket: certificate validity/expiry,
negotiated protocol version, cipher strength. No active exploitation,
just a handshake and a peek at what it negotiated."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "NULL", "EXPORT", "DES")
EXPIRY_WARNING_DAYS = 30


def _probe(host: str) -> dict:
    info: dict = {}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                info["verified"] = True
                info["protocol"] = ssock.version()
                info["cipher"] = ssock.cipher()
                info["cert"] = ssock.getpeercert()
        return info
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["verify_error"] = str(exc)
    except (OSError, socket.timeout) as exc:
        info["connect_error"] = str(exc)
        return info

    try:
        insecure = ssl._create_unverified_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with insecure.wrap_socket(sock, server_hostname=host) as ssock:
                info["protocol"] = ssock.version()
                info["cipher"] = ssock.cipher()
    except (OSError, socket.timeout, ssl.SSLError):
        pass
    return info


@PluginRegistry.register
class TlsAnalysisPlugin(Plugin):
    name = "vuln_assessment.tls_analysis"
    category = "vuln_assessment"
    description = "Inspects the TLS handshake on port 443: certificate validity/expiry, protocol version, cipher."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        host = ctx.target.host

        if ctx.http.dry_run:
            ctx.audit.record("tls_probe_skipped_dry_run", scan_id=ctx.scan_id, host=host)
            return result

        await ctx.rate_limiter.acquire(host)
        ctx.audit.record("tls_probe", scan_id=ctx.scan_id, host=host)
        info = await asyncio.to_thread(_probe, host)

        if "connect_error" in info:
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="TLS not available on port 443",
                    description=f"Could not establish a TLS connection on port 443: {info['connect_error']}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_url=ctx.target.base_url,
                )
            )
            return result

        if info.get("verified") is False:
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="TLS certificate failed validation",
                    description="The presented TLS certificate did not validate against the system trust store (expired, self-signed, hostname mismatch, or untrusted issuer).",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    evidence=[Evidence(description=info.get("verify_error", ""))],
                    remediation="Install a valid certificate from a trusted CA covering the exact hostname in use.",
                    cwe="CWE-295",
                    owasp="A02:2021-Cryptographic Failures",
                )
            )

        protocol = info.get("protocol")
        if protocol in WEAK_PROTOCOLS:
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title=f"Weak TLS protocol version negotiated: {protocol}",
                    description=f"The server negotiated {protocol}, which is deprecated and known-weak.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    remediation="Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1; require TLSv1.2 or TLSv1.3 only.",
                    cwe="CWE-326",
                    owasp="A02:2021-Cryptographic Failures",
                )
            )

        cipher = info.get("cipher")
        if cipher and any(marker in cipher[0] for marker in WEAK_CIPHER_MARKERS):
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title=f"Weak TLS cipher suite negotiated: {cipher[0]}",
                    description="The negotiated cipher suite uses a weak/deprecated algorithm.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    remediation="Restrict the server's cipher suite configuration to modern AEAD ciphers (e.g. AES-GCM, ChaCha20-Poly1305).",
                    cwe="CWE-327",
                    owasp="A02:2021-Cryptographic Failures",
                )
            )

        cert = info.get("cert")
        if cert and cert.get("notAfter"):
            try:
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                if days_left < 0:
                    result.findings.append(
                        ctx.finding(
                            category="vuln_assessment",
                            title="TLS certificate has expired",
                            description=f"The TLS certificate expired on {cert['notAfter']}.",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            affected_url=ctx.target.base_url,
                            cwe="CWE-298",
                            owasp="A02:2021-Cryptographic Failures",
                        )
                    )
                elif days_left <= EXPIRY_WARNING_DAYS:
                    result.findings.append(
                        ctx.finding(
                            category="vuln_assessment",
                            title="TLS certificate expiring soon",
                            description=f"The TLS certificate expires in {days_left} day(s) ({cert['notAfter']}).",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            affected_url=ctx.target.base_url,
                        )
                    )
            except ValueError:
                pass

        return result
