"""Regex-based secret detection in JS files. Matched values are redacted
before being stored as evidence -- the point is proving a secret is exposed,
not reproducing it in a report that then becomes its own leak."""
from __future__ import annotations

import re

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

PATTERNS: list[tuple[str, str, Severity]] = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", Severity.HIGH),
    ("AWS Secret Access Key", r"(?i)aws(?:.{0,20})?(?:secret|access)(?:.{0,20})?[\"'`]?\s*[:=]\s*[\"'`]?[0-9a-zA-Z/+]{40}", Severity.HIGH),
    ("Private key block", r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----", Severity.HIGH),
    ("Stripe live secret key", r"sk_live_[0-9a-zA-Z]{24,}", Severity.HIGH),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,}", Severity.MEDIUM),
    ("Google API key", r"AIza[0-9A-Za-z\-_]{35}", Severity.MEDIUM),
    ("JSON Web Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", Severity.MEDIUM),
    ("Generic API key assignment", r"(?i)(?:api[_-]?key|apikey)[\"'`]?\s*[:=]\s*[\"'`]?[0-9a-zA-Z\-_]{16,45}", Severity.MEDIUM),
    ("Generic secret/password assignment", r"(?i)(?:secret|password|passwd|pwd)[\"'`]?\s*[:=]\s*[\"'`][^\"'`\s]{8,}[\"'`]", Severity.LOW),
]
BUDGET = {"quick": 10, "standard": 30, "deep": 100}


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + ("*" * (len(value) - 8)) + value[-4:]


@PluginRegistry.register
class SecretDetectionPlugin(Plugin):
    name = "content_discovery.secret_detection"
    category = "content_discovery"
    description = "Scans discovered JavaScript files for hardcoded credentials/API keys using known secret patterns."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        budget = BUDGET.get(ctx.profile.value, 10)
        js_files = list(ctx.state.js_files)[:budget]

        for js_url in js_files:
            resp = await ctx.http.get(js_url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            for label, pattern, severity in PATTERNS:
                for match in re.finditer(pattern, body):
                    matched_text = match.group(0)
                    result.findings.append(
                        ctx.finding(
                            category="content_discovery",
                            title=f"Potential secret exposed in JavaScript: {label}",
                            description=f"A pattern matching '{label}' was found in a publicly served JavaScript file.",
                            severity=severity,
                            confidence=Confidence.LOW,
                            affected_url=js_url,
                            evidence=[Evidence(description=label, matched_value=_redact(matched_text))],
                            remediation="Remove hardcoded secrets from client-side code; rotate any exposed credentials immediately and load secrets server-side only.",
                            references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
                            cwe="CWE-798",
                            owasp="A07:2021-Identification and Authentication Failures",
                        )
                    )
        return result
