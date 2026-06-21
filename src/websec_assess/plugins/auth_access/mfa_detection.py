"""Heuristic, passive MFA-support detection: looks for common 2FA/MFA
language on pages with a login form. Doesn't and can't determine whether
MFA is *enforced* -- only whether the UI seems to mention it."""
from __future__ import annotations

import re

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

MFA_MARKERS = re.compile(
    r"two[\s-]?factor|2fa|multi[\s-]?factor|mfa|authenticator app|one[\s-]?time (code|password)|\botp\b|security key|verification code",
    re.IGNORECASE,
)


def _has_password_field(form: dict) -> bool:
    return any(f.get("type") == "password" for f in form.get("inputs", []))


@PluginRegistry.register
class MfaDetectionPlugin(Plugin):
    name = "auth_access.mfa_detection"
    category = "auth_access"
    description = "Passive heuristic: checks pages with a login form for common MFA/2FA language."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        login_pages = {f["page"] for f in ctx.state.forms if _has_password_field(f)}
        if not login_pages:
            return result

        mentions_mfa = False
        checked_pages = 0
        for page in login_pages:
            resp = await ctx.http.get(page)
            checked_pages += 1
            if resp is not None and resp.text and MFA_MARKERS.search(resp.text):
                mentions_mfa = True
                break

        result.findings.append(
            ctx.finding(
                category="auth_access",
                title="MFA support indication" if mentions_mfa else "No MFA indication found on login page(s)",
                description=(
                    "Login page content mentions multi-factor authentication language."
                    if mentions_mfa
                    else (
                        f"Checked {checked_pages} login page(s) for common MFA/2FA language and found none. "
                        "This is a heuristic on visible page text only -- it cannot confirm MFA is absent, "
                        "only that the UI doesn't advertise it."
                    )
                ),
                severity=Severity.INFO if mentions_mfa else Severity.LOW,
                confidence=Confidence.LOW,
                affected_url=next(iter(login_pages)),
                remediation="Offer MFA (TOTP/WebAuthn) for accounts, especially privileged ones, if not already available." if not mentions_mfa else "",
                cwe="CWE-308" if not mentions_mfa else None,
                owasp="A07:2021-Identification and Authentication Failures",
            )
        )
        return result
