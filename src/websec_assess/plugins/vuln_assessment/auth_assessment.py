"""Passive review of login forms discovered by recon: transport security and
a CSRF-token heuristic. Deliberately does not submit any credentials -- see
plugins.auth_access for the (stubbed) active authentication boundary checks."""
from __future__ import annotations

from urllib.parse import urlsplit

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

CSRF_NAME_MARKERS = ("csrf", "token", "_token", "authenticity")


def _is_login_form(form: dict) -> bool:
    return any(f.get("type") == "password" for f in form.get("inputs", []))


@PluginRegistry.register
class AuthAssessmentPlugin(Plugin):
    name = "vuln_assessment.auth_assessment"
    category = "vuln_assessment"
    description = "Passively reviews discovered login forms for transport security and CSRF-token presence."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        login_forms = [f for f in ctx.state.forms if _is_login_form(f)]

        for form in login_forms:
            action = form.get("action", "")
            page = form.get("page", ctx.target.base_url)
            scheme = urlsplit(action).scheme or urlsplit(page).scheme

            if scheme != "https":
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title="Login form submits over an insecure channel",
                        description=f"A login form on {page} posts to '{action}', which is not HTTPS, exposing credentials to network interception.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        affected_url=page,
                        remediation="Serve the login form and its submission endpoint exclusively over HTTPS, and redirect HTTP to HTTPS.",
                        cwe="CWE-319",
                        owasp="A02:2021-Cryptographic Failures",
                    )
                )

            has_csrf_field = any(
                any(marker in (f.get("name") or "").lower() for marker in CSRF_NAME_MARKERS)
                for f in form.get("inputs", [])
            )
            if form.get("method") == "post" and not has_csrf_field:
                result.findings.append(
                    ctx.finding(
                        category="vuln_assessment",
                        title="Login form has no obvious CSRF token field",
                        description=(
                            f"The login form on {page} has no hidden input whose name suggests a CSRF token. "
                            "This is a heuristic -- the application may still protect the endpoint via headers, "
                            "double-submit cookies, or SameSite cookies; confirm manually before reporting."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        affected_url=page,
                        remediation="Confirm CSRF protection is implemented (token, SameSite=Strict/Lax cookies, or header-based).",
                        cwe="CWE-352",
                        owasp="A01:2021-Broken Access Control",
                    )
                )

        if login_forms:
            result.findings.append(
                ctx.finding(
                    category="vuln_assessment",
                    title="Login surface mapped",
                    description=f"Identified {len(login_forms)} login form(s) during recon for further authentication review.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_url=ctx.target.base_url,
                    extra={"login_forms": len(login_forms)},
                )
            )
        return result
