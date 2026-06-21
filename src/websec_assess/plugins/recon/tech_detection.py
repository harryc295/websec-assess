"""Lightweight, signature-based technology fingerprinting -- a small
Wappalyzer-style rule set, not a full clone. Each rule is (kind, regex):
kind is 'header:<name>', 'cookie', or 'body'.
"""
from __future__ import annotations

import re

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity

SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "WordPress": [("body", r"wp-content/"), ("body", r"wp-includes/")],
    "Drupal": [("body", r"Drupal\.settings"), ("header:x-generator", r"Drupal")],
    "Joomla": [("body", r"/media/jui/"), ("body", r"content=\"Joomla")],
    "Laravel": [("cookie", r"laravel_session")],
    "Django": [("cookie", r"csrftoken"), ("body", r"csrfmiddlewaretoken")],
    "Express": [("header:x-powered-by", r"Express")],
    "Nginx": [("header:server", r"nginx")],
    "Apache": [("header:server", r"Apache")],
    "Microsoft IIS": [("header:server", r"Microsoft-IIS")],
    "PHP": [("header:x-powered-by", r"PHP"), ("cookie", r"PHPSESSID")],
    "jQuery": [("body", r"jquery(\.min)?\.js")],
    "Bootstrap": [("body", r"bootstrap(\.min)?\.(css|js)")],
    "React": [("body", r"react-dom|__REACT_DEVTOOLS")],
    "Vue.js": [("body", r"__vue__|vue(\.min)?\.js")],
    "Cloudflare": [("header:server", r"cloudflare"), ("header:cf-ray", r".+")],
    "AWS CloudFront": [("header:x-amz-cf-id", r".+"), ("header:via", r"CloudFront")],
}


@PluginRegistry.register
class TechDetectionPlugin(Plugin):
    name = "recon.tech_detection"
    category = "recon"
    description = "Identifies frameworks/servers/CDNs from response headers, cookies, and HTML body markers."

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)
        resp = await ctx.http.get(ctx.target.base_url)
        if resp is None:
            result.errors.append("No response from target")
            return result

        body = resp.text[:200_000] if resp.text else ""
        cookie_names = " ".join(resp.cookies.keys())
        detected: set[str] = set()

        for tech, rules in SIGNATURES.items():
            for kind, pattern in rules:
                haystack = ""
                if kind == "body":
                    haystack = body
                elif kind == "cookie":
                    haystack = cookie_names
                elif kind.startswith("header:"):
                    haystack = resp.headers.get(kind.split(":", 1)[1], "")
                if haystack and re.search(pattern, haystack, re.IGNORECASE):
                    detected.add(tech)
                    break

        for tech in detected:
            ctx.state.technologies.add(tech)
            result.assets.append(ctx.asset(asset_type="technology", value=tech, metadata={}))

        if detected:
            result.findings.append(
                ctx.finding(
                    category="recon",
                    title="Technology stack identified",
                    description="Detected the following technologies from response signatures: " + ", ".join(sorted(detected)),
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    affected_url=ctx.target.base_url,
                    extra={"technologies": sorted(detected)},
                )
            )
        return result
