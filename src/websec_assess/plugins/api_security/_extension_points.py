"""Documented extension point, not wired up: per-endpoint authentication
review needs either valid test credentials (to compare authenticated vs.
unauthenticated responses) or contextual knowledge of which endpoints are
meant to be public, neither of which a default unauthenticated scan can
safely assume. Guessing risks confident-sounding false positives/negatives.

To implement: supply credentials via config, send each api_endpoint asset
(see content_discovery.api_endpoint_id / api_security.openapi_parser) both
with and without the auth header, and flag endpoints that return the same
sensitive payload either way. Then add @PluginRegistry.register above the
class and import this module from a place PluginRegistry.discover() walks
(it already does -- this module just isn't registering itself).
"""
from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext


class ApiAuthReview(Plugin):
    name = "api_security.api_auth_review"
    category = "api_security"
    description = "STUB - needs test credentials; not registered. See module docstring."

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError("Not registered -- requires engagement-specific credentials, see module docstring.")
