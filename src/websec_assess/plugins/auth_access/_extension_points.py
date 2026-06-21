"""Documented extension points, not wired up. None of these classes are
registered with PluginRegistry -- add @PluginRegistry.register once
implemented. All four need either credentials or account-mutating actions
that a default unauthenticated, non-destructive scan shouldn't assume:

- LoginSurfaceMapping: superseded by vuln_assessment.auth_assessment, which
  already passively maps discovered login forms. Kept here as a named
  pointer because the original spec lists it as its own capability.
- PasswordPolicyReview: needs to submit candidate passwords to a
  registration/password-change form to observe enforcement -- inherently
  account-mutating.
- IdorIndicators: needs two authenticated sessions at different privilege
  levels to compare access to the same object ID.
- AuthorizationBoundaryCheck: needs role-scoped credentials supplied via
  config to probe whether a lower-privilege session can reach a
  higher-privilege resource (privilege separation).

To implement one: supply the needed credentials via config (add fields to
AppConfig), do the authenticated requests through ctx.http (it stays
scope/rate-limit/audit safe), and register the class.
"""
from __future__ import annotations

from websec_assess.core.models import PluginResult
from websec_assess.core.plugin import Plugin, PluginContext


class LoginSurfaceMapping(Plugin):
    name = "auth_access.login_surface_mapping"
    category = "auth_access"
    description = "STUB - see vuln_assessment.auth_assessment for the implemented passive version."

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError("Not registered -- see module docstring.")


class PasswordPolicyReview(Plugin):
    name = "auth_access.password_policy_review"
    category = "auth_access"
    description = "STUB - account-mutating; needs explicit opt-in and a target form. Not registered."

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError("Not registered -- see module docstring.")


class IdorIndicators(Plugin):
    name = "auth_access.idor_indicators"
    category = "auth_access"
    description = "STUB - needs two role-scoped credentials. Not registered."

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError("Not registered -- see module docstring.")


class AuthorizationBoundaryCheck(Plugin):
    name = "auth_access.authorization_boundary"
    category = "auth_access"
    description = "STUB - needs role-scoped credentials. Not registered."

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise NotImplementedError("Not registered -- see module docstring.")
