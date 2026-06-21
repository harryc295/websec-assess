"""The only path a plugin has to the network. Every request is scope-checked,
rate-limited, audit-logged, and skipped entirely in dry-run mode -- by
construction, not by convention, since plugins have no other way to make an
HTTP call.
"""
from __future__ import annotations

from typing import Any

import httpx

from websec_assess.core.config import AppConfig
from websec_assess.core.safety import AuditLog, RateLimiter, ScopeChecker


class SafeHttpClient:
    def __init__(
        self,
        config: AppConfig,
        scope: ScopeChecker,
        rate_limiter: RateLimiter,
        audit: AuditLog,
    ) -> None:
        self._config = config
        self._scope = scope
        self._rate_limiter = rate_limiter
        self._audit = audit
        self._client = httpx.AsyncClient(
            timeout=config.scan.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": config.scan.user_agent},
            verify=True,
        )

    @property
    def dry_run(self) -> bool:
        return self._config.safety.dry_run

    async def request(
        self, method: str, url: str, *, osint: bool = False, **kwargs: Any
    ) -> httpx.Response | None:
        """osint=True skips the target-scope check, for read-only lookups
        against fixed public services (crt.sh, web.archive.org) that aren't
        the target itself. Still rate-limited per-host and audit-logged --
        "not the target" doesn't mean "hammer it"."""
        host = httpx.URL(url).host
        if not osint:
            self._scope.assert_in_scope(host)
        self._audit.record("http_request", method=method, url=url, dry_run=self.dry_run, osint=osint)
        if self.dry_run:
            return None
        await self._rate_limiter.acquire(host)
        try:
            return await self._client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            self._audit.record("http_error", method=method, url=url, error=str(exc))
            return None

    async def get(self, url: str, *, osint: bool = False, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, osint=osint, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("OPTIONS", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "SafeHttpClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
