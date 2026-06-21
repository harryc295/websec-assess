"""Everything that stands between a plugin and an unauthorised request:
authorization gate, scope/allowlist enforcement, rate limiting, audit log.

Plugins never talk to the network directly -- they go through
core.http_client.SafeHttpClient, which is built from the primitives here, so
none of this can be bypassed by forgetting a check in a plugin.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import time
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

from websec_assess.core.config import AppConfig

AUTHORIZATION_BANNER = """
================================================================================
 websec-assess -- authorised security assessment use only

 You must have EXPLICIT, DOCUMENTED PERMISSION to test the target(s) of this
 scan (a signed engagement letter, a bug bounty program's published scope, a
 CTF you are participating in, or infrastructure you personally own).

 Unauthorised scanning of systems is illegal in most jurisdictions regardless
 of intent. By proceeding you confirm you have that authorisation.
================================================================================
"""


class AuthorizationError(RuntimeError):
    pass


class ScopeError(RuntimeError):
    pass


def require_authorization(config: AppConfig, *, cli_flag: bool) -> None:
    print(AUTHORIZATION_BANNER)
    if not (config.safety.authorized or cli_flag):
        raise AuthorizationError(
            "Refusing to scan: pass --i-have-authorization on the CLI or set "
            "safety.authorized: true in the config file to confirm you are "
            "authorised to test this target."
        )


class ScopeChecker:
    """Hosts/CIDRs explicitly allowed for this scan. Empty allowlist = nothing
    is in scope -- a scan can't accidentally run wide open."""

    def __init__(self, allowed_hosts: list[str], allowed_cidrs: list[str]) -> None:
        self._hosts = [h.lower() for h in allowed_hosts]
        self._networks = [ipaddress.ip_network(c, strict=False) for c in allowed_cidrs]

    def is_in_scope(self, host: str) -> bool:
        host = host.lower()
        if any(host == h or fnmatch(host, h) for h in self._hosts):
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in self._networks)

    def assert_in_scope(self, host: str) -> None:
        if not self.is_in_scope(host):
            raise ScopeError(
                f"'{host}' is not in scope.allowed_hosts / scope.allowed_cidrs -- "
                "add it to the config explicitly before scanning it."
            )


class AuditLog:
    """Append-only JSONL action log. One line per action, flushed immediately
    so a crash mid-scan doesn't lose the trail."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, action: str, **fields: object) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "action": action, **fields}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")


class RateLimiter:
    """Async token bucket, one bucket per host so a multi-host scan can't let
    one slow host's budget starve another, and one host can't be hammered
    just because the global rate looks free."""

    def __init__(self, requests_per_second: float, burst: int) -> None:
        self.rate = requests_per_second
        self.burst = burst
        self._tokens: dict[str, float] = {}
        self._last: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                tokens = self._tokens.get(host, self.burst)
                last = self._last.get(host, now)
                tokens = min(self.burst, tokens + (now - last) * self.rate)
                if tokens >= 1:
                    self._tokens[host] = tokens - 1
                    self._last[host] = now
                    return
                self._tokens[host] = tokens
                self._last[host] = now
                wait = (1 - tokens) / self.rate
            await asyncio.sleep(wait)
