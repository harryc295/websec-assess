import asyncio
import json

import pytest

from websec_assess.core.safety import AuditLog, AuthorizationError, RateLimiter, ScopeChecker, require_authorization
from websec_assess.core.config import AppConfig


def test_scope_checker_exact_match():
    checker = ScopeChecker(["example.com"], [])
    assert checker.is_in_scope("example.com")
    assert not checker.is_in_scope("other.com")


def test_scope_checker_wildcard():
    checker = ScopeChecker(["*.example.com"], [])
    assert checker.is_in_scope("api.example.com")
    assert not checker.is_in_scope("example.com")


def test_scope_checker_cidr():
    checker = ScopeChecker([], ["10.0.0.0/24"])
    assert checker.is_in_scope("10.0.0.5")
    assert not checker.is_in_scope("10.0.1.5")


def test_scope_checker_assert_raises_when_out_of_scope():
    checker = ScopeChecker(["example.com"], [])
    with pytest.raises(Exception):
        checker.assert_in_scope("notallowed.com")


def test_require_authorization_raises_without_flag():
    config = AppConfig()
    with pytest.raises(AuthorizationError):
        require_authorization(config, cli_flag=False)


def test_require_authorization_passes_with_cli_flag():
    config = AppConfig()
    require_authorization(config, cli_flag=True)  # should not raise


def test_require_authorization_passes_with_config_flag():
    config = AppConfig()
    config.safety.authorized = True
    require_authorization(config, cli_flag=False)  # should not raise


def test_audit_log_writes_jsonl(tmp_path):
    log_path = tmp_path / "audit.log"
    audit = AuditLog(log_path)
    audit.record("test_action", foo="bar")
    audit.record("another_action", n=1)
    lines = log_path.read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["action"] == "test_action"
    assert first["foo"] == "bar"


def test_rate_limiter_throttles_bursts():
    async def run():
        limiter = RateLimiter(requests_per_second=5, burst=1)
        start = asyncio.get_event_loop().time()
        await limiter.acquire("host")
        await limiter.acquire("host")  # second call should wait ~0.2s for a token
        return asyncio.get_event_loop().time() - start

    elapsed = asyncio.run(run())
    assert elapsed >= 0.15
