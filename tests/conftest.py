from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from websec_assess.core.config import AppConfig
from websec_assess.core.db.engine import make_engine, make_session_factory
from websec_assess.core.db.repository import Repository
from websec_assess.core.http_client import SafeHttpClient
from websec_assess.core.models import ScanProfile, Target
from websec_assess.core.plugin import PluginContext, ScanState
from websec_assess.core.safety import AuditLog, RateLimiter, ScopeChecker

LOGIN_PAGE = """<!DOCTYPE html><html><head><title>Test App</title></head><body>
<form method="post" action="/login">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Log in">
</form>
<a href="/api/v1/users?id=1">users</a>
<script src="/static/app.js"></script>
</body></html>"""

APP_JS = """
const usersEndpoint = "/api/v1/users";
const awsKey = "AKIAABCDEFGHIJKLMNOP";
fetch(usersEndpoint);
"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # silence test output
        pass

    def _send(self, status: int, body: bytes, content_type: str = "text/html", extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib API name)
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, LOGIN_PAGE.encode(), extra_headers={"Set-Cookie": "session=abc123; Path=/"})
        elif path == "/static/app.js":
            self._send(200, APP_JS.encode(), content_type="application/javascript")
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\n", content_type="text/plain")
        elif path == "/.env":
            self._send(200, b"DB_PASSWORD=hunter2\n", content_type="text/plain")
        elif path == "/api/v1/users":
            self._send(200, b'{"users": [1, 2, 3]}', content_type="application/json")
        else:
            self._send(404, b"not found")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        self._send(200, b"ok")


@pytest.fixture(scope="session")
def local_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def make_config(tmp_path, allowed_host: str = "127.0.0.1") -> AppConfig:
    config = AppConfig()
    config.scope.allowed_hosts = [allowed_host]
    config.safety.authorized = True
    config.safety.audit_log_path = str(tmp_path / "audit.log")
    config.database.url = f"sqlite:///{tmp_path / 'test.db'}"
    config.rate_limit.requests_per_second = 100.0
    config.rate_limit.burst = 100
    config.rate_limit.concurrency = 20
    config.scan.timeout_seconds = 5.0
    return config


def make_repository(config: AppConfig) -> Repository:
    engine = make_engine(config.database.url)
    session = make_session_factory(engine)()
    return Repository(session)


async def make_ctx(config: AppConfig, base_url: str, host: str, plugin_name: str, scan_id: str = "test-scan") -> PluginContext:
    scope = ScopeChecker(config.scope.allowed_hosts, config.scope.allowed_cidrs)
    audit = AuditLog(config.safety.audit_log_path)
    rate_limiter = RateLimiter(config.rate_limit.requests_per_second, config.rate_limit.burst)
    http = SafeHttpClient(config, scope, rate_limiter, audit)
    return PluginContext(
        target=Target(base_url=base_url, host=host),
        scan_id=scan_id,
        config=config,
        http=http,
        profile=ScanProfile.QUICK,
        state=ScanState(),
        audit=audit,
        rate_limiter=rate_limiter,
        plugin_name=plugin_name,
    )
