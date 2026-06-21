"""Adapter for ProjectDiscovery's `httpx` CLI (HTTP probing) -- unrelated to
the python `httpx` library this project uses as its own HTTP client."""
from __future__ import annotations

from websec_assess.core.plugin import PluginContext
from websec_assess.integrations.base import ToolAdapter, parse_jsonl


class HttpxToolAdapter(ToolAdapter):
    binary_key = "httpx"
    timeout_seconds = 120.0

    def build_command(self, ctx: PluginContext) -> list[str]:
        return [self.binary_path(ctx.config), "-u", ctx.target.base_url, "-json", "-silent", "-tech-detect", "-status-code"]

    def parse_raw(self, raw_output: str) -> list[dict]:
        return parse_jsonl(raw_output)
