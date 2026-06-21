from __future__ import annotations

from websec_assess.core.plugin import PluginContext
from websec_assess.integrations.base import ToolAdapter, parse_lines


class SubfinderAdapter(ToolAdapter):
    binary_key = "subfinder"
    timeout_seconds = 180.0

    def build_command(self, ctx: PluginContext) -> list[str]:
        return [self.binary_path(ctx.config), "-d", ctx.target.host, "-silent"]

    def parse_raw(self, raw_output: str) -> list[dict]:
        return parse_lines(raw_output, key="host")
