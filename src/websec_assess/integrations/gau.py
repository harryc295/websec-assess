from __future__ import annotations

from websec_assess.core.plugin import PluginContext
from websec_assess.integrations.base import ToolAdapter, parse_lines


class GauAdapter(ToolAdapter):
    binary_key = "gau"
    timeout_seconds = 120.0

    def build_command(self, ctx: PluginContext) -> list[str]:
        return [self.binary_path(ctx.config), ctx.target.host]

    def parse_raw(self, raw_output: str) -> list[dict]:
        return parse_lines(raw_output, key="url")
