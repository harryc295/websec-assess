from __future__ import annotations

from websec_assess.core.plugin import PluginContext
from websec_assess.integrations.base import ToolAdapter, parse_jsonl


class KatanaAdapter(ToolAdapter):
    binary_key = "katana"
    timeout_seconds = 300.0

    def build_command(self, ctx: PluginContext) -> list[str]:
        depth = {"quick": "1", "standard": "2", "deep": "3"}.get(ctx.profile.value, "2")
        return [self.binary_path(ctx.config), "-u", ctx.target.base_url, "-jsonl", "-silent", "-depth", depth]

    def parse_raw(self, raw_output: str) -> list[dict]:
        return parse_jsonl(raw_output)
