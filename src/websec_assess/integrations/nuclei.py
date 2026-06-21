from __future__ import annotations

from websec_assess.core.plugin import PluginContext
from websec_assess.integrations.base import ToolAdapter, parse_jsonl


class NucleiAdapter(ToolAdapter):
    binary_key = "nuclei"
    timeout_seconds = 600.0

    def build_command(self, ctx: PluginContext) -> list[str]:
        cmd = [self.binary_path(ctx.config), "-u", ctx.target.base_url, "-jsonl", "-silent", "-no-color"]
        if ctx.profile.value == "quick":
            cmd += ["-severity", "high,critical"]
        return cmd

    def parse_raw(self, raw_output: str) -> list[dict]:
        return parse_jsonl(raw_output)
