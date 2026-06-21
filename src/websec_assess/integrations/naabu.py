from __future__ import annotations

from websec_assess.core.plugin import PluginContext
from websec_assess.integrations.base import ToolAdapter, parse_jsonl


class NaabuAdapter(ToolAdapter):
    binary_key = "naabu"
    timeout_seconds = 300.0

    def build_command(self, ctx: PluginContext) -> list[str]:
        top_ports = {"quick": "100", "standard": "1000", "deep": "1000"}.get(ctx.profile.value, "100")
        return [self.binary_path(ctx.config), "-host", ctx.target.host, "-silent", "-json", "-top-ports", top_ports]

    def parse_raw(self, raw_output: str) -> list[dict]:
        return parse_jsonl(raw_output)
