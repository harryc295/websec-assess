from __future__ import annotations

from websec_assess.core.plugin import PluginContext
from websec_assess.integrations.base import ToolAdapter, parse_jsonl


class DnsxAdapter(ToolAdapter):
    binary_key = "dnsx"
    timeout_seconds = 120.0

    def build_command(self, ctx: PluginContext) -> list[str]:
        return [self.binary_path(ctx.config), "-silent", "-json", "-a", "-cname", "-resp"]

    def stdin_input(self, ctx: PluginContext) -> str | None:
        hosts = {ctx.target.host, *ctx.state.subdomains}
        return "\n".join(sorted(hosts))

    def parse_raw(self, raw_output: str) -> list[dict]:
        return parse_jsonl(raw_output)
