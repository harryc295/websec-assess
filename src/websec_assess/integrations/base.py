"""Base class for wrapping an external recon/scanning binary.

Cross-platform by construction: shutil.which() resolves .exe/.cmd on Windows
and plain PATH entries on Linux/macOS identically, and subprocess execution
uses an argument list (never shell=True), so there's no shell-quoting
difference between cmd.exe, PowerShell, and bash to worry about.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from abc import ABC, abstractmethod
from typing import ClassVar

from websec_assess.core.config import AppConfig
from websec_assess.core.plugin import PluginContext


def parse_jsonl(raw_output: str) -> list[dict]:
    records = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def parse_lines(raw_output: str, key: str) -> list[dict]:
    return [{key: line.strip()} for line in raw_output.splitlines() if line.strip()]


class ToolAdapter(ABC):
    binary_key: ClassVar[str]
    timeout_seconds: ClassVar[float] = 120.0

    def binary_path(self, config: AppConfig) -> str:
        return getattr(config.tool_paths, self.binary_key)

    def is_installed(self, config: AppConfig) -> bool:
        return shutil.which(self.binary_path(config)) is not None

    @abstractmethod
    def build_command(self, ctx: PluginContext) -> list[str]: ...

    def stdin_input(self, ctx: PluginContext) -> str | None:
        return None

    @abstractmethod
    def parse_raw(self, raw_output: str) -> list[dict]: ...

    async def execute(self, ctx: PluginContext) -> str:
        cmd = self.build_command(ctx)
        ctx.audit.record("tool_exec_start", scan_id=ctx.scan_id, tool=self.binary_key, command=cmd)

        if ctx.http.dry_run:
            ctx.audit.record("tool_exec_skipped_dry_run", tool=self.binary_key)
            return ""

        stdin_data = self.stdin_input(ctx)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(stdin_data.encode() if stdin_data is not None else None),
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError:
            ctx.audit.record("tool_exec_not_found", tool=self.binary_key)
            return ""
        except asyncio.TimeoutError:
            ctx.audit.record("tool_exec_timeout", tool=self.binary_key)
            return ""

        ctx.audit.record(
            "tool_exec_finished",
            scan_id=ctx.scan_id,
            tool=self.binary_key,
            returncode=proc.returncode,
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
        )
        return stdout.decode(errors="replace")

    async def run_and_parse(self, ctx: PluginContext) -> list[dict]:
        output = await self.execute(ctx)
        if not output.strip():
            return []
        return self.parse_raw(output)
