"""YAML-backed configuration. Plain pydantic models, no extra settings
framework: a scan needs one file read at startup, not a layered settings
system.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from websec_assess.core.models import ScanProfile


class ScopeConfig(BaseModel):
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)


class RateLimitConfig(BaseModel):
    requests_per_second: float = 5.0
    burst: int = 10
    concurrency: int = 10


class SafetyConfig(BaseModel):
    authorized: bool = False
    dry_run: bool = False
    active_injection_probes: bool = False
    audit_log_path: str = "audit.log"


class DatabaseConfig(BaseModel):
    url: str = "sqlite:///websec_assess.db"


class ScanConfig(BaseModel):
    profile: ScanProfile = ScanProfile.STANDARD
    output_dir: str = "./reports"
    timeout_seconds: float = 10.0
    user_agent: str = "websec-assess/0.1 (+authorised-assessment)"


class ToolPathsConfig(BaseModel):
    """Override binary names/paths for external tool integrations."""

    nuclei: str = "nuclei"
    katana: str = "katana"
    httpx: str = "httpx"
    subfinder: str = "subfinder"
    dnsx: str = "dnsx"
    naabu: str = "naabu"
    gau: str = "gau"
    waybackurls: str = "waybackurls"


class AppConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    tool_paths: ToolPathsConfig = Field(default_factory=ToolPathsConfig)

    @classmethod
    def load(cls, path: str | os.PathLike | None) -> "AppConfig":
        if path is None:
            return cls()
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        data: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
        return cls(**data)

    def to_snapshot(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
