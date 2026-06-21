"""Pydantic models shared across plugins, storage and reporting.

These are the in-memory/transport schema. core.db.models holds the parallel
SQLAlchemy ORM schema used for persistence; core.db.repository converts
between the two.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from websec_assess.core.severity import Confidence, Severity


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class Target(BaseModel):
    """A single in-scope target, normalised to a base URL."""

    base_url: str
    host: str
    notes: str = ""


class Evidence(BaseModel):
    description: str = ""
    request_summary: str | None = None
    response_summary: str | None = None
    matched_value: str | None = None

    def truncated(self, limit: int = 2000) -> "Evidence":
        def cut(s: str | None) -> str | None:
            if s is None:
                return None
            return s if len(s) <= limit else s[:limit] + f"... [truncated, {len(s)} chars total]"

        return Evidence(
            description=self.description,
            request_summary=cut(self.request_summary),
            response_summary=cut(self.response_summary),
            matched_value=cut(self.matched_value),
        )


class Finding(BaseModel):
    id: str = Field(default_factory=_uuid)
    scan_id: str
    plugin: str
    category: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    affected_url: str
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cwe: str | None = None
    owasp: str | None = None
    created_at: datetime = Field(default_factory=_now)
    extra: dict[str, Any] = Field(default_factory=dict)


class Asset(BaseModel):
    id: str = Field(default_factory=_uuid)
    scan_id: str
    asset_type: str  # subdomain | url | ip | file | parameter | technology | api_endpoint | cookie
    value: str
    source_plugin: str
    first_seen: datetime = Field(default_factory=_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PluginResult(BaseModel):
    """What a plugin hands back to the scheduler after a run."""

    plugin: str
    findings: list[Finding] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ScanRun(BaseModel):
    id: str = Field(default_factory=_uuid)
    target: Target
    profile: ScanProfile
    status: ScanStatus = ScanStatus.PENDING
    plugins_planned: list[str] = Field(default_factory=list)
    plugins_completed: list[str] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    config_snapshot: dict[str, Any] = Field(default_factory=dict)

    def is_resumable(self) -> bool:
        return self.status in (ScanStatus.RUNNING, ScanStatus.FAILED) and bool(
            set(self.plugins_planned) - set(self.plugins_completed)
        )
