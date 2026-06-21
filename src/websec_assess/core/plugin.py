"""Plugin base class + registry.

A plugin is a class, decorated with @PluginRegistry.register, implementing
async run(ctx) -> PluginResult. Discovery is just "import every module under
websec_assess.plugins" so the decorators execute -- no entry-point/manifest
machinery needed for a single-package tool.
"""
from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from websec_assess.core.config import AppConfig
from websec_assess.core.http_client import SafeHttpClient
from websec_assess.core.models import Asset, Evidence, Finding, PluginResult, ScanProfile, Target
from websec_assess.core.safety import AuditLog, RateLimiter
from websec_assess.core.severity import Confidence, Severity


@dataclass
class ScanState:
    """In-memory hand-off between plugin phases within one scan run.

    Recon plugins populate this; later phases (content discovery, vuln
    assessment, injection) read from it instead of re-discovering the same
    URLs/parameters. Plain lists/sets are fine -- everything here runs on one
    asyncio event loop, so there's no concurrent-mutation hazard to guard.
    """

    subdomains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    js_files: set[str] = field(default_factory=set)
    parameters: set[str] = field(default_factory=set)
    forms: list[dict[str, Any]] = field(default_factory=list)
    technologies: set[str] = field(default_factory=set)
    cookies: dict[str, dict[str, Any]] = field(default_factory=dict)
    response_cache: dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginContext:
    target: Target
    scan_id: str
    config: AppConfig
    http: SafeHttpClient
    profile: ScanProfile
    state: ScanState
    audit: AuditLog
    rate_limiter: RateLimiter
    plugin_name: str = ""

    def finding(
        self,
        *,
        category: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: Confidence,
        affected_url: str,
        evidence: list[Evidence] | None = None,
        remediation: str = "",
        references: list[str] | None = None,
        cwe: str | None = None,
        owasp: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            scan_id=self.scan_id,
            plugin=self.plugin_name,
            category=category,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            affected_url=affected_url,
            evidence=[e.truncated() for e in (evidence or [])],
            remediation=remediation,
            references=references or [],
            cwe=cwe,
            owasp=owasp,
            extra=extra or {},
        )

    def asset(self, *, asset_type: str, value: str, metadata: dict[str, Any] | None = None) -> Asset:
        return Asset(
            scan_id=self.scan_id,
            asset_type=asset_type,
            value=value,
            source_plugin=self.plugin_name,
            metadata=metadata or {},
        )


class Plugin(ABC):
    name: ClassVar[str]
    category: ClassVar[str]
    description: ClassVar[str] = ""
    profiles: ClassVar[frozenset[ScanProfile]] = frozenset(
        {ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP}
    )
    requires_active_probes: ClassVar[bool] = False

    @abstractmethod
    async def run(self, ctx: PluginContext) -> PluginResult: ...

    def runs_in(self, profile: ScanProfile) -> bool:
        return profile in self.profiles


class PluginRegistry:
    _plugins: ClassVar[dict[str, type[Plugin]]] = {}

    @classmethod
    def register(cls, plugin_cls: type[Plugin]) -> type[Plugin]:
        cls._plugins[plugin_cls.name] = plugin_cls
        return plugin_cls

    @classmethod
    def get(cls, name: str) -> type[Plugin]:
        return cls._plugins[name]

    @classmethod
    def all(cls) -> list[type[Plugin]]:
        return list(cls._plugins.values())

    @classmethod
    def by_category(cls, category: str) -> list[type[Plugin]]:
        return [p for p in cls._plugins.values() if p.category == category]

    @classmethod
    def for_profile(cls, profile: ScanProfile, *, active_probes_enabled: bool) -> list[type[Plugin]]:
        return [
            p
            for p in cls._plugins.values()
            if profile in p.profiles and (active_probes_enabled or not p.requires_active_probes)
        ]

    @classmethod
    def discover(cls, package_name: str = "websec_assess.plugins") -> None:
        package = importlib.import_module(package_name)
        for _, name, is_pkg in pkgutil.walk_packages(package.__path__, prefix=f"{package_name}."):
            importlib.import_module(name)
