"""Scan scheduler: phased async execution + resume.

A full dependency-graph scheduler would be overkill here -- there are really
only two dependency facts that matter: (1) everything wants recon's
discovered URLs/subdomains first, and (2) injection checks want the
parameters/forms that content-discovery and vuln-assessment found. Running
plugin *categories* in a fixed phase order captures both with no DAG code.
Within a phase, plugins run concurrently.
"""
from __future__ import annotations

import asyncio
from typing import Callable

from websec_assess.core.config import AppConfig
from websec_assess.core.db.repository import Repository
from websec_assess.core.http_client import SafeHttpClient
from websec_assess.core.logging import get_logger
from websec_assess.core.models import PluginResult, ScanProfile, ScanRun, ScanStatus, Target
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry, ScanState
from websec_assess.core.safety import AuditLog, RateLimiter, ScopeChecker

logger = get_logger("queue")

PHASE_ORDER = [
    "recon",
    "inventory",
    "integrations",
    "passive_intel",
    "content_discovery",
    "vuln_assessment",
    "api_security",
    "auth_access",
    "cloud_infra",
    "injection",
]


PluginEvent = Callable[[str, str], None]  # (event, plugin_name) -- "plugin_started"/"plugin_finished"/"plugin_crashed"


class Scheduler:
    def __init__(
        self,
        config: AppConfig,
        repository: Repository,
        on_plugin_event: PluginEvent | None = None,
    ) -> None:
        self.config = config
        self.repo = repository
        self.scope = ScopeChecker(config.scope.allowed_hosts, config.scope.allowed_cidrs)
        self.audit = AuditLog(config.safety.audit_log_path)
        self.rate_limiter = RateLimiter(config.rate_limit.requests_per_second, config.rate_limit.burst)
        self._max_concurrent_plugins = max(1, config.rate_limit.concurrency)
        self._on_plugin_event = on_plugin_event

    def plan(
        self, profile: ScanProfile, plugin_names: list[str] | None = None
    ) -> list[type[Plugin]]:
        candidates = PluginRegistry.for_profile(
            profile, active_probes_enabled=self.config.safety.active_injection_probes
        )
        if plugin_names:
            candidates = [p for p in candidates if p.name in plugin_names]
        order = {cat: i for i, cat in enumerate(PHASE_ORDER)}
        return sorted(candidates, key=lambda p: order.get(p.category, len(PHASE_ORDER)))

    async def run_scan(
        self,
        target: Target,
        profile: ScanProfile,
        plugin_names: list[str] | None = None,
    ) -> ScanRun:
        self.scope.assert_in_scope(target.host)
        planned = self.plan(profile, plugin_names)

        scan = ScanRun(
            target=target,
            profile=profile,
            plugins_planned=[p.name for p in planned],
            config_snapshot=self.config.to_snapshot(),
        )
        self.repo.create_scan(scan)
        self.audit.record("scan_created", scan_id=scan.id, target=target.base_url, profile=profile.value)
        await self._execute(scan, planned)
        completed = self.repo.get_scan(scan.id)
        assert completed is not None
        return completed

    async def resume_scan(self, scan_id: str) -> ScanRun:
        scan = self.repo.get_scan(scan_id)
        if scan is None:
            raise ValueError(f"No such scan: {scan_id}")
        remaining_names = self.repo.remaining_plugins(scan_id)
        all_plugins = {p.name: p for p in PluginRegistry.all()}
        remaining = [all_plugins[n] for n in remaining_names if n in all_plugins]
        order = {cat: i for i, cat in enumerate(PHASE_ORDER)}
        remaining.sort(key=lambda p: order.get(p.category, len(PHASE_ORDER)))
        self.audit.record("scan_resumed", scan_id=scan_id, remaining=remaining_names)
        await self._execute(scan, remaining)
        completed = self.repo.get_scan(scan.id)
        assert completed is not None
        return completed

    async def _execute(self, scan: ScanRun, planned: list[type[Plugin]]) -> None:
        self.repo.set_scan_status(scan.id, ScanStatus.RUNNING, started=True)
        http = SafeHttpClient(self.config, self.scope, self.rate_limiter, self.audit)
        state = ScanState()
        semaphore = asyncio.Semaphore(self._max_concurrent_plugins)
        had_errors = False

        try:
            by_phase: dict[str, list[type[Plugin]]] = {}
            for plugin_cls in planned:
                by_phase.setdefault(plugin_cls.category, []).append(plugin_cls)

            for category in PHASE_ORDER:
                phase_plugins = by_phase.get(category, [])
                if not phase_plugins:
                    continue
                results = await asyncio.gather(
                    *[
                        self._run_one(plugin_cls, scan, http, state, semaphore)
                        for plugin_cls in phase_plugins
                    ]
                )
                for plugin_cls, ok in zip(phase_plugins, results):
                    if not ok:
                        had_errors = True
        finally:
            await http.aclose()

        self.repo.set_scan_status(
            scan.id, ScanStatus.FAILED if had_errors else ScanStatus.COMPLETED, finished=True
        )
        self.audit.record("scan_finished", scan_id=scan.id, had_errors=had_errors)

    async def _run_one(
        self,
        plugin_cls: type[Plugin],
        scan: ScanRun,
        http: SafeHttpClient,
        state: ScanState,
        semaphore: asyncio.Semaphore,
    ) -> bool:
        ctx = PluginContext(
            target=scan.target,
            scan_id=scan.id,
            config=self.config,
            http=http,
            profile=scan.profile,
            state=state,
            audit=self.audit,
            rate_limiter=self.rate_limiter,
            plugin_name=plugin_cls.name,
        )
        async with semaphore:
            try:
                plugin = plugin_cls()
                self.audit.record("plugin_started", scan_id=scan.id, plugin=plugin_cls.name)
                if self._on_plugin_event:
                    self._on_plugin_event("plugin_started", plugin_cls.name)
                result: PluginResult = await plugin.run(ctx)
                self.repo.save_plugin_result(result, scan.id)
                self.repo.mark_plugin_completed(scan.id, plugin_cls.name)
                self.audit.record(
                    "plugin_finished",
                    scan_id=scan.id,
                    plugin=plugin_cls.name,
                    findings=len(result.findings),
                    errors=len(result.errors),
                )
                if self._on_plugin_event:
                    self._on_plugin_event("plugin_finished", plugin_cls.name)
                return not result.errors
            except Exception as exc:  # plugin bugs must not take the whole scan down
                logger.exception("plugin_crashed", extra={"plugin": plugin_cls.name})
                self.audit.record("plugin_crashed", scan_id=scan.id, plugin=plugin_cls.name, error=str(exc))
                if self._on_plugin_event:
                    self._on_plugin_event("plugin_crashed", plugin_cls.name)
                return False
