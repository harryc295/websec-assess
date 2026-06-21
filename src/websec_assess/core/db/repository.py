from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from websec_assess.core.db.models import AssetORM, FindingORM, ScanORM
from websec_assess.core.models import Asset, Finding, PluginResult, ScanProfile, ScanRun, ScanStatus, Target
from websec_assess.core.severity import Confidence, Severity


class Repository:
    """Thin persistence boundary: pydantic models in, pydantic models out."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # -- scans ---------------------------------------------------------
    def create_scan(self, scan: ScanRun) -> None:
        row = ScanORM(
            id=scan.id,
            target_base_url=scan.target.base_url,
            target_host=scan.target.host,
            profile=scan.profile.value,
            status=scan.status.value,
            plugins_planned=scan.plugins_planned,
            plugins_completed=scan.plugins_completed,
            config_snapshot=scan.config_snapshot,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
        )
        self.session.add(row)
        self.session.commit()

    def get_scan(self, scan_id: str) -> ScanRun | None:
        row = self.session.get(ScanORM, scan_id)
        if row is None:
            return None
        return ScanRun(
            id=row.id,
            target=Target(base_url=row.target_base_url, host=row.target_host),
            profile=ScanProfile(row.profile),
            status=ScanStatus(row.status),
            plugins_planned=row.plugins_planned,
            plugins_completed=row.plugins_completed,
            started_at=row.started_at,
            finished_at=row.finished_at,
            config_snapshot=row.config_snapshot,
        )

    def list_scans(self) -> list[ScanRun]:
        rows = self.session.scalars(select(ScanORM).order_by(ScanORM.created_at.desc())).all()
        return [self.get_scan(r.id) for r in rows]  # type: ignore[misc]

    def set_scan_status(self, scan_id: str, status: ScanStatus, *, started: bool = False, finished: bool = False) -> None:
        row = self.session.get(ScanORM, scan_id)
        if row is None:
            return
        row.status = status.value
        now = datetime.now(timezone.utc)
        if started:
            row.started_at = now
        if finished:
            row.finished_at = now
        self.session.commit()

    def mark_plugin_completed(self, scan_id: str, plugin_name: str) -> None:
        row = self.session.get(ScanORM, scan_id)
        if row is None:
            return
        if plugin_name not in row.plugins_completed:
            row.plugins_completed = [*row.plugins_completed, plugin_name]
        self.session.commit()

    def remaining_plugins(self, scan_id: str) -> list[str]:
        row = self.session.get(ScanORM, scan_id)
        if row is None:
            return []
        return [p for p in row.plugins_planned if p not in row.plugins_completed]

    # -- plugin output ---------------------------------------------------
    def save_plugin_result(self, result: PluginResult, scan_id: str) -> None:
        for finding in result.findings:
            self.session.add(
                FindingORM(
                    id=finding.id,
                    scan_id=scan_id,
                    plugin=finding.plugin,
                    category=finding.category,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity.value,
                    confidence=finding.confidence.value,
                    affected_url=finding.affected_url,
                    evidence=[e.model_dump(mode="json") for e in finding.evidence],
                    remediation=finding.remediation,
                    references=finding.references,
                    cwe=finding.cwe,
                    owasp=finding.owasp,
                    extra=finding.extra,
                )
            )
        for asset in result.assets:
            self.session.add(
                AssetORM(
                    id=asset.id,
                    scan_id=scan_id,
                    asset_type=asset.asset_type,
                    value=asset.value,
                    source_plugin=asset.source_plugin,
                    metadata_json=asset.metadata,
                )
            )
        self.session.commit()

    # -- reads -------------------------------------------------------------
    def list_findings(self, scan_id: str, severity: str | None = None) -> list[Finding]:
        stmt = select(FindingORM).where(FindingORM.scan_id == scan_id)
        if severity:
            stmt = stmt.where(FindingORM.severity == severity)
        rows = self.session.scalars(stmt).all()
        return [
            Finding(
                id=r.id,
                scan_id=r.scan_id,
                plugin=r.plugin,
                category=r.category,
                title=r.title,
                description=r.description,
                severity=Severity(r.severity),
                confidence=Confidence(r.confidence),
                affected_url=r.affected_url,
                evidence=r.evidence,
                remediation=r.remediation,
                references=r.references,
                cwe=r.cwe,
                owasp=r.owasp,
                extra=r.extra,
                created_at=r.created_at,
            )
            for r in rows
        ]

    def list_assets(self, scan_id: str, asset_type: str | None = None) -> list[Asset]:
        stmt = select(AssetORM).where(AssetORM.scan_id == scan_id)
        if asset_type:
            stmt = stmt.where(AssetORM.asset_type == asset_type)
        rows = self.session.scalars(stmt).all()
        return [
            Asset(
                id=r.id,
                scan_id=r.scan_id,
                asset_type=r.asset_type,
                value=r.value,
                source_plugin=r.source_plugin,
                metadata=r.metadata_json,
                first_seen=r.first_seen,
            )
            for r in rows
        ]
