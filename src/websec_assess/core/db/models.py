"""SQLAlchemy ORM schema. Kept deliberately small: findings and assets store
their richer structure (evidence list, metadata) as JSON columns rather than
extra join tables -- nothing here is queried by evidence sub-fields, so a
normalised evidence table would only add joins with no payoff.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScanORM(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_base_url: Mapped[str] = mapped_column(String(2048))
    target_host: Mapped[str] = mapped_column(String(512))
    profile: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    plugins_planned: Mapped[list] = mapped_column(JSON, default=list)
    plugins_completed: Mapped[list] = mapped_column(JSON, default=list)
    config_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    findings: Mapped[list["FindingORM"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    assets: Mapped[list["AssetORM"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    plugin: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    affected_url: Mapped[str] = mapped_column(String(2048))
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scan: Mapped["ScanORM"] = relationship(back_populates="findings")

    __table_args__ = (Index("ix_findings_scan_severity", "scan_id", "severity"),)


class AssetORM(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    asset_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(2048))
    source_plugin: Mapped[str] = mapped_column(String(128))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scan: Mapped["ScanORM"] = relationship(back_populates="assets")

    __table_args__ = (Index("ix_assets_scan_type", "scan_id", "asset_type"),)
