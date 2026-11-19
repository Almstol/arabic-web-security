from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_target_created", "target", "created_at"),)

    id: Mapped[object] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    target: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="site")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_scan_code", "scan_id", "code", unique=True),)

    id: Mapped[object] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[object] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    code: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title_ar: Mapped[str] = mapped_column(String(220), nullable=False)
    explanation_ar: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_ar: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    scan: Mapped[Scan] = relationship(back_populates="findings")
