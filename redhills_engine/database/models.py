"""SQLAlchemy ORM schemas syncing with the PostgreSQL backend."""

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class ScanStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PayloadCategory(str, enum.Enum):
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    EXFILTRATION = "EXFILTRATION"
    API_ABUSE = "API_ABUSE"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Target(Base):
    """Tracks the client's AI asset under assessment."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    client_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    auth_headers: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Encrypted JSON string of auth headers"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    scans: Mapped[list["Scan"]] = relationship(back_populates="target", lazy="selectin")


class Scan(Base):
    """Tracks a single red-teaming scan execution and its state."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id"), nullable=False, index=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(ScanStatus, native_enum=False),
        default=ScanStatus.QUEUED,
        nullable=False,
        index=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    start_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    end_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    target: Mapped["Target"] = relationship(back_populates="scans", lazy="selectin")
    payloads: Mapped[list["Payload"]] = relationship(
        back_populates="scan", lazy="selectin"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="scan", lazy="selectin"
    )


class Payload(Base):
    """Tracks semantic prompt variations attempted during a scan."""

    __tablename__ = "payloads"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=False, index=True
    )
    category: Mapped[PayloadCategory] = mapped_column(
        SAEnum(PayloadCategory, native_enum=False), nullable=False
    )
    raw_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    mutated_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    was_blocked: Mapped[bool] = mapped_column(Boolean, default=False)

    scan: Mapped["Scan"] = relationship(back_populates="payloads", lazy="selectin")


class Vulnerability(Base):
    """Tracks verified security breaches discovered during a scan."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=False, index=True
    )
    severity: Mapped[SeverityLevel] = mapped_column(
        SAEnum(SeverityLevel, native_enum=False), nullable=False
    )
    vulnerability_type: Mapped[str] = mapped_column(String(256), nullable=False)
    exploit_chain: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON history of successful exploit steps"
    )
    remediation_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    egress_token_triggered: Mapped[bool] = mapped_column(Boolean, default=False)

    scan: Mapped["Scan"] = relationship(
        back_populates="vulnerabilities", lazy="selectin"
    )
