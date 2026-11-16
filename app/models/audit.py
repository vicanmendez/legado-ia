"""Modelo AuditLog para registro inmutable de eventos de seguridad sin datos sensibles."""

from __future__ import annotations

from datetime import datetime

from app.db.base import (
    DeclarativeBase,
    ForeignKey,
    Integer,
    Mapped,
    String,
    Text,
    UTCDateTime,
    mapped_column,
    utc_now,
)


class AuditLog(DeclarativeBase):
    """Registro de eventos de seguridad (audit_log)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True, default=utc_now)
