"""Modelos SQLAlchemy 2.x para albaceas, eventos de sucesión y estado póstumo del sistema (Parte 6)."""

from __future__ import annotations

from datetime import datetime

from app.db.base import (
    Boolean,
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


class SystemState(DeclarativeBase):
    """Estado global del sistema (activo, transicion_pendiente, postumo)."""

    __tablename__ = "system_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mode: Mapped[str] = mapped_column(String(24), nullable=False, default="activo")
    cooldown_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=72)
    transition_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    transition_confirmable_after: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True
    )
    posthumous_activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)


class Executor(DeclarativeBase):
    """Albacea designado por el entrenador para gestionar la transición y el modo póstumo."""

    __tablename__ = "executors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    designated_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    notification_contacts: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)


class SuccessionEvent(DeclarativeBase):
    """Registro formal de cada paso en el protocolo de sucesión póstuma."""

    __tablename__ = "succession_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    notes: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, index=True, default=utc_now
    )
