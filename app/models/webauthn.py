"""Modelo SQLAlchemy 2.x para credenciales FIDO2 / Passkeys WebAuthn (Parte 3)."""

from __future__ import annotations

from datetime import datetime

from app.db.base import (
    DeclarativeBase,
    ForeignKey,
    Integer,
    LargeBinary,
    Mapped,
    String,
    UTCDateTime,
    mapped_column,
    utc_now,
)


class WebAuthnCredential(DeclarativeBase):
    """Credencial WebAuthn registrada por un usuario como segundo factor."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(512), unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(1024), nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    device_name: Mapped[str] = mapped_column(String(100), nullable=False)
    transports: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
