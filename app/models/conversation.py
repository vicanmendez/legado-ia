"""Modelos SQLAlchemy 2.x para conversaciones de amigos y ajustes de proveedor LLM (Parte 5)."""

from __future__ import annotations

from datetime import datetime

from app.db.base import (
    Boolean,
    DeclarativeBase,
    EncryptedBlob,
    ForeignKey,
    Integer,
    Mapped,
    String,
    UTCDateTime,
    mapped_column,
    utc_now,
)


class Conversation(DeclarativeBase):
    """Hilo de conversación privado entre un amigo y la simulación de un entrenador específico."""

    __tablename__ = "conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    friend_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    trainer_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    encrypted_title: Mapped[bytes] = mapped_column(EncryptedBlob, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, index=True, default=utc_now
    )


class Message(DeclarativeBase):
    """Mensaje individual dentro de una conversación, cifrado con la DEK del amigo."""

    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    friend_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sender_role: Mapped[str] = mapped_column(String(16), nullable=False)
    encrypted_content: Mapped[bytes] = mapped_column(EncryptedBlob, nullable=False)
    used_web_search: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    simulation_notice_shown: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    token_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, index=True, default=utc_now
    )


class LLMSettings(DeclarativeBase):
    """Ajustes del proveedor LLM y búsqueda web por entrenador con clave API cifrada."""

    __tablename__ = "llm_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trainer_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    provider_name: Mapped[str] = mapped_column(String(32), nullable=False, default="ollama")
    base_url: Mapped[str] = mapped_column(String(255), nullable=False)
    model_name: Mapped[str] = mapped_column(String(120), nullable=False)
    encrypted_api_key: Mapped[bytes | None] = mapped_column(EncryptedBlob, nullable=True)
    context_entries_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    daily_token_limit_per_user: Mapped[int] = mapped_column(Integer, nullable=False, default=25000)
    web_search_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    web_search_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)
