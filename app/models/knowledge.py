"""Modelos SQLAlchemy 2.x para la base de conocimiento del entrenador (Parte 4)."""

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


class InterviewTopic(DeclarativeBase):
    """Tema o pregunta del modo entrevista guiada del entrenador."""

    __tablename__ = "interview_topics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trainer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    prompt_title: Mapped[str] = mapped_column(String(255), nullable=False)
    is_covered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    covered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    display_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Entry(DeclarativeBase):
    """Entrada de recuerdo o vivencia del entrenador cifrada con la DEK del entrenador."""

    __tablename__ = "entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trainer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    topic: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    entry_date: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    encrypted_content: Mapped[bytes] = mapped_column(EncryptedBlob, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="confirmed")
    interview_topic_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("interview_topics.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)


class AudioFile(DeclarativeBase):
    """Metadatos de archivo de voz cifrado en disco asociado a una entrada."""

    __tablename__ = "audio_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entry_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("entries.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    trainer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    storage_rel_path: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(64), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    transcription_status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)


class PersonalityDoc(DeclarativeBase):
    """Versión cifrada del documento de personalidad y estilo lingüístico del entrenador."""

    __tablename__ = "personality_doc"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trainer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_body: Mapped[bytes] = mapped_column(EncryptedBlob, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)


class TrainerInterviewMessage(DeclarativeBase):
    """Mensaje del chat de entrevista guiada por IA del entrenador, cifrado con su DEK."""

    __tablename__ = "trainer_interview_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trainer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sender_role: Mapped[str] = mapped_column(String(20), nullable=False)
    topic: Mapped[str] = mapped_column(String(120), nullable=False, default="general")
    encrypted_content: Mapped[bytes] = mapped_column(EncryptedBlob, nullable=False)
    saved_entry_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, index=True, default=utc_now
    )
