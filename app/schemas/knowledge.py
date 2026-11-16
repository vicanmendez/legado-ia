"""Esquemas de validación para entradas de conocimiento, voz, personalidad y entrevista."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.db.base import utc_now
from app.schemas.auth import ValidationError


@dataclass
class EntryCreateSchema:
    topic: str
    content: str
    entry_date: datetime | None = None
    interview_topic_id: int | None = None
    status: str = "confirmed"

    def __post_init__(self) -> None:
        self.topic = self.topic.strip()[:120]
        self.content = self.content.strip()
        if not self.topic:
            raise ValidationError("El tema de la entrada es obligatorio")
        if not self.content:
            raise ValidationError("El contenido de la entrada no puede estar vacío")
        if len(self.content) > 100_000:
            raise ValidationError("El contenido supera la longitud máxima permitida")
        if self.status not in ("confirmed", "draft_transcription"):
            raise ValidationError("Estado de entrada inválido")
        if self.entry_date is None:
            self.entry_date = utc_now()


@dataclass
class EntryUpdateSchema:
    topic: str
    content: str
    status: str = "confirmed"

    def __post_init__(self) -> None:
        self.topic = self.topic.strip()[:120]
        self.content = self.content.strip()
        if not self.topic or not self.content:
            raise ValidationError("Tema y contenido son obligatorios")
        if self.status not in ("confirmed", "draft_transcription"):
            raise ValidationError("Estado de entrada inválido")


@dataclass
class PersonalityDocSchema:
    body: str

    def __post_init__(self) -> None:
        self.body = self.body.strip()
        if not self.body:
            raise ValidationError("El documento de personalidad no puede estar vacío")
        if len(self.body) > 200_000:
            raise ValidationError("El documento de personalidad excede el límite de tamaño")


@dataclass
class ExportFormatSchema:
    format: str

    def __post_init__(self) -> None:
        self.format = self.format.strip().lower()
        if self.format not in ("jsonl", "txt"):
            raise ValidationError("El formato de exportación debe ser 'jsonl' o 'txt'")
