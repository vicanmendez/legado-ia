"""Esquemas de validación para designación de albacea y protocolo de modo póstumo."""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.auth import EMAIL_RE, ValidationError


@dataclass
class DesignateExecutorSchema:
    user_id: int
    notification_contacts: list[str]
    cooldown_hours: int = 72

    def __post_init__(self) -> None:
        if self.cooldown_hours < 1 or self.cooldown_hours > 8760:
            raise ValidationError("El plazo de espera debe estar entre 1 y 8760 horas")
        cleaned: list[str] = []
        for email in self.notification_contacts:
            em = email.strip().lower()
            if em:
                if not EMAIL_RE.match(em):
                    raise ValidationError(f"Contacto de notificación inválido: {em}")
                cleaned.append(em)
        self.notification_contacts = cleaned


@dataclass
class SuccessionTransitionActionSchema:
    notes: str | None = None

    def __post_init__(self) -> None:
        if self.notes:
            self.notes = self.notes.strip()[:255]
