"""Esquemas de validación para autenticación, ALTCHA, OTP, invitaciones y códigos de recuperación."""

from __future__ import annotations

import re
from dataclasses import dataclass

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
OTP_RE = re.compile(r"^\d{6}$")


class ValidationError(ValueError):
    """Error de validación de esquema de entrada."""


@dataclass
class LoginStep1Schema:
    username: str
    password: str
    altcha_payload: str

    def __post_init__(self) -> None:
        self.username = self.username.strip()
        if not self.username or len(self.username) > 64:
            raise ValidationError("Nombre de usuario inválido")
        if not self.password or len(self.password) > 256:
            raise ValidationError("Contraseña inválida")
        if not self.altcha_payload or not self.altcha_payload.strip():
            raise ValidationError("El desafío ALTCHA es obligatorio")


@dataclass
class VerifyOTPSchema:
    code: str

    def __post_init__(self) -> None:
        self.code = self.code.strip()
        if not OTP_RE.match(self.code):
            raise ValidationError("El código OTP debe constar exactamente de 6 dígitos numéricos")


@dataclass
class VerifyRecoveryCodeSchema:
    recovery_code: str

    def __post_init__(self) -> None:
        self.recovery_code = self.recovery_code.strip().upper()
        if len(self.recovery_code) < 8 or len(self.recovery_code) > 32:
            raise ValidationError("Formato de código de recuperación inválido")


@dataclass
class CreateInvitationSchema:
    recipient_hint: str | None = None
    target_role: str = "amigo"
    expiry_hours: int | None = None

    def __post_init__(self) -> None:
        if self.target_role not in ("amigo", "albacea", "entrenador"):
            raise ValidationError("El rol de invitación debe ser 'amigo', 'albacea' o 'entrenador'")
        if self.recipient_hint:
            self.recipient_hint = self.recipient_hint.strip()[:120]


@dataclass
class RegisterInviteSchema:
    username: str
    email: str
    password: str
    altcha_payload: str

    def __post_init__(self) -> None:
        self.username = self.username.strip()
        self.email = self.email.strip().lower()
        if not USERNAME_RE.match(self.username):
            raise ValidationError("El usuario debe tener entre 3 y 64 caracteres alfanuméricos")
        if len(self.email) > 255 or not EMAIL_RE.match(self.email):
            raise ValidationError("Correo electrónico inválido")
        if len(self.password) < 10 or len(self.password) > 256:
            raise ValidationError("La contraseña debe tener al menos 10 caracteres")
        if not self.altcha_payload or not self.altcha_payload.strip():
            raise ValidationError("El desafío ALTCHA es obligatorio")
