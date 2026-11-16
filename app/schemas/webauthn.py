"""Esquemas de validación para registro, autenticación y gestión de credenciales WebAuthn."""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.auth import ValidationError


@dataclass
class WebAuthnRegisterVerifySchema:
    credential_id_b64: str
    public_key_b64: str
    challenge_b64: str
    device_name: str
    sign_count: int = 0
    user_verified: bool = True
    rp_id: str = "localhost"
    origin: str = "http://localhost:8000"

    def __post_init__(self) -> None:
        self.device_name = self.device_name.strip()[:100]
        if not self.device_name:
            raise ValidationError("El nombre del dispositivo es obligatorio")
        if not self.credential_id_b64 or not self.public_key_b64 or not self.challenge_b64:
            raise ValidationError("Faltan campos criptográficos de registro WebAuthn")


@dataclass
class WebAuthnAuthenticateVerifySchema:
    credential_id_b64: str
    challenge_b64: str
    signature_b64: str
    sign_count: int
    user_verified: bool = True
    rp_id: str = "localhost"
    origin: str = "http://localhost:8000"

    def __post_init__(self) -> None:
        if not self.credential_id_b64 or not self.challenge_b64 or not self.signature_b64:
            raise ValidationError("Faltan campos en la respuesta de autenticación WebAuthn")
        if self.sign_count < 0:
            raise ValidationError("Contador de firmas inválido")


@dataclass
class WebAuthnRenameSchema:
    device_name: str

    def __post_init__(self) -> None:
        self.device_name = self.device_name.strip()[:100]
        if not self.device_name:
            raise ValidationError("El nuevo nombre del dispositivo no puede estar vacío")


@dataclass
class WebAuthnRevokeSchema:
    recovery_code: str | None = None
