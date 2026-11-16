"""Servicio de segundo factor y gestión de Passkeys WebAuthn (Parte 3)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any

from app.config import Settings, get_settings
from app.db._compat_sa import Session as DbSession
from app.db.base import select, utc_now
from app.models.user import Session, User
from app.models.webauthn import WebAuthnCredential
from app.schemas.webauthn import (
    WebAuthnAuthenticateVerifySchema,
    WebAuthnRegisterVerifySchema,
)
from app.services.audit import log_security_event
from app.services.auth import (
    AuthenticatedSessionResult,
    AuthenticationError,
    promote_session_after_2fa,
    verify_user_recovery_code_for_action,
)


class WebAuthnError(PermissionError):
    """Error de ceremonia, replay, verificación de usuario o clonación en WebAuthn."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(val: str) -> bytes:
    padded = val.strip() + "=" * (-len(val.strip()) % 4)
    return base64.urlsafe_b64decode(padded)


def generate_registration_options_for_session(
    db: DbSession,
    sess: Session,
    user: User,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Genera opciones de registro WebAuthn y guarda el challenge de un solo uso en la sesión."""
    cfg = settings or get_settings()
    challenge_bytes = secrets.token_bytes(32)
    sess.webauthn_challenge = challenge_bytes
    db.commit()

    active_creds = db.scalars(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.revoked_at.is_(None),
        )
    ).all()

    return {
        "rp": {"id": cfg.WEBAUTHN_RP_ID, "name": cfg.WEBAUTHN_RP_NAME},
        "user": {
            "id": _b64url_encode(str(user.id).encode("utf-8")),
            "name": user.username,
            "displayName": user.username,
        },
        "challenge": _b64url_encode(challenge_bytes),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {
            "userVerification": "required",
        },
        "excludeCredentials": [
            {"type": "public-key", "id": _b64url_encode(c.credential_id)} for c in active_creds
        ],
    }


def verify_and_store_registration(
    db: DbSession,
    sess: Session,
    user: User,
    payload: WebAuthnRegisterVerifySchema,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> WebAuthnCredential:
    """Consume el challenge de sesión (uso único), verifica RP/origen/userVerification y guarda la passkey."""
    cfg = settings or get_settings()
    stored_challenge = sess.webauthn_challenge
    # Consumir siempre en el primer intento (uso único contra replay)
    sess.webauthn_challenge = None
    db.commit()

    if not stored_challenge:
        raise WebAuthnError("No hay ningún challenge WebAuthn activo en la sesión (o ya fue consumido)")

    try:
        client_challenge = _b64url_decode(payload.challenge_b64)
        cred_id = _b64url_decode(payload.credential_id_b64)
        pub_key = _b64url_decode(payload.public_key_b64)
    except Exception as exc:
        raise WebAuthnError("Datos binarios WebAuthn malformados") from exc

    if not hmac.compare_digest(stored_challenge, client_challenge):
        raise WebAuthnError("El challenge WebAuthn no coincide o es un intento de replay")

    if not payload.user_verified:
        raise WebAuthnError("Se requiere verificación de usuario (userVerification=required)")

    if payload.rp_id != cfg.WEBAUTHN_RP_ID or payload.origin.rstrip("/") != cfg.APP_BASE_URL:
        raise WebAuthnError("RP ID u origen WebAuthn no coinciden con la configuración")

    existing = db.scalar(
        select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cred_id)
    )
    if existing is not None:
        raise WebAuthnError("Esta credencial WebAuthn ya se encuentra registrada")

    now = utc_now()
    cred = WebAuthnCredential(
        user_id=user.id,
        credential_id=cred_id,
        public_key=pub_key,
        sign_count=max(0, payload.sign_count),
        device_name=payload.device_name,
        transports="internal,hybrid",
        created_at=now,
        last_used_at=None,
        revoked_at=None,
    )
    db.add(cred)
    log_security_event(
        db,
        "WEBAUTHN_REGISTERED",
        actor_user_id=user.id,
        ip_address=ip_address,
        metadata={"device_name": cred.device_name},
        commit=True,
    )
    return cred


def generate_authentication_options_for_session(
    db: DbSession,
    sess: Session,
    user: User,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Genera opciones de autenticación WebAuthn para el Paso 2 del login."""
    cfg = settings or get_settings()
    active_creds = db.scalars(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.revoked_at.is_(None),
        )
    ).all()
    if not active_creds:
        raise WebAuthnError("El usuario no tiene passkeys activas registradas")

    challenge_bytes = secrets.token_bytes(32)
    sess.webauthn_challenge = challenge_bytes
    db.commit()

    return {
        "challenge": _b64url_encode(challenge_bytes),
        "rpId": cfg.WEBAUTHN_RP_ID,
        "userVerification": "required",
        "allowCredentials": [
            {"type": "public-key", "id": _b64url_encode(c.credential_id)} for c in active_creds
        ],
    }


def compute_virtual_authenticator_signature(
    public_key: bytes,
    challenge: bytes,
    sign_count: int,
    rp_id: str,
) -> str:
    """Calcula la firma determinista de un autenticador virtual para verificación criptográfica."""
    msg = f"{rp_id}:{sign_count}:".encode("utf-8") + challenge
    sig = hmac.new(public_key, msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def verify_authentication_step2(
    db: DbSession,
    sess: Session,
    user: User,
    payload: WebAuthnAuthenticateVerifySchema,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> AuthenticatedSessionResult:
    """Verifica la ceremonia WebAuthn en el Paso 2, consume el challenge y detecta clonación por sign_count."""
    cfg = settings or get_settings()
    stored_challenge = sess.webauthn_challenge
    # Consumir siempre el challenge de sesión en el primer intento (evita replay)
    sess.webauthn_challenge = None
    db.commit()

    if not stored_challenge:
        raise WebAuthnError("El challenge WebAuthn no existe o ya fue consumido (replay bloqueado)")

    try:
        client_challenge = _b64url_decode(payload.challenge_b64)
        cred_id = _b64url_decode(payload.credential_id_b64)
    except Exception as exc:
        raise WebAuthnError("Datos de autenticación WebAuthn malformados") from exc

    if not hmac.compare_digest(stored_challenge, client_challenge):
        log_security_event(
            db, "WEBAUTHN_CHALLENGE_MISMATCH", actor_user_id=user.id, ip_address=ip_address
        )
        raise WebAuthnError("Challenge WebAuthn inválido")

    if not payload.user_verified:
        raise WebAuthnError("Se requiere verificación de usuario (userVerification=required)")

    if payload.rp_id != cfg.WEBAUTHN_RP_ID or payload.origin.rstrip("/") != cfg.APP_BASE_URL:
        raise WebAuthnError("RP ID u origen WebAuthn inválido")

    cred = db.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == cred_id,
            WebAuthnCredential.user_id == user.id,
        )
    )
    if cred is None or cred.revoked_at is not None:
        raise WebAuthnError("Credencial WebAuthn desconocida o revocada")

    # Detección de clonación de credencial mediante contador de firmas
    if (cred.sign_count > 0 or payload.sign_count > 0) and payload.sign_count <= cred.sign_count:
        cred.revoked_at = utc_now()
        log_security_event(
            db,
            "WEBAUTHN_CLONE_DETECTED",
            actor_user_id=user.id,
            ip_address=ip_address,
            metadata={
                "credential_id": cred.id,
                "stored_sign_count": cred.sign_count,
                "received_sign_count": payload.sign_count,
            },
            commit=True,
        )
        raise WebAuthnError(
            "Anomalía en contador de firmas WebAuthn (posible credencial clonada); passkey revocada"
        )

    expected_sig_b64 = compute_virtual_authenticator_signature(
        cred.public_key, stored_challenge, payload.sign_count, cfg.WEBAUTHN_RP_ID
    )
    if not hmac.compare_digest(payload.signature_b64.strip(), expected_sig_b64):
        log_security_event(
            db, "WEBAUTHN_BAD_SIGNATURE", actor_user_id=user.id, ip_address=ip_address
        )
        raise WebAuthnError("Firma criptográfica WebAuthn inválida")

    cred.sign_count = payload.sign_count
    cred.last_used_at = utc_now()
    return promote_session_after_2fa(
        db,
        sess,
        user,
        "AUTH_LOGIN_SUCCESS_WEBAUTHN",
        ip_address=ip_address,
        settings=cfg,
    )


def list_user_credentials(db: DbSession, user_id: int) -> list[WebAuthnCredential]:
    """Lista las passkeys activas de un usuario."""
    return db.scalars(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.revoked_at.is_(None),
        )
    ).all()


def rename_user_credential(
    db: DbSession,
    user: User,
    credential_db_id: int,
    new_name: str,
) -> WebAuthnCredential:
    """Renombra una credencial WebAuthn perteneciente al usuario."""
    cred = db.get(WebAuthnCredential, credential_db_id)
    if cred is None or cred.user_id != user.id or cred.revoked_at is not None:
        raise WebAuthnError("Credencial no encontrada")
    cred.device_name = new_name.strip()[:100]
    log_security_event(
        db,
        "WEBAUTHN_RENAMED",
        actor_user_id=user.id,
        metadata={"credential_id": cred.id, "device_name": cred.device_name},
        commit=True,
    )
    return cred


def revoke_user_credential(
    db: DbSession,
    user: User,
    credential_db_id: int,
    recovery_code: str | None = None,
    settings: Settings | None = None,
) -> None:
    """Revoca una passkey; si es la última activa, exige confirmación con código de recuperación."""
    cfg = settings or get_settings()
    active_creds = list_user_credentials(db, user.id)
    target = next((c for c in active_creds if c.id == credential_db_id), None)
    if target is None:
        raise WebAuthnError("Credencial no encontrada o ya revocada")

    if len(active_creds) == 1:
        if not recovery_code or not verify_user_recovery_code_for_action(
            db, user, recovery_code, settings=cfg
        ):
            raise WebAuthnError(
                "No se puede revocar la última passkey activa sin confirmar con un código de recuperación válido"
            )

    target.revoked_at = utc_now()
    log_security_event(
        db,
        "WEBAUTHN_REVOKED",
        actor_user_id=user.id,
        metadata={"credential_id": target.id},
        commit=True,
    )
