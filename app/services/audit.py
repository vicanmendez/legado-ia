"""Servicio de auditoría con saneamiento estricto contra filtración de secretos o contenido personal."""

from __future__ import annotations

import json
from typing import Any

from app.db._compat_sa import Session
from app.db.base import utc_now
from app.models.audit import AuditLog

FORBIDDEN_METADATA_KEYS = {
    "password",
    "password_hash",
    "secret",
    "token",
    "session_token",
    "otp",
    "otp_code",
    "code",
    "recovery_code",
    "kek",
    "dek",
    "encrypted_dek",
    "api_key",
    "llm_api_key",
    "content",
    "encrypted_content",
    "body",
    "message",
    "prompt",
    "transcript",
}


def sanitize_audit_metadata(metadata: dict[str, Any] | None) -> str | None:
    """Elimina cualquier clave prohibida o valor que pudiera contener secretos o recuerdos."""
    if not metadata:
        return None
    clean: dict[str, Any] = {}
    for k, v in metadata.items():
        key_lower = k.strip().lower()
        if key_lower in FORBIDDEN_METADATA_KEYS or any(
            sub in key_lower for sub in ("password", "secret", "token", "key", "otp", "content")
        ):
            clean[k] = "[REDACTED]"
        elif isinstance(v, (int, float, bool)) or v is None:
            clean[k] = v
        else:
            val_str = str(v)
            clean[k] = val_str[:160]
    return json.dumps(clean, ensure_ascii=False, sort_keys=True)


def log_security_event(
    db: Session,
    event_code: str,
    actor_user_id: int | None = None,
    ip_address: str | None = None,
    metadata: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditLog:
    """Registra un evento de seguridad en audit_log tras sanear sus metadatos."""
    entry = AuditLog(
        event_code=event_code[:64],
        actor_user_id=actor_user_id,
        ip_address=(ip_address or "")[:45] if ip_address else None,
        metadata_json=sanitize_audit_metadata(metadata),
        created_at=utc_now(),
    )
    db.add(entry)
    if commit:
        db.commit()
    else:
        db.flush()
    return entry
