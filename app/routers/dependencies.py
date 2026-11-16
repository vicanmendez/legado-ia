"""Dependencias de autorización por rol (denegar por defecto), validación CSRF y control de modo póstumo."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any

from app.config import Settings, get_settings
from app.db._compat_sa import Session as DbSession
from app.models.user import Session, User
from app.services.audit import log_security_event
from app.services.auth import (
    AuthorizationError,
    get_pending_2fa_session,
    validate_authenticated_session,
)
from app.services.succession import is_posthumous_mode

SESSION_COOKIE_NAME = "legado_session"
CSRF_COOKIE_NAME = "legado_csrf"


class CSRFError(PermissionError):
    """Error de validación de token CSRF en petición que modifica estado."""


@dataclass
class HTTPRequestContext:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    form_data: dict[str, Any] = field(default_factory=dict)
    json_data: dict[str, Any] | None = None
    body_bytes: bytes = b""
    client_ip: str = "127.0.0.1"


@dataclass
class HTTPResponseData:
    status_code: int = 200
    body: str | bytes = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, dict[str, Any]] = field(default_factory=dict)
    json_payload: dict[str, Any] | list[Any] | None = None

    def set_secure_session_cookie(self, token: str) -> None:
        self.cookies[SESSION_COOKIE_NAME] = {
            "value": token,
            "httponly": True,
            "secure": True,
            "samesite": "Strict",
            "path": "/",
        }

    def clear_session_cookie(self) -> None:
        self.cookies[SESSION_COOKIE_NAME] = {
            "value": "",
            "httponly": True,
            "secure": True,
            "samesite": "Strict",
            "max_age": 0,
            "path": "/",
        }


def verify_csrf(req: HTTPRequestContext, expected_csrf_token: str) -> None:
    """Exige y compara en tiempo constante el token CSRF en formulario o cabecera X-CSRF-Token."""
    if req.method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    header_token = ""
    for k, v in req.headers.items():
        if k.lower() == "x-csrf-token":
            header_token = v.strip()
            break
    form_token = str(req.form_data.get("_csrf_token", "")).strip()
    json_token = (
        str(req.json_data.get("_csrf_token", "")).strip()
        if isinstance(req.json_data, dict)
        else ""
    )
    candidate = header_token or form_token or json_token
    if not expected_csrf_token or not candidate or not hmac.compare_digest(
        expected_csrf_token, candidate
    ):
        raise CSRFError("Token CSRF ausente o inválido")


def require_pending_2fa_user(
    db: DbSession,
    req: HTTPRequestContext,
) -> tuple[Session, User]:
    """Obtiene una sesión válida en el Paso 2 del login y verifica su token CSRF."""
    raw_token = req.cookies.get(SESSION_COOKIE_NAME, "")
    sess, user = get_pending_2fa_session(db, raw_token)
    verify_csrf(req, sess.csrf_token)
    return sess, user


def require_user(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> tuple[Session, User]:
    """Exige una sesión autenticada con 2FA completado (is_2fa_verified=True) y valida CSRF."""
    raw_token = req.cookies.get(SESSION_COOKIE_NAME, "")
    sess, user = validate_authenticated_session(db, raw_token, settings=settings)
    verify_csrf(req, sess.csrf_token)
    return sess, user


def require_role(
    db: DbSession,
    req: HTTPRequestContext,
    allowed_roles: str | tuple[str, ...],
    settings: Settings | None = None,
) -> tuple[Session, User]:
    """Dependencia de autorización que deniega por defecto si el rol no coincide y audita el intento."""
    sess, user = require_user(db, req, settings=settings)
    roles = (allowed_roles,) if isinstance(allowed_roles, str) else allowed_roles
    if user.role not in roles:
        log_security_event(
            db,
            "ROLE_DENIED",
            actor_user_id=user.id,
            ip_address=req.client_ip,
            metadata={"user_role": user.role, "required_roles": list(roles), "path": req.path},
            commit=True,
        )
        raise AuthorizationError(
            f"Acceso denegado: el rol '{user.role}' no tiene permiso para esta funcionalidad"
        )
    return sess, user


def check_knowledge_base_writable(db: DbSession) -> None:
    """Impide cualquier escritura sobre la base de conocimiento si el sistema está en modo póstumo."""
    if is_posthumous_mode(db):
        raise AuthorizationError(
            "Operación denegada: la base de conocimiento está en solo lectura en modo póstumo"
        )
