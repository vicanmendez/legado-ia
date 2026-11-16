"""Servicio de autenticación en 2 pasos, sesiones en servidor, bloqueo progresivo, invitaciones y recuperación."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from app.config import Settings, get_settings
from app.db._compat_sa import Session as DbSession
from app.db.base import select, utc_now
from app.models.user import Invitation, OTPCode, RecoveryCode, Session, User, UserKey
from app.services.altcha import AltchaError, verify_altcha_payload
from app.services.audit import log_security_event
from app.services.crypto import (
    generate_dek,
    generate_otp_6digits,
    generate_recovery_codes,
    generate_token_256,
    hash_one_time_code,
    hash_password,
    sha256_hex,
    unwrap_dek,
    verify_dummy_password,
    verify_one_time_code,
    verify_password,
    wrap_dek,
)
from app.services.email import send_plain_email_sync

GENERIC_AUTH_ERROR = "Credenciales o verificación inválidas"


class AuthenticationError(PermissionError):
    """Error genérico de autenticación que no revela si el usuario existe."""


class AccountLockedError(PermissionError):
    """Error cuando la cuenta se encuentra temporalmente bloqueada por fallos repetidos."""


class AuthorizationError(PermissionError):
    """Error de control de acceso por rol o estado de sesión."""


class InvitationError(ValueError):
    """Error al validar o consumir un enlace de invitación."""


@dataclass
class Step1LoginResult:
    pending_session_token: str
    csrf_token: str
    user_id: int
    otp_code_for_delivery: str


@dataclass
class AuthenticatedSessionResult:
    session_token: str
    csrf_token: str
    user: User
    remaining_recovery_codes: int | None = None


def _compute_lockout_duration_seconds(failed_attempts: int) -> int:
    """Escala de bloqueo progresivo con backoff exponencial a partir del 5.º intento fallido."""
    if failed_attempts < 5:
        return 0
    exponent = min(failed_attempts - 5, 7)
    return int(60 * (2**exponent))


def _record_auth_failure(
    db: DbSession,
    user: User,
    event_code: str,
    ip_address: str | None = None,
) -> None:
    now = utc_now()
    user.failed_attempts = (user.failed_attempts or 0) + 1
    user.updated_at = now
    lock_secs = _compute_lockout_duration_seconds(user.failed_attempts)
    if lock_secs > 0:
        user.locked_until = now + timedelta(seconds=lock_secs)
        user.status = "locked"
        log_security_event(
            db,
            "AUTH_PROGRESSIVE_LOCKOUT",
            actor_user_id=user.id,
            ip_address=ip_address,
            metadata={"failed_attempts": user.failed_attempts, "lock_seconds": lock_secs},
            commit=False,
        )
    log_security_event(
        db,
        event_code,
        actor_user_id=user.id,
        ip_address=ip_address,
        metadata={"failed_attempts": user.failed_attempts},
        commit=True,
    )


def create_user_with_dek(
    db: DbSession,
    username: str,
    email: str,
    password: str,
    role: str,
    settings: Settings | None = None,
) -> tuple[User, list[str]]:
    """Crea un usuario con Argon2id, genera su DEK cifrada con la KEK y emite 8 códigos de recuperación."""
    cfg = settings or get_settings()
    if role not in ("entrenador", "amigo", "albacea"):
        raise ValueError(f"Rol inválido: {role}")

    existing_u = db.scalar(select(User).where(User.username == username))
    existing_e = db.scalar(select(User).where(User.email == email))
    if existing_u is not None or existing_e is not None:
        raise ValueError("El nombre de usuario o correo electrónico ya está registrado")

    now = utc_now()
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
        status="active",
        failed_attempts=0,
        locked_until=None,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.flush()

    kek = cfg.get_kek_bytes()
    dek = generate_dek()
    user_key = UserKey(
        user_id=user.id,
        encrypted_dek=wrap_dek(dek, kek, user.id),
        key_version=1,
        rotated_at=now,
    )
    db.add(user_key)

    plain_codes = generate_recovery_codes(count=8)
    for code in plain_codes:
        rc = RecoveryCode(
            user_id=user.id,
            code_hash=hash_one_time_code(code, cfg.APP_SECRET_KEY),
            used_at=None,
            created_at=now,
        )
        db.add(rc)

    db.commit()
    return user, plain_codes


def get_user_dek(db: DbSession, user_id: int, settings: Settings | None = None) -> bytes:
    """Obtiene y descifra en memoria la DEK de un usuario usando la KEK del servidor."""
    cfg = settings or get_settings()
    uk = db.scalar(select(UserKey).where(UserKey.user_id == user_id))
    if uk is None:
        raise ValueError(f"El usuario {user_id} no posee clave DEK registrada")
    return unwrap_dek(uk.encrypted_dek, cfg.get_kek_bytes(), user_id)


def login_step1(
    db: DbSession,
    username: str,
    password: str,
    altcha_payload: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    settings: Settings | None = None,
) -> Step1LoginResult:
    """Paso 1 del login: verifica ALTCHA, usuario/contraseña Argon2id (con hash ficticio si no existe) y emite OTP."""
    cfg = settings or get_settings()
    try:
        verify_altcha_payload(db, altcha_payload, settings=cfg)
    except AltchaError as exc:
        log_security_event(
            db,
            "AUTH_ALTCHA_FAIL",
            ip_address=ip_address,
            metadata={"reason": str(exc)},
        )
        raise AuthenticationError(GENERIC_AUTH_ERROR) from exc

    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None:
        # Hash ficticio para igualar tiempos de respuesta y evitar enumeración de usuarios
        verify_dummy_password(password)
        log_security_event(
            db,
            "AUTH_LOGIN_UNKNOWN_USER",
            ip_address=ip_address,
            metadata={"username_attempted": username[:32]},
        )
        raise AuthenticationError(GENERIC_AUTH_ERROR)

    now = utc_now()
    if user.status == "disabled":
        verify_dummy_password(password)
        log_security_event(db, "AUTH_DISABLED_USER", actor_user_id=user.id, ip_address=ip_address)
        raise AuthenticationError(GENERIC_AUTH_ERROR)

    if user.locked_until is not None and user.locked_until > now:
        log_security_event(db, "AUTH_LOCKED_ATTEMPT", actor_user_id=user.id, ip_address=ip_address)
        raise AccountLockedError("Cuenta bloqueada temporalmente por intentos fallidos")

    if not verify_password(user.password_hash, password):
        _record_auth_failure(db, user, "AUTH_LOGIN_STEP1_FAIL", ip_address=ip_address)
        raise AuthenticationError(GENERIC_AUTH_ERROR)

    # Si el entrenador inicia sesión durante una transición póstuma pendiente, se cancela automáticamente
    from app.services.succession import cancel_pending_transition_on_trainer_activity

    if user.role == "entrenador":
        cancel_pending_transition_on_trainer_activity(db, user)

    # Invalidar cualquier código OTP previo activo del usuario (un solo código activo por usuario)
    active_otps = db.scalars(
        select(OTPCode).where(OTPCode.user_id == user.id, OTPCode.consumed_at.is_(None))
    ).all()
    for prev_otp in active_otps:
        prev_otp.consumed_at = now

    raw_otp = generate_otp_6digits()
    otp_entry = OTPCode(
        user_id=user.id,
        code_hash=hash_one_time_code(raw_otp, cfg.APP_SECRET_KEY),
        attempts=0,
        expires_at=now + timedelta(minutes=10),
        consumed_at=None,
        created_at=now,
    )
    db.add(otp_entry)

    # Crear sesión en servidor en estado "pendiente de 2FA" con caducidad corta (10 min)
    raw_session_token = generate_token_256()
    csrf_token = generate_token_256()
    pending_session = Session(
        session_token_hash=sha256_hex(raw_session_token),
        user_id=user.id,
        is_2fa_verified=False,
        csrf_token=csrf_token,
        webauthn_challenge=None,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255] if user_agent else None,
        created_at=now,
        last_activity_at=now,
        expires_at=now + timedelta(minutes=cfg.PENDING_2FA_TIMEOUT_MINUTES),
        revoked_at=None,
    )
    db.add(pending_session)

    email_body = (
        f"Hola {user.username},\n\n"
        f"Tu código de verificación de segundo factor para legado-ia es: {raw_otp}\n"
        f"Este código caduca en 10 minutos y permite un máximo de 5 intentos.\n"
    )
    send_plain_email_sync(
        to_email=user.email,
        subject="Código de acceso legado-ia (2FA)",
        body_text=email_body,
        settings=cfg,
    )

    log_security_event(
        db,
        "AUTH_STEP1_SUCCESS",
        actor_user_id=user.id,
        ip_address=ip_address,
        commit=True,
    )
    return Step1LoginResult(
        pending_session_token=raw_session_token,
        csrf_token=csrf_token,
        user_id=user.id,
        otp_code_for_delivery=raw_otp,
    )


def get_pending_2fa_session(db: DbSession, raw_session_token: str) -> tuple[Session, User]:
    """Obtiene y valida una sesión que superó el Paso 1 y está pendiente de 2FA."""
    if not raw_session_token:
        raise AuthenticationError("Sesión no encontrada")
    token_hash = sha256_hex(raw_session_token)
    sess = db.scalar(select(Session).where(Session.session_token_hash == token_hash))
    now = utc_now()
    if sess is None or sess.revoked_at is not None or sess.expires_at < now:
        raise AuthenticationError("La sesión de verificación ha caducado o no es válida")
    user = db.get(User, sess.user_id)
    if user is None or user.status == "disabled":
        raise AuthenticationError("Usuario inválido")
    if user.locked_until is not None and user.locked_until > now:
        raise AccountLockedError("Cuenta bloqueada temporalmente por intentos fallidos")
    return sess, user


def promote_session_after_2fa(
    db: DbSession,
    pending_session: Session,
    user: User,
    event_code: str,
    ip_address: str | None = None,
    settings: Settings | None = None,
    remaining_recovery_codes: int | None = None,
) -> AuthenticatedSessionResult:
    """Regenera el ID de sesión de 256 bits tras superar el 2FA y reinicia contadores de bloqueo."""
    cfg = settings or get_settings()
    now = utc_now()

    # Revocar el ID anterior o regenerar el hash en la sesión activa (prevención de session fixation)
    new_raw_token = generate_token_256()
    new_csrf_token = generate_token_256()
    pending_session.session_token_hash = sha256_hex(new_raw_token)
    pending_session.csrf_token = new_csrf_token
    pending_session.is_2fa_verified = True
    pending_session.webauthn_challenge = None
    pending_session.last_activity_at = now
    pending_session.expires_at = now + timedelta(minutes=cfg.SESSION_INACTIVITY_MINUTES)

    user.failed_attempts = 0
    user.locked_until = None
    user.status = "active"
    user.updated_at = now

    log_security_event(
        db,
        event_code,
        actor_user_id=user.id,
        ip_address=ip_address,
        commit=True,
    )
    return AuthenticatedSessionResult(
        session_token=new_raw_token,
        csrf_token=new_csrf_token,
        user=user,
        remaining_recovery_codes=remaining_recovery_codes,
    )


def verify_step2_otp(
    db: DbSession,
    raw_session_token: str,
    otp_code: str,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> AuthenticatedSessionResult:
    """Paso 2 del login por OTP de 6 dígitos (caducidad 10 min, máximo 5 intentos)."""
    cfg = settings or get_settings()
    sess, user = get_pending_2fa_session(db, raw_session_token)
    now = utc_now()

    active_otp = db.scalar(
        select(OTPCode)
        .where(OTPCode.user_id == user.id, OTPCode.consumed_at.is_(None))
        .order_by(OTPCode.id.desc())
    )
    if active_otp is None:
        _record_auth_failure(db, user, "AUTH_OTP_MISSING", ip_address=ip_address)
        raise AuthenticationError("No hay ningún código OTP activo o ya fue utilizado")

    if active_otp.expires_at < now or active_otp.attempts >= 5:
        active_otp.consumed_at = now
        _record_auth_failure(db, user, "AUTH_OTP_EXPIRED_OR_EXHAUSTED", ip_address=ip_address)
        raise AuthenticationError("El código OTP ha caducado o superó el máximo de 5 intentos")

    if not verify_one_time_code(active_otp.code_hash, otp_code, cfg.APP_SECRET_KEY):
        active_otp.attempts += 1
        if active_otp.attempts >= 5:
            active_otp.consumed_at = now
        _record_auth_failure(db, user, "AUTH_OTP_INVALID", ip_address=ip_address)
        raise AuthenticationError("Código OTP incorrecto")

    # Uso único: invalidar el OTP inmediatamente
    active_otp.consumed_at = now
    return promote_session_after_2fa(
        db, sess, user, "AUTH_LOGIN_SUCCESS_OTP", ip_address=ip_address, settings=cfg
    )


def verify_step2_recovery_code(
    db: DbSession,
    raw_session_token: str,
    recovery_code: str,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> AuthenticatedSessionResult:
    """Paso 2 alternativo: verifica y consume un código de recuperación de un solo uso."""
    cfg = settings or get_settings()
    sess, user = get_pending_2fa_session(db, raw_session_token)
    now = utc_now()

    unused_codes = db.scalars(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
        )
    ).all()

    matched: RecoveryCode | None = None
    for rc in unused_codes:
        if verify_one_time_code(rc.code_hash, recovery_code, cfg.APP_SECRET_KEY):
            matched = rc
            break

    if matched is None:
        _record_auth_failure(db, user, "AUTH_RECOVERY_CODE_FAIL", ip_address=ip_address)
        raise AuthenticationError("Código de recuperación inválido o ya utilizado")

    matched.used_at = now
    remaining = len(unused_codes) - 1
    return promote_session_after_2fa(
        db,
        sess,
        user,
        "AUTH_LOGIN_SUCCESS_RECOVERY",
        ip_address=ip_address,
        settings=cfg,
        remaining_recovery_codes=remaining,
    )


def verify_user_recovery_code_for_action(
    db: DbSession,
    user: User,
    recovery_code: str,
    settings: Settings | None = None,
) -> bool:
    """Verifica y consume un código de recuperación para confirmar acciones críticas (ej. revocar última passkey)."""
    cfg = settings or get_settings()
    unused_codes = db.scalars(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
        )
    ).all()
    for rc in unused_codes:
        if verify_one_time_code(rc.code_hash, recovery_code, cfg.APP_SECRET_KEY):
            rc.used_at = utc_now()
            db.commit()
            return True
    return False


def validate_authenticated_session(
    db: DbSession,
    raw_session_token: str,
    settings: Settings | None = None,
) -> tuple[Session, User]:
    """Valida que la sesión exista, haya completado el 2FA y no haya caducado por inactividad."""
    cfg = settings or get_settings()
    if not raw_session_token:
        raise AuthorizationError("Autenticación requerida")
    token_hash = sha256_hex(raw_session_token)
    sess = db.scalar(select(Session).where(Session.session_token_hash == token_hash))
    now = utc_now()
    if sess is None or sess.revoked_at is not None:
        raise AuthorizationError("Sesión inválida o cerrada")
    if not sess.is_2fa_verified:
        raise AuthorizationError("Segundo factor de autenticación (2FA) pendiente")

    inactivity_limit = sess.last_activity_at + timedelta(minutes=cfg.SESSION_INACTIVITY_MINUTES)
    if now > sess.expires_at or now > inactivity_limit:
        sess.revoked_at = now
        log_security_event(
            db, "AUTH_SESSION_EXPIRED", actor_user_id=sess.user_id, commit=True
        )
        raise AuthorizationError("La sesión ha caducado por inactividad")

    user = db.get(User, sess.user_id)
    if user is None or user.status != "active":
        raise AuthorizationError("Cuenta de usuario no disponible")

    sess.last_activity_at = now
    sess.expires_at = now + timedelta(minutes=cfg.SESSION_INACTIVITY_MINUTES)
    db.commit()
    return sess, user


def logout_session(
    db: DbSession,
    raw_session_token: str,
    ip_address: str | None = None,
) -> str:
    """Invalida la sesión en servidor y devuelve un ID regenerado efímero para limpiar cookie."""
    if raw_session_token:
        token_hash = sha256_hex(raw_session_token)
        sess = db.scalar(select(Session).where(Session.session_token_hash == token_hash))
        if sess is not None and sess.revoked_at is None:
            sess.revoked_at = utc_now()
            sess.session_token_hash = sha256_hex(generate_token_256())
            log_security_event(
                db,
                "AUTH_LOGOUT",
                actor_user_id=sess.user_id,
                ip_address=ip_address,
                commit=True,
            )
    return generate_token_256()


def create_invitation(
    db: DbSession,
    creator: User,
    target_role: str = "amigo",
    recipient_hint: str | None = None,
    expiry_hours: int | None = None,
    settings: Settings | None = None,
) -> tuple[Invitation, str]:
    """Crea una invitación con token aleatorio de 256 bits guardando únicamente su hash SHA-256."""
    cfg = settings or get_settings()
    if creator.role not in ("entrenador", "albacea"):
        raise AuthorizationError("Solo el entrenador o el albacea autorizado pueden crear invitaciones")
    if target_role not in ("amigo", "albacea", "entrenador"):
        raise InvitationError("Rol de invitación no permitido")

    raw_token = generate_token_256()
    token_hash = sha256_hex(raw_token)
    now = utc_now()
    hours = expiry_hours if expiry_hours is not None else cfg.INVITATION_EXPIRY_HOURS

    inv = Invitation(
        token_hash=token_hash,
        target_role=target_role,
        recipient_hint=recipient_hint[:120] if recipient_hint else None,
        created_by_id=creator.id,
        used_by_id=None,
        expires_at=now + timedelta(hours=hours),
        used_at=None,
        revoked_at=None,
        created_at=now,
    )
    db.add(inv)
    log_security_event(
        db,
        "INVITATION_CREATED",
        actor_user_id=creator.id,
        metadata={"target_role": target_role, "expiry_hours": hours},
        commit=True,
    )
    return inv, raw_token


def get_valid_invitation(db: DbSession, raw_token: str) -> Invitation:
    """Verifica que el token de invitación exista, no haya sido usado, revocado ni caducado."""
    if not raw_token or len(raw_token) < 16:
        raise InvitationError("Enlace de invitación inválido")
    token_hash = sha256_hex(raw_token.strip())
    inv = db.scalar(select(Invitation).where(Invitation.token_hash == token_hash))
    now = utc_now()
    if inv is None:
        raise InvitationError("La invitación no existe")
    if inv.used_at is not None or inv.used_by_id is not None:
        raise InvitationError("Esta invitación ya fue utilizada anteriormente")
    if inv.revoked_at is not None:
        raise InvitationError("Esta invitación ha sido revocada")
    if inv.expires_at < now:
        raise InvitationError("Esta invitación ha caducado")
    return inv


def consume_invitation_and_register(
    db: DbSession,
    raw_token: str,
    username: str,
    email: str,
    password: str,
    altcha_payload: str,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> tuple[User, list[str]]:
    """Valida ALTCHA e invitación de un solo uso, activa la cuenta y genera códigos de recuperación."""
    cfg = settings or get_settings()
    try:
        verify_altcha_payload(db, altcha_payload, settings=cfg)
    except AltchaError as exc:
        raise InvitationError(f"Verificación ALTCHA fallida: {exc}") from exc

    inv = get_valid_invitation(db, raw_token)
    user, recovery_codes = create_user_with_dek(
        db,
        username=username,
        email=email,
        password=password,
        role=inv.target_role,
        settings=cfg,
    )
    inv.used_at = utc_now()
    inv.used_by_id = user.id
    if user.role == "entrenador":
        from app.services.knowledge import seed_default_interview_topics

        seed_default_interview_topics(db, user)
    log_security_event(
        db,
        "INVITATION_CONSUMED",
        actor_user_id=user.id,
        ip_address=ip_address,
        metadata={"invitation_id": inv.id, "assigned_role": inv.target_role},
        commit=True,
    )
    return user, recovery_codes
