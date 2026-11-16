"""Servicio de sucesión, gestión de albacea y protocolo de activación del modo póstumo (Parte 6)."""

from __future__ import annotations

import json
from datetime import timedelta

from app.config import Settings, get_settings
from app.db._compat_sa import Session as DbSession
from app.db.base import select, utc_now
from app.models.succession import Executor, SuccessionEvent, SystemState
from app.models.user import User
from app.services.audit import log_security_event
from app.services.auth import AuthorizationError
from app.services.email import send_plain_email_sync


class SuccessionError(ValueError):
    """Error de validación o intento prematuro en el protocolo de modo póstumo."""


def get_or_create_system_state(db: DbSession, settings: Settings | None = None) -> SystemState:
    """Obtiene o inicializa la fila singleton (id=1) de system_state."""
    cfg = settings or get_settings()
    state = db.get(SystemState, 1)
    if state is not None:
        return state
    state = SystemState(
        id=1,
        mode="activo",
        cooldown_hours=cfg.POSTHUMOUS_COOLDOWN_HOURS,
        transition_requested_at=None,
        transition_confirmable_after=None,
        posthumous_activated_at=None,
        updated_at=utc_now(),
    )
    db.add(state)
    db.commit()
    return state


def is_posthumous_mode(db: DbSession) -> bool:
    """Devuelve True si el sistema se encuentra en estado 'postumo'."""
    state = get_or_create_system_state(db)
    return state.mode == "postumo"


def designate_executor(
    db: DbSession,
    trainer: User,
    executor_user: User,
    notification_contacts: list[str] | None = None,
    cooldown_hours: int = 72,
    settings: Settings | None = None,
) -> Executor:
    """Permite al entrenador en modo activo designar un albacea y configurar el plazo de espera."""
    if trainer.role != "entrenador":
        raise AuthorizationError("Solo el entrenador puede designar albaceas")
    state = get_or_create_system_state(db, settings=settings)
    if state.mode == "postumo":
        raise AuthorizationError("No se pueden modificar albaceas una vez activado el modo póstumo")

    executor_user.role = "albacea"
    state.cooldown_hours = cooldown_hours
    state.updated_at = utc_now()

    existing = db.scalar(select(Executor).where(Executor.user_id == executor_user.id))
    contacts_json = json.dumps(notification_contacts or [], ensure_ascii=False)
    if existing is not None:
        existing.is_active = True
        existing.notification_contacts = contacts_json
        exec_record = existing
    else:
        exec_record = Executor(
            user_id=executor_user.id,
            designated_by_id=trainer.id,
            notification_contacts=contacts_json,
            is_active=True,
            created_at=utc_now(),
        )
        db.add(exec_record)

    log_security_event(
        db,
        "EXECUTOR_DESIGNATED",
        actor_user_id=trainer.id,
        metadata={"executor_user_id": executor_user.id, "cooldown_hours": cooldown_hours},
        commit=True,
    )
    return exec_record


def _require_active_executor(db: DbSession, user: User) -> Executor:
    if user.role != "albacea":
        raise AuthorizationError("Acción reservada exclusivamente al rol ALBACEA")
    exec_rec = db.scalar(
        select(Executor).where(Executor.user_id == user.id, Executor.is_active == True)  # noqa: E712
    )
    if exec_rec is None:
        raise AuthorizationError("El usuario no es un albacea activo designado por el entrenador")
    return exec_rec


def request_posthumous_transition(
    db: DbSession,
    executor_user: User,
    notes: str | None = None,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> SystemState:
    """Inicia la solicitud de transición póstuma, calcula el plazo de espera y notifica al entrenador y contactos."""
    cfg = settings or get_settings()
    exec_rec = _require_active_executor(db, executor_user)
    state = get_or_create_system_state(db, settings=cfg)

    if state.mode == "postumo":
        raise SuccessionError("El sistema ya se encuentra en modo póstumo")
    if state.mode == "transicion_pendiente":
        raise SuccessionError("Ya existe una solicitud de transición póstuma en curso")

    now = utc_now()
    state.mode = "transicion_pendiente"
    state.transition_requested_at = now
    state.transition_confirmable_after = now + timedelta(hours=state.cooldown_hours)
    state.updated_at = now

    ev_req = SuccessionEvent(
        actor_user_id=executor_user.id,
        event_type="REQUESTED",
        notes=(notes or "Solicitud de activación de modo póstumo")[:255],
        created_at=now,
    )
    db.add(ev_req)

    # Notificar por correo electrónico al entrenador y a los contactos registrados
    trainer = db.get(User, exec_rec.designated_by_id)
    recipients: list[str] = []
    if trainer is not None:
        recipients.append(trainer.email)
    if exec_rec.notification_contacts:
        try:
            extra = json.loads(exec_rec.notification_contacts)
            if isinstance(extra, list):
                recipients.extend(str(e) for e in extra if e)
        except Exception:
            pass

    for email_addr in set(recipients):
        send_plain_email_sync(
            to_email=email_addr,
            subject="AVISO URGENTE: Solicitud de activación de modo póstumo en legado-ia",
            body_text=(
                f"El albacea ({executor_user.username}) ha solicitado activar el modo póstumo.\n"
                f"Plazo de espera de seguridad: {state.cooldown_hours} horas "
                f"(confirmable a partir de {state.transition_confirmable_after.isoformat()}).\n"
                "Si eres el entrenador y te encuentras bien, inicia sesión o cancela la transición de inmediato.\n"
            ),
            settings=cfg,
        )

    ev_notif = SuccessionEvent(
        actor_user_id=executor_user.id,
        event_type="NOTIFIED",
        notes=f"Notificados {len(set(recipients))} destinatarios",
        created_at=now,
    )
    db.add(ev_notif)

    log_security_event(
        db,
        "SUCCESSION_TRANSITION_REQUESTED",
        actor_user_id=executor_user.id,
        ip_address=ip_address,
        metadata={
            "cooldown_hours": state.cooldown_hours,
            "confirmable_after": state.transition_confirmable_after.isoformat(),
        },
        commit=True,
    )
    return state


def cancel_posthumous_transition(
    db: DbSession,
    actor: User,
    notes: str | None = None,
    ip_address: str | None = None,
) -> SystemState:
    """Cancela una transición pendiente (por el entrenador o el albacea) volviendo al estado 'activo'."""
    if actor.role not in ("entrenador", "albacea"):
        raise AuthorizationError("Solo el entrenador o el albacea pueden cancelar la transición")
    state = get_or_create_system_state(db)
    if state.mode == "postumo":
        raise SuccessionError("El modo póstumo ya fue confirmado definitivamente y no puede revertirse")
    if state.mode != "transicion_pendiente":
        raise SuccessionError("No hay ninguna transición pendiente que cancelar")

    now = utc_now()
    state.mode = "activo"
    state.transition_requested_at = None
    state.transition_confirmable_after = None
    state.updated_at = now

    ev = SuccessionEvent(
        actor_user_id=actor.id,
        event_type="CANCELLED_BY_TRAINER" if actor.role == "entrenador" else "CANCELLED_BY_EXECUTOR",
        notes=(notes or "Transición cancelada")[:255],
        created_at=now,
    )
    db.add(ev)
    log_security_event(
        db,
        "SUCCESSION_TRANSITION_CANCELLED",
        actor_user_id=actor.id,
        ip_address=ip_address,
        commit=True,
    )
    return state


def cancel_pending_transition_on_trainer_activity(db: DbSession, trainer: User) -> None:
    """Si el entrenador inicia sesión mientras hay una transición pendiente, la aborta automáticamente."""
    state = get_or_create_system_state(db)
    if state.mode == "transicion_pendiente":
        cancel_posthumous_transition(
            db,
            actor=trainer,
            notes="Cancelación automática por inicio de sesión del entrenador",
        )


def confirm_posthumous_transition(
    db: DbSession,
    executor_user: User,
    notes: str | None = None,
    ip_address: str | None = None,
) -> SystemState:
    """Confirma el paso a estado 'postumo' únicamente si ha vencido el plazo de espera sin cancelación."""
    _require_active_executor(db, executor_user)
    state = get_or_create_system_state(db)
    if state.mode != "transicion_pendiente" or state.transition_confirmable_after is None:
        raise SuccessionError("No existe una solicitud de transición pendiente de confirmación")

    now = utc_now()
    if now < state.transition_confirmable_after:
        log_security_event(
            db,
            "SUCCESSION_PREMATURE_CONFIRM_BLOCKED",
            actor_user_id=executor_user.id,
            ip_address=ip_address,
        )
        raise SuccessionError(
            "El plazo de espera obligatorio aún no ha concluido; confirmación denegada"
        )

    state.mode = "postumo"
    state.posthumous_activated_at = now
    state.updated_at = now

    ev = SuccessionEvent(
        actor_user_id=executor_user.id,
        event_type="CONFIRMED_POSTHUMOUS",
        notes=(notes or "Modo póstumo activado definitivamente")[:255],
        created_at=now,
    )
    db.add(ev)
    log_security_event(
        db,
        "SUCCESSION_POSTHUMOUS_ACTIVATED",
        actor_user_id=executor_user.id,
        ip_address=ip_address,
        commit=True,
    )
    return state
