"""Router de Albacea y Modo Póstumo (/executor)."""

from __future__ import annotations

from app.config import Settings
from app.db._compat_sa import Session as DbSession
from app.db.base import select
from app.models.succession import SuccessionEvent
from app.routers.dependencies import HTTPRequestContext, HTTPResponseData, require_role
from app.schemas.succession import SuccessionTransitionActionSchema
from app.services.auth import AuthorizationError
from app.services.succession import (
    SuccessionError,
    cancel_posthumous_transition,
    confirm_posthumous_transition,
    get_or_create_system_state,
    request_posthumous_transition,
)


def handle_get_executor_panel(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, _ = require_role(db, req, ("albacea", "entrenador"), settings=settings)
    state = get_or_create_system_state(db, settings=settings)
    events = db.scalars(select(SuccessionEvent).order_by(SuccessionEvent.id.asc())).all()
    return HTTPResponseData(
        status_code=200,
        json_payload={
            "mode": state.mode,
            "cooldown_hours": state.cooldown_hours,
            "transition_requested_at": state.transition_requested_at.isoformat()
            if state.transition_requested_at
            else None,
            "transition_confirmable_after": state.transition_confirmable_after.isoformat()
            if state.transition_confirmable_after
            else None,
            "posthumous_activated_at": state.posthumous_activated_at.isoformat()
            if state.posthumous_activated_at
            else None,
            "events": [
                {
                    "id": ev.id,
                    "actor_user_id": ev.actor_user_id,
                    "event_type": ev.event_type,
                    "notes": ev.notes,
                    "created_at": ev.created_at.isoformat(),
                }
                for ev in events
            ],
        },
    )


def handle_post_request_transition(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, user = require_role(db, req, "albacea", settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    schema = SuccessionTransitionActionSchema(
        notes=str(data.get("notes", "")) if data.get("notes") else None
    )
    try:
        state = request_posthumous_transition(
            db,
            executor_user=user,
            notes=schema.notes,
            ip_address=req.client_ip,
            settings=settings,
        )
    except (SuccessionError, AuthorizationError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    return HTTPResponseData(
        status_code=200,
        json_payload={
            "mode": state.mode,
            "transition_confirmable_after": state.transition_confirmable_after.isoformat()
            if state.transition_confirmable_after
            else None,
        },
    )


def handle_post_cancel_transition(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, user = require_role(db, req, ("entrenador", "albacea"), settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    schema = SuccessionTransitionActionSchema(
        notes=str(data.get("notes", "")) if data.get("notes") else None
    )
    try:
        state = cancel_posthumous_transition(
            db,
            actor=user,
            notes=schema.notes,
            ip_address=req.client_ip,
        )
    except (SuccessionError, AuthorizationError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    return HTTPResponseData(status_code=200, json_payload={"mode": state.mode})


def handle_post_confirm_posthumous(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, user = require_role(db, req, "albacea", settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    schema = SuccessionTransitionActionSchema(
        notes=str(data.get("notes", "")) if data.get("notes") else None
    )
    try:
        state = confirm_posthumous_transition(
            db,
            executor_user=user,
            notes=schema.notes,
            ip_address=req.client_ip,
        )
    except (SuccessionError, AuthorizationError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    return HTTPResponseData(
        status_code=200,
        json_payload={
            "mode": state.mode,
            "posthumous_activated_at": state.posthumous_activated_at.isoformat()
            if state.posthumous_activated_at
            else None,
        },
    )
