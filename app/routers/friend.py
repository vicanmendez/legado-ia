"""Router del Amigo (/friend): conversaciones cifradas por amigo y streaming SSE (Parte 5)."""

from __future__ import annotations

from app.config import Settings
from app.db._compat_sa import Session as DbSession
from app.routers.dependencies import HTTPRequestContext, HTTPResponseData, require_role
from app.schemas.auth import ValidationError
from app.schemas.conversation import ConversationCreateSchema, MessageCreateSchema
from app.services.auth import AuthorizationError
from app.services.llm import (
    POSTHUMOUS_SIMULATION_NOTICE,
    SIMULATION_NOTICE,
    QuotaExceededError,
    create_conversation_for_friend,
    get_conversation_messages_for_friend,
    list_conversations_for_friend,
    send_friend_message_and_stream_response,
)
from app.services.succession import is_posthumous_mode
from app.ui import html_response, redirect_response, render_friend_dashboard, wants_html


def handle_get_friend_dashboard(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    sess, friend = require_role(db, req, "amigo", settings=settings)
    convs = list_conversations_for_friend(db, friend, settings=settings)
    conv_id_str = req.query_params.get("conv_id")
    active_conv = None
    messages = []
    if conv_id_str and conv_id_str.isdigit():
        cid = int(conv_id_str)
        active_conv = next((c for c in convs if c.id == cid), None)
    elif convs:
        active_conv = convs[0]

    if active_conv is not None:
        messages = get_conversation_messages_for_friend(
            db, friend, active_conv.id, settings=settings
        )

    html_str = render_friend_dashboard(
        csrf_token=sess.csrf_token,
        username=friend.username,
        conversations=convs,
        active_conv=active_conv,
        messages=messages,
        posthumous_mode=is_posthumous_mode(db),
    )
    return html_response(html_str, status_code=200)


def handle_get_conversations(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, friend = require_role(db, req, "amigo", settings=settings)
    convs = list_conversations_for_friend(db, friend, settings=settings)
    return HTTPResponseData(
        status_code=200,
        json_payload=[
            {
                "id": c.id,
                "title": c.title,
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat(),
            }
            for c in convs
        ],
    )


def handle_post_conversation(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, friend = require_role(db, req, "amigo", settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = ConversationCreateSchema(title=str(data.get("title", "")))
        conv = create_conversation_for_friend(db, friend, schema.title, settings=settings)
    except ValidationError as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})
    if wants_html(req):
        return redirect_response(f"/friend/dashboard?conv_id={conv.id}")
    return HTTPResponseData(
        status_code=201,
        json_payload={"id": conv.id, "title": conv.title},
    )


def handle_get_conversation_detail(
    db: DbSession,
    req: HTTPRequestContext,
    conversation_id: int,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, friend = require_role(db, req, "amigo", settings=settings)
    try:
        msgs = get_conversation_messages_for_friend(
            db, friend, conversation_id, settings=settings
        )
    except AuthorizationError as exc:
        return HTTPResponseData(status_code=403, json_payload={"detail": str(exc)})

    posthumous = is_posthumous_mode(db)
    return HTTPResponseData(
        status_code=200,
        json_payload={
            "conversation_id": conversation_id,
            "simulation_notice": SIMULATION_NOTICE,
            "posthumous_mode": posthumous,
            "posthumous_notice": POSTHUMOUS_SIMULATION_NOTICE if posthumous else None,
            "messages": [
                {
                    "id": m.id,
                    "sender_role": m.sender_role,
                    "content": m.content,
                    "used_web_search": m.used_web_search,
                    "simulation_notice_shown": m.simulation_notice_shown,
                    "token_count": m.token_count,
                }
                for m in msgs
            ],
        },
    )


def handle_post_message(
    db: DbSession,
    req: HTTPRequestContext,
    conversation_id: int,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, friend = require_role(db, req, "amigo", settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = MessageCreateSchema(content=str(data.get("content", "")))
        use_web = bool(data.get("use_web_search", False))
        sse_stream, reply_view = send_friend_message_and_stream_response(
            db,
            friend=friend,
            conversation_id=conversation_id,
            user_content=schema.content,
            use_web_search=use_web,
            settings=settings,
        )
        sse_text = "".join(sse_stream)
    except QuotaExceededError as exc:
        return HTTPResponseData(status_code=429, json_payload={"detail": str(exc)})
    except AuthorizationError as exc:
        return HTTPResponseData(status_code=403, json_payload={"detail": str(exc)})
    except ValidationError as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    if req.headers.get("Accept") == "text/event-stream":
        return HTTPResponseData(
            status_code=200,
            body=sse_text,
            headers={"Content-Type": "text/event-stream; charset=utf-8"},
        )

    if wants_html(req):
        return redirect_response(f"/friend/dashboard?conv_id={conversation_id}")

    return HTTPResponseData(
        status_code=201,
        json_payload={
            "message_id": reply_view.id,
            "content": reply_view.content,
            "used_web_search": reply_view.used_web_search,
            "simulation_notice_shown": reply_view.simulation_notice_shown,
            "sse_stream": sse_text,
        },
    )
