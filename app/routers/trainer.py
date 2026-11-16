"""Router del Entrenador (/trainer): conocimiento, voz, personalidad, entrevista, invitaciones, LLM y albacea."""

from __future__ import annotations

import base64

from app.config import Settings
from app.db._compat_sa import Session as DbSession
from app.models.user import User
from app.routers.dependencies import (
    HTTPRequestContext,
    HTTPResponseData,
    check_knowledge_base_writable,
    require_role,
)
from app.schemas.auth import CreateInvitationSchema, ValidationError
from app.schemas.conversation import LLMSettingsUpdateSchema
from app.schemas.knowledge import (
    EntryCreateSchema,
    EntryUpdateSchema,
    ExportFormatSchema,
    PersonalityDocSchema,
)
from app.schemas.succession import DesignateExecutorSchema
from app.services.audio import AudioValidationError, upload_and_transcribe_audio
from app.services.auth import AuthorizationError, create_invitation
from app.services.knowledge import (
    create_entry,
    delete_entry_securely,
    export_knowledge_base_stream,
    get_active_personality_doc,
    save_personality_doc_version,
    search_entries_in_memory,
    seed_default_interview_topics,
    update_entry,
)
from app.services.interview_chat import (
    generate_new_interviewer_question,
    list_interview_chat_messages,
    process_trainer_interview_reply,
)
from app.services.llm import (
    get_last_llm_warning,
    get_llm_settings_public_view,
    update_llm_settings_by_trainer,
)
from app.services.succession import designate_executor, is_posthumous_mode
from app.ui import html_response, render_trainer_dashboard, wants_html


def handle_get_trainer_dashboard(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
    flash_msg: str | None = None,
    created_invite_url: str | None = None,
) -> HTTPResponseData:
    sess, trainer = require_role(db, req, "entrenador", settings=settings)
    entries = search_entries_in_memory(db, trainer, settings=settings)
    pers = get_active_personality_doc(db, trainer.id, settings=settings)
    topics = seed_default_interview_topics(db, trainer)
    llm_view = get_llm_settings_public_view(db, trainer, settings=settings)
    interview_chat_msgs = list_interview_chat_messages(db, trainer, settings=settings)
    llm_warning = get_last_llm_warning(trainer.id)
    html_str = render_trainer_dashboard(
        csrf_token=sess.csrf_token,
        username=trainer.username,
        entries=entries,
        personality_body=pers.body if pers else "",
        personality_version=pers.version_number if pers else 0,
        topics=topics,
        llm_view=llm_view,
        posthumous_mode=is_posthumous_mode(db),
        interview_chat_messages=interview_chat_msgs,
        llm_warning=llm_warning,
        flash_msg=flash_msg,
        created_invite_url=created_invite_url,
    )
    return html_response(html_str, status_code=200)


def handle_get_interview_chat(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    msgs = list_interview_chat_messages(db, trainer, settings=settings)
    return HTTPResponseData(
        status_code=200,
        json_payload=[
            {
                "id": m.id,
                "sender_role": m.sender_role,
                "topic": m.topic,
                "content": m.content,
                "saved_entry_id": m.saved_entry_id,
                "created_at": m.created_at.isoformat(),
            }
            for m in msgs
        ],
    )


def handle_post_interview_chat_reply(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    check_knowledge_base_writable(db)
    data = req.json_data if req.json_data is not None else req.form_data
    reply_text = str(data.get("content", "")).strip()
    topic_override = str(data.get("topic", "")).strip() or None
    also_pers = str(data.get("also_update_personality", "")).lower() in ("1", "true", "on", "yes")
    try:
        t_msg, ai_msg, entry_id = process_trainer_interview_reply(
            db,
            trainer=trainer,
            trainer_reply_text=reply_text,
            topic_override=topic_override,
            also_update_personality=also_pers,
            settings=settings,
        )
    except Exception as exc:
        if wants_html(req):
            return handle_get_trainer_dashboard(
                db, req, settings=settings, flash_msg=f"Aviso en entrevista: {exc}"
            )
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    if wants_html(req):
        return handle_get_trainer_dashboard(
            db,
            req,
            settings=settings,
            flash_msg=f"✓ Tu respuesta fue guardada y cifrada en tu base de conocimiento (Entrada #{entry_id}) y el modelo te ha planteado una nueva pregunta.",
        )

    return HTTPResponseData(
        status_code=201,
        json_payload={
            "saved_entry_id": entry_id,
            "trainer_message": {
                "id": t_msg.id,
                "topic": t_msg.topic,
                "content": t_msg.content,
            },
            "interviewer_message": {
                "id": ai_msg.id,
                "topic": ai_msg.topic,
                "content": ai_msg.content,
            },
        },
    )


def handle_post_interview_next_question(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    check_knowledge_base_writable(db)
    data = req.json_data if req.json_data is not None else req.form_data
    requested_topic = str(data.get("topic", "")).strip() or None
    try:
        ai_msg = generate_new_interviewer_question(
            db, trainer=trainer, requested_topic=requested_topic, settings=settings
        )
    except Exception as exc:
        if wants_html(req):
            return handle_get_trainer_dashboard(
                db, req, settings=settings, flash_msg=f"Aviso al generar pregunta: {exc}"
            )
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    if wants_html(req):
        return handle_get_trainer_dashboard(
            db, req, settings=settings, flash_msg="El entrevistador IA ha formulado una nueva pregunta."
        )

    return HTTPResponseData(
        status_code=201,
        json_payload={
            "id": ai_msg.id,
            "topic": ai_msg.topic,
            "content": ai_msg.content,
        },
    )


def handle_post_create_invitation(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    # En modo activo solo el entrenador; en modo póstumo el albacea también puede gestionar invitaciones
    allowed = ("entrenador", "albacea") if is_posthumous_mode(db) else ("entrenador",)
    _, user = require_role(db, req, allowed, settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = CreateInvitationSchema(
            recipient_hint=str(data.get("recipient_hint", "")) if data.get("recipient_hint") else None,
            target_role=str(data.get("target_role", "amigo")),
            expiry_hours=int(data["expiry_hours"]) if data.get("expiry_hours") else None,
        )
        inv, raw_token = create_invitation(
            db,
            creator=user,
            target_role=schema.target_role,
            recipient_hint=schema.recipient_hint,
            expiry_hours=schema.expiry_hours,
            settings=settings,
        )
    except (ValidationError, ValueError, AuthorizationError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    if wants_html(req):
        return handle_get_trainer_dashboard(
            db,
            req,
            settings=settings,
            flash_msg="Invitación de un solo uso creada con éxito.",
            created_invite_url=f"http://localhost:8000/auth/invite/{raw_token}",
        )

    return HTTPResponseData(
        status_code=201,
        json_payload={
            "invitation_id": inv.id,
            "token": raw_token,
            "invite_path": f"/auth/invite/{raw_token}",
            "target_role": inv.target_role,
            "expires_at": inv.expires_at.isoformat(),
        },
    )


def handle_get_entries(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    q = req.query_params.get("q")
    topic = req.query_params.get("topic")
    items = search_entries_in_memory(db, trainer, query=q, topic=topic, settings=settings)
    return HTTPResponseData(
        status_code=200,
        json_payload=[
            {
                "id": e.id,
                "topic": e.topic,
                "content": e.content,
                "status": e.status,
                "entry_date": e.entry_date.isoformat(),
                "interview_topic_id": e.interview_topic_id,
            }
            for e in items
        ],
    )


def handle_post_entry(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    check_knowledge_base_writable(db)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = EntryCreateSchema(
            topic=str(data.get("topic", "")),
            content=str(data.get("content", "")),
            interview_topic_id=int(data["interview_topic_id"])
            if data.get("interview_topic_id") is not None
            else None,
            status=str(data.get("status", "confirmed")),
        )
        view = create_entry(
            db,
            trainer=trainer,
            topic=schema.topic,
            content=schema.content,
            entry_date=schema.entry_date,
            interview_topic_id=schema.interview_topic_id,
            status=schema.status,
            settings=settings,
        )
    except (ValidationError, ValueError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    if wants_html(req):
        return handle_get_trainer_dashboard(
            db, req, settings=settings, flash_msg="Recuerdo cifrado y guardado correctamente."
        )

    return HTTPResponseData(
        status_code=201,
        json_payload={
            "id": view.id,
            "topic": view.topic,
            "content": view.content,
            "status": view.status,
        },
    )


def handle_put_entry(
    db: DbSession,
    req: HTTPRequestContext,
    entry_id: int,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    check_knowledge_base_writable(db)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = EntryUpdateSchema(
            topic=str(data.get("topic", "")),
            content=str(data.get("content", "")),
            status=str(data.get("status", "confirmed")),
        )
        view = update_entry(
            db,
            trainer=trainer,
            entry_id=entry_id,
            topic=schema.topic,
            content=schema.content,
            status=schema.status,
            settings=settings,
        )
    except (ValidationError, ValueError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    return HTTPResponseData(
        status_code=200,
        json_payload={
            "id": view.id,
            "topic": view.topic,
            "content": view.content,
            "status": view.status,
        },
    )


def handle_delete_entry(
    db: DbSession,
    req: HTTPRequestContext,
    entry_id: int,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    check_knowledge_base_writable(db)
    try:
        delete_entry_securely(db, trainer, entry_id, settings=settings)
    except ValueError as exc:
        return HTTPResponseData(status_code=404, json_payload={"detail": str(exc)})
    return HTTPResponseData(status_code=200, json_payload={"status": "deleted"})


def handle_post_audio_upload(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    check_knowledge_base_writable(db)
    data = req.json_data if req.json_data is not None else req.form_data

    raw_bytes = req.body_bytes
    if not raw_bytes and data.get("audio_bytes_b64"):
        raw_bytes = base64.b64decode(str(data["audio_bytes_b64"]))
    elif not raw_bytes and isinstance(data.get("file"), bytes):
        raw_bytes = data["file"]

    topic = str(data.get("topic", "nota_de_voz"))
    try:
        res = upload_and_transcribe_audio(
            db,
            trainer=trainer,
            raw_audio_bytes=raw_bytes,
            topic=topic,
            settings=settings,
        )
    except AudioValidationError as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    return HTTPResponseData(
        status_code=201,
        json_payload={
            "entry_id": res.entry.id,
            "audio_id": res.audio_file.id,
            "mime_type": res.audio_file.mime_type,
            "status": res.entry.status,
            "draft_transcription": res.draft_transcription,
        },
    )


def handle_get_personality(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    doc = get_active_personality_doc(db, trainer.id, settings=settings)
    if doc is None:
        return HTTPResponseData(status_code=200, json_payload={"version_number": 0, "body": ""})
    return HTTPResponseData(
        status_code=200,
        json_payload={"version_number": doc.version_number, "body": doc.body},
    )


def handle_post_personality(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    check_knowledge_base_writable(db)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = PersonalityDocSchema(body=str(data.get("body", "")))
        doc = save_personality_doc_version(db, trainer, schema.body, settings=settings)
    except ValidationError as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})
    if wants_html(req):
        return handle_get_trainer_dashboard(
            db,
            req,
            settings=settings,
            flash_msg=f"Documento de personalidad guardado (versión {doc.version_number}).",
        )
    return HTTPResponseData(
        status_code=201,
        json_payload={"version_number": doc.version_number, "body": doc.body},
    )


def handle_get_interview_topics(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    topics = seed_default_interview_topics(db, trainer)
    return HTTPResponseData(
        status_code=200,
        json_payload=[
            {
                "id": t.id,
                "category": t.category,
                "prompt_title": t.prompt_title,
                "is_covered": t.is_covered,
            }
            for t in topics
        ],
    )


def handle_post_export(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = ExportFormatSchema(format=str(data.get("format", "jsonl")))
        stream = export_knowledge_base_stream(
            db, trainer, schema.format, ip_address=req.client_ip, settings=settings
        )
        full_text = "".join(stream)
    except (ValidationError, ValueError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    content_type = "application/x-ndjson" if schema.format == "jsonl" else "text/plain; charset=utf-8"
    return HTTPResponseData(
        status_code=200,
        body=full_text,
        headers={"Content-Type": content_type},
    )


def handle_get_llm_settings(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    view = get_llm_settings_public_view(db, trainer, settings=settings)
    if wants_html(req):
        return handle_get_trainer_dashboard(
            db, req, settings=settings, flash_msg="Configuración del proveedor LLM actualizada."
        )

    return HTTPResponseData(
        status_code=200,
        json_payload={
            "provider_name": view.provider_name,
            "base_url": view.base_url,
            "model_name": view.model_name,
            "has_api_key_configured": view.has_api_key_configured,
            "context_entries_limit": view.context_entries_limit,
            "daily_token_limit_per_user": view.daily_token_limit_per_user,
            "web_search_enabled": view.web_search_enabled,
            "web_search_url": view.web_search_url,
        },
    )


def handle_post_llm_settings(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = LLMSettingsUpdateSchema(
            provider_name=str(data.get("provider_name", "ollama")),
            base_url=str(data.get("base_url", "http://localhost:11434/v1")),
            model_name=str(data.get("model_name", "llama3.1:8b")),
            api_key=str(data["api_key"]) if data.get("api_key") is not None else None,
            context_entries_limit=int(data.get("context_entries_limit", 10)),
            daily_token_limit_per_user=int(data.get("daily_token_limit_per_user", 25000)),
            web_search_enabled=bool(data.get("web_search_enabled", False)),
            web_search_url=str(data["web_search_url"]) if data.get("web_search_url") else None,
        )
        view = update_llm_settings_by_trainer(db, trainer, schema, settings=settings)
    except ValidationError as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    if wants_html(req):
        return handle_get_trainer_dashboard(
            db, req, settings=settings, flash_msg="Configuración del proveedor LLM actualizada."
        )

    return HTTPResponseData(
        status_code=200,
        json_payload={
            "provider_name": view.provider_name,
            "base_url": view.base_url,
            "model_name": view.model_name,
            "has_api_key_configured": view.has_api_key_configured,
            "context_entries_limit": view.context_entries_limit,
            "daily_token_limit_per_user": view.daily_token_limit_per_user,
            "web_search_enabled": view.web_search_enabled,
            "web_search_url": view.web_search_url,
        },
    )


def handle_post_designate_executor(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, trainer = require_role(db, req, "entrenador", settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        contacts = data.get("notification_contacts", [])
        if isinstance(contacts, str):
            contacts = [c.strip() for c in contacts.split(",") if c.strip()]
        schema = DesignateExecutorSchema(
            user_id=int(data.get("user_id", 0)),
            notification_contacts=list(contacts),
            cooldown_hours=int(data.get("cooldown_hours", 72)),
        )
        exec_user = db.get(User, schema.user_id)
        if exec_user is None:
            return HTTPResponseData(status_code=404, json_payload={"detail": "Usuario no encontrado"})
        rec = designate_executor(
            db,
            trainer=trainer,
            executor_user=exec_user,
            notification_contacts=schema.notification_contacts,
            cooldown_hours=schema.cooldown_hours,
            settings=settings,
        )
    except (ValidationError, AuthorizationError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    return HTTPResponseData(
        status_code=201,
        json_payload={"executor_id": rec.id, "user_id": rec.user_id, "role": exec_user.role},
    )
