"""Servicio de Chat de Entrevista Biográfica Guiada por IA con Banco de Prompts Pre-cargados y Preguntas Variadas."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.config import Settings, get_settings
from app.db._compat_sa import Session as DbSession
from app.db.base import select, utc_now
from app.models.knowledge import InterviewTopic, TrainerInterviewMessage
from app.models.user import User
from app.services.auth import get_user_dek
from app.services.crypto import decrypt_str, encrypt_blob
from app.services.knowledge import (
    _ensure_trainer_and_writable,
    create_entry,
    get_active_personality_doc,
    save_personality_doc_version,
    seed_default_interview_topics,
)
from app.services.llm import invoke_trainer_llm

# Banco pre-cargado de prompts de entrevista biográfica variados por dimensión vital
PRELOADED_INTERVIEW_BANK: dict[str, list[str]] = {
    "infancia": [
        "¿Cuáles son los olores, sonidos o lugares que más te transportan a tu niñez y a la casa donde creciste?",
        "¿Qué persona de tu familia o de tu entorno marcó más tu infancia y qué aprendiste de ella?",
        "¿Cuál era tu juego, travesura o rincón favorito cuando eras niño y cómo recuerdas a tus amigos de entonces?",
        "Si pudieras volver por una tarde a un día concreto de tu infancia, ¿qué día elegirías y por qué?",
    ],
    "valores": [
        "¿Qué principio moral o valor consideras innegociable, incluso cuando defenderlo resulta difícil?",
        "¿Qué significa para ti la lealtad y qué esperas de las personas en las que confías?",
        "¿Cómo ha cambiado tu idea de lo que realmente importa en la vida con el paso de los años?",
        "¿Ante qué tipo de injusticia o actitud sientes que nunca podrías quedarte callado?",
    ],
    "ideología": [
        "¿Cómo describirías tu visión de la sociedad, la libertad y el bien común con tus propias palabras?",
        "¿Qué pensadores, lecturas o sucesos históricos influyeron más en tu forma de entender el mundo y la política?",
        "¿Qué matices de tu pensamiento político o filosófico sueles explicar cuando debates con amigos?",
        "¿Qué esperanzas y qué preocupaciones tienes sobre el rumbo del mundo en las próximas décadas?",
    ],
    "trabajo": [
        "¿Cuál fue el reto profesional o proyecto del que te sientes más orgulloso y cómo lo superaste?",
        "¿Qué te enseñó tu primer empleo o tus primeros pasos trabajando sobre el esfuerzo y el carácter?",
        "¿Quién fue el mejor compañero o mentor que encontraste en tu vida laboral y qué huella te dejó?",
        "¿Qué consejo le darías a alguien joven sobre cómo equilibrar la vocación profesional con la vida personal?",
    ],
    "errores": [
        "¿Qué decisión difícil o tropiezo importante te dejó la lección más valiosa de tu vida?",
        "Si pudieras hablar con tu 'yo' de hace veinte años antes de cometer un error, ¿qué le dirías con serenidad?",
        "¿Cómo aprendiste a perdonarte tus propios fallos y a pedir perdón cuando te equivocaste con alguien querido?",
    ],
    "consejos": [
        "Cuando un amigo o familiar atraviesa un duelo o una crisis profunda, ¿qué palabras sueles ofrecerle?",
        "¿Cuál es tu regla de oro para tomar decisiones importantes cuando tienes dudas?",
        "¿Qué te gustaría que tus seres queridos recuerden siempre cuando piensen en ti en un día alegre?",
    ],
    "personalidad": [
        "¿Qué frases hechas, muletillas, refranes o expresiones usas todo el tiempo al hablar con tus amigos?",
        "¿Cómo describirías tu sentido del humor? ¿Qué cosas te hacen reír a carcajadas?",
        "Cuando te enfadas o te emocionas profundamente, ¿cómo sueles expresarlo?",
    ],
    "familia": [
        "¿Qué tradiciones o costumbres familiares te parecen más entrañables y dignas de conservarse?",
        "¿Qué historia de tus padres o abuelos te gusta contar para que no se pierda en la memoria familiar?",
        "¿Cuál ha sido uno de los momentos más felices que has compartido alrededor de una mesa con los tuyos?",
    ],
    "amistad": [
        "¿Qué hace que consideres a alguien un verdadero amigo de toda la vida?",
        "¿Cuál es la anécdota más divertida o inolvidable que has vivido junto a tus amigos?",
        "¿Qué te gustaría agradecerles a los amigos que te han acompañado en las buenas y en las malas?",
    ],
    "gustos": [
        "¿Qué canciones, libros o películas sientes que te representan y por qué te emocionan tanto?",
        "¿Cuál es tu comida favorita, tu lugar ideal para descansar y tu plan perfecto para un domingo?",
        "¿Qué afición o pasión personal te hace perder la noción del tiempo?",
    ],
}

TOPIC_ROTATION_ORDER: list[str] = [
    "infancia",
    "personalidad",
    "valores",
    "ideología",
    "familia",
    "trabajo",
    "amistad",
    "gustos",
    "errores",
    "consejos",
]


@dataclass
class DecryptedInterviewChatMessage:
    id: int
    trainer_id: int
    sender_role: str
    topic: str
    content: str
    saved_entry_id: int | None
    created_at: datetime


def _select_varied_preloaded_question(
    category: str,
    previous_interviewer_messages: list[str],
    turn_index: int = 0,
) -> str:
    """Selecciona del banco pre-cargado una pregunta que NO haya aparecido aún en el historial."""
    cat_key = category.strip().lower()
    candidates = PRELOADED_INTERVIEW_BANK.get(cat_key)
    if not candidates:
        # Para cualquier tema libre (ej. viajes, deporte, espiritualidad, etc.) generar ángulos variados
        candidates = [
            f"¿Qué experiencia personal o recuerdo concreto definió tu forma de ver '{category}'?",
            f"Cuando conversas con tus amigos sobre '{category}', ¿qué postura, anécdota o reflexión sueles compartir siempre?",
            f"¿Cómo ha evolucionado con los años tu relación con '{category}' y qué significa hoy para ti?",
            f"¿Qué detalle, historia poco conocida o aprendizaje sobre '{category}' te gustaría que quede guardado en tu legado?",
        ]

    prev_joined = " ".join(previous_interviewer_messages).lower()
    for q in candidates:
        if q.lower()[:45] not in prev_joined:
            return q
    return candidates[turn_index % len(candidates)]


def _pick_next_topic_and_seed_question(
    db: DbSession,
    trainer: User,
    previous_msgs: list[DecryptedInterviewChatMessage],
    preferred_topic: str | None = None,
) -> tuple[str, str, int | None]:
    topics = seed_default_interview_topics(db, trainer)
    prev_interviewer_texts = [m.content for m in previous_msgs if m.sender_role == "interviewer"]
    turn_idx = len(previous_msgs)

    if preferred_topic and preferred_topic.strip():
        chosen_cat = preferred_topic.strip()[:120]
    else:
        # Alternar entre los temas no cubiertos y el catálogo extendido para evitar monotonía
        last_topic = previous_msgs[-1].topic.lower() if previous_msgs else ""
        uncovered = [t for t in topics if not t.is_covered and t.category.lower() != last_topic]
        if uncovered:
            chosen_cat = uncovered[0].category
        else:
            # Rotar por TOPIC_ROTATION_ORDER buscando uno distinto al último
            idx = turn_idx % len(TOPIC_ROTATION_ORDER)
            chosen_cat = TOPIC_ROTATION_ORDER[idx]
            if chosen_cat == last_topic:
                chosen_cat = TOPIC_ROTATION_ORDER[(idx + 1) % len(TOPIC_ROTATION_ORDER)]

    matched_db_topic = next(
        (t for t in topics if t.category.lower() == chosen_cat.lower()), None
    )
    seed_question = _select_varied_preloaded_question(
        chosen_cat, prev_interviewer_texts, turn_index=turn_idx
    )
    return chosen_cat, seed_question, (matched_db_topic.id if matched_db_topic else None)


def list_interview_chat_messages(
    db: DbSession,
    trainer: User,
    settings: Settings | None = None,
) -> list[DecryptedInterviewChatMessage]:
    """Devuelve el historial del chat de entrevista guiada descifrado con la DEK del entrenador."""
    _ensure_trainer_and_writable(db, trainer, write_operation=False)
    cfg = settings or get_settings()
    dek = get_user_dek(db, trainer.id, settings=cfg)
    aad = f"trainer_interview:{trainer.id}"

    rows = db.scalars(
        select(TrainerInterviewMessage)
        .where(TrainerInterviewMessage.trainer_id == trainer.id)
        .order_by(TrainerInterviewMessage.id.asc())
    ).all()

    if not rows:
        cat, seed_question, _ = _pick_next_topic_and_seed_question(db, trainer, [])
        welcome_text = (
            f"¡Hola, {trainer.username}! Soy tu entrevistador biográfico asistido por IA. "
            "Todo lo que me cuentes en este chat se cifrará con tu clave personal y se guardará "
            "automáticamente en tu base de conocimiento para que tu simulación aprenda tu historia, "
            "tus ideas y tu forma de expresarte.\n\n"
            f"Para empezar (tema: {cat}): {seed_question}"
        )
        first_msg = TrainerInterviewMessage(
            trainer_id=trainer.id,
            sender_role="interviewer",
            topic=cat,
            encrypted_content=encrypt_blob(welcome_text, dek, aad=aad),
            saved_entry_id=None,
            created_at=utc_now(),
        )
        db.add(first_msg)
        db.commit()
        rows = [first_msg]

    return [
        DecryptedInterviewChatMessage(
            id=r.id,
            trainer_id=r.trainer_id,
            sender_role=r.sender_role,
            topic=r.topic,
            content=decrypt_str(r.encrypted_content, dek, aad=aad),
            saved_entry_id=r.saved_entry_id,
            created_at=r.created_at,
        )
        for r in rows
    ]


def process_trainer_interview_reply(
    db: DbSession,
    trainer: User,
    trainer_reply_text: str,
    topic_override: str | None = None,
    also_update_personality: bool = False,
    settings: Settings | None = None,
) -> tuple[DecryptedInterviewChatMessage, DecryptedInterviewChatMessage, int]:
    """
    1. Guarda la respuesta del entrenador en el chat de entrevista.
    2. Extrae y guarda automáticamente el recuerdo cifrado en `entries` (base de conocimiento propia del entrenador).
    3. Invoca el modelo LLM elegido (OpenRouter u Ollama) con prompts pre-cargados variados para responder y hacer la siguiente pregunta.
    """
    _ensure_trainer_and_writable(db, trainer, write_operation=True)
    cfg = settings or get_settings()
    clean_reply = trainer_reply_text.strip()
    if not clean_reply:
        raise ValueError("La respuesta no puede estar vacía")

    dek = get_user_dek(db, trainer.id, settings=cfg)
    aad = f"trainer_interview:{trainer.id}"
    history = list_interview_chat_messages(db, trainer, settings=cfg)

    last_interviewer_msg = next(
        (m for m in reversed(history) if m.sender_role == "interviewer"),
        None,
    )
    active_topic = (
        topic_override.strip()[:120]
        if topic_override and topic_override.strip()
        else (last_interviewer_msg.topic if last_interviewer_msg else "recuerdos")
    )

    topics = seed_default_interview_topics(db, trainer)
    matched_topic: InterviewTopic | None = next(
        (t for t in topics if t.category.lower() == active_topic.lower()),
        None,
    )

    question_context = last_interviewer_msg.content if last_interviewer_msg else ""
    if question_context:
        kb_text = f"Pregunta de entrevista ({active_topic}): {question_context}\nRespuesta de {trainer.username}: {clean_reply}"
    else:
        kb_text = clean_reply

    saved_entry = create_entry(
        db,
        trainer=trainer,
        topic=active_topic,
        content=kb_text,
        interview_topic_id=matched_topic.id if matched_topic else None,
        status="confirmed",
        settings=cfg,
    )

    if also_update_personality or active_topic.lower() in ("personalidad", "estilo"):
        current_pers = get_active_personality_doc(db, trainer.id, settings=cfg)
        base_body = current_pers.body if current_pers else ""
        updated_body = (
            f"{base_body}\n- Rasgo/estilo compartido en entrevista ({active_topic}): {clean_reply}".strip()
        )
        save_personality_doc_version(db, trainer, updated_body, settings=cfg)

    now = utc_now()
    trainer_msg_row = TrainerInterviewMessage(
        trainer_id=trainer.id,
        sender_role="trainer",
        topic=active_topic,
        encrypted_content=encrypt_blob(clean_reply, dek, aad=aad),
        saved_entry_id=saved_entry.id,
        created_at=now,
    )
    db.add(trainer_msg_row)
    db.flush()

    next_cat, next_seed_question, _ = _pick_next_topic_and_seed_question(
        db, trainer, history, preferred_topic=topic_override
    )
    already_asked = "\n".join(
        f"- {m.content[:140]}" for m in history[-6:] if m.sender_role == "interviewer"
    )

    interviewer_system_prompt = (
        f"Eres el biógrafo y entrevistador personal de {trainer.username} en la plataforma legado-ia.\n"
        "Tu misión es mantener una conversación viva, cálida y profunda para construir su legado digital.\n"
        "REGLAS ESTRICTAS DE ENTREVISTA:\n"
        "1. Primero, reacciona de forma específica y empática (en 1-2 frases) a lo que el usuario acaba de contarte, "
        "haciendo referencia directa a algún detalle de su respuesta.\n"
        f"2. Luego, hazle UNA pregunta nueva y estimulante sobre '{next_cat}' "
        f"(puedes inspirarte o adaptar esta guía pre-cargada: \"{next_seed_question}\").\n"
        "3. PROHIBIDO repetir preguntas anteriores. Estas ya fueron formuladas:\n"
        f"{already_asked}\n"
        "4. Habla siempre en español, con naturalidad y cercanía."
    )

    llm_messages: list[dict[str, str]] = [{"role": "system", "content": interviewer_system_prompt}]
    for m in history[-8:]:
        role_str = "assistant" if m.sender_role == "interviewer" else "user"
        llm_messages.append({"role": role_str, "content": m.content})
    llm_messages.append({"role": "user", "content": clean_reply})

    snippet = clean_reply[:90] + ("..." if len(clean_reply) > 90 else "")
    fallback_varied = (
        f"Qué interesante lo que cuentas sobre \"{snippet}\", {trainer.username}; "
        f"ya ha quedado guardado y cifrado en tu base de conocimiento bajo el tema '{active_topic}'.\n\n"
        f"Pasando ahora a explorar '{next_cat}': {next_seed_question}"
    )

    ai_reply_text, _ = invoke_trainer_llm(
        db,
        trainer_id=trainer.id,
        messages=llm_messages,
        did_web_search=False,
        fallback_text=fallback_varied,
        temperature=0.85,
        settings=cfg,
    )

    ai_msg_row = TrainerInterviewMessage(
        trainer_id=trainer.id,
        sender_role="interviewer",
        topic=next_cat,
        encrypted_content=encrypt_blob(ai_reply_text, dek, aad=aad),
        saved_entry_id=None,
        created_at=utc_now(),
    )
    db.add(ai_msg_row)
    db.commit()

    return (
        DecryptedInterviewChatMessage(
            id=trainer_msg_row.id,
            trainer_id=trainer.id,
            sender_role="trainer",
            topic=active_topic,
            content=clean_reply,
            saved_entry_id=saved_entry.id,
            created_at=trainer_msg_row.created_at,
        ),
        DecryptedInterviewChatMessage(
            id=ai_msg_row.id,
            trainer_id=trainer.id,
            sender_role="interviewer",
            topic=next_cat,
            content=ai_reply_text,
            saved_entry_id=None,
            created_at=ai_msg_row.created_at,
        ),
        saved_entry.id,
    )


def generate_new_interviewer_question(
    db: DbSession,
    trainer: User,
    requested_topic: str | None = None,
    settings: Settings | None = None,
) -> DecryptedInterviewChatMessage:
    """Genera una pregunta distinta y fresca del entrevistador IA sobre el tema elegido sin repetir ninguna anterior."""
    _ensure_trainer_and_writable(db, trainer, write_operation=True)
    cfg = settings or get_settings()
    dek = get_user_dek(db, trainer.id, settings=cfg)
    aad = f"trainer_interview:{trainer.id}"
    history = list_interview_chat_messages(db, trainer, settings=cfg)

    cat, seed_question, _ = _pick_next_topic_and_seed_question(
        db, trainer, history, preferred_topic=requested_topic
    )
    already_asked = "\n".join(
        f"- {m.content[:140]}" for m in history[-8:] if m.sender_role == "interviewer"
    )

    system_prompt = (
        f"Eres el entrevistador biográfico personal de {trainer.username} en legado-ia.\n"
        f"El usuario quiere explorar ahora el tema '{cat}'.\n"
        f"Guía pre-cargada sugerida para este turno: \"{seed_question}\"\n"
        "REGLAS:\n"
        "1. Formula UNA pregunta abierta, profunda y diferente a todas las anteriores para que cuente "
        "un recuerdo, vivencia o reflexión personal sobre este tema.\n"
        "2. PROHIBIDO repetir cualquiera de estas preguntas previas:\n"
        f"{already_asked}\n"
        "3. Sé directo, cálido y conversacional en español."
    )
    llm_messages: list[dict[str, str]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": f"Cambiemos de pregunta. Hazme una pregunta nueva y distinta sobre: {cat}",
        },
    ]

    fallback_q = f"Exploremos otro ángulo sobre '{cat}': {seed_question}"
    ai_question, _ = invoke_trainer_llm(
        db,
        trainer_id=trainer.id,
        messages=llm_messages,
        did_web_search=False,
        fallback_text=fallback_q,
        temperature=0.9,
        settings=cfg,
    )

    row = TrainerInterviewMessage(
        trainer_id=trainer.id,
        sender_role="interviewer",
        topic=cat,
        encrypted_content=encrypt_blob(ai_question, dek, aad=aad),
        saved_entry_id=None,
        created_at=utc_now(),
    )
    db.add(row)
    db.commit()

    return DecryptedInterviewChatMessage(
        id=row.id,
        trainer_id=trainer.id,
        sender_role="interviewer",
        topic=cat,
        content=ai_question,
        saved_entry_id=None,
        created_at=row.created_at,
    )
