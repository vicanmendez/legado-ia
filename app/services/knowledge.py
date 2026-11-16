"""Servicio de base de conocimiento cifrada, modo entrevista guiada y exportación en streaming (Parte 4)."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.config import Settings, get_settings
from app.db._compat_sa import Session as DbSession
from app.db.base import select, utc_now
from app.models.knowledge import AudioFile, Entry, InterviewTopic, PersonalityDoc
from app.models.user import User
from app.services.audit import log_security_event
from app.services.auth import AuthorizationError, get_user_dek
from app.services.crypto import decrypt_str, encrypt_blob

DEFAULT_INTERVIEW_TOPICS: list[tuple[str, str]] = [
    ("infancia", "¿Cuáles son los recuerdos más vivos de tu infancia y de tu hogar familiar?"),
    ("valores", "¿Qué principios o valores consideras innegociables en tu forma de vivir?"),
    ("trabajo", "¿Qué aprendizajes te dejó tu trayectoria profesional y tus proyectos?"),
    ("errores", "¿Qué errores importantes cometiste y qué aprendiste de ellos?"),
    ("consejos", "¿Qué consejo le darías a un ser querido cuando atraviese un momento difícil?"),
]


@dataclass
class DecryptedEntryView:
    id: int
    trainer_id: int
    topic: str
    entry_date: datetime
    content: str
    status: str
    interview_topic_id: int | None
    created_at: datetime
    updated_at: datetime


@dataclass
class DecryptedPersonalityView:
    id: int
    trainer_id: int
    version_number: int
    body: str
    is_active: bool
    created_at: datetime


def _ensure_trainer_and_writable(db: DbSession, user: User, write_operation: bool = True) -> None:
    if user.role != "entrenador":
        log_security_event(
            db,
            "ROLE_DENIED_KNOWLEDGE",
            actor_user_id=user.id,
            metadata={"role": user.role},
        )
        raise AuthorizationError("Acceso exclusivo para el rol ENTRENADOR")
    if write_operation:
        from app.services.succession import is_posthumous_mode

        if is_posthumous_mode(db):
            raise AuthorizationError(
                "Modo Póstumo activo: la base de conocimiento se encuentra en modo de solo lectura"
            )


def seed_default_interview_topics(db: DbSession, trainer: User) -> list[InterviewTopic]:
    """Inicializa la lista de temas del modo entrevista guiada si aún no existen para el entrenador."""
    existing = db.scalars(
        select(InterviewTopic)
        .where(InterviewTopic.trainer_id == trainer.id)
        .order_by(InterviewTopic.display_order.asc())
    ).all()
    if existing:
        return existing

    created: list[InterviewTopic] = []
    for idx, (cat, prompt_title) in enumerate(DEFAULT_INTERVIEW_TOPICS, start=1):
        topic = InterviewTopic(
            trainer_id=trainer.id,
            category=cat,
            prompt_title=prompt_title,
            is_covered=False,
            covered_at=None,
            display_order=idx,
        )
        db.add(topic)
        created.append(topic)
    db.commit()
    return created


def create_entry(
    db: DbSession,
    trainer: User,
    topic: str,
    content: str,
    entry_date: datetime | None = None,
    interview_topic_id: int | None = None,
    status: str = "confirmed",
    settings: Settings | None = None,
) -> DecryptedEntryView:
    """Cifra el texto con la DEK del entrenador (AES-256-GCM) y persiste la entrada."""
    _ensure_trainer_and_writable(db, trainer, write_operation=True)
    cfg = settings or get_settings()
    dek = get_user_dek(db, trainer.id, settings=cfg)
    now = utc_now()
    eff_date = entry_date or now
    aad = f"entries:{trainer.id}"

    encrypted = encrypt_blob(content, dek, aad=aad)
    entry = Entry(
        trainer_id=trainer.id,
        topic=topic.strip()[:120],
        entry_date=eff_date,
        encrypted_content=encrypted,
        status=status,
        interview_topic_id=interview_topic_id,
        created_at=now,
        updated_at=now,
    )
    db.add(entry)
    db.flush()

    if interview_topic_id is not None and status == "confirmed":
        it = db.get(InterviewTopic, interview_topic_id)
        if it is not None and it.trainer_id == trainer.id:
            it.is_covered = True
            it.covered_at = now

    db.commit()
    return DecryptedEntryView(
        id=entry.id,
        trainer_id=entry.trainer_id,
        topic=entry.topic,
        entry_date=entry.entry_date,
        content=content,
        status=entry.status,
        interview_topic_id=entry.interview_topic_id,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


def update_entry(
    db: DbSession,
    trainer: User,
    entry_id: int,
    topic: str,
    content: str,
    status: str = "confirmed",
    settings: Settings | None = None,
) -> DecryptedEntryView:
    """Edita o confirma una entrada recifrando su contenido con la DEK del entrenador."""
    _ensure_trainer_and_writable(db, trainer, write_operation=True)
    cfg = settings or get_settings()
    entry = db.get(Entry, entry_id)
    if entry is None or entry.trainer_id != trainer.id:
        raise ValueError("Entrada no encontrada")

    dek = get_user_dek(db, trainer.id, settings=cfg)
    now = utc_now()
    entry.topic = topic.strip()[:120]
    entry.encrypted_content = encrypt_blob(content, dek, aad=f"entries:{trainer.id}")
    entry.status = status
    entry.updated_at = now

    if entry.interview_topic_id is not None and status == "confirmed":
        it = db.get(InterviewTopic, entry.interview_topic_id)
        if it is not None and it.trainer_id == trainer.id:
            it.is_covered = True
            it.covered_at = now

    db.commit()
    return DecryptedEntryView(
        id=entry.id,
        trainer_id=entry.trainer_id,
        topic=entry.topic,
        entry_date=entry.entry_date,
        content=content,
        status=entry.status,
        interview_topic_id=entry.interview_topic_id,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


def search_entries_in_memory(
    db: DbSession,
    trainer: User,
    query: str | None = None,
    topic: str | None = None,
    only_confirmed: bool = False,
    settings: Settings | None = None,
) -> list[DecryptedEntryView]:
    """Descifra en memoria las entradas del entrenador y aplica filtro por texto y tema en servidor."""
    _ensure_trainer_and_writable(db, trainer, write_operation=False)
    cfg = settings or get_settings()
    dek = get_user_dek(db, trainer.id, settings=cfg)

    stmt = (
        select(Entry)
        .where(Entry.trainer_id == trainer.id)
        .order_by(Entry.entry_date.desc(), Entry.id.desc())
    )
    rows = db.scalars(stmt).all()
    results: list[DecryptedEntryView] = []
    q_norm = query.strip().lower() if query else ""
    t_norm = topic.strip().lower() if topic else ""

    for row in rows:
        if only_confirmed and row.status != "confirmed":
            continue
        if t_norm and row.topic.lower() != t_norm:
            continue
        plain_text = decrypt_str(row.encrypted_content, dek, aad=f"entries:{trainer.id}")
        if q_norm and q_norm not in plain_text.lower() and q_norm not in row.topic.lower():
            continue
        results.append(
            DecryptedEntryView(
                id=row.id,
                trainer_id=row.trainer_id,
                topic=row.topic,
                entry_date=row.entry_date,
                content=plain_text,
                status=row.status,
                interview_topic_id=row.interview_topic_id,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
        )
    return results


def delete_entry_securely(
    db: DbSession,
    trainer: User,
    entry_id: int,
    settings: Settings | None = None,
) -> None:
    """Borrado seguro: elimina la entrada y sobrescribe/elimina el archivo de audio cifrado en disco."""
    _ensure_trainer_and_writable(db, trainer, write_operation=True)
    cfg = settings or get_settings()
    entry = db.get(Entry, entry_id)
    if entry is None or entry.trainer_id != trainer.id:
        raise ValueError("Entrada no encontrada")

    audio = db.scalar(select(AudioFile).where(AudioFile.entry_id == entry.id))
    if audio is not None:
        disk_path = Path(cfg.AUDIO_STORAGE_PATH) / audio.storage_rel_path
        if disk_path.is_file():
            size = disk_path.stat().st_size
            disk_path.write_bytes(os.urandom(max(size, 32)))
            disk_path.unlink()
        db.delete(audio)

    db.delete(entry)
    log_security_event(
        db,
        "KB_ENTRY_DELETED",
        actor_user_id=trainer.id,
        metadata={"entry_id": entry_id},
        commit=True,
    )


def save_personality_doc_version(
    db: DbSession,
    trainer: User,
    body: str,
    settings: Settings | None = None,
) -> DecryptedPersonalityView:
    """Crea una nueva versión cifrada del documento de personalidad desactivando las anteriores."""
    _ensure_trainer_and_writable(db, trainer, write_operation=True)
    cfg = settings or get_settings()
    dek = get_user_dek(db, trainer.id, settings=cfg)

    prev_docs = db.scalars(
        select(PersonalityDoc)
        .where(PersonalityDoc.trainer_id == trainer.id)
        .order_by(PersonalityDoc.version_number.desc())
    ).all()
    next_version = (prev_docs[0].version_number + 1) if prev_docs else 1
    for p in prev_docs:
        if p.is_active:
            p.is_active = False

    now = utc_now()
    encrypted = encrypt_blob(body, dek, aad=f"personality_doc:{trainer.id}")
    doc = PersonalityDoc(
        trainer_id=trainer.id,
        version_number=next_version,
        encrypted_body=encrypted,
        is_active=True,
        created_at=now,
    )
    db.add(doc)
    db.commit()
    return DecryptedPersonalityView(
        id=doc.id,
        trainer_id=doc.trainer_id,
        version_number=doc.version_number,
        body=body,
        is_active=True,
        created_at=doc.created_at,
    )


def get_active_personality_doc(
    db: DbSession,
    trainer_id: int,
    settings: Settings | None = None,
) -> DecryptedPersonalityView | None:
    """Obtiene y descifra la versión activa del documento de personalidad del entrenador."""
    cfg = settings or get_settings()
    doc = db.scalar(
        select(PersonalityDoc).where(
            PersonalityDoc.trainer_id == trainer_id,
            PersonalityDoc.is_active == True,  # noqa: E712
        )
    )
    if doc is None:
        return None
    dek = get_user_dek(db, trainer_id, settings=cfg)
    plain = decrypt_str(doc.encrypted_body, dek, aad=f"personality_doc:{trainer_id}")
    return DecryptedPersonalityView(
        id=doc.id,
        trainer_id=doc.trainer_id,
        version_number=doc.version_number,
        body=plain,
        is_active=doc.is_active,
        created_at=doc.created_at,
    )


def export_knowledge_base_stream(
    db: DbSession,
    trainer: User,
    fmt: str,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> Iterator[str]:
    """Genera en streaming la exportación de la base de conocimiento en JSONL o TXT y registra en audit_log."""
    _ensure_trainer_and_writable(db, trainer, write_operation=False)
    fmt_clean = fmt.strip().lower()
    if fmt_clean not in ("jsonl", "txt"):
        raise ValueError("Formato de exportación no soportado")

    entries = search_entries_in_memory(db, trainer, settings=settings)
    personality = get_active_personality_doc(db, trainer.id, settings=settings)

    log_security_event(
        db,
        "KB_EXPORT",
        actor_user_id=trainer.id,
        ip_address=ip_address,
        metadata={"format": fmt_clean, "entries_count": len(entries)},
        commit=True,
    )

    def _stream() -> Iterator[str]:
        if fmt_clean == "jsonl":
            if personality is not None:
                yield (
                    json.dumps(
                        {
                            "type": "personality_doc",
                            "version": personality.version_number,
                            "content": personality.body,
                            "created_at": personality.created_at.isoformat(),
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
            for item in entries:
                yield (
                    json.dumps(
                        {
                            "type": "entry",
                            "id": item.id,
                            "topic": item.topic,
                            "entry_date": item.entry_date.isoformat(),
                            "status": item.status,
                            "content": item.content,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        else:
            if personality is not None:
                yield f"=== DOCUMENTO DE PERSONALIDAD (v{personality.version_number}) ===\n"
                yield f"{personality.body}\n\n"
            for item in entries:
                yield f"--- [{item.entry_date.date().isoformat()}] Tema: {item.topic} ---\n"
                yield f"{item.content}\n\n"

    return _stream()
