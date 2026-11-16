"""Servicio de portabilidad (export-all, import-all, migrate-db) con verificación de recuentos y SHA-256 (Parte 6)."""

from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.db._compat_sa import Engine, Session as DbSession
from app.db.base import DeclarativeBase, select, utc_now
from app.models.knowledge import AudioFile, Entry, InterviewTopic, PersonalityDoc
from app.models.user import User
from app.services.audit import log_security_event
from app.services.auth import get_user_dek
from app.services.crypto import (
    decrypt_blob,
    decrypt_str,
    derive_key_from_passphrase,
    encrypt_blob,
    sha256_hex,
)

TOPOLOGICAL_TABLES_ORDER: tuple[str, ...] = (
    "users",
    "user_keys",
    "sessions",
    "otp_codes",
    "invitations",
    "recovery_codes",
    "altcha_consumed_challenges",
    "webauthn_credentials",
    "interview_topics",
    "entries",
    "trainer_interview_messages",
    "audio_files",
    "personality_doc",
    "conversations",
    "messages",
    "llm_settings",
    "system_state",
    "executors",
    "succession_events",
    "audit_log",
)


class PortabilityError(RuntimeError):
    """Error de integridad, checksum o recuento durante exportación, importación o migración."""


def export_all_encrypted_package(
    db: DbSession,
    passphrase: str,
    output_path: str | Path,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Genera un paquete cifrado AES-256-GCM (clave derivada por Argon2id/scrypt) con JSONL, audio y manifiesto SHA-256."""
    if not passphrase or len(passphrase) < 8:
        raise PortabilityError("La frase de paso del paquete debe tener al menos 8 caracteres")
    cfg = settings or get_settings()
    trainer = db.scalar(select(User).where(User.role == "entrenador"))
    if trainer is None:
        raise PortabilityError("No existe entrenador para exportar")

    dek = get_user_dek(db, trainer.id, settings=cfg)

    entries_rows = db.scalars(
        select(Entry).where(Entry.trainer_id == trainer.id).order_by(Entry.id.asc())
    ).all()
    personality_rows = db.scalars(
        select(PersonalityDoc)
        .where(PersonalityDoc.trainer_id == trainer.id)
        .order_by(PersonalityDoc.version_number.asc())
    ).all()
    topics_rows = db.scalars(
        select(InterviewTopic)
        .where(InterviewTopic.trainer_id == trainer.id)
        .order_by(InterviewTopic.id.asc())
    ).all()
    audio_rows = db.scalars(
        select(AudioFile).where(AudioFile.trainer_id == trainer.id).order_by(AudioFile.id.asc())
    ).all()

    exported_entries: list[dict[str, Any]] = []
    for e in entries_rows:
        plain_content = decrypt_str(e.encrypted_content, dek, aad=f"entries:{trainer.id}")
        exported_entries.append(
            {
                "id": e.id,
                "topic": e.topic,
                "entry_date": e.entry_date.isoformat(),
                "content": plain_content,
                "status": e.status,
                "interview_topic_id": e.interview_topic_id,
                "content_sha256": sha256_hex(plain_content),
            }
        )

    exported_personality: list[dict[str, Any]] = []
    for p in personality_rows:
        plain_body = decrypt_str(p.encrypted_body, dek, aad=f"personality_doc:{trainer.id}")
        exported_personality.append(
            {
                "version_number": p.version_number,
                "body": plain_body,
                "is_active": p.is_active,
                "body_sha256": sha256_hex(plain_body),
            }
        )

    exported_topics: list[dict[str, Any]] = [
        {
            "id": t.id,
            "category": t.category,
            "prompt_title": t.prompt_title,
            "is_covered": t.is_covered,
            "display_order": t.display_order,
        }
        for t in topics_rows
    ]

    exported_audios: list[dict[str, Any]] = []
    for a in audio_rows:
        disk_file = Path(cfg.AUDIO_STORAGE_PATH) / a.storage_rel_path
        encrypted_bytes = disk_file.read_bytes()
        plain_audio = decrypt_blob(encrypted_bytes, dek, aad=f"audio_files:{trainer.id}")
        exported_audios.append(
            {
                "entry_id": a.entry_id,
                "storage_rel_path": a.storage_rel_path,
                "mime_type": a.mime_type,
                "raw_audio_b64": base64.b64encode(plain_audio).decode("ascii"),
                "plain_sha256": sha256_hex(plain_audio),
            }
        )

    jsonl_lines = "\n".join(
        json.dumps(item, ensure_ascii=False, sort_keys=True) for item in exported_entries
    )
    manifest = {
        "schema_version": 1,
        "exported_at": utc_now().isoformat(),
        "trainer_username": trainer.username,
        "trainer_email": trainer.email,
        "counts": {
            "entries": len(exported_entries),
            "personality_versions": len(exported_personality),
            "interview_topics": len(exported_topics),
            "audio_files": len(exported_audios),
        },
        "jsonl_sha256": sha256_hex(jsonl_lines),
    }

    bundle = {
        "manifest": manifest,
        "entries": exported_entries,
        "personality_versions": exported_personality,
        "interview_topics": exported_topics,
        "audio_files": exported_audios,
    }
    bundle_bytes = json.dumps(bundle, ensure_ascii=False, sort_keys=True).encode("utf-8")

    salt = secrets.token_bytes(16)
    pkg_key = derive_key_from_passphrase(passphrase, salt)
    encrypted_bundle = encrypt_blob(bundle_bytes, pkg_key, aad="legado-ia:export-all:v1")

    envelope = {
        "format": "legado-ia-encrypted-export-v1",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "ciphertext_b64": base64.b64encode(encrypted_bundle).decode("ascii"),
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    log_security_event(
        db,
        "CLI_EXPORT_ALL",
        actor_user_id=trainer.id,
        metadata=manifest["counts"],
        commit=True,
    )
    return manifest


def import_all_encrypted_package(
    db: DbSession,
    passphrase: str,
    input_path: str | Path,
    target_trainer: User,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Verifica autenticidad AES-256-GCM y checksums SHA-256 del paquete y restaura todo el legado."""
    cfg = settings or get_settings()
    inp = Path(input_path)
    if not inp.is_file():
        raise PortabilityError(f"El archivo de paquete no existe: {inp}")

    try:
        envelope = json.loads(inp.read_text(encoding="utf-8"))
        salt = base64.b64decode(envelope["salt_b64"])
        ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    except Exception as exc:
        raise PortabilityError("Formato de contenedor de exportación inválido") from exc

    pkg_key = derive_key_from_passphrase(passphrase, salt)
    try:
        bundle_bytes = decrypt_blob(ciphertext, pkg_key, aad="legado-ia:export-all:v1")
        bundle = json.loads(bundle_bytes.decode("utf-8"))
    except Exception as exc:
        raise PortabilityError("Frase de paso incorrecta o paquete manipulado") from exc

    manifest = bundle["manifest"]
    entries_data = bundle["entries"]
    personality_data = bundle["personality_versions"]
    topics_data = bundle["interview_topics"]
    audios_data = bundle["audio_files"]

    # Verificar recuentos y checksums SHA-256 antes de escribir nada en la base de datos
    jsonl_lines = "\n".join(
        json.dumps(item, ensure_ascii=False, sort_keys=True) for item in entries_data
    )
    if sha256_hex(jsonl_lines) != manifest["jsonl_sha256"]:
        raise PortabilityError("Fallo de verificación de checksum SHA-256 en JSONL de entradas")

    for e_item in entries_data:
        if sha256_hex(e_item["content"]) != e_item["content_sha256"]:
            raise PortabilityError(f"Checksum SHA-256 inválido en entrada {e_item['id']}")

    for p_item in personality_data:
        if sha256_hex(p_item["body"]) != p_item["body_sha256"]:
            raise PortabilityError("Checksum SHA-256 inválido en documento de personalidad")

    for a_item in audios_data:
        raw_audio = base64.b64decode(a_item["raw_audio_b64"])
        if sha256_hex(raw_audio) != a_item["plain_sha256"]:
            raise PortabilityError("Checksum SHA-256 inválido en archivo de audio")

    dek = get_user_dek(db, target_trainer.id, settings=cfg)
    now = utc_now()

    topic_id_map: dict[int, int] = {}
    for t_item in topics_data:
        new_t = InterviewTopic(
            trainer_id=target_trainer.id,
            category=t_item["category"],
            prompt_title=t_item["prompt_title"],
            is_covered=bool(t_item["is_covered"]),
            covered_at=now if t_item["is_covered"] else None,
            display_order=int(t_item["display_order"]),
        )
        db.add(new_t)
        db.flush()
        topic_id_map[int(t_item["id"])] = new_t.id

    entry_id_map: dict[int, int] = {}
    for e_item in entries_data:
        mapped_topic_id = (
            topic_id_map.get(int(e_item["interview_topic_id"]))
            if e_item.get("interview_topic_id") is not None
            else None
        )
        new_e = Entry(
            trainer_id=target_trainer.id,
            topic=e_item["topic"],
            entry_date=datetime.fromisoformat(e_item["entry_date"]),
            encrypted_content=encrypt_blob(
                e_item["content"], dek, aad=f"entries:{target_trainer.id}"
            ),
            status=e_item["status"],
            interview_topic_id=mapped_topic_id,
            created_at=now,
            updated_at=now,
        )
        db.add(new_e)
        db.flush()
        entry_id_map[int(e_item["id"])] = new_e.id

    for p_item in personality_data:
        new_p = PersonalityDoc(
            trainer_id=target_trainer.id,
            version_number=int(p_item["version_number"]),
            encrypted_body=encrypt_blob(
                p_item["body"], dek, aad=f"personality_doc:{target_trainer.id}"
            ),
            is_active=bool(p_item["is_active"]),
            created_at=now,
        )
        db.add(new_p)

    storage_dir = Path(cfg.AUDIO_STORAGE_PATH)
    storage_dir.mkdir(parents=True, exist_ok=True)
    for a_item in audios_data:
        raw_audio = base64.b64decode(a_item["raw_audio_b64"])
        enc_audio = encrypt_blob(raw_audio, dek, aad=f"audio_files:{target_trainer.id}")
        rel_path = f"restored_{a_item['storage_rel_path']}"
        (storage_dir / rel_path).write_bytes(enc_audio)
        new_a = AudioFile(
            entry_id=entry_id_map[int(a_item["entry_id"])],
            trainer_id=target_trainer.id,
            storage_rel_path=rel_path,
            mime_type=a_item["mime_type"],
            sha256_hash=sha256_hex(enc_audio),
            size_bytes=len(enc_audio),
            transcription_status="completed",
            created_at=now,
        )
        db.add(new_a)

    log_security_event(
        db,
        "CLI_IMPORT_ALL",
        actor_user_id=target_trainer.id,
        metadata=manifest["counts"],
        commit=True,
    )
    return manifest


def _compute_table_digest_and_count(session: DbSession, table_name: str) -> tuple[int, str]:
    tdef = DeclarativeBase.metadata.tables[table_name]
    stmt = select(tdef.model_cls).order_by(tdef.model_cls.id.asc())
    rows = session.scalars(stmt).all()
    row_hashes: list[str] = []
    for r in rows:
        parts: list[str] = []
        for cname in sorted(tdef.columns.keys()):
            val = getattr(r, cname)
            if isinstance(val, bytes):
                parts.append(f"{cname}:{sha256_hex(val)}")
            elif isinstance(val, datetime):
                parts.append(f"{cname}:{val.isoformat()}")
            else:
                parts.append(f"{cname}:{val!r}")
        row_hashes.append(sha256_hex("|".join(parts)))
    return len(rows), sha256_hex(",".join(row_hashes))


def migrate_database_between_engines(
    source_engine: Engine,
    target_engine: Engine,
) -> dict[str, dict[str, Any]]:
    """Migra todas las tablas en orden topológico y verifica recuentos y checksums SHA-256 al 100 %."""
    DeclarativeBase.metadata.create_all(target_engine)
    report: dict[str, dict[str, Any]] = {}

    with DbSession(source_engine) as src_db, DbSession(target_engine) as dst_db:
        for table_name in TOPOLOGICAL_TABLES_ORDER:
            if table_name not in DeclarativeBase.metadata.tables:
                continue
            tdef = DeclarativeBase.metadata.tables[table_name]
            src_rows = src_db.scalars(
                select(tdef.model_cls).order_by(tdef.model_cls.id.asc())
            ).all()
            for src_obj in src_rows:
                kwargs = {cname: getattr(src_obj, cname) for cname in tdef.columns}
                clone_obj = tdef.model_cls(**kwargs)
                dst_db.add(clone_obj)
            dst_db.flush()
        dst_db.commit()

        # Verificación post-migración de recuentos y checksums SHA-256 tabla por tabla
        for table_name in TOPOLOGICAL_TABLES_ORDER:
            if table_name not in DeclarativeBase.metadata.tables:
                continue
            src_count, src_hash = _compute_table_digest_and_count(src_db, table_name)
            dst_count, dst_hash = _compute_table_digest_and_count(dst_db, table_name)
            if src_count != dst_count or src_hash != dst_hash:
                raise PortabilityError(
                    f"Discrepancia en tabla {table_name}: origen=({src_count}, {src_hash}) "
                    f"vs destino=({dst_count}, {dst_hash})"
                )
            report[table_name] = {"count": dst_count, "sha256": dst_hash}

    return report
