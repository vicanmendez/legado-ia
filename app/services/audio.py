"""Servicio de validación de audio por magic bytes, cifrado en disco y transcripción faster-whisper (Parte 4)."""

from __future__ import annotations

import io
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from app.config import Settings, get_settings
from app.db._compat_sa import Session as DbSession
from app.db.base import utc_now
from app.models.knowledge import AudioFile, Entry
from app.models.user import User
from app.services.auth import get_user_dek
from app.services.crypto import decrypt_blob, encrypt_blob, sha256_hex
from app.services.knowledge import _ensure_trainer_and_writable

MAX_AUDIO_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB máximo por grabación

# Firmas binarias (magic bytes) permitidas: validamos por contenido real, jamás por extensión
MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x1a\x45\xdf\xa3", "audio/webm"),  # WebM / Matroska (MediaRecorder por defecto)
    (b"OggS", "audio/ogg"),  # Ogg Opus / Vorbis
    (b"RIFF", "audio/wav"),  # WAV PCM (con cabecera WAVE en bytes 8..12)
]


class AudioValidationError(ValueError):
    """Error de validación de tamaño o tipo MIME real del archivo de audio."""


@dataclass
class UploadedAudioResult:
    entry: Entry
    audio_file: AudioFile
    draft_transcription: str


# Transcriptor inyectable para pruebas o faster-whisper local
_custom_transcriber: Callable[[bytes, str], str] | None = None


def set_custom_transcriber(fn: Callable[[bytes, str], str] | None) -> None:
    """Permite configurar un motor de transcripción específico o determinista en tests."""
    global _custom_transcriber
    _custom_transcriber = fn


def detect_audio_mime_by_magic_bytes(raw_bytes: bytes) -> str:
    """Valida el tipo MIME inspeccionando los magic bytes del contenido (nunca por nombre de archivo)."""
    if not raw_bytes or len(raw_bytes) < 12:
        raise AudioValidationError("Archivo de audio vacío o demasiado corto")
    if len(raw_bytes) > MAX_AUDIO_UPLOAD_BYTES:
        raise AudioValidationError(
            f"El archivo de audio supera el tamaño máximo permitido ({MAX_AUDIO_UPLOAD_BYTES} bytes)"
        )
    for magic, mime in MAGIC_SIGNATURES:
        if raw_bytes.startswith(magic):
            if mime == "audio/wav" and raw_bytes[8:12] != b"WAVE":
                continue
            return mime
    raise AudioValidationError(
        "Formato de audio no permitido (solo se admiten contenedores reales WebM, Ogg o WAV)"
    )


def _transcribe_audio_bytes_in_memory(raw_audio: bytes, mime_type: str, model_name: str) -> str:
    """Transcribe los bytes de audio en memoria (BytesIO) sin escribir archivos temporales en claro."""
    if _custom_transcriber is not None:
        return _custom_transcriber(raw_audio, mime_type)

    try:
        from faster_whisper import WhisperModel  # type: ignore[import-not-found]

        model = WhisperModel(model_name, device="cpu", compute_type="int8")
        segments, _ = model.transcribe(io.BytesIO(raw_audio), language="es")
        text = " ".join(seg.text.strip() for seg in segments).strip()
        return text or "[Transcripción sin voz detectable]"
    except Exception:
        # Si faster-whisper no tiene el modelo descargado en un entorno sin red, devuelve borrador editable
        return "[Borrador de transcripción pendiente de edición por el entrenador]"


def upload_and_transcribe_audio(
    db: DbSession,
    trainer: User,
    raw_audio_bytes: bytes,
    topic: str = "nota_de_voz",
    interview_topic_id: int | None = None,
    settings: Settings | None = None,
) -> UploadedAudioResult:
    """Valida magic bytes y tamaño, cifra el audio en disco con la DEK del entrenador y transcribe en memoria."""
    _ensure_trainer_and_writable(db, trainer, write_operation=True)
    cfg = settings or get_settings()

    detected_mime = detect_audio_mime_by_magic_bytes(raw_audio_bytes)
    dek = get_user_dek(db, trainer.id, settings=cfg)
    now = utc_now()

    # 1. Cifrar el audio con la DEK del entrenador antes de tocar el disco
    audio_aad = f"audio_files:{trainer.id}"
    encrypted_audio = encrypt_blob(raw_audio_bytes, dek, aad=audio_aad)
    encrypted_hash = sha256_hex(encrypted_audio)

    storage_dir = Path(cfg.AUDIO_STORAGE_PATH)
    storage_dir.mkdir(parents=True, exist_ok=True)
    rel_filename = f"{uuid.uuid4().hex}.enc"
    full_path = storage_dir / rel_filename
    full_path.write_bytes(encrypted_audio)

    # 2. Transcribir en segundo plano desde memoria (descifrando en un BytesIO en RAM)
    decrypted_in_ram = decrypt_blob(full_path.read_bytes(), dek, aad=audio_aad)
    draft_text = _transcribe_audio_bytes_in_memory(
        decrypted_in_ram, detected_mime, cfg.WHISPER_MODEL
    )

    # 3. Guardar la entrada en estado "draft_transcription" editable antes de confirmar
    encrypted_draft = encrypt_blob(draft_text, dek, aad=f"entries:{trainer.id}")
    entry = Entry(
        trainer_id=trainer.id,
        topic=topic.strip()[:120] or "nota_de_voz",
        entry_date=now,
        encrypted_content=encrypted_draft,
        status="draft_transcription",
        interview_topic_id=interview_topic_id,
        created_at=now,
        updated_at=now,
    )
    db.add(entry)
    db.flush()

    audio_record = AudioFile(
        entry_id=entry.id,
        trainer_id=trainer.id,
        storage_rel_path=rel_filename,
        mime_type=detected_mime,
        sha256_hash=encrypted_hash,
        size_bytes=len(encrypted_audio),
        transcription_status="completed",
        created_at=now,
    )
    db.add(audio_record)
    db.commit()

    return UploadedAudioResult(
        entry=entry,
        audio_file=audio_record,
        draft_transcription=draft_text,
    )


def read_decrypted_audio_for_trainer(
    db: DbSession,
    trainer: User,
    audio_id: int,
    settings: Settings | None = None,
) -> tuple[bytes, str]:
    """Descifra en memoria un archivo de audio verificando su hash SHA-256 en disco."""
    _ensure_trainer_and_writable(db, trainer, write_operation=False)
    cfg = settings or get_settings()
    audio = db.get(AudioFile, audio_id)
    if audio is None or audio.trainer_id != trainer.id:
        raise ValueError("Archivo de audio no encontrado")

    full_path = Path(cfg.AUDIO_STORAGE_PATH) / audio.storage_rel_path
    encrypted_bytes = full_path.read_bytes()
    if sha256_hex(encrypted_bytes) != audio.sha256_hash:
        raise ValueError("Fallo de integridad SHA-256 en el archivo de audio cifrado")

    dek = get_user_dek(db, trainer.id, settings=cfg)
    plain_bytes = decrypt_blob(encrypted_bytes, dek, aad=f"audio_files:{trainer.id}")
    return plain_bytes, audio.mime_type
