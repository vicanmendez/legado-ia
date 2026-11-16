"""Estrategia intercambiable de recuperación de entradas para construcción del prompt (Parte 5)."""

from __future__ import annotations

from typing import Protocol

from app.config import Settings, get_settings
from app.db._compat_sa import Session as DbSession
from app.db.base import select
from app.models.knowledge import Entry
from app.services.auth import get_user_dek
from app.services.crypto import decrypt_str
from app.services.knowledge import DecryptedEntryView


class RetrievalStrategy(Protocol):
    """Interfaz para sustituir en el futuro por embeddings locales sin tocar el servicio LLM."""

    def retrieve(
        self,
        db: DbSession,
        trainer_id: int,
        query: str,
        limit: int = 10,
        settings: Settings | None = None,
    ) -> list[DecryptedEntryView]: ...


class RecentEntriesStrategy:
    """Recupera las últimas N entradas confirmadas del entrenador priorizando coincidencias léxicas."""

    def retrieve(
        self,
        db: DbSession,
        trainer_id: int,
        query: str,
        limit: int = 10,
        settings: Settings | None = None,
    ) -> list[DecryptedEntryView]:
        cfg = settings or get_settings()
        dek = get_user_dek(db, trainer_id, settings=cfg)
        rows = db.scalars(
            select(Entry)
            .where(Entry.trainer_id == trainer_id, Entry.status == "confirmed")
            .order_by(Entry.entry_date.desc(), Entry.id.desc())
        ).all()

        decrypted_all: list[DecryptedEntryView] = []
        for r in rows:
            text = decrypt_str(r.encrypted_content, dek, aad=f"entries:{trainer_id}")
            decrypted_all.append(
                DecryptedEntryView(
                    id=r.id,
                    trainer_id=r.trainer_id,
                    topic=r.topic,
                    entry_date=r.entry_date,
                    content=text,
                    status=r.status,
                    interview_topic_id=r.interview_topic_id,
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                )
            )

        words = [w.lower() for w in query.split() if len(w) >= 3]
        if not words:
            return decrypted_all[:limit]

        def _score(item: DecryptedEntryView) -> int:
            haystack = f"{item.topic} {item.content}".lower()
            return sum(1 for w in words if w in haystack)

        ranked = sorted(decrypted_all, key=_score, reverse=True)
        return ranked[:limit]
