"""Entorno de migraciones Alembic con render_as_batch=True para compatibilidad SQLite y MySQL/MariaDB."""

from __future__ import annotations

from app.config import get_settings
from app.db.base import DeclarativeBase
from app.db.session import build_database_url, create_db_engine

target_metadata = DeclarativeBase.metadata
RENDER_AS_BATCH = True


def run_migrations_offline() -> dict[str, object]:
    """Configuración de migración offline con render_as_batch=True."""
    settings = get_settings()
    url = build_database_url(settings)
    return {
        "url": str(url),
        "target_metadata": target_metadata,
        "literal_binds": True,
        "render_as_batch": RENDER_AS_BATCH,
    }


def run_migrations_online() -> None:
    """Ejecución de migraciones online aplicando el esquema registrado con render_as_batch=True."""
    engine = create_db_engine(get_settings())
    target_metadata.create_all(engine)
