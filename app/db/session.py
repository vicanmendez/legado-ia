"""Construcción segura de URL.create, motor SQLAlchemy/SQLite (WAL + FK) y sesiones."""

from __future__ import annotations

from collections.abc import Generator

from app.config import Settings, get_settings
from app.db._compat_sa import URL, Engine, Session, create_engine
from app.db.base import DeclarativeBase


def build_database_url(settings: Settings) -> URL:
    """Construye la URL de base de datos mediante URL.create a partir de campos separados (nunca concatenando strings)."""
    if settings.DB_ENGINE == "sqlite":
        return URL.create(
            drivername="sqlite",
            database=settings.DB_SQLITE_PATH,
        )
    return URL.create(
        drivername="mysql+pymysql",
        username=settings.DB_USER,
        password=settings.DB_PASSWORD,
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        database=settings.DB_NAME,
        query={"charset": "utf8mb4"},
    )


def create_db_engine(settings: Settings | None = None) -> Engine:
    """Crea el Engine configurando PRAGMA foreign_keys=ON y journal_mode=WAL en SQLite o SSL/utf8mb4 en MySQL."""
    cfg = settings or get_settings()
    db_url = build_database_url(cfg)
    connect_args: dict[str, object] = {}
    if cfg.DB_ENGINE in ("mysql", "mariadb"):
        if cfg.DB_HOST not in ("localhost", "127.0.0.1") and cfg.DB_SSL_CA:
            connect_args["ssl"] = {"ca": cfg.DB_SSL_CA}
    return create_engine(db_url, connect_args=connect_args)


_default_engine: Engine | None = None


def get_engine() -> Engine:
    """Devuelve el Engine activo."""
    global _default_engine
    if _default_engine is None:
        _default_engine = create_db_engine(get_settings())
    return _default_engine


def reset_engine(new_engine: Engine | None = None) -> None:
    """Permite sustituir o reiniciar el Engine en pruebas."""
    global _default_engine
    if _default_engine is not None:
        _default_engine.dispose()
    _default_engine = new_engine


def init_db(engine: Engine | None = None) -> None:
    """Inicializa todas las tablas registradas en DeclarativeBase.metadata."""
    target = engine or get_engine()
    DeclarativeBase.metadata.create_all(target)


def get_db() -> Generator[Session, None, None]:
    """Dependencia generadora de sesión de base de datos."""
    session = Session(get_engine())
    try:
        yield session
    finally:
        session.close()
