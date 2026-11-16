"""Definición de DeclarativeBase y tipos personalizados portables (SQLite y MySQL/MariaDB)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TypeAlias, TypeVar

from app.db._compat_sa import (
    LONGBLOB,
    Boolean,
    ColumnDescriptor,
    Condition,
    DateTime,
    DeclarativeBase,
    ForeignKey,
    Integer,
    LargeBinary,
    SelectStmt,
    String,
    Text,
    UTCDateTime,
    mapped_column,
    select,
)

T = TypeVar("T")
Mapped: TypeAlias = T

# Tipo binario cifrado portable: LargeBinary en SQLite y LONGBLOB en MySQL/MariaDB
EncryptedBlob = LargeBinary().with_variant(LONGBLOB(), "mysql", "mariadb")
EncryptedBytes = EncryptedBlob


def utc_now() -> datetime:
    """Devuelve la fecha y hora actual en UTC con timezone explícito."""
    return datetime.now(timezone.utc)


__all__ = [
    "Boolean",
    "ColumnDescriptor",
    "Condition",
    "DateTime",
    "DeclarativeBase",
    "EncryptedBlob",
    "EncryptedBytes",
    "ForeignKey",
    "Integer",
    "LONGBLOB",
    "LargeBinary",
    "Mapped",
    "SelectStmt",
    "String",
    "Text",
    "UTCDateTime",
    "mapped_column",
    "select",
    "utc_now",
]
