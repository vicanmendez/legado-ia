"""Capa de compatibilidad SQLAlchemy 2.x sobre sqlite3 para ejecución en entornos sin rueda C compilada."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Generic, Iterable, TypeVar

T = TypeVar("T")


class ColumnType:
    sql_type: str = "TEXT"

    def with_variant(self, other: Any, *dialects: str) -> ColumnType:
        return self


class Integer(ColumnType):
    sql_type = "INTEGER"


class String(ColumnType):
    sql_type = "TEXT"

    def __init__(self, length: int = 255) -> None:
        self.length = length


class Text(ColumnType):
    sql_type = "TEXT"


class Boolean(ColumnType):
    sql_type = "INTEGER"


class LargeBinary(ColumnType):
    sql_type = "BLOB"

    def __init__(self, length: int | None = None) -> None:
        self.length = length


class LONGBLOB(LargeBinary):
    sql_type = "BLOB"


class DateTime(ColumnType):
    sql_type = "TEXT"

    def __init__(self, timezone: bool = True) -> None:
        self.timezone = timezone


class UTCDateTime(ColumnType):
    sql_type = "TEXT"


class ForeignKey:
    def __init__(self, target: str, ondelete: str = "NO ACTION") -> None:
        self.target = target
        self.ondelete = ondelete


class ColumnDescriptor:
    def __init__(
        self,
        col_type: ColumnType | type[ColumnType],
        *args: Any,
        primary_key: bool = False,
        autoincrement: bool = False,
        unique: bool = False,
        nullable: bool = True,
        index: bool = False,
        default: Any = None,
    ) -> None:
        self.col_type = col_type() if isinstance(col_type, type) else col_type
        self.foreign_key: ForeignKey | None = None
        for a in args:
            if isinstance(a, ForeignKey):
                self.foreign_key = a
            elif isinstance(a, ColumnType):
                self.col_type = a
            elif isinstance(a, type) and issubclass(a, ColumnType):
                self.col_type = a()
        self.primary_key = primary_key
        self.autoincrement = autoincrement
        self.unique = unique
        self.nullable = False if primary_key else nullable
        self.index = index
        self.default = default
        self.name: str = ""
        self.model_cls: type[Any] | None = None

    def __set_name__(self, owner: type[Any], name: str) -> None:
        self.name = name
        self.model_cls = owner

    def __get__(self, instance: Any, owner: type[Any] | None = None) -> Any:
        if instance is None:
            return ColumnExpr(self.model_cls, self.name)
        return instance.__dict__.get(self.name)

    def __set__(self, instance: Any, value: Any) -> None:
        if isinstance(self.col_type, UTCDateTime) and isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)
        instance.__dict__[self.name] = value


def mapped_column(*args: Any, **kwargs: Any) -> Any:
    col_type: Any = String(255)
    rest: list[Any] = []
    for a in args:
        if isinstance(a, ColumnType) or (isinstance(a, type) and issubclass(a, ColumnType)):
            col_type = a
        else:
            rest.append(a)
    return ColumnDescriptor(col_type, *rest, **kwargs)


class ColumnExpr:
    def __init__(self, model_cls: type[Any] | None, name: str) -> None:
        self.model_cls = model_cls
        self.name = name

    def __eq__(self, other: Any) -> Condition:  # type: ignore[override]
        return Condition(self.name, "=", other)

    def __ne__(self, other: Any) -> Condition:  # type: ignore[override]
        return Condition(self.name, "!=", other)

    def __lt__(self, other: Any) -> Condition:
        return Condition(self.name, "<", other)

    def __le__(self, other: Any) -> Condition:
        return Condition(self.name, "<=", other)

    def __gt__(self, other: Any) -> Condition:
        return Condition(self.name, ">", other)

    def __ge__(self, other: Any) -> Condition:
        return Condition(self.name, ">=", other)

    def is_(self, other: Any) -> Condition:
        return Condition(self.name, "IS", other)

    def is_not(self, other: Any) -> Condition:
        return Condition(self.name, "IS NOT", other)

    def desc(self) -> tuple[str, str]:
        return (self.name, "DESC")

    def asc(self) -> tuple[str, str]:
        return (self.name, "ASC")


@dataclass
class Condition:
    field: str
    op: str
    value: Any


class SelectStmt(Generic[T]):
    def __init__(self, model_cls: type[T]) -> None:
        self.model_cls = model_cls
        self.conditions: list[Condition] = []
        self.orders: list[tuple[str, str]] = []
        self.limit_val: int | None = None

    def where(self, *conds: Condition) -> SelectStmt[T]:
        self.conditions.extend(conds)
        return self

    def filter_by(self, **kwargs: Any) -> SelectStmt[T]:
        for k, v in kwargs.items():
            self.conditions.append(Condition(k, "=", v))
        return self

    def order_by(self, *orders: Any) -> SelectStmt[T]:
        for o in orders:
            if isinstance(o, tuple):
                self.orders.append(o)
            elif isinstance(o, ColumnExpr):
                self.orders.append((o.name, "ASC"))
        return self

    def limit(self, n: int) -> SelectStmt[T]:
        self.limit_val = n
        return self


def select(model_cls: type[T]) -> SelectStmt[T]:
    return SelectStmt(model_cls)


@dataclass
class TableDef:
    name: str
    model_cls: type[Any]
    columns: dict[str, ColumnDescriptor]


class MetaDataRegistry:
    def __init__(self) -> None:
        self.tables: dict[str, TableDef] = {}

    def create_all(self, bind: Engine) -> None:
        conn = bind.connect()
        try:
            for tname, tdef in self.tables.items():
                col_defs: list[str] = []
                fk_defs: list[str] = []
                for cname, col in tdef.columns.items():
                    parts = [f'"{cname}"', col.col_type.sql_type]
                    if col.primary_key:
                        parts.append("PRIMARY KEY")
                        if col.autoincrement and col.col_type.sql_type == "INTEGER":
                            parts.append("AUTOINCREMENT")
                    else:
                        if not col.nullable:
                            parts.append("NOT NULL")
                        if col.unique:
                            parts.append("UNIQUE")
                    col_defs.append(" ".join(parts))
                    if col.foreign_key is not None:
                        ref_table, ref_col = col.foreign_key.target.split(".")
                        fk_defs.append(
                            f'FOREIGN KEY ("{cname}") REFERENCES "{ref_table}"("{ref_col}") ON DELETE {col.foreign_key.ondelete}'
                        )
                all_defs = ", ".join(col_defs + fk_defs)
                conn.execute(f'CREATE TABLE IF NOT EXISTS "{tname}" ({all_defs})')
                # Si la tabla ya existía en una versión previa, añadir columnas nuevas automáticamente
                existing_cols = {
                    row[1]
                    for row in conn.execute(f'PRAGMA table_info("{tname}")').fetchall()
                }
                for cname, col in tdef.columns.items():
                    if cname not in existing_cols:
                        conn.execute(
                            f'ALTER TABLE "{tname}" ADD COLUMN "{cname}" {col.col_type.sql_type}'
                        )
            conn.commit()
        finally:
            conn.close()

    def drop_all(self, bind: Engine) -> None:
        conn = bind.connect()
        try:
            conn.execute("PRAGMA foreign_keys=OFF")
            for tname in reversed(list(self.tables.keys())):
                conn.execute(f'DROP TABLE IF EXISTS "{tname}"')
            conn.commit()
            conn.execute("PRAGMA foreign_keys=ON")
        finally:
            conn.close()


class DeclarativeMeta(type):
    def __new__(mcls, name: str, bases: tuple[type, ...], namespace: dict[str, Any]) -> Any:
        cls = super().__new__(mcls, name, bases, namespace)
        tablename = namespace.get("__tablename__")
        if tablename:
            cols: dict[str, ColumnDescriptor] = {}
            for k, v in namespace.items():
                if isinstance(v, ColumnDescriptor):
                    v.name = k
                    v.model_cls = cls
                    cols[k] = v
            cls.__columns__ = cols  # type: ignore[attr-defined]
            DeclarativeBase.metadata.tables[tablename] = TableDef(tablename, cls, cols)
        return cls


class DeclarativeBase(metaclass=DeclarativeMeta):
    metadata = MetaDataRegistry()

    def __init__(self, **kwargs: Any) -> None:
        cols: dict[str, ColumnDescriptor] = getattr(self.__class__, "__columns__", {})
        for cname, col in cols.items():
            if cname in kwargs:
                setattr(self, cname, kwargs[cname])
            elif col.default is not None:
                val = col.default() if callable(col.default) else col.default
                setattr(self, cname, val)
            else:
                setattr(self, cname, None)


@dataclass
class URL:
    drivername: str
    username: str | None = None
    password: str | None = None
    host: str | None = None
    port: int | None = None
    database: str | None = None
    query: dict[str, Any] | None = None

    @classmethod
    def create(
        cls,
        drivername: str,
        username: str | None = None,
        password: str | None = None,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
        query: dict[str, Any] | None = None,
    ) -> URL:
        return cls(
            drivername=drivername,
            username=username,
            password=password,
            host=host,
            port=port,
            database=database,
            query=query or {},
        )

    def render_as_string(self, hide_password: bool = True) -> str:
        if self.drivername.startswith("sqlite"):
            return f"{self.drivername}:///{self.database or ':memory:'}"
        pwd = "***" if hide_password and self.password else (self.password or "")
        auth = f"{self.username}:{pwd}@" if self.username else ""
        host_part = f"{self.host or 'localhost'}:{self.port or 3306}"
        return f"{self.drivername}://{auth}{host_part}/{self.database or ''}"

    def __str__(self) -> str:
        return self.render_as_string(hide_password=True)


class Engine:
    def __init__(self, url: URL | str, connect_args: dict[str, Any] | None = None) -> None:
        self.url = url if isinstance(url, URL) else URL(drivername="sqlite", database=str(url))
        self.connect_args = connect_args or {}
        self.dialect_name = "sqlite" if self.url.drivername.startswith("sqlite") else "mysql"
        self._listeners: list[Callable[[Any, Any], None]] = []

    def connect(self) -> sqlite3.Connection:
        db_path = self.url.database or ":memory:"
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        if db_path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
        for fn in self._listeners:
            fn(conn, None)
        return conn

    def dispose(self) -> None:
        return None


def create_engine(url: URL | str, connect_args: dict[str, Any] | None = None, **kwargs: Any) -> Engine:
    return Engine(url, connect_args=connect_args)


def _encode_val(col: ColumnDescriptor, val: Any) -> Any:
    if val is None:
        return None
    if isinstance(col.col_type, Boolean):
        return 1 if val else 0
    if isinstance(col.col_type, UTCDateTime) and isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        else:
            val = val.astimezone(timezone.utc)
        return val.isoformat()
    return val


def _decode_val(col: ColumnDescriptor, val: Any) -> Any:
    if val is None:
        return None
    if isinstance(col.col_type, Boolean):
        return bool(val)
    if isinstance(col.col_type, UTCDateTime) and isinstance(val, str):
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(col.col_type, LargeBinary) and isinstance(val, memoryview):
        return bytes(val)
    return val


class ScalarResult(Generic[T]):
    def __init__(self, items: list[T]) -> None:
        self._items = items

    def all(self) -> list[T]:
        return list(self._items)

    def first(self) -> T | None:
        return self._items[0] if self._items else None

    def one_or_none(self) -> T | None:
        if len(self._items) > 1:
            raise ValueError("Multiple rows returned")
        return self.first()


class Session:
    """Sesión ORM compatible con SQLAlchemy 2.x sobre sqlite3."""

    def __init__(self, bind: Engine) -> None:
        self.bind = bind
        self._conn = bind.connect()
        self._new: list[Any] = []
        self._tracked: list[Any] = []
        self._deleted: list[Any] = []

    def __enter__(self) -> Session:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc_type is not None:
            self.rollback()
        self.close()

    def add(self, obj: Any) -> None:
        if obj not in self._new and obj not in self._tracked:
            self._new.append(obj)

    def add_all(self, objs: Iterable[Any]) -> None:
        for o in objs:
            self.add(o)

    def delete(self, obj: Any) -> None:
        if obj in self._new:
            self._new.remove(obj)
        elif obj not in self._deleted:
            self._deleted.append(obj)

    def flush(self) -> None:
        cur = self._conn.cursor()
        # Procesar borrados
        for obj in list(self._deleted):
            tname = obj.__class__.__tablename__
            pk_val = getattr(obj, "id", None)
            if pk_val is not None:
                cur.execute(f'DELETE FROM "{tname}" WHERE "id" = ?', (pk_val,))
            if obj in self._tracked:
                self._tracked.remove(obj)
            self._deleted.remove(obj)

        # Procesar inserciones
        for obj in list(self._new):
            tname = obj.__class__.__tablename__
            cols: dict[str, ColumnDescriptor] = obj.__class__.__columns__
            insert_cols: list[str] = []
            insert_vals: list[Any] = []
            for cname, col in cols.items():
                val = getattr(obj, cname)
                if cname == "id" and val is None and col.autoincrement:
                    continue
                if val is None and col.default is not None:
                    val = col.default() if callable(col.default) else col.default
                    setattr(obj, cname, val)
                insert_cols.append(cname)
                insert_vals.append(_encode_val(col, val))
            col_names_sql = ", ".join(f'"{c}"' for c in insert_cols)
            placeholders = ", ".join("?" for _ in insert_cols)
            cur.execute(
                f'INSERT INTO "{tname}" ({col_names_sql}) VALUES ({placeholders})',
                tuple(insert_vals),
            )
            if getattr(obj, "id", None) is None:
                setattr(obj, "id", cur.lastrowid)
            self._new.remove(obj)
            if obj not in self._tracked:
                self._tracked.append(obj)

        # Procesar actualizaciones de objetos rastreados
        for obj in list(self._tracked):
            tname = obj.__class__.__tablename__
            cols = obj.__class__.__columns__
            pk_val = getattr(obj, "id", None)
            if pk_val is None:
                continue
            set_parts: list[str] = []
            set_vals: list[Any] = []
            for cname, col in cols.items():
                if cname == "id":
                    continue
                set_parts.append(f'"{cname}" = ?')
                set_vals.append(_encode_val(col, getattr(obj, cname)))
            set_vals.append(pk_val)
            cur.execute(
                f'UPDATE "{tname}" SET {", ".join(set_parts)} WHERE "id" = ?',
                tuple(set_vals),
            )

    def commit(self) -> None:
        self.flush()
        self._conn.commit()

    def rollback(self) -> None:
        self._new.clear()
        self._deleted.clear()
        self._conn.rollback()

    def refresh(self, obj: Any) -> None:
        fresh = self.get(obj.__class__, getattr(obj, "id"))
        if fresh is not None:
            for cname in obj.__class__.__columns__:
                setattr(obj, cname, getattr(fresh, cname))

    def get(self, model_cls: type[T], pk: Any) -> T | None:
        self.flush()
        stmt = select(model_cls).where(Condition("id", "=", pk))
        return self.scalar(stmt)

    def _hydrate(self, model_cls: type[T], row: sqlite3.Row) -> T:
        pk_val = row["id"] if "id" in row.keys() else None
        for tracked in self._tracked:
            if isinstance(tracked, model_cls) and getattr(tracked, "id", None) == pk_val:
                for cname, col in model_cls.__columns__.items():  # type: ignore[attr-defined]
                    setattr(tracked, cname, _decode_val(col, row[cname]))
                return tracked
        obj = model_cls()
        for cname, col in model_cls.__columns__.items():  # type: ignore[attr-defined]
            setattr(obj, cname, _decode_val(col, row[cname]))
        self._tracked.append(obj)
        return obj

    def scalars(self, stmt: SelectStmt[T]) -> ScalarResult[T]:
        self.flush()
        tname = stmt.model_cls.__tablename__  # type: ignore[attr-defined]
        cols: dict[str, ColumnDescriptor] = stmt.model_cls.__columns__  # type: ignore[attr-defined]
        sql = f'SELECT * FROM "{tname}"'
        params: list[Any] = []
        if stmt.conditions:
            where_clauses: list[str] = []
            for cond in stmt.conditions:
                col = cols[cond.field]
                if cond.value is None and cond.op in ("=", "IS"):
                    where_clauses.append(f'"{cond.field}" IS NULL')
                elif cond.value is None and cond.op in ("!=", "IS NOT"):
                    where_clauses.append(f'"{cond.field}" IS NOT NULL')
                else:
                    where_clauses.append(f'"{cond.field}" {cond.op} ?')
                    params.append(_encode_val(col, cond.value))
            sql += " WHERE " + " AND ".join(where_clauses)
        if stmt.orders:
            order_sql = ", ".join(f'"{f}" {d}' for f, d in stmt.orders)
            sql += f" ORDER BY {order_sql}"
        if stmt.limit_val is not None:
            sql += f" LIMIT {int(stmt.limit_val)}"
        cur = self._conn.execute(sql, tuple(params))
        rows = cur.fetchall()
        items = [self._hydrate(stmt.model_cls, r) for r in rows]
        return ScalarResult(items)

    def scalar(self, stmt: SelectStmt[T]) -> T | None:
        return self.scalars(stmt).first()

    def execute_raw(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        self.flush()
        return self._conn.execute(sql, params)

    def close(self) -> None:
        self._conn.close()
