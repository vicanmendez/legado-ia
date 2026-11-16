"""CLI de administración y continuidad de legado-ia (init-trainer, export-all, import-all, migrate-db)."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

import app.models  # noqa: F401
from app.config import Settings, get_settings
from app.db._compat_sa import Engine, Session as DbSession, URL, create_engine
from app.db.base import select
from app.db.session import create_db_engine, init_db
from app.models.user import User
from app.services.audit import log_security_event
from app.services.auth import create_user_with_dek
from app.services.knowledge import seed_default_interview_topics
from app.services.portability import (
    export_all_encrypted_package,
    import_all_encrypted_package,
    migrate_database_between_engines,
)
from app.services.succession import get_or_create_system_state


def cmd_init_trainer(
    username: str,
    email: str,
    password: str,
    engine: Engine | None = None,
    settings: Settings | None = None,
) -> tuple[User, list[str]]:
    """Crea la cuenta inicial del ENTRENADOR, inicializa system_state y entrevista, y devuelve sus códigos de recuperación."""
    cfg = settings or get_settings()
    eng = engine or create_db_engine(cfg)
    init_db(eng)

    with DbSession(eng) as db:
        existing_same = db.scalar(
            select(User).where(User.username == username.strip())
        )
        if existing_same is not None:
            raise RuntimeError(f"Ya existe un usuario con el nombre '{username}'")

        trainer, recovery_codes = create_user_with_dek(
            db,
            username=username,
            email=email,
            password=password,
            role="entrenador",
            settings=cfg,
        )
        get_or_create_system_state(db, settings=cfg)
        seed_default_interview_topics(db, trainer)
        log_security_event(
            db,
            "CLI_INIT_TRAINER",
            actor_user_id=trainer.id,
            metadata={"username": trainer.username},
            commit=True,
        )
        return trainer, recovery_codes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli", description="CLI de administración legado-ia")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-trainer", help="Aprovisiona el ENTRENADOR inicial")
    p_init.add_argument("--username", required=True)
    p_init.add_argument("--email", required=True)
    p_init.add_argument("--password", default="")

    p_email = sub.add_parser("set-email", help="Actualiza el correo electrónico de un usuario")
    p_email.add_argument("--username", required=True)
    p_email.add_argument("--email", required=True)

    p_rec = sub.add_parser(
        "reset-recovery-codes", help="Regenera los 8 códigos de recuperación de un usuario"
    )
    p_rec.add_argument("--username", required=True)

    p_mail = sub.add_parser("test-email", help="Envía un correo de prueba mediante el servidor SMTP configurado")
    p_mail.add_argument("--to", required=True, help="Dirección de correo destino")

    p_exp = sub.add_parser("export-all", help="Exporta todo el legado en un paquete cifrado")
    p_exp.add_argument("--output", required=True)
    p_exp.add_argument("--passphrase", default="")

    p_imp = sub.add_parser("import-all", help="Restaura un paquete cifrado verificando SHA-256")
    p_imp.add_argument("--input", required=True)
    p_imp.add_argument("--passphrase", default="")

    p_mig = sub.add_parser("migrate-db", help="Migra de SQLite a motor destino verificando SHA-256")
    p_mig.add_argument("--source-sqlite", required=True)
    p_mig.add_argument("--target-from-env", action="store_true")

    args = parser.parse_args(argv)
    settings = get_settings()

    if args.command == "init-trainer":
        pwd = args.password or getpass.getpass("Contraseña del entrenador: ")
        trainer, codes = cmd_init_trainer(args.username, args.email, pwd, settings=settings)
        print(f"Entrenador '{trainer.username}' creado con éxito.")
        print("Guarda estos códigos de recuperación de un solo uso en un lugar seguro:")
        for c in codes:
            print(f"  - {c}")
        return 0

    if args.command == "set-email":
        eng = create_db_engine(settings)
        init_db(eng)
        with DbSession(eng) as db:
            user = db.scalar(select(User).where(User.username == args.username.strip()))
            if user is None:
                raise RuntimeError(f"Usuario '{args.username}' no encontrado")
            user.email = args.email.strip().lower()
            user.failed_attempts = 0
            user.locked_until = None
            db.commit()
            print(f"Correo del usuario '{user.username}' actualizado a: {user.email}")
        return 0

    if args.command == "reset-recovery-codes":
        from app.db.base import utc_now
        from app.models.user import RecoveryCode
        from app.services.crypto import generate_recovery_codes, hash_one_time_code

        eng = create_db_engine(settings)
        init_db(eng)
        with DbSession(eng) as db:
            user = db.scalar(select(User).where(User.username == args.username.strip()))
            if user is None:
                raise RuntimeError(f"Usuario '{args.username}' no encontrado")
            old_codes = db.scalars(
                select(RecoveryCode).where(RecoveryCode.user_id == user.id)
            ).all()
            for oc in old_codes:
                db.delete(oc)
            db.flush()
            new_codes = generate_recovery_codes(count=8)
            now = utc_now()
            for code in new_codes:
                db.add(
                    RecoveryCode(
                        user_id=user.id,
                        code_hash=hash_one_time_code(code, settings.APP_SECRET_KEY),
                        used_at=None,
                        created_at=now,
                    )
                )
            user.failed_attempts = 0
            user.locked_until = None
            db.commit()
            print(f"Nuevos códigos de recuperación para '{user.username}':")
            for c in new_codes:
                print(f"  - {c}")
        return 0

    if args.command == "test-email":
        from app.services.email import send_plain_email_sync

        print(
            f"Enviando correo de prueba via {settings.SMTP_HOST}:{settings.SMTP_PORT} "
            f"(From: {settings.MAIL_FROM} -> To: {args.to})..."
        )
        send_plain_email_sync(
            to_email=args.to.strip(),
            subject="Prueba de conexión SMTP - legado-ia",
            body_text="Este es un correo de prueba enviado desde legado-ia para verificar el canal SMTP.",
            settings=settings,
        )
        print("¡Correo aceptado por el servidor SMTP correctamente!")
        return 0

    if args.command == "export-all":
        passphrase = args.passphrase or getpass.getpass("Frase de paso del paquete: ")
        eng = create_db_engine(settings)
        init_db(eng)
        with DbSession(eng) as db:
            manifest = export_all_encrypted_package(
                db, passphrase=passphrase, output_path=Path(args.output), settings=settings
            )
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
        return 0

    if args.command == "import-all":
        passphrase = args.passphrase or getpass.getpass("Frase de paso del paquete: ")
        eng = create_db_engine(settings)
        init_db(eng)
        with DbSession(eng) as db:
            trainer = db.scalar(select(User).where(User.role == "entrenador"))
            if trainer is None:
                raise RuntimeError("Debe inicializar un entrenador antes de importar un paquete")
            manifest = import_all_encrypted_package(
                db,
                passphrase=passphrase,
                input_path=Path(args.input),
                target_trainer=trainer,
                settings=settings,
            )
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
        return 0

    if args.command == "migrate-db":
        src_engine = create_engine(URL.create(drivername="sqlite", database=args.source_sqlite))
        dst_engine = create_db_engine(settings)
        report = migrate_database_between_engines(src_engine, dst_engine)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
