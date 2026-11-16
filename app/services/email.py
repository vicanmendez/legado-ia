"""Servicio de envío de correo electrónico en texto plano sustituible por configuración (.env)."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage

from app.config import Settings, get_settings

try:
    import aiosmtplib

    _AIOSMTPLIB_AVAILABLE = True
except ImportError:  # pragma: no cover
    _AIOSMTPLIB_AVAILABLE = False


@dataclass
class SentEmailRecord:
    to_email: str
    subject: str
    body_text: str


# Bandeja en memoria para entornos de desarrollo/pruebas cuando no hay servidor SMTP externo activo
_outbox: list[SentEmailRecord] = []


def get_outbox() -> list[SentEmailRecord]:
    """Devuelve los correos enviados en memoria durante pruebas."""
    return _outbox


def clear_outbox() -> None:
    """Limpia la bandeja de salida en memoria."""
    _outbox.clear()


async def send_plain_email_async(
    to_email: str,
    subject: str,
    body_text: str,
    settings: Settings | None = None,
) -> None:
    """Envía un correo electrónico exclusivamente en texto plano mediante aiosmtplib."""
    cfg = settings or get_settings()
    _outbox.append(SentEmailRecord(to_email=to_email, subject=subject, body_text=body_text))

    if cfg.APP_ENV in ("testing", "development") and cfg.SMTP_HOST in ("localhost", "127.0.0.1", "mock"):
        return

    msg = EmailMessage()
    msg["From"] = cfg.MAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body_text, subtype="plain", charset="utf-8")

    if _AIOSMTPLIB_AVAILABLE:
        await aiosmtplib.send(
            msg,
            hostname=cfg.SMTP_HOST,
            port=cfg.SMTP_PORT,
            username=cfg.SMTP_USER or None,
            password=cfg.SMTP_PASSWORD or None,
            start_tls=cfg.SMTP_STARTTLS,
        )


def send_plain_email_sync(
    to_email: str,
    subject: str,
    body_text: str,
    settings: Settings | None = None,
) -> None:
    """Envía un correo en texto plano usando SMTP real cuando SMTP_HOST está configurado (fuera de testing)."""
    import smtplib

    cfg = settings or get_settings()
    _outbox.append(SentEmailRecord(to_email=to_email, subject=subject, body_text=body_text))

    if cfg.APP_ENV == "testing" or cfg.SMTP_HOST in ("", "localhost", "127.0.0.1", "mock"):
        return

    msg = EmailMessage()
    msg["From"] = cfg.MAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body_text, subtype="plain", charset="utf-8")

    with smtplib.SMTP(cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=15) as server:
        if cfg.SMTP_STARTTLS:
            server.starttls()
        if cfg.SMTP_USER and cfg.SMTP_PASSWORD:
            server.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
        server.send_message(msg)
