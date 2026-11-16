"""Configuración validada por entorno (.env) con arranque fail-fast en producción."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any


class ConfigurationError(ValueError):
    """Error crítico de validación de configuración al arrancar la aplicación."""


def _parse_dotenv(env_file: str | Path | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_file:
        return values
    path = Path(env_file)
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


class Settings:
    """Configuración central de legado-ia validada al inicio (compatible con pydantic-settings)."""

    APP_ENV: str
    APP_BASE_URL: str
    APP_SECRET_KEY: str

    DB_ENGINE: str
    DB_SQLITE_PATH: str
    DB_HOST: str
    DB_PORT: int
    DB_NAME: str
    DB_USER: str
    DB_PASSWORD: str
    DB_SSL_CA: str

    ENCRYPTION_KEK_FILE: str
    ENCRYPTION_KEK: str
    AUDIO_STORAGE_PATH: str

    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USER: str
    SMTP_PASSWORD: str
    SMTP_STARTTLS: bool
    MAIL_FROM: str

    ALTCHA_HMAC_KEY: str
    WEBAUTHN_RP_ID: str
    WEBAUTHN_RP_NAME: str

    LLM_BASE_URL: str
    LLM_MODEL: str
    LLM_API_KEY: str
    WHISPER_MODEL: str

    SESSION_INACTIVITY_MINUTES: int
    PENDING_2FA_TIMEOUT_MINUTES: int
    INVITATION_EXPIRY_HOURS: int
    POSTHUMOUS_COOLDOWN_HOURS: int

    def __init__(self, _env_file: str | Path | None = ".env", **overrides: Any) -> None:
        dotenv_vals = _parse_dotenv(_env_file)

        def get_val(name: str, default: Any = "") -> Any:
            if name in overrides and overrides[name] is not None:
                return overrides[name]
            if name in os.environ:
                return os.environ[name]
            if name in dotenv_vals:
                return dotenv_vals[name]
            return default

        self.APP_ENV = str(get_val("APP_ENV", "development")).strip().lower()
        self.APP_BASE_URL = str(get_val("APP_BASE_URL", "http://localhost:8000")).strip().rstrip("/")
        self.APP_SECRET_KEY = str(
            get_val("APP_SECRET_KEY", "dev-only-secret-key-with-at-least-32-bytes!!")
        ).strip()

        self.DB_ENGINE = str(get_val("DB_ENGINE", "sqlite")).strip().lower()
        self.DB_SQLITE_PATH = str(get_val("DB_SQLITE_PATH", "./legado.db")).strip()
        self.DB_HOST = str(get_val("DB_HOST", "")).strip()
        self.DB_PORT = int(get_val("DB_PORT", 3306) or 3306)
        self.DB_NAME = str(get_val("DB_NAME", "")).strip()
        self.DB_USER = str(get_val("DB_USER", "")).strip()
        self.DB_PASSWORD = str(get_val("DB_PASSWORD", "")).strip()
        self.DB_SSL_CA = str(get_val("DB_SSL_CA", "")).strip()

        self.ENCRYPTION_KEK_FILE = str(get_val("ENCRYPTION_KEK_FILE", "")).strip()
        self.ENCRYPTION_KEK = str(
            get_val(
                "ENCRYPTION_KEK",
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
                if self.APP_ENV != "production"
                else "",
            )
        ).strip()
        self.AUDIO_STORAGE_PATH = str(get_val("AUDIO_STORAGE_PATH", "./data/audio")).strip()

        self.SMTP_HOST = str(get_val("SMTP_HOST", "localhost")).strip()
        self.SMTP_PORT = int(get_val("SMTP_PORT", 587) or 587)
        self.SMTP_USER = str(get_val("SMTP_USER", "")).strip()
        self.SMTP_PASSWORD = str(get_val("SMTP_PASSWORD", "")).strip()
        starttls_raw = str(get_val("SMTP_STARTTLS", "true")).strip().lower()
        self.SMTP_STARTTLS = starttls_raw in ("1", "true", "yes", "on")
        self.MAIL_FROM = str(get_val("MAIL_FROM", "no-reply@legado-ia.local")).strip()

        self.ALTCHA_HMAC_KEY = str(
            get_val(
                "ALTCHA_HMAC_KEY",
                "dev-only-altcha-hmac-key-minimum-32-bytes-long"
                if self.APP_ENV != "production"
                else "",
            )
        ).strip()
        self.WEBAUTHN_RP_ID = str(get_val("WEBAUTHN_RP_ID", "localhost")).strip()
        self.WEBAUTHN_RP_NAME = str(get_val("WEBAUTHN_RP_NAME", "Legado IA")).strip()

        self.LLM_BASE_URL = str(get_val("LLM_BASE_URL", "http://localhost:11434/v1")).strip()
        self.LLM_MODEL = str(get_val("LLM_MODEL", "llama3.1:8b")).strip()
        self.LLM_API_KEY = str(get_val("LLM_API_KEY", "")).strip()
        self.WHISPER_MODEL = str(get_val("WHISPER_MODEL", "base")).strip()

        self.SESSION_INACTIVITY_MINUTES = int(get_val("SESSION_INACTIVITY_MINUTES", 30) or 30)
        self.PENDING_2FA_TIMEOUT_MINUTES = int(get_val("PENDING_2FA_TIMEOUT_MINUTES", 10) or 10)
        self.INVITATION_EXPIRY_HOURS = int(get_val("INVITATION_EXPIRY_HOURS", 72) or 72)
        self.POSTHUMOUS_COOLDOWN_HOURS = int(get_val("POSTHUMOUS_COOLDOWN_HOURS", 72) or 72)

        self._validate()

    def _validate(self) -> None:
        if self.APP_ENV not in ("development", "testing", "production"):
            raise ConfigurationError(f"APP_ENV inválido: {self.APP_ENV}")

        if self.DB_ENGINE not in ("sqlite", "mysql", "mariadb"):
            raise ConfigurationError(f"DB_ENGINE no soportado: {self.DB_ENGINE}")

        if self.DB_ENGINE == "sqlite" and not self.DB_SQLITE_PATH:
            raise ConfigurationError("DB_SQLITE_PATH es obligatorio cuando DB_ENGINE=sqlite")

        if self.DB_ENGINE in ("mysql", "mariadb"):
            missing_db = [
                field
                for field in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
                if not getattr(self, field)
            ]
            if missing_db:
                raise ConfigurationError(
                    f"Faltan campos obligatorios para MySQL/MariaDB: {', '.join(missing_db)}"
                )
            if self.DB_HOST not in ("localhost", "127.0.0.1") and not self.DB_SSL_CA:
                if self.APP_ENV == "production":
                    raise ConfigurationError(
                        "DB_SSL_CA es obligatorio en producción cuando DB_HOST no es local"
                    )

        if self.APP_ENV == "production":
            if not self.APP_BASE_URL.startswith("https://"):
                raise ConfigurationError("En producción APP_BASE_URL debe comenzar con https://")
            if (
                not self.APP_SECRET_KEY
                or len(self.APP_SECRET_KEY.encode("utf-8")) < 32
                or self.APP_SECRET_KEY.startswith("CHANGE_ME")
                or self.APP_SECRET_KEY.startswith("dev-only")
            ):
                raise ConfigurationError(
                    "En producción APP_SECRET_KEY debe tener al menos 32 bytes reales"
                )
            if (
                not self.ALTCHA_HMAC_KEY
                or len(self.ALTCHA_HMAC_KEY.encode("utf-8")) < 32
                or self.ALTCHA_HMAC_KEY.startswith("CHANGE_ME")
                or self.ALTCHA_HMAC_KEY.startswith("dev-only")
            ):
                raise ConfigurationError(
                    "En producción ALTCHA_HMAC_KEY es obligatorio y debe tener >= 32 bytes"
                )
            if not self.ENCRYPTION_KEK_FILE:
                raise ConfigurationError(
                    "En producción ENCRYPTION_KEK_FILE es obligatorio (no se permite KEK en línea)"
                )
            kek_path = Path(self.ENCRYPTION_KEK_FILE)
            if not kek_path.is_file():
                raise ConfigurationError(
                    f"El archivo de clave maestra ENCRYPTION_KEK_FILE no existe: {kek_path}"
                )

        # Validar que la KEK disponible decodifique exactamente a 32 bytes (256 bits)
        kek_bytes = self.get_kek_bytes()
        if len(kek_bytes) != 32:
            raise ConfigurationError(
                f"La clave maestra KEK debe ser exactamente de 32 bytes (256 bits), obtenidos: {len(kek_bytes)}"
            )

    def get_kek_bytes(self) -> bytes:
        """Obtiene los 32 bytes de la KEK desde archivo o variable de desarrollo."""
        raw_b64 = ""
        if self.ENCRYPTION_KEK_FILE:
            kek_path = Path(self.ENCRYPTION_KEK_FILE)
            if not kek_path.is_file():
                raise ConfigurationError(f"No se encontró ENCRYPTION_KEK_FILE: {kek_path}")
            raw_b64 = kek_path.read_text(encoding="utf-8").strip()
        elif self.APP_ENV != "production" and self.ENCRYPTION_KEK:
            raw_b64 = self.ENCRYPTION_KEK.strip()
        else:
            raise ConfigurationError("No se ha configurado ninguna clave maestra KEK válida")

        try:
            decoded = base64.b64decode(raw_b64, validate=True)
        except Exception as exc:
            raise ConfigurationError("La KEK debe estar codificada en base64 válido") from exc
        if len(decoded) != 32:
            raise ConfigurationError("La KEK decodificada debe medir exactamente 32 bytes")
        return decoded


_default_settings: Settings | None = None


def get_settings() -> Settings:
    """Devuelve la instancia singleton de Settings."""
    global _default_settings
    if _default_settings is None:
        _default_settings = Settings()
    return _default_settings


def reset_settings(new_settings: Settings | None = None) -> None:
    """Permite inyectar o reiniciar Settings en pruebas automatizadas."""
    global _default_settings
    _default_settings = new_settings
