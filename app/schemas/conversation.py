"""Esquemas de validación para conversaciones, mensajes y ajustes LLM (sin exponer api_key)."""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.auth import ValidationError


@dataclass
class ConversationCreateSchema:
    title: str

    def __post_init__(self) -> None:
        self.title = self.title.strip()[:200]
        if not self.title:
            raise ValidationError("El título de la conversación es obligatorio")


@dataclass
class MessageCreateSchema:
    content: str

    def __post_init__(self) -> None:
        self.content = self.content.strip()
        if not self.content:
            raise ValidationError("El mensaje no puede estar vacío")
        if len(self.content) > 8_000:
            raise ValidationError("El mensaje supera el límite de 8000 caracteres")


@dataclass
class LLMSettingsUpdateSchema:
    provider_name: str
    base_url: str
    model_name: str
    api_key: str | None = None
    context_entries_limit: int = 10
    daily_token_limit_per_user: int = 25000
    web_search_enabled: bool = False
    web_search_url: str | None = None

    def __post_init__(self) -> None:
        self.provider_name = self.provider_name.strip().lower()[:32]
        raw_url = self.base_url.strip().rstrip("/")
        if raw_url.endswith("/chat/completions"):
            raw_url = raw_url[: -len("/chat/completions")].rstrip("/")
        self.base_url = raw_url[:255]
        self.model_name = self.model_name.strip()[:120]
        if self.provider_name not in ("ollama", "openrouter", "openai_compatible"):
            raise ValidationError("Proveedor LLM inválido")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValidationError("base_url del LLM debe ser una URL http/https válida")
        if not self.model_name:
            raise ValidationError("El nombre del modelo LLM es obligatorio")
        if self.context_entries_limit < 1 or self.context_entries_limit > 100:
            raise ValidationError("context_entries_limit debe estar entre 1 y 100")
        if self.daily_token_limit_per_user < 100:
            raise ValidationError("daily_token_limit_per_user debe ser al menos 100")


@dataclass
class LLMSettingsPublicView:
    """Vista pública hacia el entrenador (jamás incluye la clave API en claro ni cifrada)."""

    provider_name: str
    base_url: str
    model_name: str
    has_api_key_configured: bool
    context_entries_limit: int
    daily_token_limit_per_user: int
    web_search_enabled: bool
    web_search_url: str | None
