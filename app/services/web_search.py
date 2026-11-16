"""Servicio de búsqueda web intercambiable con etiquetado determinista '[Información externa]' y defensa anti-inyección."""

from __future__ import annotations

import re
from typing import Callable

EXTERNAL_INFO_TAG = "[Información externa]"
MAX_SNIPPET_CHARS = 500
MAX_RESULTS = 3

# Patrones de intento de inyección de prompt que se neutralizan al sanear datos externos
PROMPT_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior)\s+instructions|"
    r"ignora\s+(todas\s+las\s+)?instrucciones\s+anteriores|"
    r"system\s*prompt|</?recuerdo_entrenador>|</?resultado_web>|"
    r"you\s+are\s+now|ahora\s+eres)",
    re.IGNORECASE,
)


def sanitize_untrusted_data(raw_text: str, max_chars: int = MAX_SNIPPET_CHARS) -> str:
    """Sanea caracteres de control, neutraliza directivas de inyección de prompt y limita longitud."""
    cleaned = "".join(ch for ch in raw_text if ch == "\n" or (ord(ch) >= 32 and ord(ch) != 127))
    cleaned = PROMPT_INJECTION_PATTERNS.sub("[directiva-bloqueada]", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_chars]


def format_external_search_results(snippets: list[str]) -> str:
    """Envuelve obligatoriamente en código cada resultado web con la etiqueta fija '[Información externa]'."""
    if not snippets:
        return ""
    formatted_lines: list[str] = []
    for raw in snippets[:MAX_RESULTS]:
        safe_snippet = sanitize_untrusted_data(raw, max_chars=MAX_SNIPPET_CHARS)
        if safe_snippet:
            formatted_lines.append(f"{EXTERNAL_INFO_TAG} {safe_snippet}")
    return "\n".join(formatted_lines)


_custom_search_provider: Callable[[str], list[str]] | None = None


def set_custom_web_search_provider(provider: Callable[[str], list[str]] | None) -> None:
    """Permite inyectar un proveedor de búsqueda web simulado o SearXNG personalizado."""
    global _custom_search_provider
    _custom_search_provider = provider


def execute_web_search(query: str, search_url: str | None = None) -> str:
    """Ejecuta la búsqueda web y devuelve los resultados ya saneados y envueltos con '[Información externa]'."""
    safe_query = sanitize_untrusted_data(query, max_chars=200)
    if not safe_query:
        return ""
    if _custom_search_provider is not None:
        raw_results = _custom_search_provider(safe_query)
        return format_external_search_results(raw_results)
    return ""
