"""Fábrica de la aplicación legado-ia, middlewares de seguridad transversal (CSP, HSTS, CSRF, rate limit) y enrutamiento."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import app.models  # noqa: F401 - Registra todos los modelos en DeclarativeBase.metadata
from app.config import Settings, get_settings
from app.db._compat_sa import Engine, Session as DbSession
from app.db.session import get_engine, init_db
from app.routers import auth as auth_router
from app.routers import executor as executor_router
from app.routers import friend as friend_router
from app.routers import trainer as trainer_router
from app.routers import webauthn as webauthn_router
from app.routers.dependencies import (
    CSRFError,
    HTTPRequestContext,
    HTTPResponseData,
)
from app.services.auth import AccountLockedError, AuthenticationError, AuthorizationError

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "media-src 'self' blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "microphone=(self), camera=(), geolocation=()",
}


class LegadoApplication:
    """Aplicación web ASGI/HTTP con despacho de rutas, cabeceras de seguridad y sesiones en servidor."""

    def __init__(self, settings: Settings | None = None, engine: Engine | None = None) -> None:
        self.settings = settings or get_settings()
        self.engine = engine or get_engine()
        init_db(self.engine)
        self._ip_failures: dict[str, int] = {}

    def dispatch(self, req: HTTPRequestContext) -> HTTPResponseData:
        """Procesa una petición HTTP aplicando denegación por defecto, CSRF y cabeceras de seguridad."""
        parsed = urlsplit(req.path)
        clean_path = parsed.path or "/"
        if parsed.query and not req.query_params:
            req.query_params = dict(parse_qsl(parsed.query))

        with DbSession(self.engine) as db:
            try:
                resp = self._route(db, req, clean_path)
            except CSRFError as exc:
                resp = HTTPResponseData(
                    status_code=403, json_payload={"detail": f"CSRF Error: {exc}"}
                )
            except AccountLockedError as exc:
                resp = HTTPResponseData(status_code=429, json_payload={"detail": str(exc)})
            except AuthenticationError as exc:
                resp = HTTPResponseData(status_code=401, json_payload={"detail": str(exc)})
            except AuthorizationError as exc:
                resp = HTTPResponseData(status_code=403, json_payload={"detail": str(exc)})

        for hdr_k, hdr_v in SECURITY_HEADERS.items():
            resp.headers.setdefault(hdr_k, hdr_v)
        if resp.json_payload is not None and not resp.body:
            resp.body = json.dumps(resp.json_payload, ensure_ascii=False)
            resp.headers.setdefault("Content-Type", "application/json; charset=utf-8")
        return resp

    def _route(
        self,
        db: DbSession,
        req: HTTPRequestContext,
        path: str,
    ) -> HTTPResponseData:
        method = req.method.upper()

        # Raíz del sitio redirige al login
        if path == "/" and method == "GET":
            from app.ui import redirect_response

            return redirect_response("/auth/login")

        # Servir archivos estáticos locales (/static/*)
        if path.startswith("/static/") and method == "GET":
            rel = path.removeprefix("/static/")
            static_root = (Path(__file__).parent / "static").resolve()
            candidate = (static_root / rel).resolve()
            if not str(candidate).startswith(str(static_root)) or not candidate.is_file():
                return HTTPResponseData(status_code=404, json_payload={"detail": "Not Found"})
            content_type = (
                "application/javascript"
                if candidate.suffix == ".js"
                else "text/css"
                if candidate.suffix == ".css"
                else "application/octet-stream"
            )
            return HTTPResponseData(
                status_code=200,
                body=candidate.read_text(encoding="utf-8"),
                headers={"Content-Type": content_type},
            )

        # Rutas de Autenticación (/auth)
        if path == "/auth/altcha-challenge" and method == "GET":
            return auth_router.handle_get_altcha_challenge(settings=self.settings)
        if path == "/auth/login" and method == "GET":
            return auth_router.handle_get_login_page()
        if path == "/auth/login" and method == "POST":
            return auth_router.handle_post_login_step1(db, req, settings=self.settings)
        if path == "/auth/2fa" and method == "GET":
            return auth_router.handle_get_2fa_page(db, req)
        if path == "/auth/2fa/otp" and method == "POST":
            return auth_router.handle_post_2fa_otp(db, req, settings=self.settings)
        if path == "/auth/2fa/recovery" and method == "POST":
            return auth_router.handle_post_2fa_recovery(db, req, settings=self.settings)
        if path == "/auth/logout" and method == "POST":
            return auth_router.handle_post_logout(db, req)

        m_invite = re.match(r"^/auth/invite/([^/]+)$", path)
        if m_invite:
            token = m_invite.group(1)
            if method == "GET":
                return auth_router.handle_get_invite_page(db, token, req=req)
            if method == "POST":
                return auth_router.handle_post_consume_invite(
                    db, req, token, settings=self.settings
                )

        # Rutas WebAuthn (/webauthn)
        if path == "/webauthn/register/options" and method == "POST":
            return webauthn_router.handle_post_register_options(db, req, settings=self.settings)
        if path == "/webauthn/register/verify" and method == "POST":
            return webauthn_router.handle_post_register_verify(db, req, settings=self.settings)
        if path == "/webauthn/authenticate/options" and method == "POST":
            return webauthn_router.handle_post_authenticate_options(
                db, req, settings=self.settings
            )
        if path == "/webauthn/authenticate/verify" and method == "POST":
            return webauthn_router.handle_post_authenticate_verify(
                db, req, settings=self.settings
            )
        if path == "/webauthn/credentials" and method == "GET":
            return webauthn_router.handle_get_credentials(db, req, settings=self.settings)

        m_cred = re.match(r"^/webauthn/credentials/(\d+)$", path)
        if m_cred:
            cred_id = int(m_cred.group(1))
            if method == "PATCH":
                return webauthn_router.handle_patch_credential(
                    db, req, cred_id, settings=self.settings
                )
            if method == "DELETE":
                return webauthn_router.handle_delete_credential(
                    db, req, cred_id, settings=self.settings
                )

        # Rutas del Entrenador (/trainer)
        if path == "/trainer/dashboard" and method == "GET":
            return trainer_router.handle_get_trainer_dashboard(db, req, settings=self.settings)
        if path == "/trainer/invitations" and method == "POST":
            return trainer_router.handle_post_create_invitation(db, req, settings=self.settings)
        if path == "/trainer/entries" and method == "GET":
            return trainer_router.handle_get_entries(db, req, settings=self.settings)
        if path == "/trainer/entries" and method == "POST":
            return trainer_router.handle_post_entry(db, req, settings=self.settings)

        m_entry = re.match(r"^/trainer/entries/(\d+)$", path)
        if m_entry:
            entry_id = int(m_entry.group(1))
            if method == "PUT":
                return trainer_router.handle_put_entry(
                    db, req, entry_id, settings=self.settings
                )
            if method == "DELETE":
                return trainer_router.handle_delete_entry(
                    db, req, entry_id, settings=self.settings
                )

        if path == "/trainer/audio/upload" and method == "POST":
            return trainer_router.handle_post_audio_upload(db, req, settings=self.settings)
        if path == "/trainer/personality" and method == "GET":
            return trainer_router.handle_get_personality(db, req, settings=self.settings)
        if path == "/trainer/personality" and method == "POST":
            return trainer_router.handle_post_personality(db, req, settings=self.settings)
        if path == "/trainer/interview" and method == "GET":
            return trainer_router.handle_get_interview_topics(db, req, settings=self.settings)
        if path == "/trainer/interview-chat" and method == "GET":
            return trainer_router.handle_get_interview_chat(db, req, settings=self.settings)
        if path == "/trainer/interview-chat" and method == "POST":
            return trainer_router.handle_post_interview_chat_reply(db, req, settings=self.settings)
        if path == "/trainer/interview-chat/next-question" and method == "POST":
            return trainer_router.handle_post_interview_next_question(
                db, req, settings=self.settings
            )
        if path == "/trainer/export" and method == "POST":
            return trainer_router.handle_post_export(db, req, settings=self.settings)
        if path == "/trainer/llm-settings" and method == "GET":
            return trainer_router.handle_get_llm_settings(db, req, settings=self.settings)
        if path == "/trainer/llm-settings" and method == "POST":
            return trainer_router.handle_post_llm_settings(db, req, settings=self.settings)
        if path == "/trainer/executors" and method == "POST":
            return trainer_router.handle_post_designate_executor(
                db, req, settings=self.settings
            )

        # Rutas del Amigo (/friend)
        if path == "/friend/dashboard" and method == "GET":
            return friend_router.handle_get_friend_dashboard(db, req, settings=self.settings)
        if path == "/friend/conversations" and method == "GET":
            return friend_router.handle_get_conversations(db, req, settings=self.settings)
        if path == "/friend/conversations" and method == "POST":
            return friend_router.handle_post_conversation(db, req, settings=self.settings)

        m_conv = re.match(r"^/friend/conversations/(\d+)$", path)
        if m_conv and method == "GET":
            return friend_router.handle_get_conversation_detail(
                db, req, int(m_conv.group(1)), settings=self.settings
            )

        m_msg = re.match(r"^/friend/conversations/(\d+)/(messages|stream)$", path)
        if m_msg and method in ("POST", "GET"):
            return friend_router.handle_post_message(
                db, req, int(m_msg.group(1)), settings=self.settings
            )

        # Rutas del Albacea y Modo Póstumo (/executor)
        if path == "/executor/panel" and method == "GET":
            return executor_router.handle_get_executor_panel(db, req, settings=self.settings)
        if path == "/executor/request-transition" and method == "POST":
            return executor_router.handle_post_request_transition(
                db, req, settings=self.settings
            )
        if path == "/executor/cancel-transition" and method == "POST":
            return executor_router.handle_post_cancel_transition(
                db, req, settings=self.settings
            )
        if path == "/executor/confirm-posthumous" and method == "POST":
            return executor_router.handle_post_confirm_posthumous(
                db, req, settings=self.settings
            )

        # Denegar por defecto cualquier ruta desconocida
        return HTTPResponseData(status_code=404, json_payload={"detail": "Ruta no encontrada"})


def create_app(
    settings: Settings | None = None,
    engine: Engine | None = None,
) -> LegadoApplication:
    """Factoría principal de la aplicación legado-ia."""
    return LegadoApplication(settings=settings, engine=engine)


def run_local_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Arranca un servidor HTTP local para desarrollo/pruebas sin requerir demonios externos."""
    from http.cookies import SimpleCookie
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qsl

    app = create_app()

    class _Handler(BaseHTTPRequestHandler):
        def _handle_any(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(length) if length > 0 else b""
            ctype = self.headers.get("Content-Type", "")
            json_data: dict[str, Any] | None = None
            form_data: dict[str, Any] = {}
            if "application/json" in ctype and raw_body:
                try:
                    json_data = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    json_data = None
            elif "application/x-www-form-urlencoded" in ctype and raw_body:
                form_data = dict(parse_qsl(raw_body.decode("utf-8")))

            cookie_jar = SimpleCookie()
            if self.headers.get("Cookie"):
                cookie_jar.load(self.headers["Cookie"])
            cookies = {k: morsel.value for k, morsel in cookie_jar.items()}

            req = HTTPRequestContext(
                method=self.command,
                path=self.path,
                headers={k: v for k, v in self.headers.items()},
                cookies=cookies,
                form_data=form_data,
                json_data=json_data,
                body_bytes=raw_body,
                client_ip=self.client_address[0] if self.client_address else "127.0.0.1",
            )
            resp = app.dispatch(req)
            self.send_response(resp.status_code)
            for hk, hv in resp.headers.items():
                self.send_header(hk, hv)
            for cname, cmeta in resp.cookies.items():
                val = cmeta.get("value", "")
                parts = [f"{cname}={val}", f"Path={cmeta.get('path', '/')}"]
                if cmeta.get("httponly", True):
                    parts.append("HttpOnly")
                if cmeta.get("samesite"):
                    parts.append(f"SameSite={cmeta['samesite']}")
                if "max_age" in cmeta:
                    parts.append(f"Max-Age={cmeta['max_age']}")
                self.send_header("Set-Cookie", "; ".join(parts))
            self.end_headers()
            body_bytes = (
                resp.body.encode("utf-8") if isinstance(resp.body, str) else resp.body
            )
            self.wfile.write(body_bytes)

        def do_GET(self) -> None:  # noqa: N802
            self._handle_any()

        def do_POST(self) -> None:  # noqa: N802
            self._handle_any()

        def do_PUT(self) -> None:  # noqa: N802
            self._handle_any()

        def do_PATCH(self) -> None:  # noqa: N802
            self._handle_any()

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle_any()

    print(f"legado-ia escuchando en http://{host}:{port} (Ctrl+C para detener)")
    HTTPServer((host, port), _Handler).serve_forever()


if __name__ == "__main__":
    run_local_server()
