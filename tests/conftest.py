"""Fixtures y cliente HTTP de pruebas para validación en SQLite y MySQL/MariaDB."""

from __future__ import annotations

import base64
import json
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import Settings, reset_settings
from app.db._compat_sa import Engine, Session as DbSession
from app.db.session import create_db_engine, init_db, reset_engine
from app.main import LegadoApplication, create_app
from app.routers.dependencies import HTTPRequestContext, HTTPResponseData
from app.services.altcha import solve_altcha_challenge_for_client
from app.services.email import clear_outbox, get_outbox


@dataclass
class TestResponse:
    status_code: int
    headers: dict[str, str]
    cookies: dict[str, dict[str, Any]]
    body: str | bytes
    _json: Any

    @property
    def text(self) -> str:
        if isinstance(self.body, bytes):
            return self.body.decode("utf-8", errors="replace")
        return self.body

    def json(self) -> Any:
        if self._json is not None:
            return self._json
        return json.loads(self.text)


class LegadoTestClient:
    """Cliente de pruebas síncrono con gestión automática de cookies de sesión y cabeceras CSRF."""

    def __init__(self, app: LegadoApplication) -> None:
        self.app = app
        self.cookies: dict[str, str] = {}
        self.csrf_token: str = ""

    def request(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
        form_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        body_bytes: bytes = b"",
        include_csrf: bool = True,
    ) -> TestResponse:
        hdrs = dict(headers or {})
        if include_csrf and self.csrf_token and "X-CSRF-Token" not in hdrs:
            hdrs["X-CSRF-Token"] = self.csrf_token

        req = HTTPRequestContext(
            method=method,
            path=path,
            headers=hdrs,
            cookies=dict(self.cookies),
            form_data=dict(form_data or {}),
            json_data=json_body,
            body_bytes=body_bytes,
        )
        raw_resp: HTTPResponseData = self.app.dispatch(req)

        for cname, cmeta in raw_resp.cookies.items():
            val = cmeta.get("value", "")
            if cmeta.get("max_age") == 0 or not val:
                self.cookies.pop(cname, None)
            else:
                self.cookies[cname] = val
                if cname == "legado_csrf":
                    self.csrf_token = val

        if isinstance(raw_resp.json_payload, dict) and "csrf_token" in raw_resp.json_payload:
            self.csrf_token = str(raw_resp.json_payload["csrf_token"])

        return TestResponse(
            status_code=raw_resp.status_code,
            headers=raw_resp.headers,
            cookies=raw_resp.cookies,
            body=raw_resp.body,
            _json=raw_resp.json_payload,
        )

    def get(self, path: str, headers: dict[str, str] | None = None) -> TestResponse:
        return self.request("GET", path, headers=headers)

    def post(
        self,
        path: str,
        json_body: dict[str, Any] | None = None,
        form_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        body_bytes: bytes = b"",
        include_csrf: bool = True,
    ) -> TestResponse:
        return self.request(
            "POST",
            path,
            json_body=json_body,
            form_data=form_data,
            headers=headers,
            body_bytes=body_bytes,
            include_csrf=include_csrf,
        )

    def put(
        self,
        path: str,
        json_body: dict[str, Any] | None = None,
        include_csrf: bool = True,
    ) -> TestResponse:
        return self.request("PUT", path, json_body=json_body, include_csrf=include_csrf)

    def patch(
        self,
        path: str,
        json_body: dict[str, Any] | None = None,
        include_csrf: bool = True,
    ) -> TestResponse:
        return self.request("PATCH", path, json_body=json_body, include_csrf=include_csrf)

    def delete(
        self,
        path: str,
        json_body: dict[str, Any] | None = None,
        include_csrf: bool = True,
    ) -> TestResponse:
        return self.request("DELETE", path, json_body=json_body, include_csrf=include_csrf)

    def fetch_and_solve_altcha(self) -> str:
        ch = self.get("/auth/altcha-challenge").json()
        return solve_altcha_challenge_for_client(ch)

    def full_login_with_otp(self, username: str, password: str) -> TestResponse:
        self.get("/auth/login")
        altcha = self.fetch_and_solve_altcha()
        clear_outbox()
        r1 = self.post(
            "/auth/login",
            json_body={
                "username": username,
                "password": password,
                "altcha_payload": altcha,
            },
        )
        assert r1.status_code == 200, f"Login step 1 falló: {r1.text}"
        outbox = get_outbox()
        assert len(outbox) == 1
        # Extraer el código de 6 dígitos del texto del correo
        otp_code = [
            word.strip(".")
            for word in outbox[0].body_text.split()
            if word.strip(".").isdigit() and len(word.strip(".")) == 6
        ][0]
        r2 = self.post("/auth/2fa/otp", json_body={"code": otp_code})
        assert r2.status_code == 200, f"Login step 2 falló: {r2.text}"
        return r2


def make_test_environment(tmp_dir: Path | None = None) -> tuple[Settings, Engine, LegadoApplication, Path]:
    """Crea una instancia aislada de Settings, Engine SQLite (WAL + FK) y aplicación para un test."""
    base_dir = tmp_dir or Path(tempfile.mkdtemp(prefix="legado_test_"))
    db_file = base_dir / "test_legado.db"
    audio_dir = base_dir / "audio"
    kek_file = base_dir / "kek.secret"
    kek_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    kek_file.write_text(kek_b64, encoding="utf-8")

    settings = Settings(
        _env_file=None,
        APP_ENV="testing",
        APP_BASE_URL="http://localhost:8000",
        APP_SECRET_KEY="testing-secret-key-with-more-than-32-bytes-entropy!!",
        DB_ENGINE="sqlite",
        DB_SQLITE_PATH=str(db_file),
        ENCRYPTION_KEK_FILE=str(kek_file),
        ENCRYPTION_KEK="",
        AUDIO_STORAGE_PATH=str(audio_dir),
        ALTCHA_HMAC_KEY="testing-altcha-hmac-key-with-at-least-32-bytes!!",
        WEBAUTHN_RP_ID="localhost",
        WEBAUTHN_RP_NAME="Legado IA Test",
    )
    reset_settings(settings)
    engine = create_db_engine(settings)
    reset_engine(engine)
    init_db(engine)
    app = create_app(settings=settings, engine=engine)
    clear_outbox()
    return settings, engine, app, base_dir
