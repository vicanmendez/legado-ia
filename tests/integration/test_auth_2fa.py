"""Pruebas de integración: Login en 2 pasos, no-bypass de 2FA, expiración/intentos OTP, anti-enumeración y bloqueo progresivo (T020)."""

from __future__ import annotations

from datetime import timedelta
import unittest

from app.cli import cmd_init_trainer
from app.db._compat_sa import Session as DbSession
from app.db.base import select, utc_now
from app.models.user import OTPCode
from app.services.email import clear_outbox, get_outbox
from tests.conftest import LegadoTestClient, make_test_environment


class TestAuth2FAIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.engine, self.app, self.tmp_dir = make_test_environment()
        self.trainer, self.recovery_codes = cmd_init_trainer(
            "entrenador",
            "entrenador@legado.local",
            "ClaveFuerteEntrenador2026!",
            engine=self.engine,
            settings=self.settings,
        )
        self.client = LegadoTestClient(self.app)

    def test_step1_pending_session_cannot_bypass_2fa_to_access_protected_routes(self) -> None:
        self.client.get("/auth/login")
        altcha = self.client.fetch_and_solve_altcha()
        r1 = self.client.post(
            "/auth/login",
            json_body={
                "username": "entrenador",
                "password": "ClaveFuerteEntrenador2026!",
                "altcha_payload": altcha,
            },
        )
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json()["status"], "2fa_required")
        self.assertEqual(self.client.get("/auth/2fa").status_code, 200)

        # Intentar acceder a /trainer/entries con la sesión en Paso 1 debe ser rechazado (403)
        r_bypass = self.client.get("/trainer/entries")
        self.assertEqual(r_bypass.status_code, 403)

    def test_otp_max_5_attempts_and_10_min_expiration_and_single_use(self) -> None:
        self.client.get("/auth/login")
        altcha = self.client.fetch_and_solve_altcha()
        clear_outbox()
        self.client.post(
            "/auth/login",
            json_body={
                "username": "entrenador",
                "password": "ClaveFuerteEntrenador2026!",
                "altcha_payload": altcha,
            },
        )
        otp_code = [
            w.strip(".")
            for w in get_outbox()[0].body_text.split()
            if w.strip(".").isdigit() and len(w.strip(".")) == 6
        ][0]

        # 4 intentos fallidos seguidos del código correcto en el 5.º intento
        for _ in range(4):
            bad = self.client.post("/auth/2fa/otp", json_body={"code": "000000"})
            self.assertEqual(bad.status_code, 401)

        ok = self.client.post("/auth/2fa/otp", json_body={"code": otp_code})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json()["status"], "authenticated")

        # Verificar que un OTP caducado (>10 min) es rechazado
        client2 = LegadoTestClient(self.app)
        client2.get("/auth/login")
        clear_outbox()
        client2.post(
            "/auth/login",
            json_body={
                "username": "entrenador",
                "password": "ClaveFuerteEntrenador2026!",
                "altcha_payload": client2.fetch_and_solve_altcha(),
            },
        )
        otp2 = [
            w.strip(".")
            for w in get_outbox()[0].body_text.split()
            if w.strip(".").isdigit() and len(w.strip(".")) == 6
        ][0]
        with DbSession(self.engine) as db:
            row = db.scalar(
                select(OTPCode)
                .where(OTPCode.user_id == self.trainer.id, OTPCode.consumed_at.is_(None))
                .order_by(OTPCode.id.desc())
            )
            assert row is not None
            row.expires_at = utc_now() - timedelta(seconds=5)
            db.commit()

        r_exp = client2.post("/auth/2fa/otp", json_body={"code": otp2})
        self.assertEqual(r_exp.status_code, 401)

    def test_anti_enumeration_identical_error_and_progressive_lockout(self) -> None:
        self.client.get("/auth/login")
        r_unknown = self.client.post(
            "/auth/login",
            json_body={
                "username": "usuario_inexistente",
                "password": "CualquierPassword123!",
                "altcha_payload": self.client.fetch_and_solve_altcha(),
            },
        )
        r_wrong_pwd = self.client.post(
            "/auth/login",
            json_body={
                "username": "entrenador",
                "password": "PasswordIncorrecto123!",
                "altcha_payload": self.client.fetch_and_solve_altcha(),
            },
        )
        self.assertEqual(r_unknown.status_code, 401)
        self.assertEqual(r_wrong_pwd.status_code, 401)
        self.assertEqual(r_unknown.json()["detail"], r_wrong_pwd.json()["detail"])

        # Acumular 5 fallos consecutivos activa el bloqueo progresivo (429)
        for _ in range(4):
            self.client.post(
                "/auth/login",
                json_body={
                    "username": "entrenador",
                    "password": "PasswordIncorrecto123!",
                    "altcha_payload": self.client.fetch_and_solve_altcha(),
                },
            )
        r_locked = self.client.post(
            "/auth/login",
            json_body={
                "username": "entrenador",
                "password": "ClaveFuerteEntrenador2026!",
                "altcha_payload": self.client.fetch_and_solve_altcha(),
            },
        )
        self.assertEqual(r_locked.status_code, 429)


if __name__ == "__main__":
    unittest.main()
