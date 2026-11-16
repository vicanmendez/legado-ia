"""Pruebas de integración: Invitaciones de un solo uso, códigos de recuperación, RBAC (amigo vs entrenador), CSRF y sesiones (T027)."""

from __future__ import annotations

from datetime import timedelta
import unittest

from app.cli import cmd_init_trainer
from app.db._compat_sa import Session as DbSession
from app.db.base import select, utc_now
from app.models.audit import AuditLog
from app.models.user import Session
from tests.conftest import LegadoTestClient, make_test_environment


class TestRBACInvitationsCSRFAndSessions(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.engine, self.app, self.tmp_dir = make_test_environment()
        self.trainer, self.trainer_recovery_codes = cmd_init_trainer(
            "entrenador",
            "entrenador@legado.local",
            "ClaveFuerteEntrenador2026!",
            engine=self.engine,
            settings=self.settings,
        )
        self.trainer_client = LegadoTestClient(self.app)
        self.trainer_client.full_login_with_otp("entrenador", "ClaveFuerteEntrenador2026!")

    def test_invitation_single_use_and_friend_cannot_access_any_trainer_route(self) -> None:
        # 1. Verificar cabeceras de seguridad y CSP estricto 'self'
        r_check = self.trainer_client.get("/trainer/entries")
        self.assertEqual(r_check.status_code, 200)
        self.assertIn("default-src 'self'", r_check.headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", r_check.headers["Content-Security-Policy"])
        self.assertEqual(r_check.headers["X-Frame-Options"], "DENY")

        # 2. Crear invitación como entrenador
        r_inv = self.trainer_client.post(
            "/trainer/invitations",
            json_body={"recipient_hint": "Mejor Amigo", "target_role": "amigo"},
        )
        self.assertEqual(r_inv.status_code, 201)
        invite_token = r_inv.json()["token"]

        # 3. Registrar al amigo usando la invitación
        friend_client = LegadoTestClient(self.app)
        r_get_inv = friend_client.get(f"/auth/invite/{invite_token}")
        self.assertEqual(r_get_inv.status_code, 200)

        r_reg = friend_client.post(
            f"/auth/invite/{invite_token}",
            json_body={
                "username": "amigo_carlos",
                "email": "carlos@amigo.local",
                "password": "PasswordAmigoCarlos2026!",
                "altcha_payload": friend_client.fetch_and_solve_altcha(),
            },
        )
        self.assertEqual(r_reg.status_code, 201)
        friend_recovery_codes = r_reg.json()["recovery_codes"]
        self.assertEqual(len(friend_recovery_codes), 8)

        # 4. Intentar reutilizar el mismo enlace de invitación debe fallar
        r_reuse = friend_client.get(f"/auth/invite/{invite_token}")
        self.assertEqual(r_reuse.status_code, 400)

        # 5. Iniciar sesión con el amigo utilizando un código de recuperación de un solo uso
        friend_client.get("/auth/login")
        friend_client.post(
            "/auth/login",
            json_body={
                "username": "amigo_carlos",
                "password": "PasswordAmigoCarlos2026!",
                "altcha_payload": friend_client.fetch_and_solve_altcha(),
            },
        )
        first_rec_code = friend_recovery_codes[0]
        r_rec = friend_client.post(
            "/auth/2fa/recovery", json_body={"recovery_code": first_rec_code}
        )
        self.assertEqual(r_rec.status_code, 200)
        self.assertEqual(r_rec.json()["remaining_recovery_codes"], 7)

        # 6. El amigo no puede acceder a NINGUNA ruta del entrenador (403 Forbidden + audit_log)
        for path, method in [
            ("/trainer/entries", "GET"),
            ("/trainer/entries", "POST"),
            ("/trainer/personality", "GET"),
            ("/trainer/interview", "GET"),
            ("/trainer/invitations", "POST"),
            ("/trainer/llm-settings", "GET"),
            ("/trainer/export", "POST"),
        ]:
            resp = friend_client.request(method, path, json_body={})
            self.assertEqual(resp.status_code, 403, f"Fallo RBAC en {method} {path}")

        with DbSession(self.engine) as db:
            denied_logs = db.scalars(
                select(AuditLog).where(AuditLog.event_code == "ROLE_DENIED")
            ).all()
            self.assertGreaterEqual(len(denied_logs), 1)

        # 7. Verificar que el código de recuperación ya utilizado no se puede volver a usar
        friend_client2 = LegadoTestClient(self.app)
        friend_client2.get("/auth/login")
        friend_client2.post(
            "/auth/login",
            json_body={
                "username": "amigo_carlos",
                "password": "PasswordAmigoCarlos2026!",
                "altcha_payload": friend_client2.fetch_and_solve_altcha(),
            },
        )
        r_rec_reuse = friend_client2.post(
            "/auth/2fa/recovery", json_body={"recovery_code": first_rec_code}
        )
        self.assertEqual(r_rec_reuse.status_code, 401)

    def test_csrf_protection_and_session_inactivity_and_logout(self) -> None:
        # Petición POST sin cabecera CSRF es rechazada con 403
        r_no_csrf = self.trainer_client.post(
            "/trainer/entries",
            json_body={"topic": "infancia", "content": "Texto"},
            include_csrf=False,
        )
        self.assertEqual(r_no_csrf.status_code, 403)

        # Caducidad por inactividad
        with DbSession(self.engine) as db:
            sess = db.scalar(
                select(Session)
                .where(Session.user_id == self.trainer.id)
                .order_by(Session.id.desc())
            )
            assert sess is not None
            sess.last_activity_at = utc_now() - timedelta(minutes=60)
            db.commit()

        r_inactive = self.trainer_client.get("/trainer/entries")
        self.assertEqual(r_inactive.status_code, 403)

        # Re-autenticar y cerrar sesión explícitamente
        self.trainer_client.full_login_with_otp("entrenador", "ClaveFuerteEntrenador2026!")
        old_cookie = self.trainer_client.cookies.get("legado_session", "")
        r_logout = self.trainer_client.post("/auth/logout")
        self.assertEqual(r_logout.status_code, 200)

        # Intentar reutilizar el token antiguo tras logout es rechazado
        self.trainer_client.cookies["legado_session"] = old_cookie
        self.assertEqual(self.trainer_client.get("/trainer/entries").status_code, 403)

    def test_static_assets_and_trainer_update_and_views(self) -> None:
        r_js = self.trainer_client.get("/static/vendor/htmx.min.js")
        self.assertEqual(r_js.status_code, 200)
        self.assertIn("htmx", r_js.text)

        r_e = self.trainer_client.post(
            "/trainer/entries",
            json_body={"topic": "trabajo", "content": "Borrador inicial", "status": "draft_transcription"},
        )
        eid = r_e.json()["id"]
        r_put = self.trainer_client.put(
            f"/trainer/entries/{eid}",
            json_body={"topic": "trabajo", "content": "Texto revisado y confirmado", "status": "confirmed"},
        )
        self.assertEqual(r_put.status_code, 200)
        self.assertEqual(r_put.json()["status"], "confirmed")

        self.assertEqual(self.trainer_client.get("/trainer/personality").status_code, 200)
        self.assertEqual(self.trainer_client.get("/trainer/llm-settings").status_code, 200)
        self.assertEqual(self.trainer_client.get("/executor/panel").status_code, 200)
        self.assertEqual(self.trainer_client.get("/webauthn/credentials").status_code, 200)
        self.assertEqual(
            self.trainer_client.post("/trainer/export", json_body={"format": "txt"}).status_code,
            200,
        )


if __name__ == "__main__":
    unittest.main()
