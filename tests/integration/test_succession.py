"""Pruebas de integración: Protocolo de modo póstumo con albacea, abuso antes del plazo, cancelación y solo lectura (T056)."""

from __future__ import annotations

from datetime import timedelta
import unittest

from app.cli import cmd_init_trainer
from app.db._compat_sa import Session as DbSession
from app.db.base import utc_now
from app.models.succession import SystemState
from app.services.auth import create_user_with_dek
from app.services.llm import POSTHUMOUS_SIMULATION_NOTICE
from tests.conftest import LegadoTestClient, make_test_environment


class TestSuccessionAndPosthumousMode(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.engine, self.app, self.tmp_dir = make_test_environment()
        self.trainer, _ = cmd_init_trainer(
            "entrenador",
            "entrenador@legado.local",
            "ClaveFuerteEntrenador2026!",
            engine=self.engine,
            settings=self.settings,
        )
        with DbSession(self.engine) as db:
            self.albacea_user, _ = create_user_with_dek(
                db,
                "albacea_elena",
                "elena@albacea.local",
                "ClaveAlbaceaElena2026!",
                "amigo",
                self.settings,
            )
            self.friend_user, _ = create_user_with_dek(
                db,
                "amigo_pablo",
                "pablo@amigo.local",
                "ClaveAmigoPablo2026!",
                "amigo",
                self.settings,
            )

        self.trainer_client = LegadoTestClient(self.app)
        self.trainer_client.full_login_with_otp("entrenador", "ClaveFuerteEntrenador2026!")

    def test_posthumous_protocol_cooldown_cancellation_and_readonly_enforcement(self) -> None:
        # 1. El entrenador designa a Elena como albacea con un plazo de espera de 48 horas
        r_des = self.trainer_client.post(
            "/trainer/executors",
            json_body={
                "user_id": self.albacea_user.id,
                "notification_contacts": ["hermano@familia.local"],
                "cooldown_hours": 48,
            },
        )
        self.assertEqual(r_des.status_code, 201)

        executor_client = LegadoTestClient(self.app)
        executor_client.full_login_with_otp("albacea_elena", "ClaveAlbaceaElena2026!")

        # 2. El albacea solicita iniciar la transición al modo póstumo
        r_req = executor_client.post(
            "/executor/request-transition",
            json_body={"notes": "Solicitud de activación tras fallecimiento"},
        )
        self.assertEqual(r_req.status_code, 200)
        self.assertEqual(r_req.json()["mode"], "transicion_pendiente")

        # 3. ABUSO DEL PROCEDIMIENTO: Intentar confirmar antes de cumplirse las 48h es rechazado
        r_early = executor_client.post(
            "/executor/confirm-posthumous",
            json_body={"notes": "Intento prematuro"},
        )
        self.assertEqual(r_early.status_code, 400)

        # 4. El entrenador está vivo y cancela la transición -> vuelve a 'activo'
        r_cancel = self.trainer_client.post(
            "/executor/cancel-transition",
            json_body={"notes": "Estoy vivo, fue una falsa alarma"},
        )
        self.assertEqual(r_cancel.status_code, 200)
        self.assertEqual(r_cancel.json()["mode"], "activo")

        # 5. Nueva solicitud y vencimiento del plazo de espera -> confirmación exitosa
        executor_client.post("/executor/request-transition", json_body={})
        with DbSession(self.engine) as db:
            st = db.get(SystemState, 1)
            assert st is not None
            st.transition_confirmable_after = utc_now() - timedelta(minutes=1)
            db.commit()

        r_confirm = executor_client.post(
            "/executor/confirm-posthumous",
            json_body={"notes": "Plazo cumplido sin cancelación"},
        )
        self.assertEqual(r_confirm.status_code, 200)
        self.assertEqual(r_confirm.json()["mode"], "postumo")

        # 6. En modo póstumo, la base de conocimiento está en SOLO LECTURA estricto (403)
        r_write_entry = self.trainer_client.post(
            "/trainer/entries",
            json_body={"topic": "nuevo", "content": "Intento de modificar legado en modo póstumo"},
        )
        self.assertEqual(r_write_entry.status_code, 403)
        r_write_pers = self.trainer_client.post(
            "/trainer/personality",
            json_body={"body": "Intento de alterar personalidad en modo póstumo"},
        )
        self.assertEqual(r_write_pers.status_code, 403)

        # 7. En modo póstumo, el albacea puede generar invitaciones y los chats indican el fallecimiento
        r_exec_inv = executor_client.post(
            "/trainer/invitations",
            json_body={"recipient_hint": "Allegado familiar", "target_role": "amigo"},
        )
        self.assertEqual(r_exec_inv.status_code, 201)

        friend_client = LegadoTestClient(self.app)
        friend_client.full_login_with_otp("amigo_pablo", "ClaveAmigoPablo2026!")
        conv_id = friend_client.post(
            "/friend/conversations", json_body={"title": "Recuerdo póstumo"}
        ).json()["id"]
        msg_resp = friend_client.post(
            f"/friend/conversations/{conv_id}/messages",
            json_body={"content": "Hola querido amigo"},
        ).json()
        self.assertIn(POSTHUMOUS_SIMULATION_NOTICE, msg_resp["content"])


if __name__ == "__main__":
    unittest.main()
