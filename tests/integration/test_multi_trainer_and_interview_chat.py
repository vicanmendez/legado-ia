"""Pruebas de integración: Chat de Entrevista Guiada por IA y Aislamiento Multi-Entrenador (Persona A vs Persona B)."""

from __future__ import annotations

import unittest

from app.cli import cmd_init_trainer
from app.db._compat_sa import Session as DbSession
from app.db.base import select
from app.models.knowledge import Entry
from app.services.auth import get_user_dek
from app.services.crypto import CryptoError, decrypt_str
from app.services.llm import set_custom_llm_responder
from tests.conftest import LegadoTestClient, make_test_environment


class TestMultiTrainerIsolationAndInterviewChat(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.engine, self.app, self.tmp_dir = make_test_environment()
        self.trainer_a, _ = cmd_init_trainer(
            "persona_a",
            "persona_a@legado.local",
            "ClaveFuertePersonaA2026!",
            engine=self.engine,
            settings=self.settings,
        )
        self.trainer_b, _ = cmd_init_trainer(
            "persona_b",
            "persona_b@legado.local",
            "ClaveFuertePersonaB2026!",
            engine=self.engine,
            settings=self.settings,
        )

        self.client_a = LegadoTestClient(self.app)
        self.client_a.full_login_with_otp("persona_a", "ClaveFuertePersonaA2026!")

        self.client_b = LegadoTestClient(self.app)
        self.client_b.full_login_with_otp("persona_b", "ClaveFuertePersonaB2026!")

    def tearDown(self) -> None:
        set_custom_llm_responder(None)

    def test_ai_guided_interview_chat_saves_to_kb_and_isolates_trainers_a_and_b(self) -> None:
        captured_prompts: list[str] = []

        def _mock_llm(messages: list[dict[str, str]], did_web: bool) -> tuple[str, bool]:
            sys_content = messages[0]["content"]
            captured_prompts.append(sys_content)
            return ("¡Qué gran recuerdo! Cuéntame ahora qué aprendiste en tu primer trabajo.", False)

        set_custom_llm_responder(_mock_llm)

        # 1. Persona A abre su chat de entrevista y responde; se guarda en su propia base de conocimiento
        r_chat_a0 = self.client_a.get("/trainer/interview-chat")
        self.assertEqual(r_chat_a0.status_code, 200)
        self.assertEqual(len(r_chat_a0.json()), 1)

        r_reply_a = self.client_a.post(
            "/trainer/interview-chat",
            json_body={
                "content": "Yo soy marinero de Vigo y siempre digo 'buena mar y viento largo'.",
                "also_update_personality": "1",
            },
        )
        self.assertEqual(r_reply_a.status_code, 201)
        entry_id_a = r_reply_a.json()["saved_entry_id"]
        self.assertIsNotNone(entry_id_a)
        self.assertIn("primer trabajo", r_reply_a.json()["interviewer_message"]["content"])

        # 2. Persona B responde en su propio chat de entrevista con datos totalmente distintos
        r_reply_b = self.client_b.post(
            "/trainer/interview-chat",
            json_body={
                "content": "Yo soy arquitecta de Córdoba y diseño bibliotecas minimalistas.",
                "also_update_personality": "1",
            },
        )
        self.assertEqual(r_reply_b.status_code, 201)

        # 3. Verificar aislamiento de entradas y personalidad entre Persona A y Persona B
        entries_a = self.client_a.get("/trainer/entries").json()
        entries_b = self.client_b.get("/trainer/entries").json()
        self.assertEqual(len(entries_a), 1)
        self.assertEqual(len(entries_b), 1)
        self.assertIn("marinero de Vigo", entries_a[0]["content"])
        self.assertNotIn("arquitecta de Córdoba", entries_a[0]["content"])
        self.assertIn("arquitecta de Córdoba", entries_b[0]["content"])
        self.assertNotIn("marinero de Vigo", entries_b[0]["content"])

        # 4. Verificar aislamiento criptográfico: la DEK de Persona A no puede descifrar los recuerdos de Persona B
        with DbSession(self.engine) as db:
            dek_a = get_user_dek(db, self.trainer_a.id, settings=self.settings)
            entry_b_row = db.scalar(
                select(Entry).where(Entry.trainer_id == self.trainer_b.id)
            )
            assert entry_b_row is not None
            with self.assertRaises(CryptoError):
                decrypt_str(
                    entry_b_row.encrypted_content,
                    dek_a,
                    aad=f"entries:{self.trainer_b.id}",
                )

        # 5. Invitar un Amigo de Persona A y un Amigo de Persona B: cada uno conversa con la simulación de SU entrenador
        inv_a = self.client_a.post(
            "/trainer/invitations",
            json_body={"recipient_hint": "Amigo de A", "target_role": "amigo"},
        ).json()["token"]
        inv_b = self.client_b.post(
            "/trainer/invitations",
            json_body={"recipient_hint": "Amigo de B", "target_role": "amigo"},
        ).json()["token"]

        friend_a_client = LegadoTestClient(self.app)
        friend_a_client.get(f"/auth/invite/{inv_a}")
        friend_a_client.post(
            f"/auth/invite/{inv_a}",
            json_body={
                "username": "amigo_de_a",
                "email": "amigo_a@local.test",
                "password": "PasswordAmigoA2026!",
                "altcha_payload": friend_a_client.fetch_and_solve_altcha(),
            },
        )
        friend_a_client.full_login_with_otp("amigo_de_a", "PasswordAmigoA2026!")

        friend_b_client = LegadoTestClient(self.app)
        friend_b_client.get(f"/auth/invite/{inv_b}")
        friend_b_client.post(
            f"/auth/invite/{inv_b}",
            json_body={
                "username": "amigo_de_b",
                "email": "amigo_b@local.test",
                "password": "PasswordAmigoB2026!",
                "altcha_payload": friend_b_client.fetch_and_solve_altcha(),
            },
        )
        friend_b_client.full_login_with_otp("amigo_de_b", "PasswordAmigoB2026!")

        captured_prompts.clear()
        conv_a_id = friend_a_client.post(
            "/friend/conversations", json_body={"title": "Charla con Persona A"}
        ).json()["id"]
        friend_a_client.post(
            f"/friend/conversations/{conv_a_id}/messages",
            json_body={"content": "¿Cuál es tu profesión y dicho favorito?"},
        )
        prompt_for_a = captured_prompts[-1]
        self.assertIn("marinero de Vigo", prompt_for_a)
        self.assertNotIn("arquitecta de Córdoba", prompt_for_a)

        conv_b_id = friend_b_client.post(
            "/friend/conversations", json_body={"title": "Charla con Persona B"}
        ).json()["id"]
        friend_b_client.post(
            f"/friend/conversations/{conv_b_id}/messages",
            json_body={"content": "¿A qué te dedicas?"},
        )
        prompt_for_b = captured_prompts[-1]
        self.assertIn("arquitecta de Córdoba", prompt_for_b)
        self.assertNotIn("marinero de Vigo", prompt_for_b)


if __name__ == "__main__":
    unittest.main()
