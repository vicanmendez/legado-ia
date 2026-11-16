"""Pruebas de integración: Conversación de amigos con LLM simulado, etiquetado '[Información externa]', aislamiento entre amigos y cuota de tokens (T048)."""

from __future__ import annotations

from pathlib import Path
import unittest

from app.cli import cmd_init_trainer
from app.db._compat_sa import Session as DbSession
from app.services.auth import create_user_with_dek
from app.services.llm import SIMULATION_NOTICE, set_custom_llm_responder
from app.services.web_search import EXTERNAL_INFO_TAG, set_custom_web_search_provider
from tests.conftest import LegadoTestClient, make_test_environment


class TestChatLLMAndFriendIsolation(unittest.TestCase):
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
            self.friend_a, _ = create_user_with_dek(
                db, "amigo_ana", "ana@amigo.local", "PasswordAna2026!", "amigo", self.settings
            )
            self.friend_b, _ = create_user_with_dek(
                db, "amigo_beto", "beto@amigo.local", "PasswordBeto2026!", "amigo", self.settings
            )

        self.trainer_client = LegadoTestClient(self.app)
        self.trainer_client.full_login_with_otp("entrenador", "ClaveFuerteEntrenador2026!")

        self.client_a = LegadoTestClient(self.app)
        self.client_a.full_login_with_otp("amigo_ana", "PasswordAna2026!")

        self.client_b = LegadoTestClient(self.app)
        self.client_b.full_login_with_otp("amigo_beto", "PasswordBeto2026!")

    def tearDown(self) -> None:
        set_custom_llm_responder(None)
        set_custom_web_search_provider(None)

    def test_chat_sse_external_web_label_friend_isolation_and_encrypted_api_key(self) -> None:
        # 1. El entrenador crea recuerdos, personalidad y configura el proveedor LLM
        self.trainer_client.post(
            "/trainer/personality",
            json_body={"body": "Soy cercano y apasionado por la astronomía."},
        )
        self.trainer_client.post(
            "/trainer/entries",
            json_body={"topic": "astronomía", "content": "Mirábamos el eclipse desde la terraza."},
        )
        secret_api_key = "sk-openrouter-super-secret-api-key-9999"
        r_llm = self.trainer_client.post(
            "/trainer/llm-settings",
            json_body={
                "provider_name": "openrouter",
                "base_url": "https://openrouter.ai/api/v1",
                "model_name": "meta-llama/llama-3.1-70b-instruct",
                "api_key": secret_api_key,
                "context_entries_limit": 5,
                "daily_token_limit_per_user": 500,
                "web_search_enabled": True,
                "web_search_url": "http://searxng.local/search",
            },
        )
        self.assertEqual(r_llm.status_code, 200)
        self.assertTrue(r_llm.json()["has_api_key_configured"])
        self.assertNotIn(secret_api_key, r_llm.text)

        # 2. Configurar proveedor de búsqueda web y LLM simulado
        set_custom_web_search_provider(
            lambda q: ["El eclipse solar de 2026 fue visible en la península."]
        )
        set_custom_llm_responder(
            lambda msgs, used_web: (
                "En mis recuerdos hablábamos de astronomía, y según los datos actuales fue un gran evento.",
                True,
            )
        )

        # 3. Amigo Ana crea conversación y envía mensaje que activa búsqueda web
        r_conv = self.client_a.post(
            "/friend/conversations",
            json_body={"title": "Charla privada de Ana con el entrenador"},
        )
        self.assertEqual(r_conv.status_code, 201)
        conv_id = r_conv.json()["id"]

        r_msg = self.client_a.post(
            f"/friend/conversations/{conv_id}/messages",
            json_body={"content": "Busca información externa sobre el eclipse", "use_web_search": True},
        )
        self.assertEqual(r_msg.status_code, 201)
        msg_data = r_msg.json()
        self.assertTrue(msg_data["used_web_search"])
        self.assertTrue(msg_data["simulation_notice_shown"])
        self.assertIn(EXTERNAL_INFO_TAG, msg_data["content"])
        self.assertIn(SIMULATION_NOTICE, msg_data["content"])
        self.assertIn("event: token", msg_data["sse_stream"])

        # 4. Ana puede listar sus conversaciones y ver el detalle descifrado; SSE directo con Accept
        r_list = self.client_a.get("/friend/conversations")
        self.assertEqual(r_list.status_code, 200)
        self.assertEqual(len(r_list.json()), 1)

        r_detail = self.client_a.get(f"/friend/conversations/{conv_id}")
        self.assertEqual(r_detail.status_code, 200)
        self.assertEqual(len(r_detail.json()["messages"]), 2)

        r_sse_direct = self.client_a.post(
            f"/friend/conversations/{conv_id}/messages",
            json_body={"content": "¿Qué opinas de las estrellas?"},
            headers={"Accept": "text/event-stream"},
        )
        self.assertEqual(r_sse_direct.status_code, 200)
        self.assertIn("event: done", r_sse_direct.text)

        # 5. Aislamiento entre amigos: Amigo Beto NO puede ver ni escribir en la conversación de Ana
        r_beto_read = self.client_b.get(f"/friend/conversations/{conv_id}")
        self.assertEqual(r_beto_read.status_code, 403)
        r_beto_write = self.client_b.post(
            f"/friend/conversations/{conv_id}/messages",
            json_body={"content": "Intento intruso"},
        )
        self.assertEqual(r_beto_write.status_code, 403)

        # 5. Verificar en el archivo binario SQLite que ni los mensajes ni la API key están en claro
        sqlite_bytes = Path(self.settings.DB_SQLITE_PATH).read_bytes()
        self.assertNotIn(secret_api_key.encode("utf-8"), sqlite_bytes)
        self.assertNotIn(b"Charla privada de Ana", sqlite_bytes)


if __name__ == "__main__":
    unittest.main()
