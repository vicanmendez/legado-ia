"""Pruebas de integración: Base de conocimiento cifrada, verificación binaria en SQLite, audio faster-whisper y exportación (T040)."""

from __future__ import annotations

import base64
from pathlib import Path
import unittest

from app.cli import cmd_init_trainer
from app.services.audio import set_custom_transcriber
from tests.conftest import LegadoTestClient, make_test_environment


class TestKnowledgeBaseAndAudioEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.engine, self.app, self.tmp_dir = make_test_environment()
        self.trainer, _ = cmd_init_trainer(
            "entrenador",
            "entrenador@legado.local",
            "ClaveFuerteEntrenador2026!",
            engine=self.engine,
            settings=self.settings,
        )
        self.client = LegadoTestClient(self.app)
        self.client.full_login_with_otp("entrenador", "ClaveFuerteEntrenador2026!")

    def tearDown(self) -> None:
        set_custom_transcriber(None)

    def test_encrypted_entries_personality_audio_and_zero_plaintext_in_sqlite_file(self) -> None:
        secret_entry_marker = "SecretoInolvidableDeInfanciaEnMontevideo1978"
        secret_personality_marker = "ModismoUnicoDelEntrenadorJamásEnClaro9921"

        # 1. Modo entrevista guiada inicializado
        r_topics = self.client.get("/trainer/interview")
        self.assertEqual(r_topics.status_code, 200)
        topics = r_topics.json()
        self.assertGreaterEqual(len(topics), 5)
        first_topic_id = topics[0]["id"]

        # 2. Guardar entrada vinculada a un tema de entrevista
        r_entry = self.client.post(
            "/trainer/entries",
            json_body={
                "topic": "infancia",
                "content": f"Mi recuerdo más preciado: {secret_entry_marker}",
                "interview_topic_id": first_topic_id,
            },
        )
        self.assertEqual(r_entry.status_code, 201)

        # Verificar que el tema de entrevista quedó marcado como cubierto
        topics_after = self.client.get("/trainer/interview").json()
        self.assertTrue(topics_after[0]["is_covered"])

        # 3. Guardar versión del documento de personalidad
        r_pers = self.client.post(
            "/trainer/personality",
            json_body={"body": f"Hablo siempre con calma y uso {secret_personality_marker}."},
        )
        self.assertEqual(r_pers.status_code, 201)
        self.assertEqual(r_pers.json()["version_number"], 1)

        # 4. Subir grabación de audio con cabecera WebM real y transcribir en segundo plano
        set_custom_transcriber(
            lambda raw, mime: "Transcripción automática: consejo sobre la honestidad."
        )
        valid_webm_bytes = b"\x1a\x45\xdf\xa3" + b"\x00" * 64 + b"AudioRawPayloadSecret"
        r_audio = self.client.post(
            "/trainer/audio/upload",
            json_body={
                "topic": "consejos",
                "audio_bytes_b64": base64.b64encode(valid_webm_bytes).decode("ascii"),
            },
        )
        self.assertEqual(r_audio.status_code, 201)
        self.assertEqual(r_audio.json()["status"], "draft_transcription")
        audio_entry_id = r_audio.json()["entry_id"]
        audio_id = r_audio.json()["audio_id"]

        from app.db._compat_sa import Session as DbSession
        from app.services.audio import read_decrypted_audio_for_trainer

        with DbSession(self.engine) as db:
            plain_audio, mime = read_decrypted_audio_for_trainer(
                db, self.trainer, audio_id, settings=self.settings
            )
            self.assertEqual(plain_audio, valid_webm_bytes)
            self.assertEqual(mime, "audio/webm")

        # Rechazar un archivo con extensión/contenido falso (ej. ejecutable ELF o texto plano)
        r_bad_mime = self.client.post(
            "/trainer/audio/upload",
            json_body={
                "topic": "malicioso",
                "audio_bytes_b64": base64.b64encode(b"MZ-fake-executable-content-123456").decode(
                    "ascii"
                ),
            },
        )
        self.assertEqual(r_bad_mime.status_code, 400)

        # 5. INSPECCIÓN BINARIA DEL ARCHIVO SQLITE Y DEL DISCO: el dato en claro NUNCA aparece
        sqlite_raw_bytes = Path(self.settings.DB_SQLITE_PATH).read_bytes()
        self.assertNotIn(secret_entry_marker.encode("utf-8"), sqlite_raw_bytes)
        self.assertNotIn(secret_personality_marker.encode("utf-8"), sqlite_raw_bytes)
        self.assertNotIn(b"consejo sobre la honestidad", sqlite_raw_bytes)

        for enc_file in Path(self.settings.AUDIO_STORAGE_PATH).glob("*.enc"):
            self.assertNotIn(b"AudioRawPayloadSecret", enc_file.read_bytes())

        # 6. Búsqueda en memoria y exportación en streaming a JSONL y TXT
        r_search = self.client.get("/trainer/entries?q=Montevideo1978")
        self.assertEqual(len(r_search.json()), 1)

        r_exp_jsonl = self.client.post("/trainer/export", json_body={"format": "jsonl"})
        self.assertEqual(r_exp_jsonl.status_code, 200)
        self.assertIn(secret_entry_marker, r_exp_jsonl.text)
        self.assertIn(secret_personality_marker, r_exp_jsonl.text)

        # 7. Borrado seguro elimina la entrada y el archivo de audio en disco
        r_del = self.client.delete(f"/trainer/entries/{audio_entry_id}")
        self.assertEqual(r_del.status_code, 200)
        remaining_files = list(Path(self.settings.AUDIO_STORAGE_PATH).glob("*.enc"))
        self.assertEqual(len(remaining_files), 0)


if __name__ == "__main__":
    unittest.main()
