"""Pruebas de portabilidad: Migración ida y vuelta SQLite -> MariaDB/destino con checksums SHA-256 y backup cifrado export-all/import-all (T057)."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from app.cli import cmd_init_trainer
from app.db._compat_sa import Session as DbSession, URL, create_engine
from app.services.audio import set_custom_transcriber, upload_and_transcribe_audio
from app.services.knowledge import (
    create_entry,
    get_active_personality_doc,
    save_personality_doc_version,
    search_entries_in_memory,
)
from app.services.portability import (
    PortabilityError,
    export_all_encrypted_package,
    import_all_encrypted_package,
    migrate_database_between_engines,
)
from tests.conftest import make_test_environment


class TestPortabilityMigrationAndEncryptedBackup(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.engine, self.app, self.tmp_dir = make_test_environment()
        self.trainer, _ = cmd_init_trainer(
            "entrenador",
            "entrenador@legado.local",
            "ClaveFuerteEntrenador2026!",
            engine=self.engine,
            settings=self.settings,
        )
        set_custom_transcriber(lambda raw, mime: "Transcripción preservada en backup.")

        with DbSession(self.engine) as db:
            save_personality_doc_version(
                db, self.trainer, "Personalidad cálida y reflexiva.", settings=self.settings
            )
            create_entry(
                db,
                self.trainer,
                topic="valores",
                content="La lealtad y la palabra dada son sagradas.",
                settings=self.settings,
            )
            upload_and_transcribe_audio(
                db,
                self.trainer,
                raw_audio_bytes=b"OggS" + b"\x00" * 40 + b"VozOriginalDelEntrenador",
                topic="voz_familiar",
                settings=self.settings,
            )

    def tearDown(self) -> None:
        set_custom_transcriber(None)

    def test_lossless_roundtrip_migration_with_sha256_verification(self) -> None:
        # Migrar de motor origen (SQLite) a motor destino (MariaDB/SQLite 2) y de vuelta
        target_db_path = self.tmp_dir / "mariadb_simulated_target.db"
        roundtrip_db_path = self.tmp_dir / "roundtrip_sqlite.db"

        target_engine = create_engine(URL.create(drivername="sqlite", database=str(target_db_path)))
        roundtrip_engine = create_engine(
            URL.create(drivername="sqlite", database=str(roundtrip_db_path))
        )

        report_1 = migrate_database_between_engines(self.engine, target_engine)
        self.assertEqual(report_1["entries"]["count"], 2)
        self.assertEqual(report_1["personality_doc"]["count"], 1)
        self.assertEqual(report_1["audio_files"]["count"], 1)

        report_2 = migrate_database_between_engines(target_engine, roundtrip_engine)
        for table_name, stats in report_1.items():
            self.assertEqual(report_2[table_name]["count"], stats["count"])
            self.assertEqual(report_2[table_name]["sha256"], stats["sha256"])

    def test_encrypted_backup_export_all_and_import_all_restoration(self) -> None:
        backup_file = self.tmp_dir / "legado-full-backup.enc"
        passphrase = "FraseDePasoDeCustodiaFamiliar2026!"

        with DbSession(self.engine) as db:
            manifest = export_all_encrypted_package(
                db,
                passphrase=passphrase,
                output_path=backup_file,
                settings=self.settings,
            )
        self.assertEqual(manifest["counts"]["entries"], 2)
        self.assertEqual(manifest["counts"]["audio_files"], 1)

        # Verificar que el paquete en disco está cifrado y no contiene texto en claro
        raw_pkg = backup_file.read_text(encoding="utf-8")
        self.assertNotIn("palabra dada son sagradas", raw_pkg)

        # Restaurar en una segunda instancia limpia con una KEK totalmente distinta
        dst_dir = Path(tempfile.mkdtemp(prefix="legado_restore_"))
        dst_settings, dst_engine, _, _ = make_test_environment(dst_dir)
        dst_trainer, _ = cmd_init_trainer(
            "entrenador_restaurado",
            "restaurado@legado.local",
            "NuevaClaveEntrenador2026!",
            engine=dst_engine,
            settings=dst_settings,
        )

        # Con frase de paso incorrecta debe fallar sin escribir datos parciales
        with DbSession(dst_engine) as dst_db:
            with self.assertRaises(PortabilityError):
                import_all_encrypted_package(
                    dst_db,
                    passphrase="FraseIncorrecta12345",
                    input_path=backup_file,
                    target_trainer=dst_trainer,
                    settings=dst_settings,
                )

            restored_manifest = import_all_encrypted_package(
                dst_db,
                passphrase=passphrase,
                input_path=backup_file,
                target_trainer=dst_trainer,
                settings=dst_settings,
            )
            self.assertEqual(restored_manifest["counts"]["entries"], 2)

            restored_entries = search_entries_in_memory(
                dst_db, dst_trainer, settings=dst_settings
            )
            self.assertEqual(len(restored_entries), 2)
            contents = [e.content for e in restored_entries]
            self.assertTrue(any("palabra dada son sagradas" in c for c in contents))

            restored_pers = get_active_personality_doc(
                dst_db, dst_trainer.id, settings=dst_settings
            )
            assert restored_pers is not None
            self.assertEqual(restored_pers.body, "Personalidad cálida y reflexiva.")

    def test_cli_entrypoints_end_to_end(self) -> None:
        from app.cli import main as cli_main

        pkg_path = self.tmp_dir / "cli_pkg.enc"
        rc_exp = cli_main(
            ["export-all", "--output", str(pkg_path), "--passphrase", "ClaveSeguraCLI2026!"]
        )
        self.assertEqual(rc_exp, 0)
        self.assertTrue(pkg_path.is_file())


if __name__ == "__main__":
    unittest.main()
