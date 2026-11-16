"""Pruebas unitarias de validación fail-fast de .env en producción y construcción de URL de BD (T018)."""

from __future__ import annotations

import base64
import secrets
import tempfile
import unittest
from pathlib import Path

from app.config import ConfigurationError, Settings
from app.db.session import build_database_url


class TestConfigFailFast(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="legado_cfg_"))
        self.kek_file = self.tmp_dir / "kek.secret"
        self.kek_file.write_text(
            base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            encoding="utf-8",
        )

    def test_production_fails_if_base_url_not_https(self) -> None:
        with self.assertRaises(ConfigurationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                APP_BASE_URL="http://legado.example.com",
                APP_SECRET_KEY="a" * 40,
                ALTCHA_HMAC_KEY="b" * 40,
                ENCRYPTION_KEK_FILE=str(self.kek_file),
            )

    def test_production_fails_if_secret_key_is_short_or_placeholder(self) -> None:
        with self.assertRaises(ConfigurationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                APP_BASE_URL="https://legado.example.com",
                APP_SECRET_KEY="short-key",
                ALTCHA_HMAC_KEY="b" * 40,
                ENCRYPTION_KEK_FILE=str(self.kek_file),
            )
        with self.assertRaises(ConfigurationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                APP_BASE_URL="https://legado.example.com",
                APP_SECRET_KEY="CHANGE_ME_GENERATE_AT_LEAST_32_BYTES_RANDOM_SECRET_KEY",
                ALTCHA_HMAC_KEY="b" * 40,
                ENCRYPTION_KEK_FILE=str(self.kek_file),
            )

    def test_production_fails_without_encryption_kek_file(self) -> None:
        with self.assertRaises(ConfigurationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                APP_BASE_URL="https://legado.example.com",
                APP_SECRET_KEY="a" * 40,
                ALTCHA_HMAC_KEY="b" * 40,
                ENCRYPTION_KEK_FILE="",
            )

    def test_production_mysql_fails_if_fields_missing_or_remote_without_ssl_ca(self) -> None:
        with self.assertRaises(ConfigurationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                APP_BASE_URL="https://legado.example.com",
                APP_SECRET_KEY="a" * 40,
                ALTCHA_HMAC_KEY="b" * 40,
                ENCRYPTION_KEK_FILE=str(self.kek_file),
                DB_ENGINE="mysql",
                DB_HOST="db.remote.internal",
                DB_NAME="legado",
                DB_USER="user",
                DB_PASSWORD="",
            )
        with self.assertRaises(ConfigurationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                APP_BASE_URL="https://legado.example.com",
                APP_SECRET_KEY="a" * 40,
                ALTCHA_HMAC_KEY="b" * 40,
                ENCRYPTION_KEK_FILE=str(self.kek_file),
                DB_ENGINE="mysql",
                DB_HOST="db.remote.internal",
                DB_NAME="legado",
                DB_USER="user",
                DB_PASSWORD="strong-db-password",
                DB_SSL_CA="",
            )

    def test_valid_production_config_and_url_create_builder(self) -> None:
        ca_file = self.tmp_dir / "ca.pem"
        ca_file.write_text("CERT", encoding="utf-8")
        cfg = Settings(
            _env_file=None,
            APP_ENV="production",
            APP_BASE_URL="https://legado.example.com",
            APP_SECRET_KEY="a" * 40,
            ALTCHA_HMAC_KEY="b" * 40,
            ENCRYPTION_KEK_FILE=str(self.kek_file),
            DB_ENGINE="mysql",
            DB_HOST="db.remote.internal",
            DB_PORT=3306,
            DB_NAME="legado_prod",
            DB_USER="legado_u",
            DB_PASSWORD="strong-db-password",
            DB_SSL_CA=str(ca_file),
        )
        url = build_database_url(cfg)
        self.assertEqual(url.drivername, "mysql+pymysql")
        self.assertEqual(url.database, "legado_prod")
        self.assertEqual(url.query, {"charset": "utf8mb4"})
        self.assertNotIn("strong-db-password", str(url))

    def test_gitignore_protects_all_secrets_databases_and_backups(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        gitignore_path = repo_root / ".gitignore"
        self.assertTrue(gitignore_path.is_file())
        content = gitignore_path.read_text(encoding="utf-8")
        for required_pattern in (
            ".env",
            "!.env.example",
            "*.secret",
            "*.key",
            "*.db",
            "*.db-wal",
            "*.db-shm",
            "*.sqlite",
            "*.enc",
            "*.jsonl",
            "data/",
        ):
            self.assertIn(required_pattern, content)


if __name__ == "__main__":
    unittest.main()
