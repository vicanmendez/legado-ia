"""Pruebas unitarias de cifrado por sobre AES-256-GCM, rotación de KEK y Argon2id (T018)."""

from __future__ import annotations

import unittest

from app.services.crypto import (
    CryptoError,
    decrypt_str,
    encrypt_blob,
    generate_dek,
    hash_password,
    unwrap_dek,
    verify_dummy_password,
    verify_password,
    wrap_dek,
)


class TestCryptoEnvelopeAndArgon2id(unittest.TestCase):
    def test_aes256_gcm_envelope_encryption_and_aad_binding(self) -> None:
        kek = generate_dek()
        user_dek = generate_dek()
        wrapped = wrap_dek(user_dek, kek, user_id=42)
        unwrapped = unwrap_dek(wrapped, kek, user_id=42)
        self.assertEqual(user_dek, unwrapped)

        # Intentar desenvolver la DEK con un user_id distinto falla por AAD
        with self.assertRaises(CryptoError):
            unwrap_dek(wrapped, kek, user_id=99)

        secret_memory = "Recuerdo íntimo de infancia en el pueblo de mis abuelos"
        ciphertext = encrypt_blob(secret_memory, unwrapped, aad="entries:42")
        self.assertNotIn(b"abuelos", ciphertext)
        self.assertEqual(decrypt_str(ciphertext, unwrapped, aad="entries:42"), secret_memory)

        # Manipular un byte o cambiar el AAD rechaza la etiqueta GCM
        with self.assertRaises(CryptoError):
            decrypt_str(ciphertext, unwrapped, aad="entries:43")
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF
        with self.assertRaises(CryptoError):
            decrypt_str(bytes(tampered), unwrapped, aad="entries:42")

    def test_argon2id_password_hashing_and_dummy_verification(self) -> None:
        pwd = "MiClaveUltraSegura2026!"
        hashed = hash_password(pwd)
        self.assertTrue(hashed.startswith("$argon2id$"))
        self.assertTrue(verify_password(hashed, pwd))
        self.assertFalse(verify_password(hashed, "ClaveIncorrecta"))
        self.assertFalse(verify_dummy_password("Cualquier Intento"))

    def test_audit_sanitization_and_email_async(self) -> None:
        import asyncio
        from app.services.audit import sanitize_audit_metadata
        from app.services.email import clear_outbox, get_outbox, send_plain_email_async

        sanitized = sanitize_audit_metadata(
            {"username": "ana", "password": "secret", "api_key": "sk-123", "ok": True}
        )
        assert sanitized is not None
        self.assertIn("[REDACTED]", sanitized)
        self.assertNotIn("sk-123", sanitized)

        clear_outbox()
        asyncio.run(send_plain_email_async("ana@local", "Asunto", "Texto plano"))
        self.assertEqual(len(get_outbox()), 1)


if __name__ == "__main__":
    unittest.main()
