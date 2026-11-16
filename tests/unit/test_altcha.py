"""Pruebas unitarias de generación, validación HMAC, expiración y bloqueo de replay en ALTCHA (T019)."""

from __future__ import annotations

import base64
import json
import unittest

from app.db._compat_sa import Session as DbSession
from app.services.altcha import (
    AltchaError,
    create_altcha_challenge,
    solve_altcha_challenge_for_client,
    verify_altcha_payload,
)
from tests.conftest import make_test_environment


class TestAltchaService(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.engine, _, _ = make_test_environment()

    def test_valid_altcha_and_replay_rejection(self) -> None:
        ch = create_altcha_challenge(max_number=200, settings=self.settings)
        payload = solve_altcha_challenge_for_client(ch)
        with DbSession(self.engine) as db:
            self.assertTrue(verify_altcha_payload(db, payload, settings=self.settings))
            # Reutilizar exactamente la misma solución (replay) debe fallar
            with self.assertRaises(AltchaError):
                verify_altcha_payload(db, payload, settings=self.settings)

    def test_expired_or_tampered_altcha_rejected(self) -> None:
        expired_ch = create_altcha_challenge(max_number=100, ttl_seconds=-10, settings=self.settings)
        expired_payload = solve_altcha_challenge_for_client(expired_ch)
        with DbSession(self.engine) as db:
            with self.assertRaises(AltchaError):
                verify_altcha_payload(db, expired_payload, settings=self.settings)

        valid_ch = create_altcha_challenge(max_number=100, settings=self.settings)
        valid_payload = solve_altcha_challenge_for_client(valid_ch)
        decoded = json.loads(base64.b64decode(valid_payload).decode("utf-8"))
        decoded["signature"] = "0" * 64
        forged_payload = base64.b64encode(json.dumps(decoded).encode("utf-8")).decode("ascii")
        with DbSession(self.engine) as db:
            with self.assertRaises(AltchaError):
                verify_altcha_payload(db, forged_payload, settings=self.settings)


if __name__ == "__main__":
    unittest.main()
