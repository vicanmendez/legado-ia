"""Pruebas de integración: Passkeys WebAuthn con autenticador virtual, replay de challenge, detección de clonación y protección de última credencial (T034)."""

from __future__ import annotations

import base64
import secrets
import unittest

from app.cli import cmd_init_trainer
from app.services.webauthn import _b64url_decode, _b64url_encode, compute_virtual_authenticator_signature
from tests.conftest import LegadoTestClient, make_test_environment


class TestWebAuthnIntegration(unittest.TestCase):
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
        self.client.full_login_with_otp("entrenador", "ClaveFuerteEntrenador2026!")

    def test_virtual_authenticator_register_login_replay_clone_and_revoke_guard(self) -> None:
        # 1. Registrar Passkey #1 con autenticador virtual
        r_opt = self.client.post("/webauthn/register/options")
        self.assertEqual(r_opt.status_code, 200)
        reg_challenge_b64 = r_opt.json()["challenge"]

        cred1_raw_id = secrets.token_bytes(32)
        cred1_pub_key = secrets.token_bytes(32)
        reg_payload = {
            "credential_id_b64": _b64url_encode(cred1_raw_id),
            "public_key_b64": _b64url_encode(cred1_pub_key),
            "challenge_b64": reg_challenge_b64,
            "device_name": "Llave FIDO2 Principal",
            "sign_count": 1,
            "user_verified": True,
            "rp_id": "localhost",
            "origin": "http://localhost:8000",
        }
        r_ver = self.client.post("/webauthn/register/verify", json_body=reg_payload)
        self.assertEqual(r_ver.status_code, 201)
        cred1_db_id = r_ver.json()["id"]

        # Intentar reutilizar el mismo challenge de registro falla (uso único)
        r_replay_reg = self.client.post("/webauthn/register/verify", json_body=reg_payload)
        self.assertEqual(r_replay_reg.status_code, 400)

        # 2. Renombrar la credencial desde el perfil
        r_ren = self.client.patch(
            f"/webauthn/credentials/{cred1_db_id}",
            json_body={"device_name": "YubiKey Personal"},
        )
        self.assertEqual(r_ren.status_code, 200)
        self.assertEqual(r_ren.json()["device_name"], "YubiKey Personal")

        # 3. Intentar revocar la ÚNICA credencial sin código de recuperación es rechazado
        r_rev_blocked = self.client.delete(
            f"/webauthn/credentials/{cred1_db_id}", json_body={}
        )
        self.assertEqual(r_rev_blocked.status_code, 400)

        # Registrar una segunda passkey y revocarla libremente, o revocar con código de recuperación
        r_opt2 = self.client.post("/webauthn/register/options")
        r_ver2 = self.client.post(
            "/webauthn/register/verify",
            json_body={
                "credential_id_b64": _b64url_encode(secrets.token_bytes(32)),
                "public_key_b64": _b64url_encode(secrets.token_bytes(32)),
                "challenge_b64": r_opt2.json()["challenge"],
                "device_name": "Passkey Secundaria",
                "sign_count": 0,
                "user_verified": True,
                "rp_id": "localhost",
                "origin": "http://localhost:8000",
            },
        )
        cred2_db_id = r_ver2.json()["id"]
        r_del2 = self.client.delete(f"/webauthn/credentials/{cred2_db_id}", json_body={})
        self.assertEqual(r_del2.status_code, 200)

        # Revocar la última passkey pasando un código de recuperación válido y registrar una nueva
        r_del1_ok = self.client.delete(
            f"/webauthn/credentials/{cred1_db_id}",
            json_body={"recovery_code": self.recovery_codes[0]},
        )
        self.assertEqual(r_del1_ok.status_code, 200)

        cred1_raw_id = secrets.token_bytes(32)
        r_opt_re = self.client.post("/webauthn/register/options")
        r_ver_re = self.client.post(
            "/webauthn/register/verify",
            json_body={
                "credential_id_b64": _b64url_encode(cred1_raw_id),
                "public_key_b64": _b64url_encode(cred1_pub_key),
                "challenge_b64": r_opt_re.json()["challenge"],
                "device_name": "YubiKey Personal",
                "sign_count": 1,
                "user_verified": True,
                "rp_id": "localhost",
                "origin": "http://localhost:8000",
            },
        )
        self.assertEqual(r_ver_re.status_code, 201)

        # 4. Iniciar sesión en el Paso 2 usando la Passkey WebAuthn
        login_client = LegadoTestClient(self.app)
        login_client.get("/auth/login")
        login_client.post(
            "/auth/login",
            json_body={
                "username": "entrenador",
                "password": "ClaveFuerteEntrenador2026!",
                "altcha_payload": login_client.fetch_and_solve_altcha(),
            },
        )
        r_auth_opt = login_client.post("/webauthn/authenticate/options")
        self.assertEqual(r_auth_opt.status_code, 200)
        auth_challenge_b64 = r_auth_opt.json()["challenge"]
        auth_challenge_bytes = _b64url_decode(auth_challenge_b64)

        sig_b64 = compute_virtual_authenticator_signature(
            cred1_pub_key, auth_challenge_bytes, sign_count=2, rp_id="localhost"
        )
        auth_payload = {
            "credential_id_b64": _b64url_encode(cred1_raw_id),
            "challenge_b64": auth_challenge_b64,
            "signature_b64": sig_b64,
            "sign_count": 2,
            "user_verified": True,
            "rp_id": "localhost",
            "origin": "http://localhost:8000",
        }
        r_auth_ok = login_client.post("/webauthn/authenticate/verify", json_body=auth_payload)
        self.assertEqual(r_auth_ok.status_code, 200)
        self.assertEqual(r_auth_ok.json()["status"], "authenticated")

        # 5. Simular credencial clonada (sign_count <= 2) en un nuevo login -> bloquea y revoca la credencial
        clone_client = LegadoTestClient(self.app)
        clone_client.get("/auth/login")
        clone_client.post(
            "/auth/login",
            json_body={
                "username": "entrenador",
                "password": "ClaveFuerteEntrenador2026!",
                "altcha_payload": clone_client.fetch_and_solve_altcha(),
            },
        )
        ch2_b64 = clone_client.post("/webauthn/authenticate/options").json()["challenge"]
        ch2_bytes = _b64url_decode(ch2_b64)
        clone_sig = compute_virtual_authenticator_signature(
            cred1_pub_key, ch2_bytes, sign_count=2, rp_id="localhost"
        )
        r_clone = clone_client.post(
            "/webauthn/authenticate/verify",
            json_body={
                "credential_id_b64": _b64url_encode(cred1_raw_id),
                "challenge_b64": ch2_b64,
                "signature_b64": clone_sig,
                "sign_count": 2,  # No incrementó respecto a 2 -> clonación detectada
                "user_verified": True,
                "rp_id": "localhost",
                "origin": "http://localhost:8000",
            },
        )
        self.assertEqual(r_clone.status_code, 401)
        self.assertIn("clonada", r_clone.json()["detail"])


if __name__ == "__main__":
    unittest.main()
