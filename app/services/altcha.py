"""Servicio ALTCHA autoalojado con firma HMAC-SHA256 y protección contra repetición (replay)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from app.config import Settings, get_settings
from app.db._compat_sa import Session
from app.db.base import select, utc_now
from app.models.user import AltchaConsumedChallenge


class AltchaError(ValueError):
    """Error de validación o reutilización de desafío ALTCHA."""


def create_altcha_challenge(
    max_number: int = 5000,
    ttl_seconds: int = 300,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Genera un desafío proof-of-work ALTCHA firmado con ALTCHA_HMAC_KEY."""
    cfg = settings or get_settings()
    expires_ts = int((utc_now() + timedelta(seconds=ttl_seconds)).timestamp())
    random_nonce = secrets.token_hex(12)
    salt = f"{random_nonce}?expires={expires_ts}"
    secret_number = secrets.randbelow(max_number + 1)
    challenge = hashlib.sha256(f"{salt}{secret_number}".encode("utf-8")).hexdigest()
    signature = hmac.new(
        cfg.ALTCHA_HMAC_KEY.encode("utf-8"),
        challenge.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "algorithm": "SHA-256",
        "challenge": challenge,
        "maxnumber": max_number,
        "salt": salt,
        "signature": signature,
    }


def solve_altcha_challenge_for_client(
    challenge_data: dict[str, Any],
) -> str:
    """Resuelve un desafío ALTCHA y devuelve el payload codificado en base64 (utilizado por JS/tests)."""
    salt = str(challenge_data["salt"])
    target_challenge = str(challenge_data["challenge"])
    max_num = int(challenge_data.get("maxnumber", 10000))
    for num in range(max_num + 1):
        candidate = hashlib.sha256(f"{salt}{num}".encode("utf-8")).hexdigest()
        if candidate == target_challenge:
            payload = {
                "algorithm": challenge_data["algorithm"],
                "challenge": target_challenge,
                "number": num,
                "salt": salt,
                "signature": challenge_data["signature"],
            }
            return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    raise AltchaError("No se encontró solución dentro de maxnumber")


def verify_altcha_payload(
    db: Session,
    payload_b64: str,
    settings: Settings | None = None,
) -> bool:
    """Verifica firma HMAC, expiración, solución PoW y ausencia de replay en servidor."""
    cfg = settings or get_settings()
    if not payload_b64 or not payload_b64.strip():
        raise AltchaError("Payload ALTCHA vacío")

    try:
        raw_json = base64.b64decode(payload_b64.strip(), validate=True).decode("utf-8")
        data = json.loads(raw_json)
    except Exception as exc:
        raise AltchaError("Payload ALTCHA malformado") from exc

    if data.get("algorithm") != "SHA-256":
        raise AltchaError("Algoritmo ALTCHA no soportado")

    challenge = str(data.get("challenge", ""))
    salt = str(data.get("salt", ""))
    signature = str(data.get("signature", ""))
    number = data.get("number")

    if not challenge or not salt or not signature or not isinstance(number, int):
        raise AltchaError("Campos ALTCHA incompletos")

    if "?expires=" not in salt:
        raise AltchaError("Salt ALTCHA sin marca de expiración")
    try:
        expires_ts = int(salt.rsplit("?expires=", 1)[1])
    except ValueError as exc:
        raise AltchaError("Marca de expiración ALTCHA inválida") from exc

    now = utc_now()
    if int(now.timestamp()) > expires_ts:
        raise AltchaError("El desafío ALTCHA ha caducado")

    expected_sig = hmac.new(
        cfg.ALTCHA_HMAC_KEY.encode("utf-8"),
        challenge.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        raise AltchaError("Firma HMAC de ALTCHA inválida")

    computed_challenge = hashlib.sha256(f"{salt}{number}".encode("utf-8")).hexdigest()
    if not hmac.compare_digest(computed_challenge, challenge):
        raise AltchaError("Solución PoW de ALTCHA incorrecta")

    challenge_hash = hashlib.sha256(f"{challenge}:{signature}".encode("utf-8")).hexdigest()
    existing = db.scalar(
        select(AltchaConsumedChallenge).where(
            AltchaConsumedChallenge.challenge_hash == challenge_hash
        )
    )
    if existing is not None:
        raise AltchaError("El desafío ALTCHA ya fue utilizado anteriormente (replay detectado)")

    consumed = AltchaConsumedChallenge(
        challenge_hash=challenge_hash,
        expires_at=datetime.fromtimestamp(expires_ts, tz=timezone.utc),
    )
    db.add(consumed)
    db.commit()
    return True
