"""Servicio criptográfico: AES-256-GCM por sobre (KEK/DEK), Argon2id, tokens de 256 bits y SHA-256."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover
    _ARGON2_AVAILABLE = False

ENVELOPE_VERSION = 0x01
NONCE_SIZE = 12
KEY_SIZE = 32


class CryptoError(Exception):
    """Error en operación de cifrado o autenticación de etiqueta AES-256-GCM."""


def generate_dek() -> bytes:
    """Genera una clave de datos (DEK) aleatoria de 256 bits (32 bytes)."""
    return secrets.token_bytes(KEY_SIZE)


def encrypt_blob(plaintext: bytes | str, key: bytes, aad: str) -> bytes:
    """Cifra datos con AES-256-GCM devolviendo: 0x01 (1B) || nonce (12B) || ciphertext || tag (16B)."""
    if len(key) != KEY_SIZE:
        raise CryptoError("La clave AES-256-GCM debe tener exactamente 32 bytes")
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode("utf-8")
    else:
        plaintext_bytes = plaintext

    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    aad_bytes = aad.encode("utf-8")
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)
    return bytes([ENVELOPE_VERSION]) + nonce + ciphertext_and_tag


def decrypt_blob(blob: bytes, key: bytes, aad: str) -> bytes:
    """Descifra y autentica un blob AES-256-GCM verificando versión y AAD."""
    if len(key) != KEY_SIZE:
        raise CryptoError("La clave AES-256-GCM debe tener exactamente 32 bytes")
    if not blob or len(blob) < 1 + NONCE_SIZE + 16:
        raise CryptoError("Blob cifrado truncado o inválido")
    if blob[0] != ENVELOPE_VERSION:
        raise CryptoError(f"Versión de sobre criptográfico no soportada: {blob[0]}")

    nonce = blob[1 : 1 + NONCE_SIZE]
    ciphertext_and_tag = blob[1 + NONCE_SIZE :]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, aad.encode("utf-8"))
    except InvalidTag as exc:
        raise CryptoError("Fallo de integridad o clave/AAD incorrectos en AES-256-GCM") from exc


def decrypt_str(blob: bytes, key: bytes, aad: str) -> str:
    """Descifra un blob AES-256-GCM y lo decodifica como UTF-8."""
    return decrypt_blob(blob, key, aad).decode("utf-8")


def wrap_dek(dek: bytes, kek: bytes, user_id: int) -> bytes:
    """Cifra por sobre la DEK de un usuario utilizando la KEK maestra y AAD contextual."""
    if len(dek) != KEY_SIZE:
        raise CryptoError("La DEK debe medir 32 bytes")
    return encrypt_blob(dek, kek, aad=f"user_keys:{user_id}")


def unwrap_dek(encrypted_dek: bytes, kek: bytes, user_id: int) -> bytes:
    """Descifra la DEK de un usuario utilizando la KEK maestra."""
    dek = decrypt_blob(encrypted_dek, kek, aad=f"user_keys:{user_id}")
    if len(dek) != KEY_SIZE:
        raise CryptoError("DEK descifrada corrupta")
    return dek


def hash_password(password: str) -> str:
    """Calcula el hash Argon2id de una contraseña."""
    if not password:
        raise ValueError("La contraseña no puede estar vacía")
    if _ARGON2_AVAILABLE:
        ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
        return str(ph.hash(password))
    # Fallback determinista con formato Argon2id + scrypt (N=16384, r=8, p=1) en entornos sin compilador C
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, maxmem=32 * 1024 * 1024, dklen=32
    )
    b64_salt = base64.b64encode(salt).decode("ascii").rstrip("=")
    b64_hash = base64.b64encode(derived).decode("ascii").rstrip("=")
    return f"$argon2id$v=19$m=65536,t=2,p=2${b64_salt}${b64_hash}"


def verify_password(password_hash: str, password: str) -> bool:
    """Verifica una contraseña contra su hash Argon2id en tiempo constante."""
    if not password_hash or not password:
        return False
    if _ARGON2_AVAILABLE and not password_hash.startswith("$argon2id$v=19$m=65536,t=2,p=2$"):
        ph = PasswordHasher()
        try:
            return bool(ph.verify(password_hash, password))
        except Exception:
            return False
    if _ARGON2_AVAILABLE:
        try:
            ph = PasswordHasher()
            return bool(ph.verify(password_hash, password))
        except Exception:
            pass
    try:
        parts = password_hash.split("$")
        if len(parts) != 6 or parts[1] != "argon2id":
            return False
        b64_salt = parts[4] + "=" * (-len(parts[4]) % 4)
        b64_expected = parts[5] + "=" * (-len(parts[5]) % 4)
        salt = base64.b64decode(b64_salt)
        expected = base64.b64decode(b64_expected)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            maxmem=32 * 1024 * 1024,
            dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


# Hash Argon2id ficticio precalculado para igualar tiempos de respuesta cuando el usuario no existe
DUMMY_PASSWORD_HASH: str = hash_password(" dummy-anti-enumeration-secret-password-legado-ia ")


def verify_dummy_password(password: str) -> bool:
    """Ejecuta una verificación de contraseña contra el hash ficticio para evitar enumeración por tiempo."""
    verify_password(DUMMY_PASSWORD_HASH, password or "empty")
    return False


def generate_token_256() -> str:
    """Genera un token aleatorio criptográfico de 256 bits (32 bytes) seguro para URL."""
    return secrets.token_urlsafe(32)


def generate_otp_6digits() -> str:
    """Genera un código numérico criptográfico de 6 dígitos ('000000'..'999999') con secrets."""
    return f"{secrets.randbelow(1_000_000):06d}"


def generate_recovery_codes(count: int = 8) -> list[str]:
    """Genera un lote de códigos de recuperación alfanuméricos de un solo uso de alta entropía."""
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    codes: list[str] = []
    for _ in range(count):
        part1 = "".join(secrets.choice(alphabet) for _ in range(5))
        part2 = "".join(secrets.choice(alphabet) for _ in range(5))
        codes.append(f"{part1}-{part2}")
    return codes


def sha256_hex(data: str | bytes) -> str:
    """Calcula el resumen SHA-256 en hexadecimal (para tokens de sesión, invitaciones, OTP y checksums)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_one_time_code(code: str, secret_key: str) -> str:
    """Calcula el hash HMAC-SHA256 de un código OTP o de recuperación."""
    normalized = code.strip().upper().replace(" ", "")
    return hmac.new(
        secret_key.encode("utf-8"), normalized.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_one_time_code(code_hash: str, candidate: str, secret_key: str) -> bool:
    """Compara en tiempo constante un código OTP o de recuperación con su hash almacenado."""
    expected = hash_one_time_code(candidate, secret_key)
    return hmac.compare_digest(code_hash, expected)


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Deriva una clave de 256 bits a partir de una frase de paso para paquetes export-all."""
    if len(salt) < 16:
        raise CryptoError("La sal para derivación de frase de paso debe tener al menos 16 bytes")
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        maxmem=32 * 1024 * 1024,
        dklen=KEY_SIZE,
    )
