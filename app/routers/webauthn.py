"""Router de segundo factor y gestión de Passkeys WebAuthn (/webauthn)."""

from __future__ import annotations

from app.config import Settings
from app.db._compat_sa import Session as DbSession
from app.routers.dependencies import (
    HTTPRequestContext,
    HTTPResponseData,
    require_pending_2fa_user,
    require_user,
)
from app.schemas.auth import ValidationError
from app.schemas.webauthn import (
    WebAuthnAuthenticateVerifySchema,
    WebAuthnRegisterVerifySchema,
    WebAuthnRenameSchema,
    WebAuthnRevokeSchema,
)
from app.services.webauthn import (
    WebAuthnError,
    generate_authentication_options_for_session,
    generate_registration_options_for_session,
    list_user_credentials,
    rename_user_credential,
    revoke_user_credential,
    verify_and_store_registration,
    verify_authentication_step2,
)


def handle_post_register_options(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    sess, user = require_user(db, req, settings=settings)
    opts = generate_registration_options_for_session(db, sess, user, settings=settings)
    return HTTPResponseData(status_code=200, json_payload=opts)


def handle_post_register_verify(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    sess, user = require_user(db, req, settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = WebAuthnRegisterVerifySchema(
            credential_id_b64=str(data.get("credential_id_b64", "")),
            public_key_b64=str(data.get("public_key_b64", "")),
            challenge_b64=str(data.get("challenge_b64", "")),
            device_name=str(data.get("device_name", "")),
            sign_count=int(data.get("sign_count", 0)),
            user_verified=bool(data.get("user_verified", True)),
            rp_id=str(data.get("rp_id", "localhost")),
            origin=str(data.get("origin", "http://localhost:8000")),
        )
        cred = verify_and_store_registration(
            db, sess, user, schema, ip_address=req.client_ip, settings=settings
        )
    except (ValidationError, WebAuthnError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    return HTTPResponseData(
        status_code=201,
        json_payload={
            "status": "registered",
            "id": cred.id,
            "device_name": cred.device_name,
            "sign_count": cred.sign_count,
        },
    )


def handle_post_authenticate_options(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    sess, user = require_pending_2fa_user(db, req)
    try:
        opts = generate_authentication_options_for_session(db, sess, user, settings=settings)
    except WebAuthnError as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})
    return HTTPResponseData(status_code=200, json_payload=opts)


def handle_post_authenticate_verify(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    sess, user = require_pending_2fa_user(db, req)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = WebAuthnAuthenticateVerifySchema(
            credential_id_b64=str(data.get("credential_id_b64", "")),
            challenge_b64=str(data.get("challenge_b64", "")),
            signature_b64=str(data.get("signature_b64", "")),
            sign_count=int(data.get("sign_count", 0)),
            user_verified=bool(data.get("user_verified", True)),
            rp_id=str(data.get("rp_id", "localhost")),
            origin=str(data.get("origin", "http://localhost:8000")),
        )
        auth_res = verify_authentication_step2(
            db, sess, user, schema, ip_address=req.client_ip, settings=settings
        )
    except (ValidationError, WebAuthnError) as exc:
        return HTTPResponseData(status_code=401, json_payload={"detail": str(exc)})

    resp = HTTPResponseData(
        status_code=200,
        json_payload={
            "status": "authenticated",
            "role": auth_res.user.role,
            "csrf_token": auth_res.csrf_token,
        },
    )
    resp.set_secure_session_cookie(auth_res.session_token)
    return resp


def handle_get_credentials(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, user = require_user(db, req, settings=settings)
    creds = list_user_credentials(db, user.id)
    return HTTPResponseData(
        status_code=200,
        json_payload=[
            {
                "id": c.id,
                "device_name": c.device_name,
                "sign_count": c.sign_count,
                "created_at": c.created_at.isoformat(),
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            }
            for c in creds
        ],
    )


def handle_patch_credential(
    db: DbSession,
    req: HTTPRequestContext,
    credential_id: int,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, user = require_user(db, req, settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = WebAuthnRenameSchema(device_name=str(data.get("device_name", "")))
        cred = rename_user_credential(db, user, credential_id, schema.device_name)
    except (ValidationError, WebAuthnError) as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})
    return HTTPResponseData(
        status_code=200,
        json_payload={"id": cred.id, "device_name": cred.device_name},
    )


def handle_delete_credential(
    db: DbSession,
    req: HTTPRequestContext,
    credential_id: int,
    settings: Settings | None = None,
) -> HTTPResponseData:
    _, user = require_user(db, req, settings=settings)
    data = req.json_data if req.json_data is not None else req.form_data
    schema = WebAuthnRevokeSchema(
        recovery_code=str(data.get("recovery_code", "")) if data.get("recovery_code") else None
    )
    try:
        revoke_user_credential(
            db, user, credential_id, recovery_code=schema.recovery_code, settings=settings
        )
    except WebAuthnError as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})
    return HTTPResponseData(status_code=200, json_payload={"status": "revoked"})
