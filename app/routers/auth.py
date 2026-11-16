"""Router de autenticación (/auth): ALTCHA, login en 2 pasos, OTP, invitaciones, recuperación y logout."""

from __future__ import annotations

from app.config import Settings
from app.db._compat_sa import Session as DbSession
from app.routers.dependencies import (
    CSRF_COOKIE_NAME,
    HTTPRequestContext,
    HTTPResponseData,
    SESSION_COOKIE_NAME,
    require_pending_2fa_user,
    require_user,
    verify_csrf,
)
from app.schemas.auth import (
    LoginStep1Schema,
    RegisterInviteSchema,
    ValidationError,
    VerifyOTPSchema,
    VerifyRecoveryCodeSchema,
)
from app.services.altcha import create_altcha_challenge
from app.services.auth import (
    AccountLockedError,
    AuthenticationError,
    InvitationError,
    consume_invitation_and_register,
    get_pending_2fa_session,
    get_valid_invitation,
    login_step1,
    logout_session,
    verify_step2_otp,
    verify_step2_recovery_code,
)
from app.services.crypto import generate_token_256
from app.ui import (
    html_response,
    redirect_response,
    render_2fa_page,
    render_invite_register_page,
    render_login_page,
    render_recovery_codes_once_page,
    wants_html,
)


def _role_home_url(role: str) -> str:
    if role == "entrenador":
        return "/trainer/dashboard"
    if role == "albacea":
        return "/executor/panel"
    return "/friend/dashboard"


def handle_get_altcha_challenge(settings: Settings | None = None) -> HTTPResponseData:
    data = create_altcha_challenge(settings=settings)
    return HTTPResponseData(status_code=200, json_payload=data)


def handle_get_login_page() -> HTTPResponseData:
    pre_csrf = generate_token_256()
    resp = html_response(render_login_page(pre_csrf), status_code=200)
    resp.cookies[CSRF_COOKIE_NAME] = {
        "value": pre_csrf,
        "httponly": True,
        "secure": True,
        "samesite": "Strict",
        "path": "/",
    }
    return resp


def handle_post_login_step1(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    expected_csrf = req.cookies.get(CSRF_COOKIE_NAME, "")
    verify_csrf(req, expected_csrf)

    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = LoginStep1Schema(
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            altcha_payload=str(data.get("altcha_payload", "")),
        )
        res = login_step1(
            db,
            username=schema.username,
            password=schema.password,
            altcha_payload=schema.altcha_payload,
            ip_address=req.client_ip,
            user_agent=req.headers.get("User-Agent"),
            settings=settings,
        )
    except AccountLockedError as exc:
        if wants_html(req):
            return html_response(render_login_page(expected_csrf, error_msg=str(exc)), status_code=429)
        return HTTPResponseData(status_code=429, json_payload={"detail": str(exc)})
    except (ValidationError, AuthenticationError) as exc:
        if wants_html(req):
            return html_response(
                render_login_page(
                    expected_csrf, error_msg="Credenciales o verificación inválidas"
                ),
                status_code=401,
            )
        return HTTPResponseData(
            status_code=401,
            json_payload={"detail": "Credenciales o verificación inválidas", "error": str(exc)},
        )

    if wants_html(req):
        resp = redirect_response("/auth/2fa")
        resp.set_secure_session_cookie(res.pending_session_token)
        return resp

    resp = HTTPResponseData(
        status_code=200,
        json_payload={
            "status": "2fa_required",
            "next_url": "/auth/2fa",
            "csrf_token": res.csrf_token,
        },
    )
    resp.set_secure_session_cookie(res.pending_session_token)
    return resp


def handle_get_2fa_page(db: DbSession, req: HTTPRequestContext) -> HTTPResponseData:
    raw_token = req.cookies.get(SESSION_COOKIE_NAME, "")
    try:
        sess, _ = get_pending_2fa_session(db, raw_token)
    except AuthenticationError as exc:
        if wants_html(req):
            return redirect_response("/auth/login")
        return HTTPResponseData(status_code=401, json_payload={"detail": str(exc)})

    return html_response(render_2fa_page(sess.csrf_token), status_code=200)


def handle_post_2fa_otp(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    sess, _ = require_pending_2fa_user(db, req)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = VerifyOTPSchema(code=str(data.get("code", "")))
        auth_res = verify_step2_otp(
            db,
            raw_session_token=req.cookies.get(SESSION_COOKIE_NAME, ""),
            otp_code=schema.code,
            ip_address=req.client_ip,
            settings=settings,
        )
    except AccountLockedError as exc:
        if wants_html(req):
            return html_response(render_2fa_page(sess.csrf_token, error_msg=str(exc)), status_code=429)
        return HTTPResponseData(status_code=429, json_payload={"detail": str(exc)})
    except (ValidationError, AuthenticationError) as exc:
        if wants_html(req):
            return html_response(render_2fa_page(sess.csrf_token, error_msg=str(exc)), status_code=401)
        return HTTPResponseData(status_code=401, json_payload={"detail": str(exc)})

    if wants_html(req):
        resp = redirect_response(_role_home_url(auth_res.user.role))
        resp.set_secure_session_cookie(auth_res.session_token)
        return resp

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


def handle_post_2fa_recovery(
    db: DbSession,
    req: HTTPRequestContext,
    settings: Settings | None = None,
) -> HTTPResponseData:
    sess, _ = require_pending_2fa_user(db, req)
    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = VerifyRecoveryCodeSchema(recovery_code=str(data.get("recovery_code", "")))
        auth_res = verify_step2_recovery_code(
            db,
            raw_session_token=req.cookies.get(SESSION_COOKIE_NAME, ""),
            recovery_code=schema.recovery_code,
            ip_address=req.client_ip,
            settings=settings,
        )
    except AccountLockedError as exc:
        if wants_html(req):
            return html_response(render_2fa_page(sess.csrf_token, error_msg=str(exc)), status_code=429)
        return HTTPResponseData(status_code=429, json_payload={"detail": str(exc)})
    except (ValidationError, AuthenticationError) as exc:
        if wants_html(req):
            return html_response(render_2fa_page(sess.csrf_token, error_msg=str(exc)), status_code=401)
        return HTTPResponseData(status_code=401, json_payload={"detail": str(exc)})

    if wants_html(req):
        resp = redirect_response(_role_home_url(auth_res.user.role))
        resp.set_secure_session_cookie(auth_res.session_token)
        return resp

    resp = HTTPResponseData(
        status_code=200,
        json_payload={
            "status": "authenticated",
            "role": auth_res.user.role,
            "csrf_token": auth_res.csrf_token,
            "remaining_recovery_codes": auth_res.remaining_recovery_codes,
        },
    )
    resp.set_secure_session_cookie(auth_res.session_token)
    return resp


def handle_post_logout(db: DbSession, req: HTTPRequestContext) -> HTTPResponseData:
    require_user(db, req)
    raw_token = req.cookies.get(SESSION_COOKIE_NAME, "")
    logout_session(db, raw_token, ip_address=req.client_ip)
    if wants_html(req):
        resp = redirect_response("/auth/login")
        resp.clear_session_cookie()
        return resp
    resp = HTTPResponseData(status_code=200, json_payload={"status": "logged_out"})
    resp.clear_session_cookie()
    return resp


def handle_get_invite_page(
    db: DbSession,
    token: str,
    req: HTTPRequestContext | None = None,
) -> HTTPResponseData:
    try:
        inv = get_valid_invitation(db, token)
    except InvitationError as exc:
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    pre_csrf = generate_token_256()
    if req is not None and wants_html(req):
        resp = html_response(
            render_invite_register_page(pre_csrf, token=token, target_role=inv.target_role),
            status_code=200,
        )
    else:
        resp = HTTPResponseData(
            status_code=200,
            json_payload={
                "status": "valid_invitation",
                "target_role": inv.target_role,
                "csrf_token": pre_csrf,
            },
        )
    resp.cookies[CSRF_COOKIE_NAME] = {
        "value": pre_csrf,
        "httponly": True,
        "secure": True,
        "samesite": "Strict",
        "path": "/",
    }
    return resp


def handle_post_consume_invite(
    db: DbSession,
    req: HTTPRequestContext,
    token: str,
    settings: Settings | None = None,
) -> HTTPResponseData:
    expected_csrf = req.cookies.get(CSRF_COOKIE_NAME, "")
    verify_csrf(req, expected_csrf)

    data = req.json_data if req.json_data is not None else req.form_data
    try:
        schema = RegisterInviteSchema(
            username=str(data.get("username", "")),
            email=str(data.get("email", "")),
            password=str(data.get("password", "")),
            altcha_payload=str(data.get("altcha_payload", "")),
        )
        user, recovery_codes = consume_invitation_and_register(
            db,
            raw_token=token,
            username=schema.username,
            email=schema.email,
            password=schema.password,
            altcha_payload=schema.altcha_payload,
            ip_address=req.client_ip,
            settings=settings,
        )
    except (ValidationError, InvitationError, ValueError) as exc:
        if wants_html(req):
            return html_response(
                render_invite_register_page(
                    expected_csrf, token=token, target_role="amigo", error_msg=str(exc)
                ),
                status_code=400,
            )
        return HTTPResponseData(status_code=400, json_payload={"detail": str(exc)})

    if wants_html(req):
        return html_response(
            render_recovery_codes_once_page(user.username, user.role, recovery_codes),
            status_code=201,
        )

    return HTTPResponseData(
        status_code=201,
        json_payload={
            "status": "account_activated",
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "recovery_codes": recovery_codes,
        },
    )
