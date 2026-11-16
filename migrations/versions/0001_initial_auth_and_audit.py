"""Initial auth, sessions, OTP, invitations, recovery codes and audit_log

Revision ID: 0001
Revises: None
Create Date: 2026-11-16
"""

from __future__ import annotations

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None
RENDER_AS_BATCH = True

TABLES_IN_REVISION = (
    "users",
    "user_keys",
    "sessions",
    "otp_codes",
    "invitations",
    "recovery_codes",
    "altcha_consumed_challenges",
    "audit_log",
)
