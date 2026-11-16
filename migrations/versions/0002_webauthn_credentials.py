"""WebAuthn credentials table

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-16
"""

from __future__ import annotations

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None
RENDER_AS_BATCH = True

TABLES_IN_REVISION = ("webauthn_credentials",)
