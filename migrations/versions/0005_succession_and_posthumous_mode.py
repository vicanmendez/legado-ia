"""Succession events, executors and posthumous system state

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-16
"""

from __future__ import annotations

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None
RENDER_AS_BATCH = True

TABLES_IN_REVISION = ("system_state", "executors", "succession_events")
