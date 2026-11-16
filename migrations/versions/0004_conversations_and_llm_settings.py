"""Conversations, messages and LLM settings

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-16
"""

from __future__ import annotations

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None
RENDER_AS_BATCH = True

TABLES_IN_REVISION = ("conversations", "messages", "llm_settings")
