"""Knowledge base entries, audio files, personality doc and interview topics

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-16
"""

from __future__ import annotations

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None
RENDER_AS_BATCH = True

TABLES_IN_REVISION = ("interview_topics", "entries", "audio_files", "personality_doc")
