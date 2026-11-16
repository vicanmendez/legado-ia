"""Exportación centralizada de todos los modelos SQLAlchemy 2.x para registro en metadata."""

from app.models.audit import AuditLog
from app.models.conversation import Conversation, LLMSettings, Message
from app.models.knowledge import (
    AudioFile,
    Entry,
    InterviewTopic,
    PersonalityDoc,
    TrainerInterviewMessage,
)
from app.models.succession import Executor, SuccessionEvent, SystemState
from app.models.user import (
    AltchaConsumedChallenge,
    Invitation,
    OTPCode,
    RecoveryCode,
    Session,
    User,
    UserKey,
)
from app.models.webauthn import WebAuthnCredential

__all__ = [
    "AltchaConsumedChallenge",
    "AudioFile",
    "AuditLog",
    "Conversation",
    "Entry",
    "Executor",
    "InterviewTopic",
    "Invitation",
    "LLMSettings",
    "Message",
    "OTPCode",
    "PersonalityDoc",
    "TrainerInterviewMessage",
    "RecoveryCode",
    "Session",
    "SuccessionEvent",
    "SystemState",
    "User",
    "UserKey",
    "WebAuthnCredential",
]
