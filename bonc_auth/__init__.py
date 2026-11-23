"""Reusable BONC authentication integrations."""

from .client import BoncAuth
from .exceptions import (
    AuthServiceUnavailable,
    BoncAuthError,
    InsufficientPermission,
    InvalidToken,
    InvalidVerificationResponse,
)
from .models import VerifiedUser

__all__ = [
    "BoncAuth",
    "VerifiedUser",
    "BoncAuthError",
    "InvalidToken",
    "InsufficientPermission",
    "AuthServiceUnavailable",
    "InvalidVerificationResponse",
]

__version__ = "0.1.0"
