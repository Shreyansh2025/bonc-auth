"""Exceptions raised by bonc-auth."""


class BoncAuthError(Exception):
    """Base class for authentication-related errors."""


class InvalidToken(BoncAuthError):
    """The supplied bearer token is missing, invalid, expired, or revoked."""


class InsufficientPermission(BoncAuthError):
    """The authenticated identity does not have the required access."""


class AuthServiceUnavailable(BoncAuthError):
    """The central BONC verification service could not be used safely."""


class InvalidVerificationResponse(AuthServiceUnavailable):
    """The verification service returned an unexpected response."""
