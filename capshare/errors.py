"""Exceptions with *safe* messages.

Every error that can reach a remote device is a CapShareError: it carries a short
machine-readable `code` plus a human message that never contains file-system paths,
SQL text, or stack traces. Anything else becomes a generic "internal error" at the API.
"""
from __future__ import annotations


class CapShareError(Exception):
    status = 400
    code = "ERROR"

    def __init__(self, message: str, code: str | None = None, details: dict | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details or {}


class BadRequest(CapShareError):
    status = 400
    code = "BAD_REQUEST"


class AuthRequired(CapShareError):
    status = 401
    code = "AUTH_REQUIRED"


class Forbidden(CapShareError):
    status = 403
    code = "FORBIDDEN"


class NotFound(CapShareError):
    status = 404
    code = "NOT_FOUND"


class GrantRejected(CapShareError):
    """A grant/delegation/revoke was refused by the permission engine.

    `code` says exactly why (ESCALATION, DEPTH_LIMIT, EXPIRY_OUTLIVES_PARENT, ...).
    """
    status = 403
    code = "GRANT_REJECTED"


class TooLarge(CapShareError):
    status = 413
    code = "TOO_LARGE"


class CascadeLimitExceeded(CapShareError):
    """Revocation would touch more grants than the configured safety ceiling."""
    status = 409
    code = "CASCADE_LIMIT_EXCEEDED"


class AclError(CapShareError):
    """A POSIX ACL command failed or could not be verified."""
    status = 500
    code = "ACL_ERROR"


class TransferTerminated(CapShareError):
    """Raised inside a streaming transfer when authority disappears mid-way."""
    status = 403
    code = "TRANSFER_TERMINATED"
