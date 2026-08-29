"""Stable, fail-closed decision reasons."""

from __future__ import annotations

from enum import StrEnum


class Reason(StrEnum):
    ALLOW = "ALLOW"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    CHALLENGE_INVALID = "CHALLENGE_INVALID"
    CHALLENGE_STALE = "CHALLENGE_STALE"
    CHALLENGE_CONSUMED = "CHALLENGE_CONSUMED"
    TPM_INVALID = "TPM_INVALID"
    TPM_UNTRUSTED = "TPM_UNTRUSTED"
    PCR_POLICY = "PCR_POLICY"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    MANIFEST_POLICY = "MANIFEST_POLICY"
    IDENTITY_UNAUTHORIZED = "IDENTITY_UNAUTHORIZED"
    IDENTITY_SIGNATURE = "IDENTITY_SIGNATURE"
    REQUEST_BINDING = "REQUEST_BINDING"
    CREDENTIAL_INVALID = "CREDENTIAL_INVALID"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    SCOPE_DENIED = "SCOPE_DENIED"
    HOLDER_PROOF_INVALID = "HOLDER_PROOF_INVALID"
    CREDENTIAL_SPENT = "CREDENTIAL_SPENT"
    RECEIPT_INVALID = "RECEIPT_INVALID"
    HANDLER_FAILED = "HANDLER_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class DecisionError(Exception):
    """Expected fail-closed decision with a stable public reason."""

    def __init__(self, reason: Reason, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


class PostInvocationError(RuntimeError):
    """Receipt/result failure after the private handler was invoked."""

    def __init__(self, message: str, *, invocation_id: int, completed: bool) -> None:
        super().__init__(message)
        self.invocation_id = invocation_id
        self.completed = completed
