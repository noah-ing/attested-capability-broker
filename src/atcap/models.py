"""Small wire and decision models for the reference experiment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json


@dataclass(frozen=True)
class IssuanceRequest:
    """Identity-endorsed request whose digest is placed in TPM extraData."""

    version: str
    broker_id: str
    challenge: str
    manifest_digest: str
    identity_key: str
    holder_key: str
    resource_issuer_kid: str
    resource_issuer_key: str
    requested_scope: str
    identity_signature: str = ""

    def body(self) -> dict[str, str]:
        return {
            "version": self.version,
            "broker_id": self.broker_id,
            "challenge": self.challenge,
            "manifest_digest": self.manifest_digest,
            "identity_key": self.identity_key,
            "holder_key": self.holder_key,
            "resource_issuer_kid": self.resource_issuer_kid,
            "resource_issuer_key": self.resource_issuer_key,
            "requested_scope": self.requested_scope,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json(self.body())

    def to_dict(self) -> dict[str, str]:
        return {**self.body(), "identity_signature": self.identity_signature}


@dataclass(frozen=True)
class ResourceChallenge:
    token: str
    credential_id: str
    method: str
    arguments_digest: str
    record_id: str
    audience: str
    expires_at: int


@dataclass(frozen=True)
class SignedDecisionReceipt:
    """A compact JWS whose payload is an RFC 8785 decision object."""

    compact_jws: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    receipt: SignedDecisionReceipt
    result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "allowed": self.allowed,
            "reason": self.reason,
            "receipt_jws": self.receipt.compact_jws,
        }
        if self.result is not None:
            value["result"] = self.result
        return value


@dataclass(frozen=True)
class TpmEvidence:
    """Raw released-verifier inputs from one TPM quote operation."""

    attest: bytes
    signature: bytes
    ak_chain_pem: bytes

    def digestable(self) -> dict[str, str]:
        """Return hashes suitable for receipts without embedding certificates."""

        from .canonical import sha256_hex

        return {
            "tpm_attest_sha256": sha256_hex(self.attest),
            "tpm_signature_sha256": sha256_hex(self.signature),
            "tpm_ak_chain_sha256": sha256_hex(self.ak_chain_pem),
        }
