"""Explicit verifier-owned policy for the one-resource experiment."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ManifestPolicy:
    expected_digest: str
    issuer: str
    signing_key_id: str
    signing_public_b64url: str
    identity_public_hex: str
    system_prompt_hash: str
    policy_bundle_hash: str
    model_hash: str

    def public_dict(self) -> dict[str, str]:
        return {
            "expected_digest": self.expected_digest,
            "issuer": self.issuer,
            "signing_key_id": self.signing_key_id,
            "signing_public_b64url": self.signing_public_b64url,
            "identity_public_hex": self.identity_public_hex,
            "system_prompt_hash": self.system_prompt_hash,
            "policy_bundle_hash": self.policy_bundle_hash,
            "model_hash": self.model_hash,
        }


@dataclass(frozen=True)
class TpmPolicy:
    selection: tuple[tuple[str, tuple[int, ...]], ...]
    expected_pcr_digest: bytes
    trusted_roots_pem: bytes

    def public_dict(self) -> dict[str, object]:
        return {
            "selection": [
                {"bank": bank, "indices": list(indices)} for bank, indices in self.selection
            ],
            "expected_pcr_digest": self.expected_pcr_digest.hex(),
            "trusted_roots_sha256": hashlib.sha256(self.trusted_roots_pem).hexdigest(),
        }


@dataclass(frozen=True)
class BrokerPolicy:
    broker_id: str
    qualified_scope: str
    resource_issuer_kid: str
    resource_issuer_public_hex: str
    challenge_ttl_seconds: int
    credential_ttl_seconds: int
    manifest: ManifestPolicy
    tpm: TpmPolicy

    def public_dict(self) -> dict[str, object]:
        return {
            "broker_id": self.broker_id,
            "qualified_scope": self.qualified_scope,
            "resource_issuer_kid": self.resource_issuer_kid,
            "resource_issuer_public_hex": self.resource_issuer_public_hex,
            "resource_issuer_key_sha256": hashlib.sha256(
                bytes.fromhex(self.resource_issuer_public_hex)
            ).hexdigest(),
            "challenge_ttl_seconds": self.challenge_ttl_seconds,
            "credential_ttl_seconds": self.credential_ttl_seconds,
            "manifest": self.manifest.public_dict(),
            "tpm": self.tpm.public_dict(),
        }


@dataclass(frozen=True)
class ResourcePolicy:
    audience: str
    method: str
    qualified_scope: str
    trusted_broker_public_hex: str
    challenge_ttl_seconds: int
    max_credential_lifetime_seconds: int

    def public_dict(self) -> dict[str, object]:
        return {
            "audience": self.audience,
            "method": self.method,
            "qualified_scope": self.qualified_scope,
            "trusted_broker_public_hex": self.trusted_broker_public_hex,
            "challenge_ttl_seconds": self.challenge_ttl_seconds,
            "max_credential_lifetime_seconds": self.max_credential_lifetime_seconds,
        }
