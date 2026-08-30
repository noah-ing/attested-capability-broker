"""Attested Capability Broker issuance decision."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from typing import Any, Literal

from ca2a_runtime.challenge import verify_challenge
from ca2a_runtime.delegation import DelegationCredential
from ca2a_runtime.errors import AttestationFailed
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_digest, challenge_token_hash
from .challenge import issue_ca2a_challenge_at
from .errors import DecisionError, Reason
from .identity import verify_identity_endorsement
from .manifest_verifier import verify_signed_manifest
from .models import Decision, IssuanceRequest, SignedDecisionReceipt, TpmEvidence
from .policy import BrokerPolicy
from .receipt import DecisionReceiptPayload, ReceiptSigner
from .storage import SQLiteStore
from .tpm import TpmAppraiser, issuance_qualifying_data

Clock = Callable[[], int]

_ISSUANCE_REQUEST_STRING_FIELDS = (
    "version",
    "broker_id",
    "challenge",
    "manifest_digest",
    "identity_key",
    "holder_key",
    "resource_issuer_kid",
    "resource_issuer_key",
    "requested_scope",
    "identity_signature",
)
_TPM_EVIDENCE_BYTES_FIELDS = ("attest", "signature", "ak_chain_pem")
_MISSING = object()


def _validate_issuance_request_runtime(request: IssuanceRequest) -> IssuanceRequest:
    """Reject malformed in-memory request models before hashing or verification."""

    if type(request) is not IssuanceRequest:
        raise DecisionError(
            Reason.REQUEST_BINDING,
            "issuance request has an invalid runtime type",
        )
    for field_name in _ISSUANCE_REQUEST_STRING_FIELDS:
        value = getattr(request, field_name, _MISSING)
        if type(value) is not str:
            raise DecisionError(
                Reason.REQUEST_BINDING,
                f"issuance request field {field_name} must be a string",
            )
    return request


def _validate_tpm_evidence_runtime(evidence: TpmEvidence) -> TpmEvidence:
    """Reject malformed in-memory evidence models before hashing or appraisal."""

    if type(evidence) is not TpmEvidence:
        raise DecisionError(Reason.TPM_INVALID, "TPM evidence has an invalid runtime type")
    for field_name in _TPM_EVIDENCE_BYTES_FIELDS:
        value = getattr(evidence, field_name, _MISSING)
        if type(value) is not bytes:
            raise DecisionError(
                Reason.TPM_INVALID,
                f"TPM evidence field {field_name} must be bytes",
            )
    return evidence


def credential_to_dict(credential: DelegationCredential) -> dict[str, Any]:
    return {**credential.body(), "signature": credential.signature}


def _challenge_expiry(token: str) -> int:
    try:
        return int(token.split(".")[1])
    except (IndexError, ValueError) as exc:
        raise DecisionError(Reason.CHALLENGE_INVALID, "challenge has no valid expiry") from exc


class CapabilityBroker:
    """One-manifest, one-identity, one-resource reference broker."""

    def __init__(
        self,
        *,
        policy: BrokerPolicy,
        store: SQLiteStore,
        challenge_secret: bytes,
        issuer_private_key: Ed25519PrivateKey,
        receipt_signer: ReceiptSigner,
        tpm_appraiser: TpmAppraiser,
        clock: Clock | None = None,
    ) -> None:
        if len(challenge_secret) < 32:
            raise ValueError("broker challenge secret must be at least 32 bytes")
        issuer_public = issuer_private_key.public_key().public_bytes_raw().hex()
        if issuer_public != policy.resource_issuer_public_hex:
            raise ValueError("resource issuer private key does not match broker policy")
        self.policy = policy
        self.store = store
        self.challenge_secret = challenge_secret
        self.issuer_private_key = issuer_private_key
        self.issuer_public = issuer_public
        self.receipt_signer = receipt_signer
        self.tpm_appraiser = tpm_appraiser
        if policy.challenge_ttl_seconds <= 0:
            raise ValueError("broker challenge TTL must be positive")
        if policy.credential_ttl_seconds <= 0:
            raise ValueError("credential TTL must be positive")
        self.clock = clock or (lambda: int(time.time()))

    def new_challenge(self) -> str:
        issued_at = self.clock()
        token, expiry = issue_ca2a_challenge_at(
            self.challenge_secret,
            now=issued_at,
            ttl_seconds=self.policy.challenge_ttl_seconds,
        )
        self.store.store_broker_challenge(
            token_hash=challenge_token_hash(token), issued_at=issued_at, expires_at=expiry
        )
        return token

    def issue(
        self,
        request: IssuanceRequest,
        *,
        manifest: dict[str, Any],
        tpm_evidence: TpmEvidence,
    ) -> Decision:
        token_hash: str | None = None
        manifest_digest: str | None = None
        artifact_hashes: dict[str, str] = {}
        try:
            artifact_hashes["broker_policy_sha256"] = canonical_digest(self.policy.public_dict())
            request = _validate_issuance_request_runtime(request)
            manifest_digest = request.manifest_digest
            token_hash = challenge_token_hash(request.challenge)
            tpm_evidence = _validate_tpm_evidence_runtime(tpm_evidence)
            artifact_hashes.update(tpm_evidence.digestable())
            artifact_hashes["issuance_request_sha256"] = canonical_digest(request.to_dict())

            try:
                verify_challenge(self.challenge_secret, request.challenge, now=self.clock())
            except AttestationFailed as exc:
                message = str(exc).lower()
                reason = (
                    Reason.CHALLENGE_STALE if "expired" in message else Reason.CHALLENGE_INVALID
                )
                raise DecisionError(reason, "broker challenge is not usable") from exc

            verify_signed_manifest(manifest, self.policy.manifest)
            verify_identity_endorsement(request, self.policy)
            self.tpm_appraiser.appraise(
                tpm_evidence,
                expected_qualifying_data=issuance_qualifying_data(request),
                policy=self.policy.tpm,
            )

            # Appraisal is non-mutating. The final transaction is immediately
            # before minting, so invalid evidence cannot burn another holder's
            # bearer challenge and concurrent requests cannot both issue.
            self.store.consume_broker_challenge(token_hash=token_hash, clock=self.clock)

            now = self.clock()
            credential = DelegationCredential(
                credential_id=secrets.token_hex(32),
                issuer=self.issuer_public,
                subject=request.holder_key,
                scope=frozenset({self.policy.qualified_scope}),
                depth=0,
                parent_id=None,
                not_before=now,
                not_after=now + self.policy.credential_ttl_seconds,
            ).sign(self.issuer_private_key)
            receipt = self._receipt(
                decision="allow",
                reason=Reason.ALLOW,
                credential_id=credential.credential_id,
                challenge_hash=token_hash,
                manifest_digest=manifest_digest,
                artifact_hashes=artifact_hashes,
            )
            return Decision(
                allowed=True,
                reason=Reason.ALLOW,
                receipt=receipt,
                result={"credential": credential_to_dict(credential)},
            )
        except DecisionError as exc:
            receipt = self._receipt(
                decision="deny",
                reason=exc.reason,
                credential_id=None,
                challenge_hash=token_hash,
                manifest_digest=manifest_digest,
                artifact_hashes=artifact_hashes,
            )
            return Decision(False, exc.reason, receipt)
        except Exception:
            receipt = self._receipt(
                decision="deny",
                reason=Reason.INTERNAL_ERROR,
                credential_id=None,
                challenge_hash=token_hash,
                manifest_digest=manifest_digest,
                artifact_hashes=artifact_hashes,
            )
            return Decision(False, Reason.INTERNAL_ERROR, receipt)

    def _receipt(
        self,
        *,
        decision: Literal["allow", "deny"],
        reason: Reason,
        credential_id: str | None,
        challenge_hash: str | None,
        manifest_digest: str | None,
        artifact_hashes: dict[str, str],
    ) -> SignedDecisionReceipt:
        payload = DecisionReceiptPayload(
            schema_version="atcap-decision-receipt/v1",
            receipt_id=secrets.token_hex(16),
            deciding_service="broker",
            decision=decision,
            reason=reason,
            decided_at=self.clock(),
            credential_id=credential_id,
            qualified_scope=self.policy.qualified_scope,
            challenge_token_hash=challenge_hash,
            manifest_digest=manifest_digest,
            method=None,
            audience=None,
            arguments_digest=None,
            record_id=None,
            invocation_id=None,
            handler_count_snapshot=0,
            handler_invoked=False,
            business_result="not_applicable",
            artifact_hashes=artifact_hashes,
        )
        return self.receipt_signer.sign(payload)
