"""Canonical decision receipts signed with standards-based compact JWS."""

from __future__ import annotations

import json
from typing import Any, Literal

from joserfc import jws
from joserfc.jwk import OKPKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical import canonical_json
from .errors import DecisionError, Reason
from .models import SignedDecisionReceipt

JWS_ALGORITHM = "Ed25519"
JWS_TYPE = "atcap-decision+jws"


class DecisionReceiptPayload(BaseModel):
    """Authenticated claims; validation is deliberately non-coercing and semantic."""

    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)

    schema_version: Literal["atcap-decision-receipt/v1"]
    receipt_id: str = Field(min_length=32)
    deciding_service: Literal["broker", "inventoryd"]
    decision: Literal["allow", "deny"]
    reason: str
    decided_at: int = Field(ge=0)
    credential_id: str | None
    qualified_scope: str | None
    challenge_token_hash: str | None
    manifest_digest: str | None
    method: str | None
    audience: str | None
    arguments_digest: str | None
    record_id: str | None
    invocation_id: int | None = Field(ge=1)
    handler_count_snapshot: int = Field(ge=0)
    handler_invoked: bool
    business_result: Literal["not_applicable", "not_invoked", "completed", "failed"]
    artifact_hashes: dict[str, str]

    @field_validator("reason")
    @classmethod
    def _known_reason(cls, value: str) -> str:
        try:
            Reason(value)
        except ValueError as exc:
            raise ValueError("unknown decision reason") from exc
        return value

    @model_validator(mode="after")
    def _consistent_decision_state(self) -> DecisionReceiptPayload:
        reason = Reason(self.reason)
        if self.handler_invoked != (self.invocation_id is not None):
            raise ValueError("handler_invoked and invocation_id disagree")
        if self.invocation_id is not None and self.handler_count_snapshot < self.invocation_id:
            raise ValueError("handler counter snapshot precedes this invocation")

        if self.deciding_service == "broker":
            if self.handler_invoked or self.business_result != "not_applicable":
                raise ValueError("broker receipts cannot describe handler execution")
            if self.handler_count_snapshot != 0:
                raise ValueError("broker receipts cannot carry a handler counter")
            if reason == Reason.HANDLER_FAILED:
                raise ValueError("broker receipts cannot carry a handler result reason")
            if (self.decision == "allow") != (reason == Reason.ALLOW):
                raise ValueError("broker decision and reason disagree")
            if self.decision == "allow" and self.credential_id is None:
                raise ValueError("broker allow receipt must identify the credential")
            if self.decision == "deny" and self.credential_id is not None:
                raise ValueError("broker denial receipt cannot identify an issued credential")
            if self.decision == "allow" and not all(
                (
                    self.manifest_digest,
                    self.challenge_token_hash,
                    self.qualified_scope,
                    self.artifact_hashes.get("broker_policy_sha256"),
                )
            ):
                raise ValueError("broker allow receipt is missing security bindings")
            return self

        if not all((self.qualified_scope, self.method, self.audience, self.arguments_digest)):
            raise ValueError("inventory receipt is missing resource-binding claims")
        if self.decision == "deny":
            if reason in {Reason.ALLOW, Reason.HANDLER_FAILED}:
                raise ValueError("denial receipt carries an allow-path reason")
            if self.handler_invoked or self.business_result != "not_invoked":
                raise ValueError("denial receipt cannot describe handler execution")
            return self

        if self.credential_id is None or not self.handler_invoked:
            raise ValueError("inventory allow receipt must identify an invocation")
        if not all(
            (
                self.challenge_token_hash,
                self.record_id,
                self.artifact_hashes.get("resource_policy_sha256"),
            )
        ):
            raise ValueError("inventory allow receipt is missing security bindings")
        if reason == Reason.ALLOW and self.business_result == "completed":
            return self
        if reason == Reason.HANDLER_FAILED and self.business_result == "failed":
            return self
        raise ValueError("inventory allow decision, reason, and result disagree")


class ReceiptSigner:
    def __init__(self, private_key: OKPKey, *, key_id: str) -> None:
        self._private_key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, *, key_id: str) -> ReceiptSigner:
        key = OKPKey.generate_key(
            "Ed25519", parameters={"alg": JWS_ALGORITHM, "kid": key_id, "use": "sig"}
        )
        return cls(key, key_id=key_id)

    def public_key(self) -> OKPKey:
        return OKPKey.import_key(self._private_key.as_dict(private=False))

    def sign(self, payload: DecisionReceiptPayload) -> SignedDecisionReceipt:
        protected = {"alg": JWS_ALGORITHM, "kid": self.key_id, "typ": JWS_TYPE}
        compact = jws.serialize_compact(
            protected,
            canonical_json(payload.model_dump(mode="json")),
            self._private_key,
            algorithms=[JWS_ALGORITHM],
        )
        return SignedDecisionReceipt(compact_jws=compact)


class ReceiptVerifier:
    def __init__(self, public_key: OKPKey, *, key_id: str) -> None:
        self._public_key = public_key
        self.key_id = key_id

    def public_jwk(self) -> dict[str, Any]:
        """Return the configured public-only JWK for audit tooling."""

        return self._public_key.as_dict(private=False)

    def verify(self, signed_receipt: SignedDecisionReceipt) -> DecisionReceiptPayload:
        expected = {"alg": JWS_ALGORITHM, "kid": self.key_id, "typ": JWS_TYPE}
        try:
            signed = jws.deserialize_compact(
                signed_receipt.compact_jws,
                self._public_key,
                algorithms=[JWS_ALGORITHM],
            )
            if signed.protected != expected:
                raise ValueError("unexpected protected JWS header")
            decoded: Any = json.loads(signed.payload)
            if not isinstance(decoded, dict):
                raise ValueError("receipt payload is not an object")
            if canonical_json(decoded) != signed.payload:
                raise ValueError("receipt payload is not RFC 8785 canonical JSON")
            return DecisionReceiptPayload.model_validate(decoded)
        except Exception as exc:
            raise DecisionError(
                Reason.RECEIPT_INVALID, "decision receipt failed verification"
            ) from exc
