"""Standards-based local JWS for the observed experiment transcript."""

from __future__ import annotations

from collections import Counter
from typing import Any

from joserfc import jws
from joserfc.jwk import OKPKey

from atcap.canonical import canonical_json
from atcap.errors import Reason
from atcap.models import SignedDecisionReceipt
from atcap.receipt import ReceiptVerifier

from .errors import ExperimentRecordError
from .wire import (
    Ed25519PublicJwk,
    ExperimentRecordPayload,
    SignedExperimentRecord,
    strict_json_object,
)

JWS_ALGORITHM = "Ed25519"
JWS_TYPE = "atcap-runpod-experiment+jws"
EXPECTED_QUALIFIED_SCOPE = "mcp://inventoryd/tool/inventory.lookup"
EXPECTED_METHOD = "inventory.lookup"
EXPECTED_AUDIENCE = "inventoryd"


class ExperimentRecordSigner:
    def __init__(self, private_key: OKPKey, *, key_id: str) -> None:
        self._private_key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, *, key_id: str) -> ExperimentRecordSigner:
        key = OKPKey.generate_key(
            "Ed25519",
            parameters={"alg": JWS_ALGORITHM, "kid": key_id, "use": "sig"},
        )
        return cls(key, key_id=key_id)

    @classmethod
    def from_private_jwk(
        cls, private_jwk: dict[str, Any], *, key_id: str
    ) -> ExperimentRecordSigner:
        return cls(OKPKey.import_key(private_jwk), key_id=key_id)

    def private_jwk(self) -> dict[str, Any]:
        return self._private_key.as_dict(private=True)

    def public_jwk(self) -> dict[str, Any]:
        return self._private_key.as_dict(private=False)

    def sign(self, payload: ExperimentRecordPayload) -> SignedExperimentRecord:
        compact = jws.serialize_compact(
            {"alg": JWS_ALGORITHM, "kid": self.key_id, "typ": JWS_TYPE},
            canonical_json(payload.model_dump(mode="json")),
            self._private_key,
            algorithms=[JWS_ALGORITHM],
        )
        return SignedExperimentRecord(compact_jws=compact)


class ExperimentRecordVerifier:
    def __init__(self, public_key: OKPKey, *, key_id: str) -> None:
        self._public_key = public_key
        self.key_id = key_id

    @classmethod
    def from_public_jwk(
        cls, public_jwk: dict[str, Any] | Ed25519PublicJwk, *, key_id: str
    ) -> ExperimentRecordVerifier:
        value = (
            public_jwk.model_dump(mode="python")
            if isinstance(public_jwk, Ed25519PublicJwk)
            else public_jwk
        )
        return cls(OKPKey.import_key(value), key_id=key_id)

    def verify(self, signed: SignedExperimentRecord) -> ExperimentRecordPayload:
        expected = {"alg": JWS_ALGORITHM, "kid": self.key_id, "typ": JWS_TYPE}
        try:
            value = jws.deserialize_compact(
                signed.compact_jws,
                self._public_key,
                algorithms=[JWS_ALGORITHM],
            )
            if value.protected != expected:
                raise ValueError("unexpected protected header")
            decoded = strict_json_object(value.payload)
            if canonical_json(decoded) != value.payload:
                raise ValueError("record is not RFC 8785 canonical JSON")
            payload = ExperimentRecordPayload.model_validate(decoded)
            self._verify_embedded_receipts(payload)
            return payload
        except Exception as exc:
            raise ExperimentRecordError("experiment record verification failed") from exc

    @staticmethod
    def _verify_embedded_receipts(payload: ExperimentRecordPayload) -> None:
        """Re-verify every included receipt and its observable case semantics."""

        def lower_hex(value: str) -> bool:
            return len(value) == 64 and all(character in "0123456789abcdef" for character in value)

        broker_key = payload.broker_receipt_verifier
        resource_key = payload.resource_receipt_verifier
        broker_verifier = ReceiptVerifier(
            OKPKey.import_key(broker_key.public_jwk.model_dump(mode="python")),
            key_id=broker_key.key_id,
        )
        resource_verifier = ReceiptVerifier(
            OKPKey.import_key(resource_key.public_jwk.model_dump(mode="python")),
            key_id=resource_key.key_id,
        )
        broker_jws_values: set[str] = set()
        resource_jws_values: set[str] = set()
        broker_receipt_ids: set[str] = set()
        resource_receipt_ids: set[str] = set()
        credential_ids: set[str] = set()
        broker_challenge_hashes: set[str] = set()
        qualified_scopes: set[str] = set()
        methods: set[str] = set()
        audiences: set[str] = set()
        manifest_digests: set[str] = set()
        broker_policy_digests: set[str] = set()
        resource_policy_digests: set[str] = set()
        issuance_request_digests: set[str] = set()
        tpm_attest_digests: set[str] = set()
        tpm_signature_digests: set[str] = set()
        tpm_ak_chain_digests: set[str] = set()
        handler_count_snapshots: list[int] = []
        resource_challenge_hashes: list[str] = []
        replay_challenge_hash: str | None = None
        broker_artifacts = {
            "broker_policy_sha256",
            "issuance_request_sha256",
            "tpm_ak_chain_sha256",
            "tpm_attest_sha256",
            "tpm_signature_sha256",
        }

        for case in payload.cases:
            if case.broker_receipt_jws in broker_jws_values:
                raise ValueError("experiment reuses a broker receipt")
            broker_jws_values.add(case.broker_receipt_jws)
            broker = broker_verifier.verify(
                SignedDecisionReceipt(compact_jws=case.broker_receipt_jws)
            )
            if (
                broker.receipt_id in broker_receipt_ids
                or broker.deciding_service != "broker"
                or broker.decision != "allow"
                or broker.reason != Reason.ALLOW
                or broker.credential_id is None
                or broker.credential_id in credential_ids
                or broker.qualified_scope is None
                or broker.challenge_token_hash is None
                or broker.challenge_token_hash in broker_challenge_hashes
                or broker.manifest_digest is None
                or broker.decided_at > payload.observed_at
                or set(broker.artifact_hashes) != broker_artifacts
                or any(
                    not lower_hex(value)
                    for value in (
                        broker.credential_id,
                        broker.challenge_token_hash,
                        *broker.artifact_hashes.values(),
                    )
                )
                or not broker.manifest_digest.startswith("sha256:")
                or not lower_hex(broker.manifest_digest.removeprefix("sha256:"))
                or any(
                    value is not None
                    for value in (
                        broker.method,
                        broker.audience,
                        broker.arguments_digest,
                        broker.record_id,
                    )
                )
            ):
                raise ValueError("broker receipt contradicts the experiment case")
            broker_receipt_ids.add(broker.receipt_id)
            credential_ids.add(broker.credential_id)
            broker_challenge_hashes.add(broker.challenge_token_hash)
            qualified_scopes.add(broker.qualified_scope)
            manifest_digests.add(broker.manifest_digest)
            broker_policy_digests.add(broker.artifact_hashes["broker_policy_sha256"])
            issuance_request_digests.add(broker.artifact_hashes["issuance_request_sha256"])
            tpm_attest_digests.add(broker.artifact_hashes["tpm_attest_sha256"])
            tpm_signature_digests.add(broker.artifact_hashes["tpm_signature_sha256"])
            tpm_ak_chain_digests.add(broker.artifact_hashes["tpm_ak_chain_sha256"])

            case_challenge_hashes: list[str | None] = []
            case_record_ids: list[str] = []
            case_arguments_digests: list[str] = []
            case_decided_at: list[int] = []
            case_handler_snapshots: list[int] = []
            for attempt in case.attempts:
                if attempt.receipt_jws in resource_jws_values:
                    raise ValueError("experiment reuses a resource receipt")
                resource_jws_values.add(attempt.receipt_jws)
                resource = resource_verifier.verify(
                    SignedDecisionReceipt(compact_jws=attempt.receipt_jws)
                )
                expected_decision = "allow" if attempt.allowed else "deny"
                expected_challenge = None if case.variant == "malformed" else True
                if (
                    resource.receipt_id in resource_receipt_ids
                    or resource.deciding_service != "inventoryd"
                    or resource.decision != expected_decision
                    or resource.reason != attempt.reason
                    or resource.credential_id != broker.credential_id
                    or resource.qualified_scope != broker.qualified_scope
                    or resource.method is None
                    or resource.audience is None
                    or resource.arguments_digest is None
                    or resource.record_id is None
                    or resource.manifest_digest is not None
                    or resource.decided_at < broker.decided_at
                    or resource.decided_at > payload.observed_at
                    or resource.handler_invoked is not attempt.handler_invoked
                    or resource.business_result != attempt.business_result
                    or resource.invocation_id != attempt.invocation_id
                    or set(resource.artifact_hashes) != {"resource_policy_sha256"}
                    or not lower_hex(resource.artifact_hashes["resource_policy_sha256"])
                    or not lower_hex(resource.arguments_digest)
                    or (expected_challenge is None and resource.challenge_token_hash is not None)
                    or (
                        expected_challenge is True
                        and (
                            resource.challenge_token_hash is None
                            or not lower_hex(resource.challenge_token_hash)
                        )
                    )
                ):
                    raise ValueError("resource receipt contradicts the experiment attempt")
                resource_receipt_ids.add(resource.receipt_id)
                handler_count_snapshots.append(resource.handler_count_snapshot)
                case_challenge_hashes.append(resource.challenge_token_hash)
                if resource.challenge_token_hash is not None:
                    resource_challenge_hashes.append(resource.challenge_token_hash)
                case_record_ids.append(resource.record_id)
                case_arguments_digests.append(resource.arguments_digest)
                case_decided_at.append(resource.decided_at)
                case_handler_snapshots.append(resource.handler_count_snapshot)
                methods.add(resource.method)
                audiences.add(resource.audience)
                resource_policy_digests.add(resource.artifact_hashes["resource_policy_sha256"])
            if case.variant == "replay" and any(
                len(set(values)) != 1
                for values in (
                    case_challenge_hashes,
                    case_record_ids,
                    case_arguments_digests,
                )
            ):
                raise ValueError("replay receipts do not reuse the same call context")
            if case.variant == "replay":
                replay_challenge_hash = case_challenge_hashes[0]
                if case_decided_at != sorted(case_decided_at) or case_handler_snapshots != sorted(
                    case_handler_snapshots
                ):
                    raise ValueError("replay receipts contradict their redemption order")
            if case.variant == "concurrent" and (
                len(set(case_challenge_hashes)) != len(case_challenge_hashes)
                or len(set(case_record_ids)) != len(case_record_ids)
                or len(set(case_arguments_digests)) != 1
            ):
                raise ValueError("concurrent receipts contradict their fresh call contexts")
            expected_invocation_id = {
                "valid": 1,
                "replay": 2,
                "concurrent": 3,
            }.get(case.variant)
            allowed_invocation_ids = [
                attempt.invocation_id for attempt in case.attempts if attempt.allowed
            ]
            if expected_invocation_id is not None and allowed_invocation_ids != [
                expected_invocation_id
            ]:
                raise ValueError("allowed receipt contradicts the fixed case execution order")

        if any(
            len(values) != 1
            for values in (
                qualified_scopes,
                methods,
                audiences,
                manifest_digests,
                broker_policy_digests,
                resource_policy_digests,
            )
        ):
            raise ValueError("embedded receipts disagree on resource bindings")
        if (
            qualified_scopes != {EXPECTED_QUALIFIED_SCOPE}
            or methods != {EXPECTED_METHOD}
            or audiences != {EXPECTED_AUDIENCE}
        ):
            raise ValueError("embedded receipts do not name the fixed inventory capability")
        if len(issuance_request_digests) != len(payload.cases):
            raise ValueError("broker receipts reuse an issuance request")
        if payload.tpm_mode == "real-swtpm" and (
            len(tpm_ak_chain_digests) != 1
            or len(tpm_attest_digests) != len(payload.cases)
            or len(tpm_signature_digests) != len(payload.cases)
        ):
            raise ValueError("real-swtpm broker receipts contradict the fresh-quote trace")
        if (
            not handler_count_snapshots
            or any(
                snapshot > payload.handler_invocation_count for snapshot in handler_count_snapshots
            )
            or max(handler_count_snapshots) != payload.handler_invocation_count
        ):
            raise ValueError("resource receipt snapshots contradict the final handler count")
        challenge_counts = Counter(resource_challenge_hashes)
        if (
            replay_challenge_hash is None
            or challenge_counts.get(replay_challenge_hash) != 2
            or any(
                count != (2 if challenge == replay_challenge_hash else 1)
                for challenge, count in challenge_counts.items()
            )
        ):
            raise ValueError("resource challenge hashes are reused outside the replay pair")
