"""Trusted local controller for the untrusted disposable-holder worker."""

from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any, Literal

from ca2a_runtime.delegation import DelegationCredential, HolderProof, verify_holder_proof
from ca2a_runtime.errors import HolderProofInvalid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from atcap.broker import credential_to_dict
from atcap.canonical import canonical_digest, canonical_json, challenge_token_hash
from atcap.errors import DecisionError, Reason
from atcap.inventory import InventoryApplication, InventoryArguments, LookupInput
from atcap.models import Decision, SignedDecisionReceipt
from atcap.receipt import ReceiptVerifier
from atcap.storage import SQLiteStore

from .errors import DuplicateRunIdError, LabBindingError, LabProtocolError
from .record import ExperimentRecordSigner
from .transport import FakeWorkerTransport
from .wire import (
    ASSURANCE_DISCLAIMER,
    TRUST_BOUNDARY,
    AttemptObservation,
    CapabilityGrantWire,
    CaseObservation,
    CaseSpec,
    Ed25519PublicJwk,
    ExperimentRecordPayload,
    InventoryArgumentsWire,
    PreparedCase,
    PublicReceiptVerifier,
    SignedExperimentRecord,
    UntrustedRunpodObservation,
    WorkerRequest,
    WorkerResponse,
    WorkerResponseBundle,
    strict_json_object,
)

MAX_WORKER_RESPONSE_BYTES = 1_048_576


@dataclass(frozen=True)
class CapabilityGrant:
    credential: DelegationCredential
    broker_receipt: SignedDecisionReceipt
    expected_manifest_digest: str
    expected_broker_policy_sha256: str
    expected_broker_challenge_token_hash: str
    expected_tpm_attest_sha256: str
    expected_tpm_signature_sha256: str
    expected_tpm_ak_chain_sha256: str
    expected_issuance_request_sha256: str

    def to_wire(self) -> CapabilityGrantWire:
        return CapabilityGrantWire(
            credential=credential_to_dict(self.credential),
            broker_receipt_jws=self.broker_receipt.compact_jws,
            expected_manifest_digest=self.expected_manifest_digest,
            expected_broker_policy_sha256=self.expected_broker_policy_sha256,
            expected_broker_challenge_token_hash=self.expected_broker_challenge_token_hash,
            expected_tpm_attest_sha256=self.expected_tpm_attest_sha256,
            expected_tpm_signature_sha256=self.expected_tpm_signature_sha256,
            expected_tpm_ak_chain_sha256=self.expected_tpm_ak_chain_sha256,
            expected_issuance_request_sha256=self.expected_issuance_request_sha256,
        )

    @classmethod
    def from_wire(cls, value: CapabilityGrantWire) -> CapabilityGrant:
        try:
            credential = DelegationCredential.from_dict(value.credential)
        except Exception as exc:
            raise LabProtocolError("prepared credential is malformed") from exc
        return cls(
            credential=credential,
            broker_receipt=SignedDecisionReceipt(compact_jws=value.broker_receipt_jws),
            expected_manifest_digest=value.expected_manifest_digest,
            expected_broker_policy_sha256=value.expected_broker_policy_sha256,
            expected_broker_challenge_token_hash=value.expected_broker_challenge_token_hash,
            expected_tpm_attest_sha256=value.expected_tpm_attest_sha256,
            expected_tpm_signature_sha256=value.expected_tpm_signature_sha256,
            expected_tpm_ak_chain_sha256=value.expected_tpm_ak_chain_sha256,
            expected_issuance_request_sha256=value.expected_issuance_request_sha256,
        )


class TrustedController:
    """Own local policy, stores, receipt trust roots, and experiment signer."""

    def __init__(
        self,
        *,
        inventory: InventoryApplication,
        store: SQLiteStore,
        broker_receipt_verifier: ReceiptVerifier,
        resource_receipt_verifier: ReceiptVerifier,
        experiment_signer: ExperimentRecordSigner,
        expected_worker_public_key: str,
        worker_image: str,
        worker_code_digest: str,
        clock: Any | None = None,
    ) -> None:
        try:
            self._worker_public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(expected_worker_public_key)
            )
        except ValueError as exc:
            raise ValueError("expected worker public key must be 32-byte Ed25519 hex") from exc
        self.inventory = inventory
        self.store = store
        self.broker_receipt_verifier = broker_receipt_verifier
        self.resource_receipt_verifier = resource_receipt_verifier
        self.experiment_signer = experiment_signer
        self.expected_worker_public_key = expected_worker_public_key
        self.worker_image = worker_image
        self.worker_code_digest = worker_code_digest
        self.clock = clock or (lambda: int(time.time()))
        self._case_ids: set[str] = set()
        self._case_lock = threading.Lock()

    def _reserve_case_id(self, case_id: str) -> None:
        with self._case_lock:
            if case_id in self._case_ids:
                raise DuplicateRunIdError("controller case ID was already reserved")
            self._case_ids.add(case_id)

    def _verify_grant(self, grant: CapabilityGrant) -> None:
        try:
            payload = self.broker_receipt_verifier.verify(grant.broker_receipt)
        except DecisionError as exc:
            raise LabBindingError("broker receipt did not verify") from exc
        if (
            payload.deciding_service != "broker"
            or payload.decision != "allow"
            or payload.reason != Reason.ALLOW
            or payload.credential_id != grant.credential.credential_id
            or payload.qualified_scope != self.inventory.policy.qualified_scope
            or payload.manifest_digest != grant.expected_manifest_digest
            or payload.challenge_token_hash != grant.expected_broker_challenge_token_hash
            or payload.artifact_hashes
            != {
                "broker_policy_sha256": grant.expected_broker_policy_sha256,
                "tpm_attest_sha256": grant.expected_tpm_attest_sha256,
                "tpm_signature_sha256": grant.expected_tpm_signature_sha256,
                "tpm_ak_chain_sha256": grant.expected_tpm_ak_chain_sha256,
                "issuance_request_sha256": grant.expected_issuance_request_sha256,
            }
        ):
            raise LabBindingError("broker receipt does not bind this capability")
        if grant.credential.subject != self.expected_worker_public_key:
            raise LabBindingError("credential subject does not match the expected worker key")
        if grant.credential.issuer != self.inventory.policy.trusted_broker_public_hex:
            raise LabBindingError("credential issuer does not match resource policy")
        if grant.credential.scope != frozenset({self.inventory.policy.qualified_scope}):
            raise LabBindingError("credential scope does not match resource policy")

    def prepare_case(self, grant: CapabilityGrant, spec: CaseSpec) -> PreparedCase:
        """Verify issuance evidence locally, then issue exact resource challenges."""

        self._reserve_case_id(spec.case_id)
        self._verify_grant(grant)
        count = spec.concurrency if spec.variant == "concurrent" else 1
        requests: list[WorkerRequest] = []
        for index in range(count):
            run_id = spec.case_id if count == 1 else f"{spec.case_id}.{index + 1:02d}"
            record_id = spec.record_id if count == 1 else f"{spec.record_id}.{index + 1:02d}"
            arguments = InventoryArguments(sku=spec.sku)
            challenge = self.inventory.issue_resource_challenge(
                credential_id=grant.credential.credential_id,
                arguments=arguments,
                record_id=record_id,
            )
            requests.append(
                WorkerRequest(
                    schema_version="atcap-runpod-worker-request/v1",
                    case_id=spec.case_id,
                    run_id=run_id,
                    variant=spec.variant,
                    credential=credential_to_dict(grant.credential),
                    challenge=challenge.token,
                    audience=self.inventory.policy.audience,
                    qualified_scope=self.inventory.policy.qualified_scope,
                    record_id=record_id,
                    arguments=InventoryArgumentsWire(sku=spec.sku),
                    worker_image=self.worker_image,
                    worker_code_digest=self.worker_code_digest,
                )
            )
        return PreparedCase(
            spec=spec,
            grant=grant.to_wire(),
            requests=requests,
            invocation_count_before=self.inventory.invocation_count,
        )

    @staticmethod
    def parse_response(raw: bytes) -> WorkerResponse:
        if type(raw) is not bytes or len(raw) > MAX_WORKER_RESPONSE_BYTES:
            raise LabProtocolError("worker response failed bounded bytes validation")
        try:
            decoded = strict_json_object(raw)
            if canonical_json(decoded) != raw:
                raise ValueError("response is not canonical")
            return WorkerResponse.model_validate(decoded)
        except Exception as exc:
            raise LabProtocolError("worker response failed strict canonical validation") from exc

    @staticmethod
    def parse_response_bundle(raw: bytes) -> WorkerResponseBundle:
        if type(raw) is not bytes or len(raw) > MAX_WORKER_RESPONSE_BYTES:
            raise LabProtocolError("worker response bundle failed bounded bytes validation")
        try:
            decoded = strict_json_object(raw)
            if canonical_json(decoded) != raw:
                raise ValueError("response bundle is not canonical")
            return WorkerResponseBundle.model_validate(decoded)
        except Exception as exc:
            raise LabProtocolError(
                "worker response bundle failed strict canonical validation"
            ) from exc

    def _verify_worker_response(self, request: WorkerRequest, response: WorkerResponse) -> None:
        expected_digest = canonical_digest(request.model_dump(mode="json"))
        if response.case_id != request.case_id or response.run_id != request.run_id:
            raise LabBindingError("worker response run binding does not match the request")
        if response.request_sha256 != expected_digest:
            raise LabBindingError("worker response request digest does not match")
        if response.worker_public_key != self.expected_worker_public_key:
            raise LabBindingError("worker response public key does not match")
        if response.worker_image != self.worker_image:
            raise LabBindingError("worker response image does not match")
        if response.worker_code_digest != self.worker_code_digest:
            raise LabBindingError("worker response code digest does not match")
        try:
            self._worker_public_key.verify(
                bytes.fromhex(response.holder_signature),
                canonical_json(response.signed_body().model_dump(mode="json")),
            )
        except (InvalidSignature, ValueError) as exc:
            raise LabBindingError("worker holder signature did not verify") from exc

    def _proof_verifies(
        self,
        *,
        request: WorkerRequest,
        response: WorkerResponse,
        credential: DelegationCredential,
        record_id: str,
        arguments: dict[str, Any],
    ) -> bool:
        """Non-mutating cA2A proof appraisal for the prescribed test context."""

        try:
            proof = HolderProof.from_dict(response.holder_proof.model_dump(mode="json"))
            verify_holder_proof(
                proof,
                credential,
                audience=request.audience,
                challenge_secret=self.inventory.challenge_secret,
                requested_capability=request.qualified_scope,
                record_id=record_id,
                sealed_payload=canonical_json(arguments),
                caller_channel_key=None,
                parent_record_hash=None,
            )
        except (HolderProofInvalid, TypeError, ValueError):
            return False
        return True

    def _preappraise_prescribed_proof(
        self, request: WorkerRequest, response: WorkerResponse
    ) -> None:
        """Require the remote proof to match its test variant before any spend."""

        try:
            credential = DelegationCredential.from_dict(request.credential)
        except Exception as exc:
            raise LabProtocolError("prepared credential failed proof pre-appraisal") from exc
        if response.holder_proof.challenge != request.challenge:
            raise LabBindingError("worker proof challenge does not match the prepared request")
        if request.variant == "wrong-holder":
            if response.proof_subject == credential.subject:
                raise LabBindingError("wrong-holder case did not use a distinct proof subject")
        elif response.proof_subject != credential.subject:
            raise LabBindingError("worker proof subject does not match the prepared credential")

        original_arguments = request.arguments.model_dump(mode="json")
        verifies_original = self._proof_verifies(
            request=request,
            response=response,
            credential=credential,
            record_id=request.record_id,
            arguments=original_arguments,
        )
        if request.variant in {"valid", "replay", "concurrent"}:
            if not verifies_original:
                raise LabBindingError("allow-path worker proof failed local pre-appraisal")
            return
        if verifies_original:
            raise LabBindingError("denial-case worker returned a valid original proof")

        if request.variant == "argument-substitution":
            prescribed = self._proof_verifies(
                request=request,
                response=response,
                credential=credential,
                record_id=request.record_id,
                arguments={"sku": f"{request.arguments.sku}-substituted"},
            )
        elif request.variant == "record-substitution":
            prescribed = self._proof_verifies(
                request=request,
                response=response,
                credential=credential,
                record_id=f"{request.record_id}-substituted",
                arguments=original_arguments,
            )
        elif request.variant == "wrong-holder":
            prescribed = self._proof_verifies(
                request=request,
                response=response,
                credential=replace(credential, subject=response.proof_subject),
                record_id=request.record_id,
                arguments=original_arguments,
            )
        else:
            prescribed = response.holder_proof.signature == 7
        if not prescribed:
            raise LabBindingError("worker proof does not match the prescribed adversarial variant")

    def _observe_decision(
        self,
        *,
        decision: Decision,
        request: WorkerRequest,
        response: WorkerResponse,
        redemption_sequence: int,
    ) -> AttemptObservation:
        try:
            payload = self.resource_receipt_verifier.verify(decision.receipt)
        except DecisionError as exc:
            raise LabBindingError("resource receipt did not verify") from exc
        expected_decision = "allow" if decision.allowed else "deny"
        expected_arguments_digest = canonical_digest(request.arguments.model_dump(mode="json"))
        expected_token_hash = (
            None if request.variant == "malformed" else challenge_token_hash(request.challenge)
        )
        if (
            payload.deciding_service != "inventoryd"
            or payload.decision != expected_decision
            or payload.reason != decision.reason
            or payload.credential_id
            != DelegationCredential.from_dict(request.credential).credential_id
            or payload.qualified_scope != request.qualified_scope
            or payload.method != self.inventory.policy.method
            or payload.audience != request.audience
            or payload.arguments_digest != expected_arguments_digest
            or payload.record_id != request.record_id
            or payload.challenge_token_hash != expected_token_hash
            or payload.artifact_hashes
            != {"resource_policy_sha256": canonical_digest(self.inventory.policy.public_dict())}
        ):
            raise LabBindingError("resource receipt does not bind the observed decision")
        if payload.handler_invoked:
            if decision.result is None:
                raise LabBindingError("invoked decision omitted its result state")
            invocation_number = decision.result.get("invocation_number")
            if invocation_number != payload.invocation_id:
                raise LabBindingError("resource receipt invocation ID does not match result")
        elif payload.invocation_id is not None:
            raise LabBindingError("non-invocation receipt contains an invocation ID")
        if payload.business_result == "not_applicable":
            raise LabBindingError("inventory receipt has a broker-only business result")
        return AttemptObservation(
            run_id=request.run_id,
            redemption_sequence=redemption_sequence,
            request_sha256=canonical_digest(request.model_dump(mode="json")),
            worker_response_sha256=canonical_digest(response.model_dump(mode="json")),
            holder_proof_sha256=canonical_digest(response.holder_proof.model_dump(mode="json")),
            allowed=decision.allowed,
            reason=decision.reason,
            receipt_jws=decision.receipt.compact_jws,
            receipt_verified=True,
            handler_invoked=payload.handler_invoked,
            business_result=payload.business_result,
            invocation_id=payload.invocation_id,
        )

    def _validate_case_inputs(
        self,
        prepared: PreparedCase,
        responses: list[WorkerResponse],
    ) -> tuple[CapabilityGrant, list[WorkerResponse]]:
        """Validate one complete case without mutating challenge or spend state."""
        grant = CapabilityGrant.from_wire(prepared.grant)
        self._verify_grant(grant)
        if len(responses) != len(prepared.requests):
            raise LabProtocolError("worker response count does not match prepared requests")
        by_run_id = {response.run_id: response for response in responses}
        if len(by_run_id) != len(responses):
            raise LabProtocolError("worker returned duplicate run IDs")
        expected_run_ids = {request.run_id for request in prepared.requests}
        if set(by_run_id) != expected_run_ids:
            raise LabProtocolError("worker response run IDs do not match prepared requests")
        ordered_responses = [by_run_id[request.run_id] for request in prepared.requests]
        for request, response in zip(prepared.requests, ordered_responses, strict=True):
            self._verify_worker_response(request, response)
            self._preappraise_prescribed_proof(request, response)
        return grant, ordered_responses

    def _redeem_validated_case(
        self,
        prepared: PreparedCase,
        grant: CapabilityGrant,
        ordered_responses: list[WorkerResponse],
    ) -> CaseObservation:
        """Redeem inputs that already passed complete-bundle validation."""

        invocation_before = self.inventory.invocation_count
        observations: list[AttemptObservation] = []

        def redeem(request: WorkerRequest, response: WorkerResponse) -> Decision:
            lookup = LookupInput(
                sku=request.arguments.sku,
                credential=request.credential,
                holder_proof=response.holder_proof.model_dump(mode="json"),
                record_id=request.record_id,
            )
            return self.inventory.redeem(lookup)

        if prepared.spec.variant == "concurrent":
            barrier = threading.Barrier(len(prepared.requests) + 1)

            def race_one(request: WorkerRequest, response: WorkerResponse) -> Decision:
                barrier.wait(timeout=10)
                return redeem(request, response)

            with ThreadPoolExecutor(max_workers=len(prepared.requests)) as executor:
                futures = [
                    (request, executor.submit(race_one, request, response))
                    for request, response in zip(prepared.requests, ordered_responses, strict=True)
                ]
                barrier.wait(timeout=10)
                decisions = [
                    (request, response, future.result(timeout=15))
                    for (request, future), response in zip(futures, ordered_responses, strict=True)
                ]
            for request, response, decision in decisions:
                observations.append(
                    self._observe_decision(
                        decision=decision,
                        request=request,
                        response=response,
                        redemption_sequence=1,
                    )
                )
        else:
            request = prepared.requests[0]
            response = ordered_responses[0]
            first = redeem(request, response)
            observations.append(
                self._observe_decision(
                    decision=first,
                    request=request,
                    response=response,
                    redemption_sequence=1,
                )
            )
            if prepared.spec.variant == "replay":
                replayed = redeem(request, response)
                observations.append(
                    self._observe_decision(
                        decision=replayed,
                        request=request,
                        response=response,
                        redemption_sequence=2,
                    )
                )

        self._require_expected_outcomes(prepared.spec, observations)
        invocation_delta = self.inventory.invocation_count - invocation_before
        redemption_count = self.store.redemption_count(grant.credential.credential_id)
        expected_invocations = (
            1 if prepared.spec.variant in {"valid", "replay", "concurrent"} else 0
        )
        expected_redemptions = expected_invocations
        if invocation_delta != expected_invocations or redemption_count != expected_redemptions:
            raise LabBindingError("observed handler/spend counts violate the case invariant")
        return CaseObservation(
            case_id=prepared.spec.case_id,
            variant=prepared.spec.variant,
            broker_receipt_jws=grant.broker_receipt.compact_jws,
            broker_receipt_verified=True,
            worker_binding_verified=True,
            worker_public_key=self.expected_worker_public_key,
            worker_image=self.worker_image,
            worker_code_digest=self.worker_code_digest,
            worker_binding_scope="holder-key-and-claimed-digest-only",
            runpod_metadata=[response.runpod_metadata for response in ordered_responses],
            attempts=observations,
            invocation_delta=invocation_delta,
            credential_redemption_count=redemption_count,
        )

    def finalize_cases(
        self,
        inputs: list[tuple[PreparedCase, list[WorkerResponse]]],
    ) -> list[CaseObservation]:
        """Validate every remote case before the first state-mutating redemption."""

        validated = [
            (prepared, *self._validate_case_inputs(prepared, responses))
            for prepared, responses in inputs
        ]
        return [
            self._redeem_validated_case(prepared, grant, responses)
            for prepared, grant, responses in validated
        ]

    def finalize_case(
        self,
        prepared: PreparedCase,
        responses: list[WorkerResponse],
    ) -> CaseObservation:
        """Validate one untrusted case, redeem, and enforce its invariants."""

        return self.finalize_cases([(prepared, responses)])[0]

    @staticmethod
    def _require_expected_outcomes(spec: CaseSpec, observations: list[AttemptObservation]) -> None:
        observed = [(attempt.allowed, attempt.reason) for attempt in observations]
        if spec.variant == "valid":
            expected = [(True, Reason.ALLOW)]
        elif spec.variant == "replay":
            expected = [(True, Reason.ALLOW), (False, Reason.CHALLENGE_CONSUMED)]
        elif spec.variant == "concurrent":
            expected = [(True, Reason.ALLOW)] + [(False, Reason.CREDENTIAL_SPENT)] * (
                spec.concurrency - 1
            )
            observed = sorted(observed, key=lambda item: (not item[0], item[1]))
        else:
            expected = [(False, Reason.HOLDER_PROOF_INVALID)]
        if observed != expected:
            raise LabBindingError("observed decision set does not match the adversarial case")

    async def run_case(
        self,
        grant: CapabilityGrant,
        spec: CaseSpec,
        transport: FakeWorkerTransport,
        *,
        timeout_seconds: float = 5.0,
    ) -> CaseObservation:
        prepared = self.prepare_case(grant, spec)
        raw_responses = await asyncio.gather(
            *(
                transport.submit(request, timeout_seconds=timeout_seconds)
                for request in prepared.requests
            )
        )
        responses = [self.parse_response(raw) for raw in raw_responses]
        return self.finalize_case(prepared, responses)

    def sign_record(
        self,
        *,
        experiment_id: str,
        commit_sha: str,
        uv_lock_sha256: str,
        tpm_mode: Literal["test-double", "real-swtpm"],
        tpm_evidence_verified: bool,
        runpod_observation: UntrustedRunpodObservation,
        cases: list[CaseObservation],
    ) -> tuple[ExperimentRecordPayload, SignedExperimentRecord]:
        attempts = [attempt for case in cases for attempt in case.attempts]
        payload = ExperimentRecordPayload(
            schema_version="atcap-runpod-experiment-record/v1",
            experiment_id=experiment_id,
            observed_at=self.clock(),
            commit_sha=commit_sha,
            uv_lock_sha256=uv_lock_sha256,
            assurance_scope="local-controller-observation-only",
            trust_boundary=TRUST_BOUNDARY,
            assurance_disclaimer=ASSURANCE_DISCLAIMER,
            tpm_mode=tpm_mode,
            tpm_evidence_verified=tpm_evidence_verified,
            tpm_assurance_included=tpm_mode == "real-swtpm" and tpm_evidence_verified,
            worker_public_key=self.expected_worker_public_key,
            worker_image=self.worker_image,
            worker_code_digest=self.worker_code_digest,
            worker_binding_scope="holder-key-and-claimed-digest-only",
            broker_receipt_verifier=PublicReceiptVerifier(
                key_id=self.broker_receipt_verifier.key_id,
                public_jwk=Ed25519PublicJwk.model_validate(
                    self.broker_receipt_verifier.public_jwk()
                ),
            ),
            resource_receipt_verifier=PublicReceiptVerifier(
                key_id=self.resource_receipt_verifier.key_id,
                public_jwk=Ed25519PublicJwk.model_validate(
                    self.resource_receipt_verifier.public_jwk()
                ),
            ),
            runpod_observation=runpod_observation,
            broker_receipt_count=len(cases),
            resource_receipt_count=len(attempts),
            allowed_attempt_count=sum(attempt.allowed for attempt in attempts),
            denied_attempt_count=sum(not attempt.allowed for attempt in attempts),
            handler_invocation_count=sum(case.invocation_delta for case in cases),
            credential_redemption_count=sum(case.credential_redemption_count for case in cases),
            cases=cases,
        )
        return payload, self.experiment_signer.sign(payload)
