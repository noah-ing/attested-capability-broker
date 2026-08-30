"""Trusted-controller state and signed-evidence schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from atcap.errors import Reason

from .worker_wire import (
    HEX_32_PATTERN,
    IMAGE_PATTERN,
    RUN_ID_PATTERN,
    InventoryArgumentsWire,
    RunpodJobEnvelope,
    UntrustedRunpodMetadata,
    Variant,
    WorkerPayload,
    WorkerRequest,
    WorkerResponse,
    WorkerResponseBody,
    WorkerResponseBundle,
    strict_json_object,
)

COMMIT_PATTERN = r"^[0-9a-f]{40}$"
AGENT_MANIFEST_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
ASSURANCE_DISCLAIMER: Literal[
    "This experiment tests application-level behavior against a remote untrusted caller. "
    "The self-contained JWS and bundled verifier establish internal signature consistency "
    "only; controller origin requires independently pinning the verifier key. With that "
    "pin, the JWS authenticates only the configured local controller's observed transcript; "
    "it does not attest Runpod, its host, control plane, queue, or worker; "
    "registry metadata or worker-image execution; holder-key residency; TPM/worker "
    "co-location; agent execution; TEE, network, or runtime integrity; or safe behavior."
] = (
    "This experiment tests application-level behavior against a remote untrusted caller. "
    "The self-contained JWS and bundled verifier establish internal signature consistency "
    "only; controller origin requires independently pinning the verifier key. With that "
    "pin, the JWS authenticates only the configured local controller's observed transcript; "
    "it does not attest Runpod, its host, control plane, queue, or worker; "
    "registry metadata or worker-image execution; holder-key residency; TPM/worker "
    "co-location; agent execution; TEE, network, or runtime integrity; or safe behavior."
)
TRUST_BOUNDARY: Literal[
    "local-controller-policy-store-tpm-root-and-verification-keys-trusted;"
    "runpod-host-control-plane-queue-worker-registry-metadata-and-output-untrusted"
] = (
    "local-controller-policy-store-tpm-root-and-verification-keys-trusted;"
    "runpod-host-control-plane-queue-worker-registry-metadata-and-output-untrusted"
)


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


class CaseSpec(ClosedModel):
    case_id: str = Field(pattern=RUN_ID_PATTERN)
    variant: Variant
    sku: str = Field(default="widget-42", min_length=1, max_length=128)
    record_id: str = Field(min_length=1, max_length=256)
    concurrency: int = Field(default=1, ge=1, le=64)

    @model_validator(mode="after")
    def _variant_count(self) -> CaseSpec:
        if self.variant == "concurrent" and self.concurrency < 2:
            raise ValueError("concurrent case requires at least two attempts")
        if self.variant != "concurrent" and self.concurrency != 1:
            raise ValueError("only concurrent cases may request multiple attempts")
        return self


class CapabilityGrantWire(ClosedModel):
    credential: dict[str, JsonValue]
    broker_receipt_jws: str = Field(min_length=1)
    expected_manifest_digest: str = Field(pattern=AGENT_MANIFEST_DIGEST_PATTERN)
    expected_broker_policy_sha256: str = Field(pattern=HEX_32_PATTERN)
    expected_broker_challenge_token_hash: str = Field(pattern=HEX_32_PATTERN)
    expected_tpm_attest_sha256: str = Field(pattern=HEX_32_PATTERN)
    expected_tpm_signature_sha256: str = Field(pattern=HEX_32_PATTERN)
    expected_tpm_ak_chain_sha256: str = Field(pattern=HEX_32_PATTERN)
    expected_issuance_request_sha256: str = Field(pattern=HEX_32_PATTERN)


class PreparedCase(ClosedModel):
    spec: CaseSpec
    grant: CapabilityGrantWire
    requests: list[WorkerRequest] = Field(min_length=1, max_length=64)
    invocation_count_before: int = Field(ge=0)

    @model_validator(mode="after")
    def _request_shape(self) -> PreparedCase:
        expected = self.spec.concurrency if self.spec.variant == "concurrent" else 1
        if len(self.requests) != expected:
            raise ValueError("prepared request count does not match case specification")
        if any(request.case_id != self.spec.case_id for request in self.requests):
            raise ValueError("prepared request names another case")
        if any(request.variant != self.spec.variant for request in self.requests):
            raise ValueError("prepared request names another adversarial variant")
        run_ids = [request.run_id for request in self.requests]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("prepared case has duplicate worker run IDs")
        return self


class AttemptObservation(ClosedModel):
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    redemption_sequence: int = Field(ge=1, le=2)
    request_sha256: str = Field(pattern=HEX_32_PATTERN)
    worker_response_sha256: str = Field(pattern=HEX_32_PATTERN)
    holder_proof_sha256: str = Field(pattern=HEX_32_PATTERN)
    allowed: bool
    reason: str
    receipt_jws: str = Field(min_length=1)
    receipt_verified: Literal[True]
    handler_invoked: bool
    business_result: Literal["not_invoked", "completed", "failed"]
    invocation_id: int | None = Field(ge=1)

    @field_validator("reason")
    @classmethod
    def _known_reason(cls, value: str) -> str:
        try:
            Reason(value)
        except ValueError as exc:
            raise ValueError("attempt has an unknown reason") from exc
        return value

    @model_validator(mode="after")
    def _decision_semantics(self) -> AttemptObservation:
        if self.allowed:
            if (
                self.reason != Reason.ALLOW
                or not self.handler_invoked
                or self.business_result != "completed"
                or self.invocation_id is None
            ):
                raise ValueError("allowed attempt has inconsistent execution semantics")
        elif (
            self.reason == Reason.ALLOW
            or self.handler_invoked
            or self.business_result != "not_invoked"
            or self.invocation_id is not None
        ):
            raise ValueError("denied attempt has inconsistent execution semantics")
        return self


class CaseObservation(ClosedModel):
    case_id: str = Field(pattern=RUN_ID_PATTERN)
    variant: Variant
    broker_receipt_jws: str = Field(min_length=1)
    broker_receipt_verified: Literal[True]
    worker_binding_verified: Literal[True]
    worker_public_key: str = Field(pattern=HEX_32_PATTERN)
    worker_image: str = Field(pattern=IMAGE_PATTERN)
    worker_code_digest: str = Field(pattern=HEX_32_PATTERN)
    worker_binding_scope: Literal["holder-key-and-claimed-digest-only"]
    runpod_metadata: list[UntrustedRunpodMetadata] = Field(min_length=1, max_length=64)
    attempts: list[AttemptObservation] = Field(min_length=1, max_length=65)
    invocation_delta: int = Field(ge=0, le=1)
    credential_redemption_count: int = Field(ge=0, le=1)

    @model_validator(mode="after")
    def _case_semantics(self) -> CaseObservation:
        run_ids = [attempt.run_id for attempt in self.attempts]
        observed = [(attempt.allowed, attempt.reason) for attempt in self.attempts]
        if self.variant == "valid":
            expected = [(True, Reason.ALLOW)]
        elif self.variant == "replay":
            expected = [
                (True, Reason.ALLOW),
                (False, Reason.CHALLENGE_CONSUMED),
            ]
            if [attempt.redemption_sequence for attempt in self.attempts] != [1, 2]:
                raise ValueError("replay case has inconsistent redemption sequence")
            if len(set(run_ids)) != 1:
                raise ValueError("replay case must repeat exactly one worker request")
            replay_bindings = {
                (
                    attempt.request_sha256,
                    attempt.worker_response_sha256,
                    attempt.holder_proof_sha256,
                )
                for attempt in self.attempts
            }
            if len(replay_bindings) != 1:
                raise ValueError("replay case must reuse the exact request and proof")
        elif self.variant == "concurrent":
            if len(self.attempts) < 2 or any(
                attempt.redemption_sequence != 1 for attempt in self.attempts
            ):
                raise ValueError("concurrent case has inconsistent attempt shape")
            if len(run_ids) != len(set(run_ids)):
                raise ValueError("concurrent case has duplicate attempt run IDs")
            for field_name in (
                "request_sha256",
                "worker_response_sha256",
                "holder_proof_sha256",
            ):
                if len({getattr(attempt, field_name) for attempt in self.attempts}) != len(
                    self.attempts
                ):
                    raise ValueError("concurrent case has duplicate request/proof bindings")
            expected = [(True, Reason.ALLOW)] + [(False, Reason.CREDENTIAL_SPENT)] * (
                len(self.attempts) - 1
            )
            observed = sorted(observed, key=lambda item: (not item[0], item[1]))
        else:
            expected = [(False, Reason.HOLDER_PROOF_INVALID)]
        if self.variant not in {"replay", "concurrent"} and (
            len(set(run_ids)) != 1 or self.attempts[0].redemption_sequence != 1
        ):
            raise ValueError("single-attempt case has inconsistent run/sequence bindings")
        expected_metadata = len(self.attempts) if self.variant == "concurrent" else 1
        if len(self.runpod_metadata) != expected_metadata:
            raise ValueError("case metadata count does not match worker requests")
        expected_count = 1 if self.variant in {"valid", "replay", "concurrent"} else 0
        if (
            observed != expected
            or self.invocation_delta != expected_count
            or self.credential_redemption_count != expected_count
        ):
            raise ValueError("case observation contradicts its adversarial variant")
        return self


class UntrustedRunpodObservation(ClosedModel):
    """Bounded local projection of provider metadata; identifiers are hashed."""

    provider: Literal["runpod"]
    trust: Literal["untrusted"]
    endpoint_id_sha256: str = Field(pattern=HEX_32_PATTERN)
    job_id_sha256: str = Field(pattern=HEX_32_PATTERN)
    worker_id_sha256: str | None = Field(pattern=HEX_32_PATTERN)
    status: Literal["COMPLETED"]
    worker_image_argument: str = Field(pattern=IMAGE_PATTERN)
    delay_time_ms: int | None = Field(ge=0, le=86_400_000)
    execution_time_ms: int | None = Field(ge=0, le=86_400_000)


class Ed25519PublicJwk(ClosedModel):
    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    alg: Literal["Ed25519"]
    kid: str = Field(min_length=1, max_length=128)
    use: Literal["sig"]


class PublicReceiptVerifier(ClosedModel):
    key_id: str = Field(min_length=1, max_length=128)
    public_jwk: Ed25519PublicJwk

    @model_validator(mode="after")
    def _matching_key_id(self) -> PublicReceiptVerifier:
        if self.public_jwk.kid != self.key_id:
            raise ValueError("receipt verifier key ID disagrees with its public JWK")
        return self


class ExperimentRecordPayload(ClosedModel):
    schema_version: Literal["atcap-runpod-experiment-record/v1"]
    experiment_id: str = Field(pattern=RUN_ID_PATTERN)
    observed_at: int = Field(ge=0)
    commit_sha: str = Field(pattern=COMMIT_PATTERN)
    uv_lock_sha256: str = Field(pattern=HEX_32_PATTERN)
    assurance_scope: Literal["local-controller-observation-only"]
    trust_boundary: Literal[
        "local-controller-policy-store-tpm-root-and-verification-keys-trusted;"
        "runpod-host-control-plane-queue-worker-registry-metadata-and-output-untrusted"
    ]
    assurance_disclaimer: Literal[
        "This experiment tests application-level behavior against a remote untrusted caller. "
        "The self-contained JWS and bundled verifier establish internal signature consistency "
        "only; controller origin requires independently pinning the verifier key. With that "
        "pin, the JWS authenticates only the configured local controller's observed transcript; "
        "it does not attest Runpod, its host, control plane, queue, or worker; "
        "registry metadata or worker-image execution; holder-key residency; TPM/worker "
        "co-location; agent execution; TEE, network, or runtime integrity; or safe behavior."
    ]
    tpm_mode: Literal["test-double", "real-swtpm"]
    tpm_evidence_verified: bool
    tpm_assurance_included: bool
    worker_public_key: str = Field(pattern=HEX_32_PATTERN)
    worker_image: str = Field(pattern=IMAGE_PATTERN)
    worker_code_digest: str = Field(pattern=HEX_32_PATTERN)
    worker_binding_scope: Literal["holder-key-and-claimed-digest-only"]
    broker_receipt_verifier: PublicReceiptVerifier
    resource_receipt_verifier: PublicReceiptVerifier
    runpod_observation: UntrustedRunpodObservation
    broker_receipt_count: int = Field(ge=1)
    resource_receipt_count: int = Field(ge=1)
    allowed_attempt_count: int = Field(ge=0)
    denied_attempt_count: int = Field(ge=0)
    handler_invocation_count: int = Field(ge=0)
    credential_redemption_count: int = Field(ge=0)
    cases: list[CaseObservation] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def _record_semantics(self) -> ExperimentRecordPayload:
        if (
            self.broker_receipt_verifier.key_id == self.resource_receipt_verifier.key_id
            or self.broker_receipt_verifier.public_jwk.x
            == self.resource_receipt_verifier.public_jwk.x
        ):
            raise ValueError("broker and resource receipt verifiers must be distinct")
        if self.runpod_observation.worker_image_argument != self.worker_image:
            raise ValueError("provider observation contradicts the configured worker image")
        if self.tpm_evidence_verified is not (self.tpm_mode == "real-swtpm"):
            raise ValueError("TPM evidence flag contradicts the selected appraisal mode")
        expected_tpm_assurance = self.tpm_mode == "real-swtpm" and self.tpm_evidence_verified
        if self.tpm_assurance_included is not expected_tpm_assurance:
            raise ValueError("TPM assurance flag disagrees with the verified evidence path")
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("experiment record has duplicate case IDs")
        required_variants = {
            "valid",
            "replay",
            "argument-substitution",
            "record-substitution",
            "wrong-holder",
            "malformed",
            "concurrent",
        }
        observed_variants = [case.variant for case in self.cases]
        if (
            len(observed_variants) != len(required_variants)
            or set(observed_variants) != required_variants
        ):
            raise ValueError("experiment record does not contain the exact required case matrix")
        for case in self.cases:
            if (
                case.worker_public_key != self.worker_public_key
                or case.worker_image != self.worker_image
                or case.worker_code_digest != self.worker_code_digest
            ):
                raise ValueError("experiment case has inconsistent worker bindings")
        attempts = [attempt for case in self.cases for attempt in case.attempts]
        invocation_ids = [
            attempt.invocation_id for attempt in attempts if attempt.invocation_id is not None
        ]
        if len(invocation_ids) != len(set(invocation_ids)) or set(invocation_ids) != set(
            range(1, len(invocation_ids) + 1)
        ):
            raise ValueError("allowed attempts do not identify distinct local invocations")
        observed = {
            "broker": len(self.cases),
            "resource": len(attempts),
            "allowed": sum(attempt.allowed for attempt in attempts),
            "denied": sum(not attempt.allowed for attempt in attempts),
            "invocations": sum(case.invocation_delta for case in self.cases),
            "redemptions": sum(case.credential_redemption_count for case in self.cases),
        }
        declared = {
            "broker": self.broker_receipt_count,
            "resource": self.resource_receipt_count,
            "allowed": self.allowed_attempt_count,
            "denied": self.denied_attempt_count,
            "invocations": self.handler_invocation_count,
            "redemptions": self.credential_redemption_count,
        }
        if declared != observed:
            raise ValueError("experiment aggregate counts do not match observed cases")
        return self


class SignedExperimentRecord(ClosedModel):
    compact_jws: str = Field(min_length=1)


class PublicExperimentVerifier(ClosedModel):
    schema_version: Literal["atcap-runpod-experiment-verifier/v1"]
    key_id: str = Field(min_length=1, max_length=128)
    public_jwk: Ed25519PublicJwk

    @model_validator(mode="after")
    def _matching_key_id(self) -> PublicExperimentVerifier:
        if self.public_jwk.kid != self.key_id:
            raise ValueError("experiment verifier key ID disagrees with its public JWK")
        return self


class ResourcePolicyState(ClosedModel):
    audience: str
    method: str
    qualified_scope: str
    trusted_broker_public_hex: str = Field(pattern=HEX_32_PATTERN)
    challenge_ttl_seconds: int = Field(gt=0)
    max_credential_lifetime_seconds: int = Field(gt=0)


class TrustedLabState(ClosedModel):
    """Reconstructible local-only state; this file must remain mode 0600."""

    schema_version: Literal["atcap-runpod-trusted-state/v1"]
    experiment_id: str = Field(pattern=RUN_ID_PATTERN)
    commit_sha: str = Field(pattern=COMMIT_PATTERN)
    uv_lock_sha256: str = Field(pattern=HEX_32_PATTERN)
    tpm_mode: Literal["test-double", "real-swtpm"]
    tpm_evidence_verified: bool
    database_filename: Literal["lab.sqlite3"]
    resource_policy: ResourcePolicyState
    resource_challenge_secret: str = Field(min_length=64)
    inventory_receipt_key_id: str
    inventory_receipt_private_jwk: dict[str, JsonValue]
    broker_receipt_key_id: str
    broker_receipt_public_jwk: dict[str, JsonValue]
    experiment_key_id: str
    experiment_private_jwk: dict[str, JsonValue]
    expected_worker_public_key: str = Field(pattern=HEX_32_PATTERN)
    worker_image: str = Field(pattern=IMAGE_PATTERN)
    worker_code_digest: str = Field(pattern=HEX_32_PATTERN)
    prepared_cases: list[PreparedCase] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def _complete_prepared_matrix(self) -> TrustedLabState:
        required_variants = {
            "valid",
            "replay",
            "argument-substitution",
            "record-substitution",
            "wrong-holder",
            "malformed",
            "concurrent",
        }
        case_ids = [case.spec.case_id for case in self.prepared_cases]
        variants = [case.spec.variant for case in self.prepared_cases]
        run_ids = [request.run_id for case in self.prepared_cases for request in case.requests]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("trusted state has duplicate case IDs")
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("trusted state has duplicate global worker run IDs")
        if len(variants) != len(required_variants) or set(variants) != required_variants:
            raise ValueError("trusted state does not contain the exact required case matrix")
        for case in self.prepared_cases:
            if any(
                request.worker_image != self.worker_image
                or request.worker_code_digest != self.worker_code_digest
                for request in case.requests
            ):
                raise ValueError("trusted state has inconsistent worker bindings")
        return self


__all__ = [
    "ASSURANCE_DISCLAIMER",
    "TRUST_BOUNDARY",
    "AttemptObservation",
    "CapabilityGrantWire",
    "CaseObservation",
    "CaseSpec",
    "Ed25519PublicJwk",
    "ExperimentRecordPayload",
    "InventoryArgumentsWire",
    "PreparedCase",
    "PublicExperimentVerifier",
    "PublicReceiptVerifier",
    "ResourcePolicyState",
    "RunpodJobEnvelope",
    "SignedExperimentRecord",
    "TrustedLabState",
    "UntrustedRunpodMetadata",
    "UntrustedRunpodObservation",
    "Variant",
    "WorkerPayload",
    "WorkerRequest",
    "WorkerResponse",
    "WorkerResponseBody",
    "WorkerResponseBundle",
    "strict_json_object",
]
