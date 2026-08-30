"""Strict canonical experiment-record JWS coverage."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from joserfc import jws
from joserfc.jwk import OKPKey
from lab.errors import ExperimentRecordError
from lab.record import (
    JWS_ALGORITHM,
    JWS_TYPE,
    ExperimentRecordSigner,
    ExperimentRecordVerifier,
)
from lab.wire import (
    ASSURANCE_DISCLAIMER,
    TRUST_BOUNDARY,
    AttemptObservation,
    CaseObservation,
    ExperimentRecordPayload,
    PublicExperimentVerifier,
    PublicReceiptVerifier,
    SignedExperimentRecord,
    UntrustedRunpodMetadata,
    UntrustedRunpodObservation,
    Variant,
)
from lab_test_support import WORKER_DIGEST, WORKER_IMAGE
from pydantic import ValidationError

from atcap.canonical import canonical_json
from atcap.errors import Reason
from atcap.receipt import DecisionReceiptPayload, ReceiptSigner


def _payload(
    *,
    qualified_scope: str = "mcp://inventoryd/tool/inventory.lookup",
    method: str = "inventory.lookup",
    audience: str = "inventoryd",
    valid_handler_count_snapshot: int | None = None,
    observed_at: int = 1_800_000_000,
    broker_decided_at: int = 1_800_000_000,
    resource_decided_at: int = 1_800_000_000,
    replay_second_record_id: str | None = None,
    replay_second_arguments_label: str | None = None,
    wrong_holder_challenge_label: str | None = None,
    replay_second_decided_at: int | None = None,
    replay_second_handler_count_snapshot: int = 2,
    real_swtpm: bool = False,
    duplicate_issuance_request: bool = False,
    reuse_real_tpm_attest: bool = False,
    reuse_real_tpm_signature: bool = False,
    split_real_tpm_ak_chain: bool = False,
    valid_invocation_id: int = 1,
    replay_invocation_id: int = 2,
    concurrent_invocation_id: int = 3,
) -> ExperimentRecordPayload:
    broker_receipts = ReceiptSigner.generate(key_id="record-broker-receipts-v1")
    resource_receipts = ReceiptSigner.generate(key_id="record-resource-receipts-v1")

    def stable_digest(label: str) -> str:
        return hashlib.sha256(label.encode()).hexdigest()

    def attempt(
        run_id: str,
        *,
        credential_label: str,
        case_variant: Variant,
        allowed: bool,
        reason: Reason,
        sequence: int = 1,
        invocation_id: int | None = None,
        digest_sequence: int | None = None,
        handler_count_snapshot: int | None = None,
        record_id: str | None = None,
        arguments_label: str = "widget-42",
        challenge_label: str | None = None,
        decided_at: int | None = None,
    ) -> AttemptObservation:
        digest_sequence = sequence if digest_sequence is None else digest_sequence

        def digest(label: str) -> str:
            return hashlib.sha256(f"{label}:{run_id}:{digest_sequence}".encode()).hexdigest()

        receipt = resource_receipts.sign(
            DecisionReceiptPayload(
                schema_version="atcap-decision-receipt/v1",
                receipt_id=stable_digest(f"resource-receipt:{run_id}:{sequence}"),
                deciding_service="inventoryd",
                decision="allow" if allowed else "deny",
                reason=reason,
                decided_at=resource_decided_at if decided_at is None else decided_at,
                credential_id=stable_digest(f"credential:{credential_label}"),
                qualified_scope=qualified_scope,
                challenge_token_hash=(
                    None
                    if case_variant == "malformed"
                    else stable_digest(
                        f"challenge:{challenge_label or f'{run_id}:{digest_sequence}'}"
                    )
                ),
                manifest_digest=None,
                method=method,
                audience=audience,
                arguments_digest=stable_digest(f"arguments:{arguments_label}"),
                record_id=record_id or f"record-id:{run_id}",
                invocation_id=invocation_id,
                handler_count_snapshot=(
                    invocation_id if handler_count_snapshot is None else handler_count_snapshot
                )
                or 0,
                handler_invoked=allowed,
                business_result="completed" if allowed else "not_invoked",
                artifact_hashes={"resource_policy_sha256": stable_digest("resource-policy")},
            )
        )

        return AttemptObservation(
            run_id=run_id,
            redemption_sequence=sequence,
            request_sha256=digest("request"),
            worker_response_sha256=digest("response"),
            holder_proof_sha256=digest("proof"),
            allowed=allowed,
            reason=reason,
            receipt_jws=receipt.compact_jws,
            receipt_verified=True,
            handler_invoked=allowed,
            business_result="completed" if allowed else "not_invoked",
            invocation_id=invocation_id,
        )

    def case(
        variant: Variant,
        attempts: list[AttemptObservation],
        *,
        invoked: int,
        metadata_count: int = 1,
    ) -> CaseObservation:
        credential_id = stable_digest(f"credential:{variant}")

        def broker_artifact_label(name: str) -> str:
            if name == "broker_policy_sha256":
                return name
            if name == "issuance_request_sha256" and duplicate_issuance_request:
                return name
            if real_swtpm and name == "tpm_ak_chain_sha256":
                return f"{name}:{variant}" if split_real_tpm_ak_chain else name
            if real_swtpm and name == "tpm_attest_sha256" and reuse_real_tpm_attest:
                return name
            if real_swtpm and name == "tpm_signature_sha256" and reuse_real_tpm_signature:
                return name
            return f"{name}:{variant}"

        broker_receipt = broker_receipts.sign(
            DecisionReceiptPayload(
                schema_version="atcap-decision-receipt/v1",
                receipt_id=stable_digest(f"broker-receipt:{variant}"),
                deciding_service="broker",
                decision="allow",
                reason=Reason.ALLOW,
                decided_at=broker_decided_at,
                credential_id=credential_id,
                qualified_scope=qualified_scope,
                challenge_token_hash=stable_digest(f"broker-challenge:{variant}"),
                manifest_digest="sha256:" + stable_digest("manifest"),
                method=None,
                audience=None,
                arguments_digest=None,
                record_id=None,
                invocation_id=None,
                handler_count_snapshot=0,
                handler_invoked=False,
                business_result="not_applicable",
                artifact_hashes={
                    name: stable_digest(broker_artifact_label(name))
                    for name in (
                        "broker_policy_sha256",
                        "issuance_request_sha256",
                        "tpm_ak_chain_sha256",
                        "tpm_attest_sha256",
                        "tpm_signature_sha256",
                    )
                },
            )
        )
        return CaseObservation(
            case_id=f"record-case-{variant}",
            variant=variant,
            broker_receipt_jws=broker_receipt.compact_jws,
            broker_receipt_verified=True,
            worker_binding_verified=True,
            worker_public_key="3" * 64,
            worker_image=WORKER_IMAGE,
            worker_code_digest=WORKER_DIGEST,
            worker_binding_scope="holder-key-and-claimed-digest-only",
            runpod_metadata=[
                UntrustedRunpodMetadata(provider="runpod", trust="untrusted")
                for _ in range(metadata_count)
            ],
            attempts=attempts,
            invocation_delta=invoked,
            credential_redemption_count=invoked,
        )

    cases = [
        case(
            "valid",
            [
                attempt(
                    "record-valid",
                    credential_label="valid",
                    case_variant="valid",
                    allowed=True,
                    reason=Reason.ALLOW,
                    invocation_id=valid_invocation_id,
                    handler_count_snapshot=valid_handler_count_snapshot,
                )
            ],
            invoked=1,
        ),
        case(
            "replay",
            [
                attempt(
                    "record-replay",
                    credential_label="replay",
                    case_variant="replay",
                    allowed=True,
                    reason=Reason.ALLOW,
                    invocation_id=replay_invocation_id,
                ),
                attempt(
                    "record-replay",
                    credential_label="replay",
                    case_variant="replay",
                    allowed=False,
                    reason=Reason.CHALLENGE_CONSUMED,
                    sequence=2,
                    digest_sequence=1,
                    record_id=replay_second_record_id,
                    arguments_label=replay_second_arguments_label or "widget-42",
                    decided_at=replay_second_decided_at,
                    handler_count_snapshot=replay_second_handler_count_snapshot,
                ),
            ],
            invoked=1,
        ),
        *[
            case(
                variant,
                [
                    attempt(
                        f"record-{variant}",
                        credential_label=variant,
                        case_variant=variant,
                        allowed=False,
                        reason=Reason.HOLDER_PROOF_INVALID,
                        challenge_label=(
                            wrong_holder_challenge_label if variant == "wrong-holder" else None
                        ),
                    )
                ],
                invoked=0,
            )
            for variant in (
                "argument-substitution",
                "record-substitution",
                "wrong-holder",
                "malformed",
            )
        ],
        case(
            "concurrent",
            [
                attempt(
                    "record-concurrent-1",
                    credential_label="concurrent",
                    case_variant="concurrent",
                    allowed=True,
                    reason=Reason.ALLOW,
                    invocation_id=concurrent_invocation_id,
                    handler_count_snapshot=concurrent_invocation_id,
                ),
                attempt(
                    "record-concurrent-2",
                    credential_label="concurrent",
                    case_variant="concurrent",
                    allowed=False,
                    reason=Reason.CREDENTIAL_SPENT,
                ),
            ],
            invoked=1,
            metadata_count=2,
        ),
    ]
    return ExperimentRecordPayload(
        schema_version="atcap-runpod-experiment-record/v1",
        experiment_id="record-experiment",
        observed_at=observed_at,
        commit_sha="a" * 40,
        uv_lock_sha256="b" * 64,
        assurance_scope="local-controller-observation-only",
        trust_boundary=TRUST_BOUNDARY,
        assurance_disclaimer=ASSURANCE_DISCLAIMER,
        tpm_mode="real-swtpm" if real_swtpm else "test-double",
        tpm_evidence_verified=real_swtpm,
        tpm_assurance_included=real_swtpm,
        worker_public_key="3" * 64,
        worker_image=WORKER_IMAGE,
        worker_code_digest=WORKER_DIGEST,
        worker_binding_scope="holder-key-and-claimed-digest-only",
        broker_receipt_verifier=PublicReceiptVerifier(
            key_id=broker_receipts.key_id,
            public_jwk=broker_receipts.public_key().as_dict(private=False),
        ),
        resource_receipt_verifier=PublicReceiptVerifier(
            key_id=resource_receipts.key_id,
            public_jwk=resource_receipts.public_key().as_dict(private=False),
        ),
        runpod_observation=UntrustedRunpodObservation(
            provider="runpod",
            trust="untrusted",
            endpoint_id_sha256="e" * 64,
            job_id_sha256="c" * 64,
            worker_id_sha256="d" * 64,
            status="COMPLETED",
            worker_image_argument=WORKER_IMAGE,
            delay_time_ms=None,
            execution_time_ms=None,
        ),
        broker_receipt_count=7,
        resource_receipt_count=9,
        allowed_attempt_count=3,
        denied_attempt_count=6,
        handler_invocation_count=3,
        credential_redemption_count=3,
        cases=cases,
    )


def _sign_raw(signer: ExperimentRecordSigner, raw: bytes) -> SignedExperimentRecord:
    key = OKPKey.import_key(signer.private_jwk())
    compact = jws.serialize_compact(
        {"alg": JWS_ALGORITHM, "kid": signer.key_id, "typ": JWS_TYPE},
        raw,
        key,
        algorithms=[JWS_ALGORITHM],
    )
    return SignedExperimentRecord(compact_jws=compact)


def test_experiment_record_is_canonical_closed_and_explicitly_non_attesting() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    signed = signer.sign(_payload())
    verified = verifier.verify(signed)

    assert verified.assurance_scope == "local-controller-observation-only"
    assert verified.trust_boundary == TRUST_BOUNDARY
    assert verified.assurance_disclaimer == ASSURANCE_DISCLAIMER
    assert verified.tpm_mode == "test-double"
    assert verified.tpm_assurance_included is False
    assert verified.runpod_observation.trust == "untrusted"
    assert verified.broker_receipt_count == 7
    assert verified.resource_receipt_count == 9
    assert verified.cases[0].broker_receipt_jws.count(".") == 2
    assert verified.cases[0].attempts[0].receipt_jws.count(".") == 2


def test_public_experiment_verifier_is_public_only_and_kid_bound() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    valid = {
        "schema_version": "atcap-runpod-experiment-verifier/v1",
        "key_id": signer.key_id,
        "public_jwk": signer.public_jwk(),
    }
    PublicExperimentVerifier.model_validate(valid)

    with pytest.raises(ValidationError):
        PublicExperimentVerifier.model_validate(
            {
                **valid,
                "public_jwk": {**signer.public_jwk(), "d": "A" * 43},
            }
        )
    with pytest.raises(ValidationError):
        PublicExperimentVerifier.model_validate({**valid, "key_id": "substituted-kid"})


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param({"unknown": "rejected"}, id="unknown-field"),
        pytest.param({"observed_at": "1800000000"}, id="wrong-type"),
        pytest.param({"resource_receipt_count": 2}, id="false-aggregate"),
        pytest.param({"tpm_assurance_included": True}, id="false-tpm-assurance"),
        pytest.param({"tpm_evidence_verified": True}, id="false-test-double-evidence"),
    ],
)
def test_correctly_signed_but_semantically_invalid_record_is_rejected(
    mutation: dict[str, Any],
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    value = {**_payload().model_dump(mode="json"), **mutation}
    signed = _sign_raw(signer, canonical_json(value))

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signed)


def test_correctly_signed_duplicate_json_member_is_rejected() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    canonical = canonical_json(_payload().model_dump(mode="json"))
    duplicated = canonical[:-1] + b',"observed_at":1800000000}'
    signed = _sign_raw(signer, duplicated)

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signed)


def test_correctly_signed_noncanonical_record_is_rejected() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    noncanonical = json.dumps(_payload().model_dump(mode="json"), indent=2).encode()

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(_sign_raw(signer, noncanonical))


def test_wrong_record_key_and_tampering_are_rejected() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    attacker = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    signed = signer.sign(_payload())
    parts = signed.compact_jws.split(".")
    tampered = SignedExperimentRecord(
        compact_jws=".".join((parts[0], parts[1][:-1] + "A", parts[2]))
    )

    with pytest.raises(ExperimentRecordError):
        verifier.verify(attacker.sign(_payload()))
    with pytest.raises(ExperimentRecordError):
        verifier.verify(tampered)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            {"qualified_scope": "mcp://other/tool/inventory.lookup"},
            id="wrong-qualified-scope",
        ),
        pytest.param({"method": "other.lookup"}, id="wrong-method"),
        pytest.param({"audience": "other-resource"}, id="wrong-audience"),
    ],
)
def test_self_consistent_receipts_for_another_resource_are_rejected(
    mutation: dict[str, str],
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    signed = signer.sign(_payload(**mutation))

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signed)


def test_authenticated_handler_snapshots_must_reconcile_with_final_count() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signer.sign(_payload(valid_handler_count_snapshot=999)))


def test_authenticated_invocation_ids_must_match_fixed_case_execution_order() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(
            signer.sign(
                _payload(
                    valid_invocation_id=2,
                    valid_handler_count_snapshot=2,
                    replay_invocation_id=1,
                )
            )
        )


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            {"replay_second_record_id": "record-id:substituted"},
            id="replay-record-id",
        ),
        pytest.param(
            {"replay_second_arguments_label": "substituted"},
            id="replay-arguments-digest",
        ),
    ],
)
def test_authenticated_replay_receipts_must_reuse_exact_call_context(
    mutation: dict[str, str],
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signer.sign(_payload(**mutation)))


def test_authenticated_challenge_hash_cannot_be_reused_across_cases() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signer.sign(_payload(wrong_holder_challenge_label="record-valid:1")))


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param({"observed_at": 1_799_999_999}, id="receipts-after-observation"),
        pytest.param(
            {"observed_at": 1_800_000_001, "broker_decided_at": 1_800_000_001},
            id="broker-after-resource",
        ),
    ],
)
def test_authenticated_receipt_times_must_precede_observation_in_order(
    mutation: dict[str, int],
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signer.sign(_payload(**mutation)))


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            {
                "broker_decided_at": 1_799_999_998,
                "replay_second_decided_at": 1_799_999_999,
            },
            id="second-receipt-time-precedes-first",
        ),
        pytest.param(
            {"replay_second_handler_count_snapshot": 1},
            id="second-handler-snapshot-precedes-first",
        ),
    ],
)
def test_authenticated_replay_receipts_are_nondecreasing(
    mutation: dict[str, int],
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signer.sign(_payload(**mutation)))


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            {"duplicate_issuance_request": True},
            id="duplicate-issuance-request",
        ),
        pytest.param(
            {"real_swtpm": True, "reuse_real_tpm_attest": True},
            id="reused-real-tpm-attest",
        ),
        pytest.param(
            {"real_swtpm": True, "reuse_real_tpm_signature": True},
            id="reused-real-tpm-signature",
        ),
        pytest.param(
            {"real_swtpm": True, "split_real_tpm_ak_chain": True},
            id="different-real-tpm-ak-chain",
        ),
    ],
)
def test_authenticated_broker_trace_requires_fresh_requests_and_real_quotes(
    mutation: dict[str, Any],
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    verifier.verify(signer.sign(_payload(real_swtpm=True)))

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signer.sign(_payload(**mutation)))


def test_record_model_forbids_unknown_fields_and_inconsistent_real_tpm_flag() -> None:
    value = _payload().model_dump(mode="json")
    with pytest.raises(ValidationError):
        ExperimentRecordPayload.model_validate({**value, "unknown": "rejected"})
    with pytest.raises(ValidationError):
        ExperimentRecordPayload.model_validate(
            {
                **value,
                "tpm_mode": "real-swtpm",
                "tpm_evidence_verified": True,
                "tpm_assurance_included": False,
            }
        )


def test_single_attempt_case_requires_first_redemption_sequence() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    value = _payload().model_dump(mode="json")
    value["cases"][0]["attempts"][0]["redemption_sequence"] = 2

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(_sign_raw(signer, canonical_json(value)))


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            {
                "allowed": False,
                "reason": Reason.ALLOW,
                "handler_invoked": True,
                "business_result": "not_invoked",
                "invocation_id": None,
            },
            id="denial-claims-allow-and-invocation",
        ),
        pytest.param(
            {
                "allowed": True,
                "reason": Reason.CREDENTIAL_SPENT,
                "handler_invoked": False,
                "business_result": "completed",
                "invocation_id": 1,
            },
            id="allow-claims-denial-and-no-handler",
        ),
    ],
)
def test_correctly_signed_contradictory_attempt_is_rejected(
    mutation: dict[str, Any],
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    value = _payload().model_dump(mode="json")
    value["cases"][0]["attempts"][0].update(mutation)
    signed = _sign_raw(signer, canonical_json(value))

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signed)


def test_correctly_signed_case_variant_contradiction_is_rejected() -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    value = _payload().model_dump(mode="json")
    value["cases"][0]["variant"] = "argument-substitution"
    signed = _sign_raw(signer, canonical_json(value))

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(signed)


@pytest.mark.parametrize(
    ("variant", "attempt_index", "field"),
    [
        ("replay", 1, "holder_proof_sha256"),
        ("concurrent", 1, "worker_response_sha256"),
    ],
)
def test_correctly_signed_inconsistent_replay_or_race_binding_is_rejected(
    variant: str,
    attempt_index: int,
    field: str,
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    value = _payload().model_dump(mode="json")
    case = next(item for item in value["cases"] if item["variant"] == variant)
    if variant == "replay":
        case["attempts"][attempt_index][field] = "f" * 64
    else:
        case["attempts"][attempt_index][field] = case["attempts"][0][field]

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(_sign_raw(signer, canonical_json(value)))


@pytest.mark.parametrize("contradiction", ["worker-image", "invocation-id"])
def test_correctly_signed_cross_record_contradiction_is_rejected(
    contradiction: str,
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    value = _payload().model_dump(mode="json")
    if contradiction == "worker-image":
        value["runpod_observation"]["worker_image_argument"] = (
            "evil.invalid/worker@sha256:" + "f" * 64
        )
    else:
        replay = next(item for item in value["cases"] if item["variant"] == "replay")
        replay["attempts"][0]["invocation_id"] = 1

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(_sign_raw(signer, canonical_json(value)))


@pytest.mark.parametrize(
    ("container", "field"),
    [
        ("record", "schema_version"),
        ("record", "trust_boundary"),
        ("record", "assurance_disclaimer"),
        ("record", "broker_receipt_verifier"),
        ("record", "resource_receipt_verifier"),
        ("case", "broker_receipt_verified"),
        ("case", "worker_binding_verified"),
        ("attempt", "receipt_verified"),
        ("attempt", "request_sha256"),
        ("attempt", "worker_response_sha256"),
        ("attempt", "holder_proof_sha256"),
        ("provider", "provider"),
        ("provider", "trust"),
        ("provider", "status"),
    ],
)
def test_correctly_signed_omitted_security_claim_is_rejected(
    container: str,
    field: str,
) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    value = _payload().model_dump(mode="json")
    if container == "record":
        value.pop(field)
    elif container == "case":
        value["cases"][0].pop(field)
    elif container == "attempt":
        value["cases"][0]["attempts"][0].pop(field)
    else:
        value["runpod_observation"].pop(field)

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(_sign_raw(signer, canonical_json(value)))


@pytest.mark.parametrize("mutation", ["receipt", "wrong-key", "private-key", "kid"])
def test_embedded_receipt_verification_material_is_fail_closed(mutation: str) -> None:
    signer = ExperimentRecordSigner.generate(key_id="record-key-v1")
    verifier = ExperimentRecordVerifier.from_public_jwk(signer.public_jwk(), key_id=signer.key_id)
    value = _payload().model_dump(mode="json")
    if mutation == "receipt":
        value["cases"][0]["attempts"][0]["receipt_jws"] = value["cases"][0]["broker_receipt_jws"]
    elif mutation == "wrong-key":
        attacker = ReceiptSigner.generate(key_id="record-resource-receipts-v1")
        value["resource_receipt_verifier"]["public_jwk"] = attacker.public_key().as_dict(
            private=False
        )
    elif mutation == "private-key":
        value["resource_receipt_verifier"]["public_jwk"]["d"] = "A" * 43
    else:
        value["resource_receipt_verifier"]["key_id"] = "substituted-kid"

    with pytest.raises(ExperimentRecordError, match="verification failed"):
        verifier.verify(_sign_raw(signer, canonical_json(value)))
