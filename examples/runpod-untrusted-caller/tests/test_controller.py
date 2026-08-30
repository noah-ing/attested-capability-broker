"""Adversarial controller, transport, receipt, and race coverage."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from ca2a_runtime.delegation import DelegationCredential, build_holder_proof
from lab.controller import TrustedController
from lab.errors import (
    DuplicateRunIdError,
    LabBindingError,
    LabProtocolError,
    LabTimeoutError,
)
from lab.transport import FakeWorkerTransport
from lab.wire import (
    CaseSpec,
    UntrustedRunpodMetadata,
    WorkerRequest,
    WorkerResponse,
    strict_json_object,
)
from lab.worker import DisposableHolderWorker
from lab.worker_wire import HolderProofWire, Variant, WorkerResponseBody
from lab_test_support import WORKER_DIGEST, WORKER_IMAGE, issue_grant
from pydantic import ValidationError

from atcap.canonical import canonical_digest, canonical_json
from atcap.errors import Reason
from atcap.models import SignedDecisionReceipt
from tests.support import Harness


def _malicious_valid_original_response(
    request: WorkerRequest,
    harness: Harness,
    *,
    proof_sku: str | None = None,
) -> WorkerResponse:
    credential = DelegationCredential.from_dict(request.credential)
    proof = build_holder_proof(
        harness.holder_private,
        credential,
        audience=request.audience,
        challenge=request.challenge,
        requested_capability=request.qualified_scope,
        record_id=request.record_id,
        sealed_payload=canonical_json(
            {"sku": proof_sku}
            if proof_sku is not None
            else request.arguments.model_dump(mode="json")
        ),
        caller_channel_key=None,
        parent_record_hash=None,
    )
    body = WorkerResponseBody(
        schema_version="atcap-runpod-worker-response/v1",
        case_id=request.case_id,
        run_id=request.run_id,
        request_sha256=canonical_digest(request.model_dump(mode="json")),
        worker_public_key=harness.holder_public,
        proof_subject=credential.subject,
        worker_image=WORKER_IMAGE,
        worker_code_digest=WORKER_DIGEST,
        holder_proof=HolderProofWire.model_validate(proof.to_dict()),
        runpod_metadata=UntrustedRunpodMetadata(provider="runpod", trust="untrusted"),
    )
    return WorkerResponse(
        **body.model_dump(mode="json"),
        holder_signature=harness.holder_private.sign(
            canonical_json(body.model_dump(mode="json"))
        ).hex(),
    )


@pytest.mark.asyncio
async def test_all_worker_variants_verify_receipts_and_exact_resource_invariants(
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    worker: DisposableHolderWorker = lab_components["worker"]
    transport = FakeWorkerTransport(worker)
    cases = []
    variants = [
        "valid",
        "replay",
        "argument-substitution",
        "record-substitution",
        "wrong-holder",
        "malformed",
    ]
    for variant in variants:
        observation = await controller.run_case(
            issue_grant(harness),
            CaseSpec(
                case_id=f"case-{variant}",
                variant=variant,
                record_id=f"record-{variant}",
            ),
            transport,
        )
        cases.append(observation)

    concurrent = await controller.run_case(
        issue_grant(harness),
        CaseSpec(
            case_id="case-concurrent",
            variant="concurrent",
            record_id="record-concurrent",
            concurrency=12,
        ),
        transport,
    )
    cases.append(concurrent)

    by_variant = {case.variant: case for case in cases}
    assert [(item.allowed, item.reason) for item in by_variant["valid"].attempts] == [
        (True, Reason.ALLOW)
    ]
    assert [(item.allowed, item.reason) for item in by_variant["replay"].attempts] == [
        (True, Reason.ALLOW),
        (False, Reason.CHALLENGE_CONSUMED),
    ]
    for variant in (
        "argument-substitution",
        "record-substitution",
        "wrong-holder",
        "malformed",
    ):
        assert [item.reason for item in by_variant[variant].attempts] == [
            Reason.HOLDER_PROOF_INVALID
        ]
        assert by_variant[variant].invocation_delta == 0
        assert by_variant[variant].credential_redemption_count == 0

    concurrent_reasons = [item.reason for item in concurrent.attempts]
    assert concurrent_reasons.count(Reason.ALLOW) == 1
    assert concurrent_reasons.count(Reason.CREDENTIAL_SPENT) == 11
    assert concurrent.invocation_delta == concurrent.credential_redemption_count == 1
    assert harness.inventory.invocation_count == 3

    for case in cases:
        broker = harness.broker_receipts.verify(
            SignedDecisionReceipt(compact_jws=case.broker_receipt_jws)
        )
        assert broker.decision == "allow"
        for attempt in case.attempts:
            resource = harness.inventory_receipts.verify(
                SignedDecisionReceipt(compact_jws=attempt.receipt_jws)
            )
            assert resource.reason == attempt.reason
            assert resource.handler_invoked is attempt.handler_invoked
        assert all(metadata.trust == "untrusted" for metadata in case.runpod_metadata)
        assert case.worker_binding_scope == "holder-key-and-claimed-digest-only"


def test_duplicate_controller_case_id_is_rejected_before_second_preparation(
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    first = issue_grant(harness)
    second = issue_grant(harness)
    spec = CaseSpec(case_id="duplicate-case", variant="valid", record_id="duplicate-record")
    controller.prepare_case(first, spec)

    with pytest.raises(DuplicateRunIdError, match="already reserved"):
        controller.prepare_case(second, spec)

    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(first.credential.credential_id) == 0
    assert harness.store.redemption_count(second.credential.credential_id) == 0


@pytest.mark.asyncio
async def test_fake_transport_rejects_duplicate_worker_run_id(
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    transport = FakeWorkerTransport(lab_components["worker"])
    grant = issue_grant(harness)
    prepared = controller.prepare_case(
        grant,
        CaseSpec(case_id="duplicate-worker", variant="valid", record_id="duplicate-worker"),
    )
    await transport.submit(prepared.requests[0], timeout_seconds=1)

    with pytest.raises(DuplicateRunIdError, match="already submitted"):
        await transport.submit(prepared.requests[0], timeout_seconds=1)

    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(grant.credential.credential_id) == 0


@pytest.mark.asyncio
async def test_corrupt_worker_output_fails_before_redemption(
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    grant = issue_grant(harness)
    transport = FakeWorkerTransport(lab_components["worker"], corrupt_run_ids={"corrupt-output"})

    with pytest.raises(LabProtocolError, match="strict canonical"):
        await controller.run_case(
            grant,
            CaseSpec(
                case_id="corrupt-output",
                variant="valid",
                record_id="corrupt-output",
            ),
            transport,
        )

    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(grant.credential.credential_id) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("worker_public_key", "f" * 64, "public key"),
        ("worker_code_digest", "e" * 64, "code digest"),
        ("worker_image", "evil.invalid/w@sha256:" + "d" * 64, "image"),
    ],
)
async def test_worker_key_and_digest_bindings_fail_before_redemption(
    field: str,
    replacement: str,
    message: str,
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    grant = issue_grant(harness)

    def mutate(raw: bytes, _request: object) -> bytes:
        decoded = strict_json_object(raw)
        decoded[field] = replacement
        return canonical_json(decoded)

    transport = FakeWorkerTransport(lab_components["worker"], response_mutator=mutate)
    with pytest.raises(LabBindingError, match=message):
        await controller.run_case(
            grant,
            CaseSpec(
                case_id=f"mismatch-{field}",
                variant="valid",
                record_id=f"mismatch-{field}",
            ),
            transport,
        )

    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(grant.credential.credential_id) == 0


@pytest.mark.asyncio
async def test_worker_timeout_is_stable_and_does_not_redeem(
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    grant = issue_grant(harness)
    transport = FakeWorkerTransport(lab_components["worker"], delays={"timeout-case": 0.2})

    with pytest.raises(LabTimeoutError, match="deadline expired"):
        await controller.run_case(
            grant,
            CaseSpec(
                case_id="timeout-case",
                variant="valid",
                record_id="timeout-case",
            ),
            transport,
            timeout_seconds=0.01,
        )

    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(grant.credential.credential_id) == 0


def test_duplicate_json_names_in_worker_output_are_rejected_without_echo() -> None:
    marker = "RAW_DUPLICATE_WORKER_VALUE_MUST_NOT_ESCAPE"
    raw = ('{"run_id":"first","run_id":"' + marker + '"}').encode()

    with pytest.raises(LabProtocolError, match="strict canonical") as caught:
        TrustedController.parse_response(raw)

    assert marker not in str(caught.value)


def test_worker_response_schema_is_closed_and_noncoercing(
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    prepared = controller.prepare_case(
        issue_grant(harness),
        CaseSpec(case_id="wire-strict", variant="valid", record_id="wire-strict"),
    )
    worker: DisposableHolderWorker = lab_components["worker"]
    response = worker.generate(prepared.requests[0])

    with pytest.raises(ValidationError):
        WorkerResponse.model_validate({**response.model_dump(mode="json"), "unknown": "rejected"})
    with pytest.raises(ValidationError):
        WorkerResponse.model_validate({**response.model_dump(mode="json"), "worker_code_digest": 7})
    missing_version = response.model_dump(mode="json")
    missing_version.pop("schema_version")
    with pytest.raises(ValidationError):
        WorkerResponse.model_validate(missing_version)
    missing_trust = response.model_dump(mode="json")
    missing_trust["runpod_metadata"].pop("trust")
    with pytest.raises(ValidationError):
        WorkerResponse.model_validate(missing_trust)
    assert response.worker_image == WORKER_IMAGE
    assert response.worker_code_digest == WORKER_DIGEST


@pytest.mark.parametrize(
    "grant",
    [
        "expected_manifest_digest",
        "expected_broker_policy_sha256",
        "expected_broker_challenge_token_hash",
        "expected_tpm_attest_sha256",
        "expected_tpm_signature_sha256",
        "expected_tpm_ak_chain_sha256",
        "expected_issuance_request_sha256",
    ],
)
def test_trusted_broker_receipt_must_match_every_persisted_expected_binding(
    grant: str,
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    original = issue_grant(harness)
    substituted = replace(original, **{grant: "0" * 64})

    with pytest.raises(LabBindingError, match="broker receipt does not bind"):
        controller.prepare_case(
            substituted,
            CaseSpec(case_id=f"wrong-{grant}", variant="valid", record_id=f"wrong-{grant}"),
        )

    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(original.credential.credential_id) == 0


@pytest.mark.parametrize(
    "malicious_variant",
    ["argument-substitution", "record-substitution", "wrong-holder", "malformed"],
)
def test_valid_proof_in_any_denial_case_is_rejected_before_global_redemption(
    malicious_variant: Variant,
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    worker: DisposableHolderWorker = lab_components["worker"]
    inputs = []
    grants = []
    variants: tuple[Variant, ...] = (
        "argument-substitution",
        "record-substitution",
        "wrong-holder",
        "malformed",
    )
    for variant in variants:
        grant = issue_grant(harness)
        prepared = controller.prepare_case(
            grant,
            CaseSpec(
                case_id=f"preappraise-{malicious_variant}-{variant}",
                variant=variant,
                record_id=f"preappraise-{malicious_variant}-{variant}",
            ),
        )
        request = prepared.requests[0]
        response = (
            _malicious_valid_original_response(request, harness)
            if variant == malicious_variant
            else worker.generate(request)
        )
        inputs.append((prepared, [response]))
        grants.append(grant)

    with pytest.raises(LabBindingError, match=r"denial-case worker|wrong-holder case"):
        controller.finalize_cases(inputs)

    assert harness.inventory.invocation_count == 0
    assert all(
        harness.store.redemption_count(grant.credential.credential_id) == 0 for grant in grants
    )


def test_non_prescribed_negative_mutation_is_rejected_before_redemption(
    harness: Harness,
    lab_components: dict[str, Any],
) -> None:
    controller: TrustedController = lab_components["controller"]
    grant = issue_grant(harness)
    prepared = controller.prepare_case(
        grant,
        CaseSpec(
            case_id="non-prescribed-argument",
            variant="argument-substitution",
            record_id="non-prescribed-argument",
        ),
    )
    request = prepared.requests[0]
    response = _malicious_valid_original_response(
        request,
        harness,
        proof_sku=f"{request.arguments.sku}-other",
    )

    with pytest.raises(LabBindingError, match="prescribed adversarial variant"):
        controller.finalize_cases([(prepared, [response])])

    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(grant.credential.credential_id) == 0
