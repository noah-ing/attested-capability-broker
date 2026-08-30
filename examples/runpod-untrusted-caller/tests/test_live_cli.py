"""Two-phase CLI state, secret-boundary, and signed-evidence coverage."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from lab.errors import LabError, LabProtocolError
from lab.live_cli import (
    MAX_EXPERIMENT_VERIFIER_BYTES,
    MAX_RUNPOD_ENVELOPE_BYTES,
    finalize,
    prepare_test_double,
    verify_evidence_bundle,
)
from lab.record import ExperimentRecordVerifier
from lab.wire import (
    PublicExperimentVerifier,
    RunpodJobEnvelope,
    TrustedLabState,
    WorkerPayload,
    WorkerResponseBundle,
    strict_json_object,
)
from lab.worker import DisposableHolderWorker
from lab_test_support import WORKER_IMAGE
from pydantic import ValidationError

from atcap.canonical import canonical_json
from atcap.inventory import InventoryApplication
from atcap.storage import SQLiteStore


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def _prepare_worker_response(payload_path: Path, response_path: Path) -> None:
    bundle_raw = DisposableHolderWorker.process_payload(payload_path.read_bytes())
    bundle = WorkerResponseBundle.model_validate(strict_json_object(bundle_raw))
    envelope = RunpodJobEnvelope(
        id="provider-job-123",
        status="COMPLETED",
        delayTime=17,
        executionTime=31,
        workerId="untrusted-worker-123",
        output=bundle,
    )
    response_path.write_bytes(canonical_json(envelope.model_dump(mode="json")))


def test_prepare_worker_finalize_redeems_real_inventory_and_writes_public_evidence(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    evidence_dir = tmp_path / "evidence"
    payload_path = tmp_path / "worker-payload.json"
    response_path = tmp_path / "worker-response.json"
    _private_directory(state_dir)
    _private_directory(evidence_dir)

    prepare_test_double(
        worker_image=WORKER_IMAGE,
        state_dir=state_dir,
        payload_path=payload_path,
        concurrency=8,
    )
    state = TrustedLabState.model_validate(
        strict_json_object((state_dir / "trusted-state.json").read_bytes())
    )
    worker_payload = WorkerPayload.model_validate(strict_json_object(payload_path.read_bytes()))
    _prepare_worker_response(payload_path, response_path)
    signed = finalize(
        state_dir=state_dir,
        worker_response_path=response_path,
        endpoint_id="provider-endpoint-observed",
        worker_image=WORKER_IMAGE,
        evidence_dir=evidence_dir,
    )

    verifier_document = PublicExperimentVerifier.model_validate(
        strict_json_object((evidence_dir / "experiment-verifier.json").read_bytes())
    )
    verifier = ExperimentRecordVerifier.from_public_jwk(
        verifier_document.public_jwk, key_id=verifier_document.key_id
    )
    record = verifier.verify(signed)
    assert verify_evidence_bundle(evidence_dir) == signed
    assert record.commit_sha == state.commit_sha
    assert record.uv_lock_sha256 == state.uv_lock_sha256
    assert record.worker_image == WORKER_IMAGE
    assert record.worker_public_key == state.expected_worker_public_key
    assert record.worker_code_digest == state.worker_code_digest
    assert record.worker_code_digest != WORKER_IMAGE.rsplit("@sha256:", maxsplit=1)[-1]
    assert record.tpm_mode == "test-double"
    assert record.tpm_evidence_verified is False
    assert record.tpm_assurance_included is False
    assert (
        record.runpod_observation.endpoint_id_sha256
        == hashlib.sha256(b"provider-endpoint-observed").hexdigest()
    )
    assert (
        record.runpod_observation.job_id_sha256 == hashlib.sha256(b"provider-job-123").hexdigest()
    )
    assert record.runpod_observation.trust == "untrusted"
    assert record.runpod_observation.delay_time_ms == 17
    assert record.runpod_observation.execution_time_ms == 31
    assert (
        record.runpod_observation.worker_id_sha256
        == hashlib.sha256(b"untrusted-worker-123").hexdigest()
    )
    assert len(record.cases) == record.broker_receipt_count == 7
    assert record.resource_receipt_count == 15
    assert record.allowed_attempt_count == 3
    assert record.denied_attempt_count == 12
    assert record.handler_invocation_count == 3
    assert record.credential_redemption_count == 3
    assert all(
        metadata.model_dump(mode="json") == {"provider": "runpod", "trust": "untrusted"}
        for case in record.cases
        for metadata in case.runpod_metadata
    )

    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((state_dir / "trusted-state.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((state_dir / "lab.sqlite3").stat().st_mode) == 0o600
    assert stat.S_IMODE(payload_path.stat().st_mode) == 0o600
    assert sorted(path.name for path in evidence_dir.iterdir()) == [
        "experiment-record.json",
        "experiment-record.jws",
        "experiment-verifier.json",
    ]

    evidence = b"".join(path.read_bytes() for path in evidence_dir.iterdir())
    private_values = [
        state.resource_challenge_secret,
        str(state.inventory_receipt_private_jwk["d"]),
        str(state.experiment_private_jwk["d"]),
        worker_payload.disposable_holder_private_key,
    ]
    assert all(value.encode() not in evidence for value in private_values)
    payload_text = payload_path.read_text()
    assert state.resource_challenge_secret not in payload_text
    assert str(state.inventory_receipt_private_jwk["d"]) not in payload_text
    assert str(state.experiment_private_jwk["d"]) not in payload_text


def test_prepare_requires_existing_empty_mode_0700_state_directory(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(LabProtocolError, match="must exist with mode 0700"):
        prepare_test_double(
            worker_image=WORKER_IMAGE,
            state_dir=missing,
            payload_path=tmp_path / "missing-payload.json",
        )

    broad = tmp_path / "broad"
    broad.mkdir(mode=0o755)
    os.chmod(broad, 0o755)  # noqa: S103 - deliberately test insecure permissions
    with pytest.raises(LabProtocolError, match="must exist with mode 0700"):
        prepare_test_double(
            worker_image=WORKER_IMAGE,
            state_dir=broad,
            payload_path=tmp_path / "broad-payload.json",
        )

    nonempty = tmp_path / "nonempty"
    _private_directory(nonempty)
    (nonempty / "unrelated").write_text("preserve")
    with pytest.raises(LabProtocolError, match="must be empty"):
        prepare_test_double(
            worker_image=WORKER_IMAGE,
            state_dir=nonempty,
            payload_path=tmp_path / "nonempty-payload.json",
        )
    assert (nonempty / "unrelated").read_text() == "preserve"


def test_finalize_rejects_duplicate_outer_json_and_image_mismatch(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    evidence_dir = tmp_path / "evidence"
    payload_path = tmp_path / "payload.json"
    response_path = tmp_path / "response.json"
    _private_directory(state_dir)
    _private_directory(evidence_dir)
    prepare_test_double(
        worker_image=WORKER_IMAGE,
        state_dir=state_dir,
        payload_path=payload_path,
        concurrency=2,
    )
    response_path.write_bytes(
        b'{"id":"one","id":"RAW_DUPLICATE_PROVIDER_ID","status":"COMPLETED","output":{}}'
    )
    with pytest.raises(LabProtocolError, match="envelope failed strict") as duplicate:
        finalize(
            state_dir=state_dir,
            worker_response_path=response_path,
            endpoint_id="endpoint",
            worker_image=WORKER_IMAGE,
            evidence_dir=evidence_dir,
        )
    assert "RAW_DUPLICATE_PROVIDER_ID" not in str(duplicate.value)

    with pytest.raises(LabProtocolError, match="does not match prepared state"):
        finalize(
            state_dir=state_dir,
            worker_response_path=response_path,
            endpoint_id="endpoint",
            worker_image="evil.invalid/worker@sha256:" + "f" * 64,
            evidence_dir=evidence_dir,
        )


def test_worker_payload_schema_rejects_unknown_and_wrong_type(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    payload_path = tmp_path / "payload.json"
    _private_directory(state_dir)
    payload = prepare_test_double(
        worker_image=WORKER_IMAGE,
        state_dir=state_dir,
        payload_path=payload_path,
        concurrency=2,
    )
    value: dict[str, Any] = payload.model_dump(mode="json")

    with pytest.raises(ValidationError):
        WorkerPayload.model_validate({**value, "unexpected": "rejected"})
    with pytest.raises(ValidationError):
        WorkerPayload.model_validate({**value, "disposable_holder_private_key": 7})
    with pytest.raises(ValidationError):
        WorkerPayload.model_validate(
            {**value, "requests": [value["requests"][0], value["requests"][0]]}
        )
    missing_version = dict(value)
    missing_version.pop("schema_version")
    with pytest.raises(ValidationError):
        WorkerPayload.model_validate(missing_version)


@pytest.mark.parametrize(
    "mutation",
    ["late-signature", "missing", "extra", "proof-extra", "huge-timing"],
)
def test_complete_bundle_is_validated_before_any_redemption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    state_dir = tmp_path / "state"
    evidence_dir = tmp_path / "evidence"
    payload_path = tmp_path / "payload.json"
    response_path = tmp_path / "response.json"
    _private_directory(state_dir)
    _private_directory(evidence_dir)
    prepare_test_double(
        worker_image=WORKER_IMAGE,
        state_dir=state_dir,
        payload_path=payload_path,
        concurrency=2,
    )
    state = TrustedLabState.model_validate(
        strict_json_object((state_dir / "trusted-state.json").read_bytes())
    )
    bundle = WorkerResponseBundle.model_validate(
        strict_json_object(DisposableHolderWorker.process_payload(payload_path.read_bytes()))
    )
    envelope: dict[str, Any] = RunpodJobEnvelope(
        id="provider-job",
        status="COMPLETED",
        output=bundle,
    ).model_dump(mode="json")
    responses = envelope["output"]["responses"]
    assert isinstance(responses, list)
    if mutation == "late-signature":
        responses[-1]["holder_signature"] = "0" * 128
    elif mutation == "missing":
        responses.pop()
    elif mutation == "extra":
        extra = copy.deepcopy(responses[-1])
        extra["run_id"] = "unprepared-extra"
        extra["case_id"] = "unprepared-extra"
        responses.append(extra)
    elif mutation == "proof-extra":
        responses[-1]["holder_proof"]["reflected"] = "not-accepted"
    else:
        envelope["executionTime"] = 10**100
    response_path.write_text(
        json.dumps(envelope, separators=(",", ":")),
        encoding="utf-8",
    )

    handler_calls = 0
    original_lookup = InventoryApplication._inventory_lookup

    def counted_lookup(self: InventoryApplication, arguments: Any) -> dict[str, Any]:
        nonlocal handler_calls
        handler_calls += 1
        return original_lookup(self, arguments)

    monkeypatch.setattr(InventoryApplication, "_inventory_lookup", counted_lookup)
    with pytest.raises(LabError):
        finalize(
            state_dir=state_dir,
            worker_response_path=response_path,
            endpoint_id="endpoint",
            worker_image=WORKER_IMAGE,
            evidence_dir=evidence_dir,
        )

    store = SQLiteStore(state_dir / state.database_filename)
    assert handler_calls == 0
    assert all(
        store.redemption_count(str(prepared.grant.credential["credential_id"])) == 0
        for prepared in state.prepared_cases
    )
    assert not any(evidence_dir.iterdir())


def test_provider_identifiers_are_hashed_and_cannot_reflect_holder_key(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    evidence_dir = tmp_path / "evidence"
    payload_path = tmp_path / "payload.json"
    response_path = tmp_path / "response.json"
    _private_directory(state_dir)
    _private_directory(evidence_dir)
    payload = prepare_test_double(
        worker_image=WORKER_IMAGE,
        state_dir=state_dir,
        payload_path=payload_path,
        concurrency=2,
    )
    marker = payload.disposable_holder_private_key
    bundle = WorkerResponseBundle.model_validate(
        strict_json_object(DisposableHolderWorker.process_payload(payload_path.read_bytes()))
    )
    envelope = RunpodJobEnvelope(
        id=marker,
        status="COMPLETED",
        workerId=marker,
        output=bundle,
    )
    response_path.write_bytes(canonical_json(envelope.model_dump(mode="json")))

    signed = finalize(
        state_dir=state_dir,
        worker_response_path=response_path,
        endpoint_id="endpoint",
        worker_image=WORKER_IMAGE,
        evidence_dir=evidence_dir,
    )
    verifier_document = PublicExperimentVerifier.model_validate(
        strict_json_object((evidence_dir / "experiment-verifier.json").read_bytes())
    )
    record = ExperimentRecordVerifier.from_public_jwk(
        verifier_document.public_jwk,
        key_id=verifier_document.key_id,
    ).verify(signed)

    expected_hash = hashlib.sha256(marker.encode()).hexdigest()
    assert record.runpod_observation.job_id_sha256 == expected_hash
    assert record.runpod_observation.worker_id_sha256 == expected_hash
    assert all(marker.encode() not in path.read_bytes() for path in evidence_dir.iterdir())


def test_finalize_rejects_oversized_provider_envelope_before_read_or_spend(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    evidence_dir = tmp_path / "evidence"
    payload_path = tmp_path / "payload.json"
    response_path = tmp_path / "response.json"
    _private_directory(state_dir)
    _private_directory(evidence_dir)
    prepare_test_double(
        worker_image=WORKER_IMAGE,
        state_dir=state_dir,
        payload_path=payload_path,
        concurrency=2,
    )
    response_path.write_bytes(b"x" * (MAX_RUNPOD_ENVELOPE_BYTES + 1))

    with pytest.raises(LabProtocolError, match="envelope failed strict"):
        finalize(
            state_dir=state_dir,
            worker_response_path=response_path,
            endpoint_id="endpoint",
            worker_image=WORKER_IMAGE,
            evidence_dir=evidence_dir,
        )
    assert not any(evidence_dir.iterdir())


def test_public_bundle_verifier_rejects_projection_tampering(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    evidence_dir = tmp_path / "evidence"
    payload_path = tmp_path / "payload.json"
    response_path = tmp_path / "response.json"
    _private_directory(state_dir)
    _private_directory(evidence_dir)
    prepare_test_double(
        worker_image=WORKER_IMAGE,
        state_dir=state_dir,
        payload_path=payload_path,
        concurrency=2,
    )
    _prepare_worker_response(payload_path, response_path)
    finalize(
        state_dir=state_dir,
        worker_response_path=response_path,
        endpoint_id="endpoint",
        worker_image=WORKER_IMAGE,
        evidence_dir=evidence_dir,
    )
    projection = strict_json_object((evidence_dir / "experiment-record.json").read_bytes())
    projection["observed_at"] += 1
    (evidence_dir / "experiment-record.json").write_bytes(canonical_json(projection))

    with pytest.raises(LabProtocolError, match="bundle verification failed"):
        verify_evidence_bundle(evidence_dir)


def test_public_bundle_verifier_rejects_oversized_file_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = tmp_path / "evidence"
    _private_directory(evidence_dir)
    (evidence_dir / "experiment-verifier.json").write_bytes(
        b"x" * (MAX_EXPERIMENT_VERIFIER_BYTES + 1)
    )

    def forbidden_read(_descriptor: int, _amount: int) -> bytes:
        raise AssertionError("oversized evidence must be rejected before reading")

    monkeypatch.setattr(os, "read", forbidden_read)
    with pytest.raises(LabProtocolError, match="bundle verification failed"):
        verify_evidence_bundle(evidence_dir)


def test_public_bundle_verifier_rejects_symlinked_file(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    _private_directory(evidence_dir)
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    (evidence_dir / "experiment-verifier.json").symlink_to(target)

    with pytest.raises(LabProtocolError, match="bundle verification failed"):
        verify_evidence_bundle(evidence_dir)


@pytest.mark.skipif(
    not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
    reason="FIFO nonblocking check requires POSIX support",
)
def test_public_bundle_verifier_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    _private_directory(evidence_dir)
    os.mkfifo(evidence_dir / "experiment-verifier.json", mode=0o600)

    with pytest.raises(LabProtocolError, match="bundle verification failed"):
        verify_evidence_bundle(evidence_dir)
