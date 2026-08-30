"""Full optional-lab flow driven by genuine local software-TPM quotes."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from lab.live_cli import finalize, prepare_real_swtpm
from lab.record import ExperimentRecordVerifier
from lab.wire import (
    PublicExperimentVerifier,
    RunpodJobEnvelope,
    WorkerResponseBundle,
    strict_json_object,
)
from lab.worker import DisposableHolderWorker
from lab_test_support import WORKER_IMAGE

from atcap.canonical import canonical_json


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


@pytest.mark.swtpm
def test_real_swtpm_issues_every_remote_case_and_binds_signed_record(tmp_path: Path) -> None:
    """No test double participates in this end-to-end lab preparation path."""

    tcti = os.environ.get("ATCAP_SWTPM_TCTI")
    if not tcti:
        pytest.skip("ATCAP_SWTPM_TCTI is not configured")
    state_dir = tmp_path / "trusted-state"
    evidence_dir = tmp_path / "public-evidence"
    payload_path = tmp_path / "worker-payload.json"
    response_path = tmp_path / "provider-response.json"
    _private_directory(state_dir)
    _private_directory(evidence_dir)

    prepare_real_swtpm(
        worker_image=WORKER_IMAGE,
        state_dir=state_dir,
        payload_path=payload_path,
        tcti=tcti,
        concurrency=8,
        capability_ttl_seconds=300,
    )
    raw_bundle = DisposableHolderWorker.process_payload(payload_path.read_bytes())
    bundle = WorkerResponseBundle.model_validate(strict_json_object(raw_bundle))
    envelope = RunpodJobEnvelope(
        id="untrusted-provider-job-real-swtpm",
        status="COMPLETED",
        output=bundle,
    )
    response_path.write_bytes(canonical_json(envelope.model_dump(mode="json")))
    signed = finalize(
        state_dir=state_dir,
        worker_response_path=response_path,
        endpoint_id="untrusted-provider-endpoint-real-swtpm",
        worker_image=WORKER_IMAGE,
        evidence_dir=evidence_dir,
    )

    verifier_document = PublicExperimentVerifier.model_validate(
        strict_json_object((evidence_dir / "experiment-verifier.json").read_bytes())
    )
    verifier = ExperimentRecordVerifier.from_public_jwk(
        verifier_document.public_jwk,
        key_id=verifier_document.key_id,
    )
    record = verifier.verify(signed)
    assert record.tpm_mode == "real-swtpm"
    assert record.tpm_evidence_verified is True
    assert record.tpm_assurance_included is True
    assert record.broker_receipt_count == 7
    assert record.resource_receipt_count == 15
    assert record.allowed_attempt_count == 3
    assert record.denied_attempt_count == 12
    assert record.handler_invocation_count == 3
    assert record.credential_redemption_count == 3
