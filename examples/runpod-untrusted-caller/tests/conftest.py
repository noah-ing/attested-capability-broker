"""Fixtures for the isolated no-provider-infrastructure adversarial lab."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

LAB_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(LAB_ROOT))
if str(REPOSITORY_ROOT) in sys.path:
    sys.path.remove(str(REPOSITORY_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT))

from lab.controller import TrustedController  # noqa: E402
from lab.record import ExperimentRecordSigner  # noqa: E402
from lab.worker import DisposableHolderWorker  # noqa: E402
from lab_test_support import WORKER_DIGEST, WORKER_IMAGE  # noqa: E402

from tests.support import Harness  # noqa: E402


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness.create(tmp_path / "lab.sqlite3")


@pytest.fixture
def lab_components(harness: Harness) -> dict[str, Any]:
    signer = ExperimentRecordSigner.generate(key_id="experiment-test-v1")
    worker = DisposableHolderWorker(
        holder_private_key=harness.holder_private,
        worker_image=WORKER_IMAGE,
        worker_code_digest=WORKER_DIGEST,
    )
    controller = TrustedController(
        inventory=harness.inventory,
        store=harness.store,
        broker_receipt_verifier=harness.broker_receipts,
        resource_receipt_verifier=harness.inventory_receipts,
        experiment_signer=signer,
        expected_worker_public_key=harness.holder_public,
        worker_image=WORKER_IMAGE,
        worker_code_digest=WORKER_DIGEST,
        clock=harness.clock,
    )
    return {"controller": controller, "worker": worker, "signer": signer}
