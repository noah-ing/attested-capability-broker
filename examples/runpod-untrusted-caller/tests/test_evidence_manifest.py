"""Evidence checksum/cleanup summary coverage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from evidence_manifest import write_manifest
from lab_test_support import WORKER_IMAGE


def test_evidence_manifest_hashes_files_and_records_cleanup(tmp_path: Path) -> None:
    evidence = tmp_path / "dedicated-evidence"
    evidence.mkdir()
    (evidence / "record.jws").write_bytes(b"signed-record\n")
    write_manifest(
        root=evidence,
        worker_image=WORKER_IMAGE,
        endpoint_id_sha256="a" * 64,
        template_id_sha256="b" * 64,
        cleanup_complete=True,
    )

    expected_hash = hashlib.sha256(b"signed-record\n").hexdigest()
    assert (evidence / "SHA256SUMS").read_text() == f"{expected_hash}  record.jws\n"
    manifest = json.loads((evidence / "verification-manifest.json").read_text())
    assert manifest == {
        "schema_version": "atcap-runpod-live-evidence-manifest/v1",
        "worker_image": WORKER_IMAGE,
        "endpoint_id_sha256": "a" * 64,
        "template_id_sha256": "b" * 64,
        "cleanup_complete": True,
        "files": {"record.jws": expected_hash},
    }
