"""Secret-safe billing projection coverage."""

from __future__ import annotations

import hashlib
from pathlib import Path

from billing_observation import MAX_BILLING_RESPONSE_BYTES, project_billing_response


def test_provider_billing_content_is_never_reflected_into_evidence(tmp_path: Path) -> None:
    marker = "PROVIDER_REFLECTED_PRIVATE_MARKER"
    raw = tmp_path / "private-billing.raw"
    output = tmp_path / "billing-observation.json"
    raw.write_text('{"provider":"' + marker + '"}', encoding="utf-8")

    projection = project_billing_response(
        raw_path=raw,
        output_path=output,
        endpoint_id_sha256="a" * 64,
        command_succeeded=True,
    )

    assert projection["retrieval"] == "received"
    assert projection["response_sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert marker not in output.read_text(encoding="utf-8")


def test_oversized_billing_response_is_not_read_or_hashed(tmp_path: Path) -> None:
    raw = tmp_path / "oversized.raw"
    output = tmp_path / "billing-observation.json"
    raw.write_bytes(b"x" * (MAX_BILLING_RESPONSE_BYTES + 1))

    projection = project_billing_response(
        raw_path=raw,
        output_path=output,
        endpoint_id_sha256="b" * 64,
        command_succeeded=True,
    )

    assert projection["retrieval"] == "oversized"
    assert projection["response_sha256"] is None
