"""Write a bounded local projection of an untrusted Runpod billing response."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Literal, TypedDict

MAX_BILLING_RESPONSE_BYTES = 1_048_576
HEX_32 = re.compile(r"^[0-9a-f]{64}$")


class BillingProjection(TypedDict):
    schema_version: Literal["atcap-runpod-billing-observation/v1"]
    provider: Literal["runpod"]
    trust: Literal["untrusted"]
    retrieval: Literal["received", "unavailable", "oversized"]
    endpoint_id_sha256: str
    response_bytes: int
    response_sha256: str | None


def project_billing_response(
    *,
    raw_path: Path,
    output_path: Path,
    endpoint_id_sha256: str,
    command_succeeded: bool,
) -> BillingProjection:
    """Persist no provider-selected content; only size and a bounded digest."""

    if HEX_32.fullmatch(endpoint_id_sha256) is None:
        raise ValueError("endpoint ID digest must be lowercase SHA-256")
    response_bytes = raw_path.stat().st_size if raw_path.exists() else 0
    response_sha256: str | None = None
    if not command_succeeded:
        retrieval: Literal["received", "unavailable", "oversized"] = "unavailable"
    elif response_bytes > MAX_BILLING_RESPONSE_BYTES:
        retrieval = "oversized"
    else:
        response_sha256 = hashlib.sha256(raw_path.read_bytes()).hexdigest()
        retrieval = "received"
    projection: BillingProjection = {
        "schema_version": "atcap-runpod-billing-observation/v1",
        "provider": "runpod",
        "trust": "untrusted",
        "retrieval": retrieval,
        "endpoint_id_sha256": endpoint_id_sha256,
        "response_bytes": response_bytes,
        "response_sha256": response_sha256,
    }
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(projection, output, indent=2, sort_keys=True)
        output.write("\n")
    return projection


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--endpoint-id-sha256", required=True)
    parser.add_argument("--command-status", choices=["success", "failure"], required=True)
    arguments = parser.parse_args(argv)
    project_billing_response(
        raw_path=arguments.raw,
        output_path=arguments.output,
        endpoint_id_sha256=arguments.endpoint_id_sha256,
        command_succeeded=arguments.command_status == "success",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
