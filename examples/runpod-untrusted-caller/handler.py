"""Runpod Serverless entrypoint for the disposable cA2A holder worker."""

from __future__ import annotations

import json
from typing import Any

import rfc8785
import runpod
from lab.worker import DisposableHolderWorker
from lab.worker_wire import UntrustedRunpodMetadata


def handler(event: dict[str, Any]) -> dict[str, Any]:
    """Generate holder proofs without treating the provider as authoritative."""

    payload = event.get("input")
    if not isinstance(payload, dict):
        raise ValueError("worker input must be a JSON object")
    try:
        response = DisposableHolderWorker.process_payload(
            rfc8785.dumps(payload),
            runpod_metadata=UntrustedRunpodMetadata(provider="runpod", trust="untrusted"),
        )
        decoded = json.loads(response)
    except Exception:
        # The provider may log exception text. Never reflect the payload or its
        # disposable private key in an error message.
        raise ValueError("worker rejected the proof-generation request") from None
    if not isinstance(decoded, dict):
        raise RuntimeError("worker produced a non-object response")
    return decoded


if __name__ == "__main__":
    runpod.serverless.start({"handler": handler})
