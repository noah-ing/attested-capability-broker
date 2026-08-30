"""Exercise the exact Runpod handler and its secret-safe failure boundary."""

from __future__ import annotations

import os

from handler import handler
from lab.worker_wire import UntrustedRunpodMetadata, WorkerResponseBundle
from self_test import build_payload


def main() -> int:
    worker_image = os.environ.get(
        "ATCAP_SELF_TEST_WORKER_IMAGE",
        "example.invalid/atcap/worker@sha256:" + ("0" * 64),
    )
    payload, _credential, _challenge_secret = build_payload(worker_image)
    result = handler(
        {
            "id": "untrusted-provider-handler-self-test",
            "input": payload.model_dump(mode="json"),
        }
    )
    bundle = WorkerResponseBundle.model_validate(result)
    if bundle.responses[0].runpod_metadata != UntrustedRunpodMetadata(
        provider="runpod", trust="untrusted"
    ):
        raise AssertionError("handler metadata is not the fixed untrusted marker")
    private_marker = payload.disposable_holder_private_key
    malformed = payload.model_dump(mode="json")
    malformed["disposable_holder_private_key"] = f"INVALID-{private_marker}"
    try:
        handler({"id": "malformed-job", "input": malformed})
    except ValueError as exc:
        if str(exc) != "worker rejected the proof-generation request":
            raise AssertionError("handler exposed a non-generic failure") from exc
        if private_marker in str(exc):
            raise AssertionError("handler failure exposed disposable key material") from exc
    else:
        raise AssertionError("handler accepted malformed private key material")
    print("deployed handler secret-safe boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
