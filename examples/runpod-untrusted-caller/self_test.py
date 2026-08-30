"""Non-networked smoke test for the exact deployed worker contract."""

from __future__ import annotations

import hashlib
import os

import rfc8785
from ca2a_runtime.challenge import issue_challenge
from ca2a_runtime.delegation import (
    DelegationCredential,
    HolderProof,
    verify_holder_proof,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from lab.worker import DisposableHolderWorker
from lab.worker_wire import (
    InventoryArgumentsWire,
    UntrustedRunpodMetadata,
    WorkerPayload,
    WorkerRequest,
    WorkerResponseBundle,
    strict_json_object,
)

AUDIENCE = "inventoryd"
SCOPE = "mcp://inventoryd/tool/inventory.lookup"
RECORD_ID = "worker-self-test-record"
SKU = "worker-self-test-sku"


def build_payload(worker_image: str) -> tuple[WorkerPayload, DelegationCredential, bytes]:
    """Build the deterministic fake credential/proof input used by image checks."""

    holder_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
    issuer_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
    holder_public = holder_private.public_key().public_bytes_raw().hex()
    credential = DelegationCredential(
        credential_id="33" * 32,
        issuer=issuer_private.public_key().public_bytes_raw().hex(),
        subject=holder_public,
        scope=frozenset({SCOPE}),
        depth=0,
        not_before=1,
        not_after=4_102_444_800,
    ).sign(issuer_private)
    challenge_secret = b"worker-self-test-challenge-secret"
    challenge = issue_challenge(challenge_secret, ttl_seconds=60)
    code_digest = hashlib.sha256(b"atcap-runpod-worker-self-test-contract/v1").hexdigest()
    request = WorkerRequest(
        schema_version="atcap-runpod-worker-request/v1",
        case_id="worker-self-test",
        run_id="worker-self-test-1",
        variant="valid",
        credential={**credential.body(), "signature": credential.signature},
        challenge=challenge,
        audience=AUDIENCE,
        qualified_scope=SCOPE,
        record_id=RECORD_ID,
        arguments=InventoryArgumentsWire(sku=SKU),
        worker_image=worker_image,
        worker_code_digest=code_digest,
    )
    payload = WorkerPayload(
        schema_version="atcap-runpod-worker-payload/v1",
        disposable_holder_private_key=holder_private.private_bytes_raw().hex(),
        worker_image=worker_image,
        worker_code_digest=code_digest,
        requests=[request],
    )
    return payload, credential, challenge_secret


def main() -> int:
    worker_image = os.environ.get(
        "ATCAP_SELF_TEST_WORKER_IMAGE",
        "example.invalid/atcap/worker@sha256:" + ("0" * 64),
    )
    payload, credential, challenge_secret = build_payload(worker_image)
    holder_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
    private_hex = payload.disposable_holder_private_key
    raw_response = DisposableHolderWorker.process_payload(
        rfc8785.dumps(payload.model_dump(mode="json")),
        runpod_metadata=UntrustedRunpodMetadata(provider="runpod", trust="untrusted"),
    )
    if private_hex.encode() in raw_response:
        raise AssertionError("worker response disclosed the disposable private key")
    decoded = strict_json_object(raw_response)
    if rfc8785.dumps(decoded) != raw_response:
        raise AssertionError("worker response is not canonical JSON")
    bundle = WorkerResponseBundle.model_validate(decoded)
    if len(bundle.responses) != 1:
        raise AssertionError("worker returned an unexpected response count")
    response = bundle.responses[0]
    if response.runpod_metadata != UntrustedRunpodMetadata(provider="runpod", trust="untrusted"):
        raise AssertionError("worker metadata is not the fixed untrusted marker")
    proof = HolderProof.from_dict(response.holder_proof.model_dump(mode="json"))
    verify_holder_proof(
        proof,
        credential,
        audience=AUDIENCE,
        challenge_secret=challenge_secret,
        requested_capability=SCOPE,
        record_id=RECORD_ID,
        sealed_payload=rfc8785.dumps({"sku": SKU}),
        caller_channel_key=None,
        parent_record_hash=None,
    )
    holder_private.public_key().verify(
        bytes.fromhex(response.holder_signature),
        rfc8785.dumps(response.signed_body().model_dump(mode="json")),
    )
    print("deployed worker fake contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
