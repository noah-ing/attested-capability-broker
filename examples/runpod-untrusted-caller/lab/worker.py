"""Disposable holder worker that generates real cA2A holder proofs."""

from __future__ import annotations

import argparse
import hashlib
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import rfc8785
from ca2a_runtime.delegation import DelegationCredential, build_holder_proof
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from .errors import LabProtocolError
from .worker_wire import (
    HolderProofWire,
    UntrustedRunpodMetadata,
    WorkerPayload,
    WorkerRequest,
    WorkerResponse,
    WorkerResponseBody,
    WorkerResponseBundle,
    strict_json_object,
)


def canonical_json(value: Any) -> bytes:
    return rfc8785.dumps(value)


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _parse_canonical(raw: bytes, model: type[WorkerPayload] | type[WorkerRequest]) -> Any:
    try:
        decoded = strict_json_object(raw)
        if canonical_json(decoded) != raw:
            raise ValueError("document is not RFC 8785 canonical JSON")
        return model.model_validate(decoded)
    except Exception as exc:
        raise LabProtocolError("worker input failed strict canonical validation") from exc


class DisposableHolderWorker:
    """Proof generator holding only one disposable holder private key.

    A holder-signed response authenticates key possession and the bytes the key
    signed. It is not evidence of Runpod identity, image execution, or platform
    attestation. The controller therefore treats all provider metadata and the
    claimed code digest as untrusted until comparing them with local expectations.
    """

    def __init__(
        self,
        *,
        holder_private_key: Ed25519PrivateKey,
        worker_image: str,
        worker_code_digest: str,
        runpod_metadata: UntrustedRunpodMetadata | None = None,
    ) -> None:
        self._holder_private_key = holder_private_key
        self.worker_public_key = holder_private_key.public_key().public_bytes_raw().hex()
        self.worker_image = worker_image
        self.worker_code_digest = worker_code_digest
        self.runpod_metadata = runpod_metadata or UntrustedRunpodMetadata(
            provider="runpod", trust="untrusted"
        )

    @classmethod
    def from_payload(
        cls,
        payload: WorkerPayload,
        *,
        runpod_metadata: UntrustedRunpodMetadata | None = None,
    ) -> DisposableHolderWorker:
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(payload.disposable_holder_private_key)
            )
        except ValueError as exc:
            raise LabProtocolError("disposable holder key is malformed") from exc
        return cls(
            holder_private_key=private_key,
            worker_image=payload.worker_image,
            worker_code_digest=payload.worker_code_digest,
            runpod_metadata=runpod_metadata,
        )

    def generate(self, request: WorkerRequest) -> WorkerResponse:
        try:
            credential = DelegationCredential.from_dict(request.credential)
            proof_key = self._holder_private_key
            proof_credential = credential
            proof_record_id = request.record_id
            proof_arguments = request.arguments.model_dump(mode="json")

            if request.variant == "argument-substitution":
                proof_arguments = {"sku": f"{request.arguments.sku}-substituted"}
            elif request.variant == "record-substitution":
                proof_record_id = f"{request.record_id}-substituted"
            elif request.variant == "wrong-holder":
                proof_key = Ed25519PrivateKey.generate()
                proof_credential = replace(
                    credential,
                    subject=proof_key.public_key().public_bytes_raw().hex(),
                )

            proof = build_holder_proof(
                proof_key,
                proof_credential,
                audience=request.audience,
                challenge=request.challenge,
                requested_capability=request.qualified_scope,
                record_id=proof_record_id,
                sealed_payload=canonical_json(proof_arguments),
                caller_channel_key=None,
                parent_record_hash=None,
            )
            holder_proof = HolderProofWire.model_validate(proof.to_dict())
            if request.variant == "malformed":
                holder_proof = HolderProofWire(
                    challenge=proof.challenge,
                    signature=7,
                )

            observed_metadata = UntrustedRunpodMetadata(
                provider=self.runpod_metadata.provider,
                trust=self.runpod_metadata.trust,
            )
            body = WorkerResponseBody(
                schema_version="atcap-runpod-worker-response/v1",
                case_id=request.case_id,
                run_id=request.run_id,
                request_sha256=canonical_digest(request.model_dump(mode="json")),
                worker_public_key=self.worker_public_key,
                proof_subject=proof_credential.subject,
                worker_image=self.worker_image,
                worker_code_digest=self.worker_code_digest,
                holder_proof=holder_proof,
                runpod_metadata=observed_metadata,
            )
            signature = self._holder_private_key.sign(
                canonical_json(body.model_dump(mode="json"))
            ).hex()
            return WorkerResponse(
                **body.model_dump(mode="json"),
                holder_signature=signature,
            )
        except LabProtocolError:
            raise
        except Exception as exc:
            raise LabProtocolError("worker could not generate the requested proof") from exc

    def handle_bytes(self, raw_request: bytes) -> bytes:
        request = _parse_canonical(raw_request, WorkerRequest)
        return canonical_json(self.generate(request).model_dump(mode="json"))

    @classmethod
    def process_payload(
        cls,
        raw_payload: bytes,
        *,
        runpod_metadata: UntrustedRunpodMetadata | None = None,
    ) -> bytes:
        payload = _parse_canonical(raw_payload, WorkerPayload)
        worker = cls.from_payload(payload, runpod_metadata=runpod_metadata)
        responses = [worker.generate(request) for request in payload.requests]
        bundle = WorkerResponseBundle(
            schema_version="atcap-runpod-worker-response-bundle/v1",
            responses=responses,
        )
        return canonical_json(bundle.model_dump(mode="json"))


def _write_private(path: Path, contents: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(contents)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        raw_payload = arguments.payload.read_bytes()
        response = DisposableHolderWorker.process_payload(raw_payload)
        _write_private(arguments.output, response)
    except (OSError, LabProtocolError, ValidationError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
