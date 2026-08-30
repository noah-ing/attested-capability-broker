"""Pure, shared worker wire contract used by local and deployment code."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

HEX_32_PATTERN = r"^[0-9a-f]{64}$"
HEX_64_PATTERN = r"^[0-9a-f]{128}$"
RUN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
IMAGE_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]*/[A-Za-z0-9][A-Za-z0-9._:/-]*"
    r"@sha256:[0-9a-f]{64}$"
)

Variant = Literal[
    "valid",
    "replay",
    "argument-substitution",
    "record-substitution",
    "wrong-holder",
    "malformed",
    "concurrent",
]


class ClosedWorkerModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


class InventoryArgumentsWire(ClosedWorkerModel):
    sku: str = Field(min_length=1, max_length=128)


class UntrustedRunpodMetadata(ClosedWorkerModel):
    """Fixed trust label; no provider-controlled value is reflected in evidence."""

    provider: Literal["runpod"]
    trust: Literal["untrusted"]


ProofSignature = Annotated[str, Field(pattern=HEX_64_PATTERN)] | Literal[7]


class HolderProofWire(ClosedWorkerModel):
    """Exact cA2A proof shape plus one bounded malformed-test sentinel."""

    challenge: str = Field(min_length=1, max_length=8192)
    signature: ProofSignature


class WorkerRequest(ClosedWorkerModel):
    schema_version: Literal["atcap-runpod-worker-request/v1"]
    case_id: str = Field(pattern=RUN_ID_PATTERN)
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    variant: Variant
    credential: dict[str, JsonValue]
    challenge: str = Field(min_length=1)
    audience: str = Field(min_length=1, max_length=256)
    qualified_scope: str = Field(min_length=1, max_length=512)
    record_id: str = Field(min_length=1, max_length=256)
    arguments: InventoryArgumentsWire
    worker_image: str = Field(pattern=IMAGE_PATTERN)
    worker_code_digest: str = Field(pattern=HEX_32_PATTERN)


class WorkerPayload(ClosedWorkerModel):
    """Remote payload; its only private field is the disposable holder key."""

    schema_version: Literal["atcap-runpod-worker-payload/v1"]
    disposable_holder_private_key: str = Field(pattern=HEX_32_PATTERN)
    worker_image: str = Field(pattern=IMAGE_PATTERN)
    worker_code_digest: str = Field(pattern=HEX_32_PATTERN)
    requests: list[WorkerRequest] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def _consistent_requests(self) -> WorkerPayload:
        run_ids = [request.run_id for request in self.requests]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("worker payload has duplicate run IDs")
        for request in self.requests:
            if request.worker_image != self.worker_image:
                raise ValueError("worker image is inconsistent across the payload")
            if request.worker_code_digest != self.worker_code_digest:
                raise ValueError("worker digest is inconsistent across the payload")
        return self


class WorkerResponseBody(ClosedWorkerModel):
    schema_version: Literal["atcap-runpod-worker-response/v1"]
    case_id: str = Field(pattern=RUN_ID_PATTERN)
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    request_sha256: str = Field(pattern=HEX_32_PATTERN)
    worker_public_key: str = Field(pattern=HEX_32_PATTERN)
    proof_subject: str = Field(pattern=HEX_32_PATTERN)
    worker_image: str = Field(pattern=IMAGE_PATTERN)
    worker_code_digest: str = Field(pattern=HEX_32_PATTERN)
    holder_proof: HolderProofWire
    runpod_metadata: UntrustedRunpodMetadata


class WorkerResponse(WorkerResponseBody):
    """Holder-signed output; never platform or image-execution attestation."""

    holder_signature: str = Field(pattern=HEX_64_PATTERN)

    def signed_body(self) -> WorkerResponseBody:
        return WorkerResponseBody.model_validate(
            self.model_dump(mode="json", exclude={"holder_signature"})
        )


class WorkerResponseBundle(ClosedWorkerModel):
    schema_version: Literal["atcap-runpod-worker-response-bundle/v1"]
    responses: list[WorkerResponse] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def _unique_run_ids(self) -> WorkerResponseBundle:
        run_ids = [response.run_id for response in self.responses]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("worker response bundle has duplicate run IDs")
        return self


class RunpodJobEnvelope(ClosedWorkerModel):
    """Narrow locally accepted projection of one provider job response."""

    id: str = Field(min_length=1, max_length=256)
    status: Literal["COMPLETED"]
    delayTime: int | None = Field(default=None, ge=0, le=86_400_000)
    executionTime: int | None = Field(default=None, ge=0, le=86_400_000)
    workerId: str | None = Field(default=None, min_length=1, max_length=256)
    output: WorkerResponseBundle


def strict_json_object(raw: bytes) -> dict[str, Any]:
    """Decode one JSON object and reject duplicate names at every depth."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("wire document has duplicate JSON member names")
            result[key] = value
        return result

    decoded: Any = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(decoded, dict):
        raise ValueError("wire document must be a JSON object")
    return decoded
