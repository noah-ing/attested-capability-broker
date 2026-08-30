"""Fail-closed validation for Runpod template and endpoint read-backs.

This module intentionally uses only the Python standard library so the live
runner can validate provider state before installing or trusting any additional
code.  It validates the security-relevant fields that the runner requested; it
does not treat Runpod's response as attestation evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import cast

MAX_JSON_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 10_000
MAX_OBJECT_KEYS = 256
MAX_ARRAY_ITEMS = 1_024
MAX_STRING_CHARS = 16_384
MAX_NUMBER_CHARS = 128

_RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RESOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_WORKER_IMAGE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]*/[A-Za-z0-9][A-Za-z0-9._:/-]*"
    r"@sha256:[0-9a-f]{64}$"
)
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MISSING = object()
_RUNPODCTL_2120_PROVIDER_DEFAULT_PORTS = ("8888/http", "22/tcp")


class ProviderReadbackError(ValueError):
    """A provider read-back was malformed or did not match requested policy."""


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProviderReadbackError("JSON contains a duplicate object member")
        result[key] = value
    return result


def _bounded_int(raw: str) -> int:
    if len(raw) > MAX_NUMBER_CHARS:
        raise ProviderReadbackError("JSON contains an oversized number")
    return int(raw)


def _bounded_decimal(raw: str) -> Decimal:
    if len(raw) > MAX_NUMBER_CHARS:
        raise ProviderReadbackError("JSON contains an oversized number")
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise ProviderReadbackError("JSON contains an invalid number") from exc
    if not value.is_finite():
        raise ProviderReadbackError("JSON contains a non-finite number")
    return value


def _reject_constant(_raw: str) -> object:
    raise ProviderReadbackError("JSON contains a non-standard numeric constant")


def _validate_json_shape(value: object, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > MAX_JSON_NODES:
        raise ProviderReadbackError("JSON exceeds the node limit")
    if depth > MAX_JSON_DEPTH:
        raise ProviderReadbackError("JSON exceeds the nesting limit")

    if value is None or type(value) in (bool, int, Decimal):
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            raise ProviderReadbackError("JSON contains an oversized string")
        return
    if isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise ProviderReadbackError("JSON array exceeds the item limit")
        for item in value:
            _validate_json_shape(item, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            raise ProviderReadbackError("JSON object exceeds the member limit")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProviderReadbackError("JSON object contains a non-string member name")
            if len(key) > MAX_STRING_CHARS:
                raise ProviderReadbackError("JSON contains an oversized member name")
            _validate_json_shape(item, depth=depth + 1, nodes=nodes)
        return
    raise ProviderReadbackError("JSON contains an unsupported value type")


def _load_bounded_json_and_raw(path: Path) -> tuple[object, bytes]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ProviderReadbackError("provider JSON must be a regular file")
            if metadata.st_size > MAX_JSON_BYTES:
                raise ProviderReadbackError("provider JSON exceeds the byte limit")
            raw = source.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise ProviderReadbackError("provider JSON could not be read") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise ProviderReadbackError("provider JSON exceeds the byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProviderReadbackError("provider JSON is not valid UTF-8") from exc

    try:
        value = cast(
            object,
            json.loads(
                text,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_int=_bounded_int,
                parse_float=_bounded_decimal,
                parse_constant=_reject_constant,
            ),
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ProviderReadbackError("provider JSON is malformed") from exc
    _validate_json_shape(value, depth=0, nodes=[0])
    return value, raw


def load_bounded_json(path: Path) -> object:
    """Load one bounded, duplicate-safe UTF-8 JSON value from *path*."""

    return _load_bounded_json_and_raw(path)[0]


def load_bounded_json_object(path: Path) -> dict[str, object]:
    """Load one bounded, duplicate-safe UTF-8 JSON object from *path*."""

    value = load_bounded_json(path)
    if not isinstance(value, dict):
        raise ProviderReadbackError("provider JSON must be a top-level object")
    return cast(dict[str, object], value)


def _validate_expected(label: str, value: str, pattern: re.Pattern[str]) -> None:
    if pattern.fullmatch(value) is None:
        raise ProviderReadbackError(f"expected {label} is invalid")


def _expect_exact(
    document: dict[str, object], field: str, expected: object, *, context: str
) -> None:
    observed = document.get(field, _MISSING)
    if observed is _MISSING:
        raise ProviderReadbackError(f"{context} omitted required field {field}")
    if type(observed) is not type(expected) or observed != expected:
        raise ProviderReadbackError(f"{context} field {field} did not match requested policy")


def _is_exact_empty(value: object, allowed: tuple[object, ...]) -> bool:
    return any(type(value) is type(candidate) and value == candidate for candidate in allowed)


def _expect_absent_or_empty(
    document: dict[str, object],
    field: str,
    *,
    allowed: tuple[object, ...],
    context: str,
) -> None:
    observed = document.get(field, _MISSING)
    if observed is _MISSING:
        return
    if not _is_exact_empty(observed, allowed):
        raise ProviderReadbackError(f"{context} field {field} must be empty")


def _expect_absent(document: dict[str, object], field: str, *, context: str) -> None:
    if field in document:
        raise ProviderReadbackError(f"{context} field {field} must be absent")


def _validate_provider_default_ports(document: dict[str, object], *, context: str) -> None:
    ports = document.get("ports", _MISSING)
    if type(ports) is not list or ports != list(_RUNPODCTL_2120_PROVIDER_DEFAULT_PORTS):
        raise ProviderReadbackError(
            f"{context} field ports did not match the reviewed runpodctl 2.12.0 provider defaults"
        )


def _validate_template(
    document: dict[str, object],
    *,
    template_id: str,
    template_name: str,
    worker_image: str,
    context: str,
) -> None:
    expected: tuple[tuple[str, object], ...] = (
        ("id", template_id),
        ("name", template_name),
        ("imageName", worker_image),
        ("isServerless", True),
        ("containerDiskInGb", 5),
    )
    for field, value in expected:
        _expect_exact(document, field, value, context=context)

    # runpodctl 2.12 marshals its typed integer with ``omitempty``: requested
    # zero volume may therefore be absent, while any present value must be int 0.
    volume = document.get("volumeInGb", _MISSING)
    if volume is not _MISSING and (type(volume) is not int or volume != 0):
        raise ProviderReadbackError(f"{context} field volumeInGb must be absent or integer 0")

    _expect_absent_or_empty(document, "env", allowed=(None, {}, []), context=context)
    # runpodctl 2.12.0 omits an empty ``ports`` slice from its REST create request,
    # and the current provider fills exactly these two template defaults. The
    # worker image does not run SSH or Jupyter, but Runpod and its networking are
    # outside the trust boundary; accept no additional or duplicate declaration.
    _validate_provider_default_ports(document, context=context)
    for field in ("dockerEntrypoint", "dockerStartCmd"):
        _expect_absent_or_empty(document, field, allowed=(None, "", []), context=context)
    _expect_absent_or_empty(
        document, "containerRegistryAuthId", allowed=(None, ""), context=context
    )


def _identifier_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _template_projection(
    *, template_id: str, template_name: str, worker_image: str
) -> dict[str, object]:
    return {
        "schema_version": "atcap.runpod.provider-readback-projection.v2",
        "resource": "template",
        "template_id_sha256": _identifier_sha256(template_id),
        "requested_config": {
            "container_disk_gb": 5,
            "container_registry_auth": False,
            "docker_entrypoint_override": False,
            "docker_start_command_override": False,
            "environment": False,
            "port_reachability_assurance": "none",
            "ports_requested": False,
            "provider_default_ports": list(_RUNPODCTL_2120_PROVIDER_DEFAULT_PORTS),
            "serverless": True,
            "template_name": template_name,
            "volume_gb": 0,
            "worker_image": worker_image,
        },
        "validation": "passed",
    }


def validate_template_readback(
    path: Path, *, template_id: str, template_name: str, worker_image: str
) -> dict[str, object]:
    """Validate the exact security-relevant configuration of a template read-back."""

    _validate_expected("template ID", template_id, _RESOURCE_ID)
    _validate_expected("template name", template_name, _RESOURCE_NAME)
    _validate_expected("worker image", worker_image, _WORKER_IMAGE)
    _validate_template(
        load_bounded_json_object(path),
        template_id=template_id,
        template_name=template_name,
        worker_image=worker_image,
        context="template read-back",
    )
    return _template_projection(
        template_id=template_id,
        template_name=template_name,
        worker_image=worker_image,
    )


def validate_endpoint_readback(
    path: Path,
    *,
    create_path: Path,
    endpoint_id: str,
    endpoint_name: str,
    template_id: str,
    template_name: str,
    instance_id: str,
    worker_image: str,
) -> dict[str, object]:
    """Validate composed create/get evidence before submitting one provider job.

    runpodctl 2.12.0's GraphQL create response carries the CPU instance binding,
    while its subsequent REST get omits those compute fields.  The REST response
    independently rebinds the endpoint/template identity and mutable policy
    fields.  Neither provider response is attestation evidence.
    """

    _validate_expected("endpoint ID", endpoint_id, _RESOURCE_ID)
    _validate_expected("endpoint name", endpoint_name, _RESOURCE_NAME)
    _validate_expected("template ID", template_id, _RESOURCE_ID)
    _validate_expected("template name", template_name, _RESOURCE_NAME)
    _validate_expected("CPU instance ID", instance_id, _RESOURCE_ID)
    _validate_expected("worker image", worker_image, _WORKER_IMAGE)

    create_document = load_bounded_json_object(create_path)
    create_expected: tuple[tuple[str, object], ...] = (
        ("id", endpoint_id),
        ("name", endpoint_name),
        ("templateId", template_id),
        ("computeType", "CPU"),
        ("instanceIds", [instance_id]),
        ("workersMin", 0),
        ("workersMax", 1),
        ("idleTimeout", 5),
        ("scalerType", "REQUEST_COUNT"),
        ("scalerValue", 1),
        ("executionTimeoutMs", 120_000),
        # The provider returns this generic value even for the CPU instance
        # binding above. It is checked for response stability, never interpreted
        # as GPU allocation evidence.
        ("gpuCount", 1),
        ("flashBootType", "OFF"),
    )
    for field, value in create_expected:
        _expect_exact(create_document, field, value, context="endpoint create response")

    _expect_absent_or_empty(
        create_document,
        "gpuIds",
        allowed=(None, "", []),
        context="endpoint create response",
    )
    for field in ("gpuTypeIds", "gpuPoolIds", "serverlessGpuPools"):
        _expect_absent_or_empty(
            create_document,
            field,
            allowed=(None, "", []),
            context="endpoint create response",
        )
    _expect_absent_or_empty(
        create_document,
        "networkVolumeId",
        allowed=(None, ""),
        context="endpoint create response",
    )
    _expect_absent_or_empty(
        create_document,
        "networkVolumeIds",
        allowed=(None, []),
        context="endpoint create response",
    )
    create_empty_fields: tuple[tuple[str, tuple[object, ...]], ...] = (
        ("networkVolume", (None, {})),
        ("networkVolumes", (None, [])),
        ("locations", (None, "", [])),
        ("modelReferences", (None, [])),
    )
    for field, allowed in create_empty_fields:
        _expect_absent_or_empty(
            create_document,
            field,
            allowed=allowed,
            context="endpoint create response",
        )
    for field in ("flashboot", "flashBoot", "template", "workers"):
        _expect_absent(create_document, field, context="endpoint create response")

    document = load_bounded_json_object(path)
    get_expected: tuple[tuple[str, object], ...] = (
        ("id", endpoint_id),
        ("name", endpoint_name),
        ("templateId", template_id),
        ("workersMin", 0),
        ("workersMax", 1),
        ("idleTimeout", 5),
        ("scalerType", "REQUEST_COUNT"),
        ("scalerValue", 1),
        ("executionTimeoutMs", 120_000),
        ("gpuCount", 1),
        ("flashboot", False),
    )
    for field, value in get_expected:
        _expect_exact(document, field, value, context="endpoint REST read-back")
    for field in ("computeType", "instanceIds", "flashBootType", "flashBoot"):
        _expect_absent(document, field, context="endpoint REST read-back")
    _expect_absent_or_empty(
        document, "gpuIds", allowed=(None, "", []), context="endpoint REST read-back"
    )
    for field in ("gpuTypeIds", "gpuPoolIds", "serverlessGpuPools"):
        _expect_absent_or_empty(
            document,
            field,
            allowed=(None, "", []),
            context="endpoint REST read-back",
        )
    get_empty_fields: tuple[tuple[str, tuple[object, ...]], ...] = (
        ("networkVolumeId", (None, "")),
        ("networkVolumeIds", (None, [])),
        ("networkVolume", (None, {})),
        ("networkVolumes", (None, [])),
        ("locations", (None, "", [])),
        ("modelReferences", (None, [])),
    )
    for field, allowed in get_empty_fields:
        _expect_absent_or_empty(
            document,
            field,
            allowed=allowed,
            context="endpoint REST read-back",
        )

    nested = document.get("template", _MISSING)
    if not isinstance(nested, dict):
        raise ProviderReadbackError("endpoint REST read-back omitted the included template")
    nested_document = cast(dict[str, object], nested)
    nested_expected: tuple[tuple[str, object], ...] = (
        ("id", template_id),
        ("name", template_name),
        ("isServerless", True),
        ("containerDiskInGb", 5),
        ("containerRegistryAuthId", ""),
        ("readme", ""),
        ("startJupyter", True),
        ("startSsh", True),
        ("config", {"templateId": template_id}),
    )
    for field, value in nested_expected:
        _expect_exact(nested_document, field, value, context="endpoint included template")
    _validate_provider_default_ports(nested_document, context="endpoint included template")
    for field in (
        "imageName",
        "volumeInGb",
        "volumeMountPath",
        "env",
        "dockerEntrypoint",
        "dockerStartCmd",
    ):
        _expect_absent(nested_document, field, context="endpoint included template")

    return {
        "schema_version": "atcap.runpod.provider-readback-projection.v3",
        "resource": "endpoint",
        "endpoint_id_sha256": _identifier_sha256(endpoint_id),
        "template_id_sha256": _identifier_sha256(template_id),
        "provider_observation": {
            "compute_binding_source": "runpodctl-2.12.0-create-graphql-response",
            "generic_gpu_count": 1,
            "generic_gpu_count_is_allocation_evidence": False,
            "rest_compute_fields": "omitted",
            "template_image_source": "prior-standalone-template-readback",
            "template_start_jupyter": True,
            "template_start_ssh": True,
        },
        "requested_config": {
            "compute_type": "CPU",
            "cpu_instance_id": instance_id,
            "endpoint_name": endpoint_name,
            "execution_timeout_seconds": 120,
            "flash_boot": False,
            "gpu": False,
            "network_runtime_assurance": "none",
            "idle_timeout_seconds": 5,
            "network_volume": False,
            "scaler_request_count": 1,
            "template": _template_projection(
                template_id=template_id,
                template_name=template_name,
                worker_image=worker_image,
            )["requested_config"],
            "template_name": template_name,
            "workers_max": 1,
            "workers_min": 0,
        },
        "validation": "passed",
    }


def validate_image_manifest_readback(path: Path, *, worker_image: str) -> dict[str, object]:
    """Validate an anonymous registry manifest inspection and return a safe projection."""

    _validate_expected("worker image", worker_image, _WORKER_IMAGE)
    expected_digest = worker_image.rsplit("@", 1)[1]
    loaded, raw = _load_bounded_json_and_raw(path)
    if not isinstance(loaded, dict):
        raise ProviderReadbackError("image inspection must be a top-level object")
    document = cast(dict[str, object], loaded)
    observed_digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    cli_trailing_lf_removed = False
    if observed_digest != expected_digest and raw.endswith(b"\n"):
        observed_digest = f"sha256:{hashlib.sha256(raw[:-1]).hexdigest()}"
        cli_trailing_lf_removed = observed_digest == expected_digest
    if observed_digest != expected_digest:
        raise ProviderReadbackError("raw image index bytes did not match the requested digest")
    _expect_exact(document, "schemaVersion", 2, context="image inspection")
    media_type = document.get("mediaType", _MISSING)
    accepted_index_types = {
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    }
    if not isinstance(media_type, str) or media_type not in accepted_index_types:
        raise ProviderReadbackError("image inspection did not return a supported image index")
    members = document.get("manifests", _MISSING)
    if not isinstance(members, list):
        raise ProviderReadbackError("image inspection omitted the platform index")
    accepted_manifest_types = {
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    }
    linux_amd64_matches = 0
    for member in members:
        if not isinstance(member, dict):
            raise ProviderReadbackError("image inspection platform member is malformed")
        descriptor_digest = member.get("digest", _MISSING)
        descriptor_media_type = member.get("mediaType", _MISSING)
        if (
            not isinstance(descriptor_digest, str)
            or _SHA256_DIGEST.fullmatch(descriptor_digest) is None
            or not isinstance(descriptor_media_type, str)
            or descriptor_media_type not in accepted_manifest_types
        ):
            raise ProviderReadbackError("image inspection platform descriptor is malformed")
        platform = member.get("platform", _MISSING)
        if not isinstance(platform, dict):
            raise ProviderReadbackError("image inspection platform is malformed")
        operating_system = platform.get("os", _MISSING)
        architecture = platform.get("architecture", _MISSING)
        if not isinstance(operating_system, str) or not isinstance(architecture, str):
            raise ProviderReadbackError("image inspection platform fields are malformed")
        if operating_system == "linux" and architecture == "amd64":
            variant = platform.get("variant", _MISSING)
            if variant is not _MISSING and variant not in (None, ""):
                raise ProviderReadbackError("linux/amd64 image descriptor has a variant")
            linux_amd64_matches += 1
    if linux_amd64_matches != 1:
        raise ProviderReadbackError(
            "image inspection must contain exactly one linux/amd64 descriptor"
        )
    return {
        "schema_version": "atcap.registry-image-projection.v1",
        "worker_image": worker_image,
        "manifest_digest": expected_digest,
        "linux_amd64": True,
        "anonymous_inspection": True,
        "cli_trailing_lf_removed": cli_trailing_lf_removed,
        "validation": "passed",
    }


def extract_created_resource_id(path: Path, *, kind: str) -> str:
    """Extract one consistent, syntactically valid ID from a create response."""

    if kind not in {"template", "endpoint"}:
        raise ProviderReadbackError("created resource kind is invalid")
    document = load_bounded_json_object(path)
    candidates = [document]
    for key in ("data", kind):
        nested = document.get(key)
        if isinstance(nested, dict):
            candidates.append(cast(dict[str, object], nested))
    names = ("id", f"{kind}Id", f"{kind}_id")
    observed: set[str] = set()
    for candidate in candidates:
        for name in names:
            value = candidate.get(name, _MISSING)
            if value is _MISSING:
                continue
            if not isinstance(value, str) or _RESOURCE_ID.fullmatch(value) is None:
                raise ProviderReadbackError("create response contains an invalid resource ID")
            observed.add(value)
    if len(observed) != 1:
        raise ProviderReadbackError("create response did not contain one consistent resource ID")
    return observed.pop()


def inspect_resource_listing(
    path: Path, *, resource_name: str, resource_id: str | None
) -> dict[str, object]:
    """Inspect one complete typed listing for exact-name and optional-ID presence."""

    _validate_expected("resource name", resource_name, _RESOURCE_NAME)
    if resource_id is not None:
        _validate_expected("resource ID", resource_id, _RESOURCE_ID)
    document = load_bounded_json(path)
    # runpodctl 2.12 serializes an empty user-template listing as JSON null.
    # Treat that one observed top-level representation as the empty collection;
    # every nonempty response must still use a typed array (directly or in data).
    if document is None:
        items: list[object] = []
    elif isinstance(document, list):
        items = document
    elif isinstance(document, dict):
        items = document.get("data", _MISSING)
        if not isinstance(items, list):
            raise ProviderReadbackError("resource listing omitted its item array")
    else:
        raise ProviderReadbackError("resource listing must be an array or data object")

    exact_name_ids: list[str] = []
    identifier_present = False
    for item in items:
        if not isinstance(item, dict):
            raise ProviderReadbackError("resource listing contains a malformed item")
        identifier = item.get("id", _MISSING)
        name = item.get("name", _MISSING)
        if not isinstance(identifier, str) or _RESOURCE_ID.fullmatch(identifier) is None:
            raise ProviderReadbackError("resource listing contains an invalid item ID")
        if not isinstance(name, str):
            raise ProviderReadbackError("resource listing contains an invalid item name")
        if name == resource_name:
            exact_name_ids.append(identifier)
        if resource_id is not None and identifier == resource_id:
            identifier_present = True
    if len(exact_name_ids) > 1:
        raise ProviderReadbackError("resource listing contains duplicate exact-name matches")
    return {
        "schema_version": "atcap.provider-listing-observation.v1",
        "exact_name_id": exact_name_ids[0] if exact_name_ids else None,
        "requested_id_present": identifier_present,
    }


def write_safe_projection(path: Path, projection: dict[str, object]) -> None:
    """Create a mode-0600 projection without following or replacing a path."""

    encoded = (
        json.dumps(projection, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ProviderReadbackError("safe projection could not be created") from exc
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(encoded)
    except OSError as exc:
        raise ProviderReadbackError("safe projection could not be written") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    template = subparsers.add_parser("template")
    template.add_argument("--json", type=Path, required=True)
    template.add_argument("--projection", type=Path, required=True)
    template.add_argument("--template-id", required=True)
    template.add_argument("--template-name", required=True)
    template.add_argument("--worker-image", required=True)

    endpoint = subparsers.add_parser("endpoint")
    endpoint.add_argument("--json", type=Path, required=True)
    endpoint.add_argument("--create-json", type=Path, required=True)
    endpoint.add_argument("--projection", type=Path, required=True)
    endpoint.add_argument("--endpoint-id", required=True)
    endpoint.add_argument("--endpoint-name", required=True)
    endpoint.add_argument("--template-id", required=True)
    endpoint.add_argument("--template-name", required=True)
    endpoint.add_argument("--instance-id", required=True)
    endpoint.add_argument("--worker-image", required=True)

    image = subparsers.add_parser("image")
    image.add_argument("--json", type=Path, required=True)
    image.add_argument("--projection", type=Path, required=True)
    image.add_argument("--worker-image", required=True)

    created_id = subparsers.add_parser("created-id")
    created_id.add_argument("--json", type=Path, required=True)
    created_id.add_argument("--kind", choices=["template", "endpoint"], required=True)

    listing = subparsers.add_parser("listing")
    listing.add_argument("--json", type=Path, required=True)
    listing.add_argument("--result", type=Path, required=True)
    listing.add_argument("--resource-name", required=True)
    listing.add_argument("--resource-id", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "template":
            projection = validate_template_readback(
                arguments.json,
                template_id=arguments.template_id,
                template_name=arguments.template_name,
                worker_image=arguments.worker_image,
            )
            write_safe_projection(arguments.projection, projection)
        elif arguments.command == "endpoint":
            projection = validate_endpoint_readback(
                arguments.json,
                create_path=arguments.create_json,
                endpoint_id=arguments.endpoint_id,
                endpoint_name=arguments.endpoint_name,
                template_id=arguments.template_id,
                template_name=arguments.template_name,
                instance_id=arguments.instance_id,
                worker_image=arguments.worker_image,
            )
            write_safe_projection(arguments.projection, projection)
        elif arguments.command == "image":
            projection = validate_image_manifest_readback(
                arguments.json,
                worker_image=arguments.worker_image,
            )
            write_safe_projection(arguments.projection, projection)
        elif arguments.command == "created-id":
            print(extract_created_resource_id(arguments.json, kind=arguments.kind))
        else:
            observation = inspect_resource_listing(
                arguments.json,
                resource_name=arguments.resource_name,
                resource_id=arguments.resource_id or None,
            )
            write_safe_projection(arguments.result, observation)
    except ProviderReadbackError as exc:
        print(f"provider read-back rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
