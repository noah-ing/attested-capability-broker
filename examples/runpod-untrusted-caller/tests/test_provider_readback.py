"""Runpod 2.12 read-back fixtures and fail-closed policy regressions.

The schema-derived fixtures model the CLI's typed JSON reserialization,
including ``omitempty`` fields, rather than claiming to be captured provider
responses. Extra provider metadata is tolerated but never copied into evidence.
"""

from __future__ import annotations

import copy
import hashlib
import json
import stat
from pathlib import Path
from typing import Any

import pytest
from provider_readback import (
    MAX_JSON_BYTES,
    ProviderReadbackError,
    extract_created_resource_id,
    inspect_resource_listing,
    load_bounded_json_object,
    main,
    validate_endpoint_readback,
    validate_image_manifest_readback,
    validate_template_readback,
    write_safe_projection,
)

FIXTURES = Path(__file__).with_name("fixtures")
TEMPLATE_FIXTURE = FIXTURES / "runpodctl-2.12-template-get.json"
ENDPOINT_FIXTURE = FIXTURES / "runpodctl-2.12-endpoint-get.json"
TEMPLATE_ID = "tpl-runpodctl-212-test"
ENDPOINT_ID = "ep-runpodctl-212-test"
RESOURCE_NAME = "atcap-holder-runpodctl-212-test"
WORKER_IMAGE = (
    "ghcr.io/noah-ing/atcap-worker@sha256:"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
INSTANCE_ID = "cpu3g-4-16"


def _document(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write(tmp_path: Path, document: object, name: str = "provider.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _image_reference(document: object) -> str:
    raw = json.dumps(document).encode("utf-8")
    return f"ghcr.io/noah-ing/atcap-worker@sha256:{hashlib.sha256(raw).hexdigest()}"


def _validate_template(path: Path) -> dict[str, object]:
    return validate_template_readback(
        path,
        template_id=TEMPLATE_ID,
        template_name=RESOURCE_NAME,
        worker_image=WORKER_IMAGE,
    )


def _validate_endpoint(path: Path) -> dict[str, object]:
    return validate_endpoint_readback(
        path,
        endpoint_id=ENDPOINT_ID,
        endpoint_name=RESOURCE_NAME,
        template_id=TEMPLATE_ID,
        template_name=RESOURCE_NAME,
        instance_id=INSTANCE_ID,
        worker_image=WORKER_IMAGE,
    )


def test_sanitized_runpodctl_212_fixtures_validate() -> None:
    template = _validate_template(TEMPLATE_FIXTURE)
    endpoint = _validate_endpoint(ENDPOINT_FIXTURE)

    assert template["validation"] == "passed"
    assert template["template_id_sha256"] == hashlib.sha256(TEMPLATE_ID.encode()).hexdigest()
    assert endpoint["validation"] == "passed"
    assert endpoint["endpoint_id_sha256"] == hashlib.sha256(ENDPOINT_ID.encode()).hexdigest()


def test_explicit_integer_zero_volume_is_also_accepted(tmp_path: Path) -> None:
    template = _document(TEMPLATE_FIXTURE)
    template["volumeInGb"] = 0
    _validate_template(_write(tmp_path, template))

    endpoint = _document(ENDPOINT_FIXTURE)
    nested = endpoint["template"]
    assert isinstance(nested, dict)
    nested["volumeInGb"] = 0
    _validate_endpoint(_write(tmp_path, endpoint))


def test_reviewed_provider_default_ports_are_exact_and_explicit(tmp_path: Path) -> None:
    projection = _validate_template(TEMPLATE_FIXTURE)

    requested = projection["requested_config"]
    assert isinstance(requested, dict)
    assert requested["ports_requested"] is False
    assert requested["provider_default_ports"] == ["8888/http", "22/tcp"]
    assert requested["port_reachability_assurance"] == "none"


@pytest.mark.parametrize(
    "bad_ports",
    [
        None,
        [],
        ["22/tcp", "8888/http"],
        ["8888/http"],
        ["8888/http", "22/tcp", "22/tcp"],
        ["8888/http", "22/tcp", "8000/http"],
        ["8888/http", "22/TCP"],
        ["8888/http", 22],
        "8888/http,22/tcp",
    ],
)
def test_provider_default_port_deviations_fail_top_level_and_nested(
    tmp_path: Path,
    bad_ports: object,
) -> None:
    template = _document(TEMPLATE_FIXTURE)
    template["ports"] = bad_ports
    with pytest.raises(ProviderReadbackError, match="ports"):
        _validate_template(_write(tmp_path, template, "template.json"))

    endpoint = _document(ENDPOINT_FIXTURE)
    nested = endpoint["template"]
    assert isinstance(nested, dict)
    nested["ports"] = bad_ports
    with pytest.raises(ProviderReadbackError, match=r"included template.*ports"):
        _validate_endpoint(_write(tmp_path, endpoint, "endpoint.json"))


def test_provider_default_ports_cannot_be_omitted(tmp_path: Path) -> None:
    template = _document(TEMPLATE_FIXTURE)
    template.pop("ports")
    with pytest.raises(ProviderReadbackError, match="ports"):
        _validate_template(_write(tmp_path, template))


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("id", "wrong-template"),
        ("name", "wrong-name"),
        ("imageName", WORKER_IMAGE.replace("a", "b")),
        ("isServerless", False),
        ("containerDiskInGb", 6),
        ("containerDiskInGb", True),
        ("volumeInGb", 1),
        ("volumeInGb", True),
    ],
)
def test_template_rejects_wrong_required_policy(
    tmp_path: Path, field: str, bad_value: object
) -> None:
    document = _document(TEMPLATE_FIXTURE)
    document[field] = bad_value
    with pytest.raises(ProviderReadbackError, match=field):
        _validate_template(_write(tmp_path, document))


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("env", [{"key": "SECRET", "value": "reflected"}]),
        ("ports", ["8888/http"]),
        ("dockerEntrypoint", ["/bin/sh"]),
        ("dockerStartCmd", ["-c", "cat /secrets"]),
        ("containerRegistryAuthId", "registry-secret-id"),
    ],
)
def test_template_rejects_runtime_or_registry_overrides(
    tmp_path: Path, field: str, bad_value: object
) -> None:
    document = _document(TEMPLATE_FIXTURE)
    document[field] = bad_value
    with pytest.raises(ProviderReadbackError, match=field):
        _validate_template(_write(tmp_path, document))


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("id", "wrong-endpoint"),
        ("name", "wrong-name"),
        ("templateId", "wrong-template"),
        ("computeType", "GPU"),
        ("instanceIds", ["cpu3c-2-4"]),
        ("workersMin", 1),
        ("workersMax", 2),
        ("idleTimeout", 6),
        ("scalerType", "QUEUE_DELAY"),
        ("scalerValue", 2),
        ("executionTimeoutMs", 120001),
        ("executionTimeoutMs", True),
        ("gpuCount", 1),
        ("flashBootType", "FLASHBOOT"),
    ],
)
def test_endpoint_rejects_wrong_required_policy(
    tmp_path: Path, field: str, bad_value: object
) -> None:
    document = _document(ENDPOINT_FIXTURE)
    document[field] = bad_value
    with pytest.raises(ProviderReadbackError, match=field):
        _validate_endpoint(_write(tmp_path, document))


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("gpuIds", "AMPERE_16"),
        ("gpuTypeIds", ["NVIDIA RTX A4000"]),
        ("gpuPoolIds", ["secure-cloud"]),
        ("serverlessGpuPools", ["AMPERE_16"]),
        ("networkVolumeId", "volume-1"),
        ("networkVolumeIds", ["volume-1"]),
        ("networkVolume", {"id": "volume-1"}),
        ("networkVolumes", [{"id": "volume-1"}]),
        ("flashboot", True),
        ("flashBoot", True),
    ],
)
def test_endpoint_rejects_gpu_volume_or_flash_aliases(
    tmp_path: Path, field: str, bad_value: object
) -> None:
    document = _document(ENDPOINT_FIXTURE)
    document[field] = bad_value
    with pytest.raises(ProviderReadbackError, match=field):
        _validate_endpoint(_write(tmp_path, document))


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("id", "different-template"),
        ("name", "different-template-name"),
        ("imageName", WORKER_IMAGE.replace("a", "b")),
        ("isServerless", False),
        ("containerDiskInGb", 6),
        ("volumeInGb", 1),
        ("env", {"REFLECT": "provider-value"}),
        ("ports", ["8888/http"]),
        ("dockerEntrypoint", ["/bin/sh"]),
        ("dockerStartCmd", ["python", "unexpected.py"]),
        ("containerRegistryAuthId", "registry-secret-id"),
    ],
)
def test_endpoint_rejects_included_template_substitution(
    tmp_path: Path, field: str, bad_value: object
) -> None:
    document = _document(ENDPOINT_FIXTURE)
    nested = copy.deepcopy(document["template"])
    assert isinstance(nested, dict)
    nested[field] = bad_value
    document["template"] = nested

    with pytest.raises(ProviderReadbackError, match=rf"included template.*{field}"):
        _validate_endpoint(_write(tmp_path, document))


def test_duplicate_member_is_rejected(tmp_path: Path) -> None:
    raw = TEMPLATE_FIXTURE.read_text(encoding="utf-8").replace(
        '"id": "tpl-runpodctl-212-test",',
        '"id": "tpl-runpodctl-212-test", "id": "shadow",',
    )
    path = tmp_path / "duplicate.json"
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(ProviderReadbackError, match="duplicate"):
        load_bounded_json_object(path)


def test_oversized_document_is_rejected_before_json_parsing(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (MAX_JSON_BYTES + 1))

    with pytest.raises(ProviderReadbackError, match="byte limit"):
        load_bounded_json_object(path)


def test_excessive_nesting_is_rejected(tmp_path: Path) -> None:
    value: object = "leaf"
    for _ in range(40):
        value = [value]
    path = _write(tmp_path, {"nested": value})

    with pytest.raises(ProviderReadbackError, match="nesting limit"):
        load_bounded_json_object(path)


def test_provider_readback_does_not_follow_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "provider.json"
    link.symlink_to(target)

    with pytest.raises(ProviderReadbackError, match="could not be read"):
        load_bounded_json_object(link)


def test_nonstandard_numeric_constant_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "nan.json"
    path.write_text('{"value":NaN}', encoding="utf-8")

    with pytest.raises(ProviderReadbackError, match="non-standard"):
        load_bounded_json_object(path)


def test_safe_projection_excludes_ignored_provider_reflection(tmp_path: Path) -> None:
    marker = "REFLECTION_MARKER_DISPOSABLE_HOLDER_KEY_MATERIAL_9f01"
    document = _document(ENDPOINT_FIXTURE)
    document["providerControlledMetadata"] = {
        "debug": marker,
        "credential": marker,
    }
    raw_path = _write(tmp_path, document, "raw-private.json")
    projection_path = tmp_path / "safe-projection.json"

    projection = _validate_endpoint(raw_path)
    write_safe_projection(projection_path, projection)

    evidence = projection_path.read_text(encoding="utf-8")
    assert marker not in evidence
    assert ENDPOINT_ID not in evidence
    assert TEMPLATE_ID not in evidence
    assert hashlib.sha256(ENDPOINT_ID.encode()).hexdigest() in evidence
    assert json.loads(evidence) == projection
    assert stat.S_IMODE(projection_path.stat().st_mode) == 0o600

    with pytest.raises(ProviderReadbackError, match="could not be created"):
        write_safe_projection(projection_path, projection)


def test_cli_writes_projection_only_after_validation(tmp_path: Path) -> None:
    invalid = _document(TEMPLATE_FIXTURE)
    invalid["env"] = {"UNEXPECTED_SETTING": "must-not-be-copied"}
    source = _write(tmp_path, invalid)
    projection = tmp_path / "projection.json"

    result = main(
        [
            "template",
            "--json",
            str(source),
            "--projection",
            str(projection),
            "--template-id",
            TEMPLATE_ID,
            "--template-name",
            RESOURCE_NAME,
            "--worker-image",
            WORKER_IMAGE,
        ]
    )

    assert result == 2
    assert not projection.exists()


def test_endpoint_cli_validates_fixture_and_writes_safe_projection(tmp_path: Path) -> None:
    projection = tmp_path / "endpoint-projection.json"

    result = main(
        [
            "endpoint",
            "--json",
            str(ENDPOINT_FIXTURE),
            "--projection",
            str(projection),
            "--endpoint-id",
            ENDPOINT_ID,
            "--endpoint-name",
            RESOURCE_NAME,
            "--template-id",
            TEMPLATE_ID,
            "--template-name",
            RESOURCE_NAME,
            "--instance-id",
            INSTANCE_ID,
            "--worker-image",
            WORKER_IMAGE,
        ]
    )

    assert result == 0
    assert json.loads(projection.read_text())["validation"] == "passed"


def test_image_manifest_projection_is_closed_and_linux_amd64(tmp_path: Path) -> None:
    marker = "REGISTRY_REFLECTION_MARKER_73a1"
    document = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": "sha256:" + "b" * 64,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"architecture": "amd64", "os": "linux"},
                "provider": marker,
            }
        ],
        "provider": marker,
    }
    source = _write(tmp_path, document)

    projection = validate_image_manifest_readback(
        source,
        worker_image=_image_reference(document),
    )

    assert projection["validation"] == "passed"
    assert projection["anonymous_inspection"] is True
    assert marker not in json.dumps(projection)


@pytest.mark.parametrize(
    "mutation",
    ["wrong-schema", "wrong-media-type", "no-index", "no-amd64", "malformed-member"],
)
def test_image_manifest_mismatch_is_rejected(tmp_path: Path, mutation: str) -> None:
    manifest: dict[str, Any] = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": "sha256:" + "b" * 64,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
        ],
    }
    if mutation == "wrong-schema":
        manifest["schemaVersion"] = True
    elif mutation == "wrong-media-type":
        manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
    elif mutation == "no-index":
        manifest.pop("manifests")
    elif mutation == "no-amd64":
        manifest["manifests"] = [{"platform": {"architecture": "arm64", "os": "linux"}}]
    else:
        manifest["manifests"] = ["not-an-object"]

    with pytest.raises(ProviderReadbackError):
        source = _write(tmp_path, manifest)
        validate_image_manifest_readback(
            source,
            worker_image=_image_reference(manifest),
        )


def test_image_manifest_rejects_well_shaped_bytes_under_false_digest(tmp_path: Path) -> None:
    document = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": "sha256:" + "b" * 64,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }

    with pytest.raises(ProviderReadbackError, match="raw image index bytes"):
        validate_image_manifest_readback(
            _write(tmp_path, document),
            worker_image=WORKER_IMAGE,
        )


def test_image_manifest_accepts_only_one_cli_framing_newline(tmp_path: Path) -> None:
    document = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": "sha256:" + "b" * 64,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }
    source = _write(tmp_path, document)
    reference = _image_reference(document)
    source.write_bytes(source.read_bytes() + b"\n")

    projection = validate_image_manifest_readback(source, worker_image=reference)

    assert projection["cli_trailing_lf_removed"] is True


def test_image_manifest_rejects_duplicate_linux_amd64_descriptors(tmp_path: Path) -> None:
    member = {
        "digest": "sha256:" + "b" * 64,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "platform": {"architecture": "amd64", "os": "linux"},
    }
    document = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [member, {**member, "digest": "sha256:" + "c" * 64}],
    }

    with pytest.raises(ProviderReadbackError, match="exactly one"):
        validate_image_manifest_readback(
            _write(tmp_path, document),
            worker_image=_image_reference(document),
        )


def test_create_id_requires_one_consistent_valid_identifier(tmp_path: Path) -> None:
    valid = _write(
        tmp_path,
        {"id": TEMPLATE_ID, "data": {"templateId": TEMPLATE_ID}},
        "valid-create.json",
    )
    assert extract_created_resource_id(valid, kind="template") == TEMPLATE_ID

    conflicting = _write(
        tmp_path,
        {"id": TEMPLATE_ID, "data": {"templateId": "different-id"}},
        "conflicting-create.json",
    )
    with pytest.raises(ProviderReadbackError, match="consistent"):
        extract_created_resource_id(conflicting, kind="template")


def test_listing_observation_is_exact_name_and_optional_id_bound(tmp_path: Path) -> None:
    listing = _write(
        tmp_path,
        [
            {"id": ENDPOINT_ID, "name": RESOURCE_NAME, "provider": "ignored"},
            {"id": "another-endpoint", "name": "unrelated name"},
        ],
    )

    observation = inspect_resource_listing(
        listing,
        resource_name=RESOURCE_NAME,
        resource_id=ENDPOINT_ID,
    )

    assert observation == {
        "schema_version": "atcap.provider-listing-observation.v1",
        "exact_name_id": ENDPOINT_ID,
        "requested_id_present": True,
    }


def test_runpodctl_212_null_listing_is_the_empty_collection(tmp_path: Path) -> None:
    listing = _write(tmp_path, None)

    observation = inspect_resource_listing(
        listing,
        resource_name=RESOURCE_NAME,
        resource_id=ENDPOINT_ID,
    )

    assert observation == {
        "schema_version": "atcap.provider-listing-observation.v1",
        "exact_name_id": None,
        "requested_id_present": False,
    }


def test_listing_rejects_duplicate_exact_name_matches(tmp_path: Path) -> None:
    listing = _write(
        tmp_path,
        [
            {"id": ENDPOINT_ID, "name": RESOURCE_NAME},
            {"id": "different-endpoint", "name": RESOURCE_NAME},
        ],
    )

    with pytest.raises(ProviderReadbackError, match="duplicate"):
        inspect_resource_listing(listing, resource_name=RESOURCE_NAME, resource_id=None)


def test_live_runner_keeps_raw_readbacks_out_of_evidence() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "run-live.sh"
    source = script.read_text(encoding="utf-8")

    assert "${state_dir}/template-readback.raw.json" in source
    assert "${state_dir}/endpoint-readback.raw.json" in source
    assert "${evidence_dir}/template-readback-projection.json" in source
    assert "${evidence_dir}/endpoint-readback-projection.json" in source
    assert "${evidence_dir}/template-readback.raw.json" not in source
    assert "${evidence_dir}/endpoint-readback.raw.json" not in source
