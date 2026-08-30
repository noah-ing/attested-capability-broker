"""No-Runpod-infrastructure shell regressions for supervision and cleanup."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import textwrap
import time
from pathlib import Path

import pytest

RAW_IMAGE_INDEX = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": "sha256:" + "b" * 64,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    },
    separators=(",", ":"),
)
LIVE_WORKER_IMAGE = (
    "ghcr.io/noah-ing/atcap-worker@sha256:" + hashlib.sha256(RAW_IMAGE_INDEX.encode()).hexdigest()
)


def _executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _fake_path(tmp_path: Path) -> tuple[Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state = tmp_path / "provider-state"
    state.mkdir()
    _executable(
        fake_bin / "git",
        """
        #!/usr/bin/env bash
        if [[ "$*" == *"rev-parse HEAD"* ]]; then
          printf '%040d\n' 1
        fi
        exit 0
        """,
    )
    _executable(
        fake_bin / "docker",
        """
        #!/usr/bin/env bash
        if [[ "${FAKE_REQUIRE_KEY_ISOLATION:-0}" == "1" \
          && -n "${RUNPOD_API_KEY:-}" ]]; then
          exit 74
        fi
        if [[ "$*" == *"lab.live_cli prepare"* ]]; then
          state_dir=""
          payload=""
          volume=""
          while (($#)); do
            if [[ "$1" == "--state-dir" ]]; then
              state_dir="$2"
              shift 2
            elif [[ "$1" == "--payload" ]]; then
              payload="$2"
              shift 2
            elif [[ "$1" == "--volume" ]]; then
              volume="$2"
              shift 2
            else
              shift
            fi
          done
          printf '%s\n' "$state_dir" >"${FAKE_RUNPOD_STATE}/prepare-state-dir"
          printf '%s\n' "$payload" >"${FAKE_RUNPOD_STATE}/prepare-payload"
          [[ "$state_dir" == "/runpod-state/trusted-state" ]] || exit 77
          [[ "$payload" == "/runpod-state/worker-payload.json" ]] || exit 78
          [[ "$volume" == *":/runpod-state" ]] || exit 79
          host_parent="${volume%:/runpod-state}"
          host_child="${host_parent}/trusted-state"
          parent_mode="$(python3 -c \
            'import os,stat,sys; print(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))' \
            "$host_parent")"
          child_mode="$(python3 -c \
            'import os,stat,sys; print(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))' \
            "$host_child")"
          child_entries="$(python3 -c \
            'import pathlib,sys; print(sum(1 for _ in pathlib.Path(sys.argv[1]).iterdir()))' \
            "$host_child")"
          operational_entries="$(python3 -c \
            'import os,sys; print(len(os.listdir(sys.argv[1])) - 1)' \
            "$host_parent")"
          child_empty=false
          [[ "$child_entries" == "0" ]] && child_empty=true
          {
            printf 'child_empty_before_prepare=%s\n' "$child_empty"
            printf 'child_mode=%s\n' "$child_mode"
            printf 'operational_entry_count=%s\n' "$operational_entries"
            printf 'parent_mode=%s\n' "$parent_mode"
          } >"${FAKE_RUNPOD_STATE}/prepare-layout.txt"
          [[ "$parent_mode" == "448" ]] || exit 80
          [[ "$child_mode" == "448" ]] || exit 81
          [[ "$child_entries" == "0" ]] || exit 82
          ((operational_entries >= 1)) || exit 83
          printf '%s\n' "$host_child" >"${FAKE_RUNPOD_STATE}/prepare-host-state-dir"
          printf 'fake prepared state\n' >"${host_child}/fake-prepared-state"
          chmod 0600 "${host_child}/fake-prepared-state"
        fi
        if [[ "${1:-}" == "pull" ]]; then
          printf 'pull\n' >>"${FAKE_RUNPOD_STATE}/worker-preflight-events"
          printf '%s\n' "$@" >"${FAKE_RUNPOD_STATE}/worker-pull-args"
          if [[ -n "${RUNPOD_API_KEY+x}" ]]; then
            printf 'present\n' >"${FAKE_RUNPOD_STATE}/worker-pull-api-key"
          else
            printf 'absent\n' >"${FAKE_RUNPOD_STATE}/worker-pull-api-key"
          fi
          if [[ "${FAKE_REQUIRE_ANONYMOUS_REGISTRY:-0}" == "1" \
            && ( -n "${DOCKER_AUTH_CONFIG:-}" || -n "${REGISTRY_AUTH_FILE:-}" ) ]]; then
            exit 76
          fi
        elif [[ "${1:-}" == "run" ]]; then
          printf 'run\n' >>"${FAKE_RUNPOD_STATE}/worker-preflight-events"
          printf '%s\n' "$@" >"${FAKE_RUNPOD_STATE}/worker-runtime-args"
          if [[ -n "${RUNPOD_API_KEY+x}" ]]; then
            printf 'present\n' >"${FAKE_RUNPOD_STATE}/worker-runtime-api-key"
          else
            printf 'absent\n' >"${FAKE_RUNPOD_STATE}/worker-runtime-api-key"
          fi
          [[ ! -e "${FAKE_RUNPOD_STATE}/template-name" ]] || exit 86
          [[ ! -e "${FAKE_RUNPOD_STATE}/endpoint-name" ]] || exit 87
          if [[ "${FAKE_WORKER_PREFLIGHT_FAIL:-0}" == "1" ]]; then
            exit 88
          fi
        elif [[ "${1:-}" == "info" ]]; then
          printf '[{"Name":"buildx","Path":"%s"}]\n' "$FAKE_DOCKER_PLUGIN"
        elif [[ "${1:-} ${2:-} ${3:-}" == "buildx imagetools inspect" ]]; then
          if [[ "${FAKE_REQUIRE_ANONYMOUS_REGISTRY:-0}" == "1" \
            && ( -n "${DOCKER_AUTH_CONFIG:-}" || -n "${REGISTRY_AUTH_FILE:-}" ) ]]; then
            exit 76
          fi
          [[ -n "${DOCKER_CONFIG:-}" && -d "$DOCKER_CONFIG" ]] || exit 71
          config_mode="$(
            python3 -c \
              'import os,stat,sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])' \
              "$DOCKER_CONFIG"
          )"
          [[ "$config_mode" == "700" ]] || exit 72
          [[ ! -e "${DOCKER_CONFIG}/config.json" ]] || exit 73
          printf '%s\n' "$DOCKER_CONFIG" >"${FAKE_RUNPOD_STATE}/anonymous-docker-config"
          printf '%s' "$FAKE_IMAGE_INDEX"
        fi
        exit 0
        """,
    )
    _executable(fake_bin / "docker-buildx", "#!/usr/bin/env bash\nexit 0\n")
    _executable(
        fake_bin / "curl",
        """
        #!/usr/bin/env bash
        if [[ "${FAKE_REQUIRE_KEY_ISOLATION:-0}" == "1" \
          && -n "${RUNPOD_API_KEY:-}" ]]; then
          exit 74
        fi
        if [[ "${FAKE_OVERSIZE_COMMAND:-}" == "curl" ]]; then
          while :; do printf '0123456789abcdef'; done
        fi
        printf '1\n' >"${FAKE_RUNPOD_STATE}/curl-called"
        printf 'fake-current-source\n'
        """,
    )
    _executable(
        fake_bin / "find",
        """
        #!/usr/bin/env bash
        if [[ "${FAKE_FIND_DELETE_FAILURE:-0}" == "1" \
          && "${1:-}" == *"/atcap-runpod-state."* ]]; then
          exit 1
        fi
        exec /usr/bin/find "$@"
        """,
    )
    _executable(
        fake_bin / "runpodctl",
        """
        #!/usr/bin/env bash
        if [[ "${FAKE_REQUIRE_KEY_ISOLATION:-0}" == "1" \
          && -z "${RUNPOD_API_KEY:-}" ]]; then
          exit 75
        fi
        case "${1:-} ${2:-}" in
          "version ")
            printf 'runpodctl version %s\n' "${FAKE_RUNPODCTL_VERSION:-2.12.0}"
            ;;
          "user ")
            if [[ "${FAKE_OVERSIZE_COMMAND:-}" == "runpod-user-stdout" ]]; then
              while :; do printf '0123456789abcdef'; done
            elif [[ "${FAKE_OVERSIZE_COMMAND:-}" == "runpod-user-stderr" ]]; then
              while :; do printf '0123456789abcdef' >&2; done
            fi
            printf '{"provider":"%s"}\n' "${FAKE_REFLECTION_MARKER:-}"
            ;;
          "template create")
            shift 2
            while (($#)); do
              if [[ "$1" == "--name" ]]; then
                printf '%s\n' "$2" >"${FAKE_RUNPOD_STATE}/template-name"
                shift 2
              elif [[ "$1" == "--image" ]]; then
                printf '%s\n' "$2" >"${FAKE_RUNPOD_STATE}/template-image"
                shift 2
              else
                shift
              fi
            done
            if [[ "${FAKE_CREATE_MODE:-template}" == "template" ]]; then
              printf '{"truncated":'
              exit 1
            elif [[ "${FAKE_CREATE_MODE:-}" == "template-wrong-id" ]]; then
              printf '{"id":"unrelated-template-id"}\n'
              exit 0
            fi
            printf '{"id":"created-template-id"}\n'
            ;;
          "template list")
            printf '%s\n' "${FAKE_REFLECTION_MARKER:-}" >&2
            count_file="${FAKE_RUNPOD_STATE}/template-list-count"
            count=0
            [[ ! -f "$count_file" ]] || count="$(cat "$count_file")"
            count=$((count + 1))
            printf '%s\n' "$count" >"$count_file"
            if [[ "${FAKE_HUNG_CLEANUP_KIND:-}" == "template" && $count -ge 2 ]]; then
              /bin/sleep 30
            fi
            if [[ -f "${FAKE_RUNPOD_STATE}/template-name" ]]; then
              delay_through="${FAKE_DELAYED_APPEAR_THROUGH:-2}"
              if [[ "${FAKE_DELAYED_APPEAR_KIND:-}" == "template" \
                && $count -le $delay_through ]]; then
                printf '[]\n'
                exit 0
              fi
              name="$(cat "${FAKE_RUNPOD_STATE}/template-name")"
              printf '[{"id":"created-template-id","name":"%s"}]\n' "$name"
            else
              printf '[]\n'
            fi
            ;;
          "template get")
            if [[ "${3:-}" == "unrelated-template-id" ]]; then
              printf '{"id":"unrelated-template-id","name":"unrelated-resource"}\n'
              exit 0
            fi
            name="$(cat "${FAKE_RUNPOD_STATE}/template-name")"
            image="$(cat "${FAKE_RUNPOD_STATE}/template-image")"
            printf '%s' '{"id":"created-template-id","name":"'
            printf '%s' "$name"
            printf '%s' '","imageName":"'
            printf '%s' "$image"
            printf '%s' '","isServerless":true,"containerDiskInGb":5,"volumeInGb":0'
            printf '%s' ',"dockerEntrypoint":[],"dockerStartCmd":[],'
            printf '%s\n' '"ports":["8888/http","22/tcp"],"env":{}}'
            ;;
          "template delete")
            printf '%s\n' "${FAKE_REFLECTION_MARKER:-}" >&2
            printf 'template:%s\n' "${3:-}" >>"${FAKE_RUNPOD_STATE}/deleted-ids"
            rm -f "${FAKE_RUNPOD_STATE}/template-name"
            printf '{}\n'
            ;;
          "serverless create")
            shift 2
            while (($#)); do
              if [[ "$1" == "--name" ]]; then
                printf '%s\n' "$2" >"${FAKE_RUNPOD_STATE}/endpoint-name"
                break
              fi
              shift
            done
            if [[ "${FAKE_CREATE_MODE:-endpoint}" == "endpoint-wrong-id" ]]; then
              printf '{"id":"unrelated-endpoint-id"}\n'
              exit 0
            elif [[ "${FAKE_CREATE_MODE:-}" == "success" ]]; then
              endpoint_name="$(cat "${FAKE_RUNPOD_STATE}/endpoint-name")"
              compute_type="${FAKE_ENDPOINT_CREATE_COMPUTE_TYPE:-CPU}"
              printf '%s' '{"computeType":"'
              printf '%s' "$compute_type"
              printf '%s' '","executionTimeoutMs":120000,"flashBootType":"OFF",'
              printf '%s' '"gpuCount":1,"id":"created-endpoint-id","idleTimeout":5,'
              printf '%s' '"instanceIds":["cpu3g-4-16"],"name":"'
              printf '%s' "$endpoint_name"
              printf '%s' '","scalerType":"REQUEST_COUNT","scalerValue":1,'
              printf '%s\n' '"templateId":"created-template-id","workersMax":1,"workersMin":0}'
              exit 0
            fi
            printf '{"truncated":'
            exit 1
            ;;
          "serverless list")
            printf '%s\n' "${FAKE_REFLECTION_MARKER:-}" >&2
            count_file="${FAKE_RUNPOD_STATE}/endpoint-list-count"
            count=0
            [[ ! -f "$count_file" ]] || count="$(cat "$count_file")"
            count=$((count + 1))
            printf '%s\n' "$count" >"$count_file"
            if [[ "${FAKE_HUNG_CLEANUP_KIND:-}" == "endpoint" && $count -ge 2 ]]; then
              /bin/sleep 30
            fi
            if [[ -f "${FAKE_RUNPOD_STATE}/endpoint-name" ]]; then
              delay_through="${FAKE_DELAYED_APPEAR_THROUGH:-2}"
              if [[ "${FAKE_DELAYED_APPEAR_KIND:-}" == "endpoint" \
                && $count -le $delay_through ]]; then
                printf '[]\n'
                exit 0
              fi
              name="$(cat "${FAKE_RUNPOD_STATE}/endpoint-name")"
              printf '[{"id":"created-endpoint-id","name":"%s"}]\n' "$name"
            else
              printf '[]\n'
            fi
            ;;
          "serverless delete")
            printf '%s\n' "${FAKE_REFLECTION_MARKER:-}" >&2
            printf 'endpoint:%s\n' "${3:-}" >>"${FAKE_RUNPOD_STATE}/deleted-ids"
            rm -f "${FAKE_RUNPOD_STATE}/endpoint-name"
            printf '{}\n'
            ;;
          "serverless get")
            if [[ "${FAKE_CREATE_MODE:-}" == "success" ]]; then
              template_name="$(cat "${FAKE_RUNPOD_STATE}/template-name")"
              endpoint_name="$(cat "${FAKE_RUNPOD_STATE}/endpoint-name")"
              printf '%s' '{"executionTimeoutMs":120000,"flashboot":false,"gpuCount":1,'
              printf '%s' '"id":"created-endpoint-id","idleTimeout":5,"name":"'
              printf '%s' "$endpoint_name"
              printf '%s' '","scalerType":"REQUEST_COUNT","scalerValue":1,'
              printf '%s' '"template":{"config":{"templateId":"created-template-id"},'
              printf '%s' '"containerDiskInGb":5,"containerRegistryAuthId":"",'
              printf '%s' '"id":"created-template-id","isServerless":true,"name":"'
              printf '%s' "$template_name"
              printf '%s' '","ports":["8888/http","22/tcp"],"readme":"",'
              printf '%s' '"startJupyter":true,"startSsh":true},'
              printf '%s' '"templateId":"created-template-id",'
              printf '%s' '"urls":{"health":"https://api.runpod.ai/v2/created-endpoint-id/health",'
              printf '%s' '"run":"https://api.runpod.ai/v2/created-endpoint-id/run",'
              printf '%s' '"runsync":"https://api.runpod.ai/v2/created-endpoint-id/runsync"},'
              printf '%s\n' '"workersMax":1,"workersMin":0}'
              exit 0
            fi
            printf '{"id":"unrelated-endpoint-id","name":"unrelated-resource"}\n'
            ;;
          "serverless run")
            printf '1\n' >>"${FAKE_RUNPOD_STATE}/serverless-run-called"
            printf '{}\n'
            ;;
          *)
            printf '{}\n'
            ;;
        esac
        """,
    )
    _executable(
        fake_bin / "uv",
        """
        #!/usr/bin/env bash
        if [[ "$*" == *"lab.live_cli finalize"* ]]; then
          state_dir=""
          while (($#)); do
            if [[ "$1" == "--state-dir" ]]; then
              state_dir="$2"
              shift 2
            else
              shift
            fi
          done
          expected="$(<"${FAKE_RUNPOD_STATE}/prepare-host-state-dir")"
          printf '%s\n' "$state_dir" >"${FAKE_RUNPOD_STATE}/finalize-state-dir"
          [[ "$state_dir" == "$expected" ]] || exit 84
          [[ -f "${state_dir}/fake-prepared-state" ]] || exit 85
        fi
        exit 0
        """,
    )
    _executable(fake_bin / "sleep", "#!/usr/bin/env bash\nexit 0\n")
    return fake_bin, state


def _live_command(evidence_root: Path) -> list[str]:
    script = Path(__file__).resolve().parents[1] / "scripts" / "run-live.sh"
    return [
        str(script),
        "--worker-image",
        LIVE_WORKER_IMAGE,
        "--max-duration-minutes",
        "5",
        "--evidence-root",
        str(evidence_root),
        "--confirm-cost",
        "I ACCEPT RUNPOD CHARGES",
    ]


def _environment(fake_bin: Path, provider_state: Path, **extra: str) -> dict[str, str]:
    return {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_RUNPOD_STATE": str(provider_state),
        "FAKE_DOCKER_PLUGIN": str(fake_bin / "docker-buildx"),
        "FAKE_IMAGE_INDEX": RAW_IMAGE_INDEX,
        **extra,
    }


def _assert_option(args: list[str], name: str, value: str) -> None:
    joined = f"{name}={value}"
    if joined in args:
        return
    assert any(
        argument == name and index + 1 < len(args) and args[index + 1] == value
        for index, argument in enumerate(args)
    )


def test_worker_runtime_preflight_is_hardened_exact_and_before_remote_work(
    tmp_path: Path,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE="success",
        FAKE_REQUIRE_ANONYMOUS_REGISTRY="1",
        FAKE_REQUIRE_KEY_ISOLATION="1",
    )
    environment["RUNPOD_" + "API_KEY"] = "fake-provider-key"
    environment["DOCKER_" + "AUTH_CONFIG"] = '{"auths":{"registry.invalid":{}}}'
    environment["REGISTRY_" + "AUTH_FILE"] = str(tmp_path / "must-not-be-read.json")

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (provider_state / "worker-preflight-events").read_text().splitlines() == [
        "pull",
        "run",
    ]
    assert (provider_state / "worker-pull-api-key").read_text() == "absent\n"
    assert (provider_state / "worker-runtime-api-key").read_text() == "absent\n"

    pull_args = (provider_state / "worker-pull-args").read_text().splitlines()
    assert pull_args[0] == "pull"
    _assert_option(pull_args, "--platform", "linux/amd64")
    assert pull_args.count(LIVE_WORKER_IMAGE) == 1

    runtime_args = (provider_state / "worker-runtime-args").read_text().splitlines()
    assert runtime_args[0] == "run"
    _assert_option(runtime_args, "--pull", "never")
    _assert_option(runtime_args, "--platform", "linux/amd64")
    _assert_option(runtime_args, "--network", "none")
    _assert_option(runtime_args, "--cap-drop", "ALL")
    _assert_option(runtime_args, "--security-opt", "no-new-privileges")
    assert "--read-only" in runtime_args
    assert runtime_args.count(LIVE_WORKER_IMAGE) == 1
    command = " ".join(runtime_args)
    assert "test -s" in command and "requirements.lock" in command
    assert "python -m pip check" in command
    assert "self_test.py" in command
    assert "handler_self_test.py" in command


def test_worker_runtime_preflight_failure_has_no_provider_mutation_or_local_prep(
    tmp_path: Path,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE="success",
        FAKE_WORKER_PREFLIGHT_FAIL="1",
    )
    environment["RUNPOD_" + "API_KEY"] = "fake-provider-key"

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode != 0
    assert (provider_state / "worker-preflight-events").read_text().splitlines() == [
        "pull",
        "run",
    ]
    assert (provider_state / "worker-runtime-api-key").read_text() == "absent\n"
    assert not (provider_state / "curl-called").exists()
    assert not (provider_state / "prepare-state-dir").exists()
    assert not (provider_state / "template-name").exists()
    assert not (provider_state / "endpoint-name").exists()
    assert not (provider_state / "serverless-run-called").exists()
    assert not (provider_state / "deleted-ids").exists()


def test_worker_runtime_preflight_precedes_pricing_prep_and_provider_mutation() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "run-live.sh"
    source = script.read_text(encoding="utf-8")

    pull_at = source.index("docker pull")
    runtime_at = source.index("docker run")
    assert pull_at < runtime_at
    for later_boundary in (
        'pricing_source_status="not_attempted"',
        "python -m lab.live_cli prepare",
        "runpodctl template create",
        "runpodctl serverless create",
        "runpodctl serverless run",
    ):
        assert runtime_at < source.index(later_boundary)


def test_prepare_uses_a_dedicated_empty_trusted_state_subdirectory(tmp_path: Path) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=_environment(fake_bin, provider_state, FAKE_CREATE_MODE="template"),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 2
    assert (provider_state / "prepare-state-dir").read_text() == "/runpod-state/trusted-state\n"
    assert (provider_state / "prepare-payload").read_text() == "/runpod-state/worker-payload.json\n"
    layout = dict(
        line.split("=", maxsplit=1)
        for line in (provider_state / "prepare-layout.txt").read_text().splitlines()
    )
    assert layout["child_empty_before_prepare"] == "true"
    assert int(layout["child_mode"]) == 0o700
    assert int(layout["operational_entry_count"]) >= 1
    assert int(layout["parent_mode"]) == 0o700


def test_successful_fake_lifecycle_finalizes_the_exact_prepared_host_child(
    tmp_path: Path,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=_environment(fake_bin, provider_state, FAKE_CREATE_MODE="success"),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    prepared = (provider_state / "prepare-host-state-dir").read_text().strip()
    finalized = (provider_state / "finalize-state-dir").read_text().strip()
    assert finalized == prepared
    assert not Path(prepared).exists()
    assert (provider_state / "deleted-ids").read_text().splitlines() == [
        "endpoint:created-endpoint-id",
        "template:created-template-id",
    ]
    assert (provider_state / "serverless-run-called").read_text().splitlines() == ["1"]
    evidence_dir = next(evidence_root.iterdir())
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=1\n"
    manifest = json.loads((evidence_dir / "verification-manifest.json").read_text())
    assert manifest["cleanup_complete"] is True
    assert manifest["endpoint_id_sha256"] == hashlib.sha256(b"created-endpoint-id").hexdigest()
    assert manifest["template_id_sha256"] == hashlib.sha256(b"created-template-id").hexdigest()
    projection = json.loads((evidence_dir / "endpoint-readback-projection.json").read_text())
    assert projection["schema_version"] == "atcap.runpod.provider-readback-projection.v3"
    assert projection["provider_observation"]["compute_binding_source"] == (
        "runpodctl-2.12.0-create-graphql-response"
    )
    assert projection["provider_observation"]["generic_gpu_count_is_allocation_evidence"] is False


def test_create_response_compute_substitution_fails_before_provider_job(
    tmp_path: Path,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=_environment(
            fake_bin,
            provider_state,
            FAKE_CREATE_MODE="success",
            FAKE_ENDPOINT_CREATE_COMPUTE_TYPE="GPU",
        ),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 2
    assert "computeType" in result.stderr
    assert not (provider_state / "serverless-run-called").exists()
    assert (provider_state / "deleted-ids").read_text().splitlines() == [
        "endpoint:created-endpoint-id",
        "template:created-template-id",
    ]
    evidence_dir = next(evidence_root.iterdir())
    assert not (evidence_dir / "endpoint-readback-projection.json").exists()
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=1\n"


@pytest.mark.parametrize("ambiguous_kind", ["template", "endpoint"])
def test_ambiguous_create_is_resolved_deleted_and_secret_safe(
    tmp_path: Path,
    ambiguous_kind: str,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    marker = "PROVIDER_REFLECTION_MUST_NOT_REACH_EVIDENCE"
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE=ambiguous_kind,
        FAKE_REFLECTION_MARKER=marker,
    )

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 2
    evidence_dirs = list(evidence_root.iterdir())
    assert len(evidence_dirs) == 1
    evidence_dir = evidence_dirs[0]
    assert not (evidence_dir / "RECOVERY.txt").exists()
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=1\n"
    manifest = json.loads((evidence_dir / "verification-manifest.json").read_text())
    assert manifest["cleanup_complete"] is True
    assert all(marker.encode() not in path.read_bytes() for path in evidence_dir.iterdir())
    assert not (provider_state / "template-name").exists()
    assert not (provider_state / "endpoint-name").exists()
    anonymous_config = (provider_state / "anonymous-docker-config").read_text().strip()
    assert "/atcap-runpod-state." in anonymous_config
    assert anonymous_config.endswith("/anonymous-docker-config")


@pytest.mark.parametrize(
    ("create_mode", "unrelated_id", "expected_deleted_id"),
    [
        ("template-wrong-id", "unrelated-template-id", "created-template-id"),
        ("endpoint-wrong-id", "unrelated-endpoint-id", "created-endpoint-id"),
    ],
)
def test_unverified_returned_id_is_never_deleted(
    tmp_path: Path,
    create_mode: str,
    unrelated_id: str,
    expected_deleted_id: str,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE=create_mode,
    )

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 2
    deleted = (provider_state / "deleted-ids").read_text(encoding="utf-8")
    assert unrelated_id not in deleted
    assert expected_deleted_id in deleted
    evidence_dir = next(evidence_root.iterdir())
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=1\n"
    manifest = json.loads((evidence_dir / "verification-manifest.json").read_text())
    digest_field = (
        "template_id_sha256" if create_mode.startswith("template") else "endpoint_id_sha256"
    )
    assert manifest[digest_field] is None


def test_preset_supervisor_environment_cannot_bypass_wrapper(tmp_path: Path) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        ATCAP_RUNPOD_SUPERVISION_SHA256="0" * 64,
    )

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert result.returncode == 2
    assert "invalid inherited Runpod supervisor state" in result.stderr
    assert not any(evidence_root.iterdir())
    assert not (provider_state / "template-name").exists()


@pytest.mark.parametrize("version", ["2.11.9", "2.12.1", "2.13.0", "3.0.0"])
def test_only_exact_reviewed_runpodctl_2120_release_is_accepted(
    tmp_path: Path,
    version: str,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_RUNPODCTL_VERSION=version,
    )

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    assert "exact reviewed runpodctl 2.12.0 release" in result.stderr
    evidence_dir = next(evidence_root.iterdir())
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=1\n"


def test_key_is_removed_from_external_nonprovider_children_and_evidence(
    tmp_path: Path,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE="template",
        FAKE_REQUIRE_KEY_ISOLATION="1",
        FAKE_REQUIRE_ANONYMOUS_REGISTRY="1",
    )
    key_marker = f"key-sentinel-{tmp_path.name}"
    environment["RUNPOD_" + "API_KEY"] = key_marker
    environment["DOCKER_" + "AUTH_CONFIG"] = '{"auths":{"registry.invalid":{}}}'
    environment["REGISTRY_" + "AUTH_FILE"] = str(tmp_path / "must-not-be-read.json")

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 2
    assert "template:created-template-id" in (provider_state / "deleted-ids").read_text(
        encoding="utf-8"
    )
    evidence_dir = next(evidence_root.iterdir())
    assert all(key_marker.encode() not in path.read_bytes() for path in evidence_dir.iterdir())


@pytest.mark.parametrize("kind", ["template", "endpoint"])
def test_cleanup_does_not_trust_one_empty_listing_before_resource_appears(
    tmp_path: Path,
    kind: str,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE=kind,
        FAKE_DELAYED_APPEAR_KIND=kind,
    )

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 2
    assert not (provider_state / f"{kind}-name").exists()
    count_name = "endpoint-list-count" if kind == "endpoint" else "template-list-count"
    assert int((provider_state / count_name).read_text()) >= 6
    evidence_dir = next(evidence_root.iterdir())
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=1\n"


@pytest.mark.parametrize("kind", ["template", "endpoint"])
def test_ambiguous_create_waits_beyond_three_empty_listings_for_late_resource(
    tmp_path: Path,
    kind: str,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE=kind,
        FAKE_DELAYED_APPEAR_KIND=kind,
        FAKE_DELAYED_APPEAR_THROUGH="5",
    )

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 2
    assert not (provider_state / f"{kind}-name").exists()
    count_name = "endpoint-list-count" if kind == "endpoint" else "template-list-count"
    assert int((provider_state / count_name).read_text()) >= 9
    evidence_dir = next(evidence_root.iterdir())
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=1\n"


def test_hung_cleanup_query_is_bounded_and_cleanup_remains_incomplete(
    tmp_path: Path,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE="template",
        FAKE_HUNG_CLEANUP_KIND="template",
    )

    started = time.monotonic()
    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    elapsed = time.monotonic() - started

    assert result.returncode == 2
    assert elapsed < 10
    assert (provider_state / "template-name").exists()
    evidence_dir = next(evidence_root.iterdir())
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=0\n"
    assert (evidence_dir / "RECOVERY.txt").exists()


@pytest.mark.parametrize(
    "oversize_mode",
    ["runpod-user-stdout", "runpod-user-stderr", "curl"],
)
def test_untrusted_output_caps_fail_closed_without_provider_reflection(
    tmp_path: Path,
    oversize_mode: str,
) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    marker = "OVERSIZED_PROVIDER_REFLECTION_MARKER"
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_OVERSIZE_COMMAND=oversize_mode,
        FAKE_REFLECTION_MARKER=marker,
    )

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode != 0
    evidence_dir = next(evidence_root.iterdir())
    assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=1\n"
    assert all(marker.encode() not in path.read_bytes() for path in evidence_dir.iterdir())
    pricing = evidence_dir / "current-serverless-pricing.html"
    if pricing.exists():
        assert pricing.stat().st_size <= 2_097_152


def test_private_state_deletion_failure_is_honest_and_recoverable(tmp_path: Path) -> None:
    fake_bin, provider_state = _fake_path(tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    environment = _environment(
        fake_bin,
        provider_state,
        FAKE_CREATE_MODE="template",
        FAKE_FIND_DELETE_FAILURE="1",
    )

    result = subprocess.run(  # noqa: S603
        _live_command(evidence_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    match = re.search(r"retained exact state path: (.+)", result.stderr)
    assert match is not None
    retained = Path(match.group(1).strip())
    try:
        assert retained.is_dir()
        assert retained.name.startswith("atcap-runpod-state.")
        evidence_dir = next(evidence_root.iterdir())
        assert (evidence_dir / "cleanup-status.txt").read_text() == "cleanup_complete=0\n"
        recovery = (evidence_dir / "RECOVERY.txt").read_text()
        assert str(retained) in recovery
        assert "contains secrets" in recovery
        manifest = json.loads((evidence_dir / "verification-manifest.json").read_text())
        assert manifest["cleanup_complete"] is False
    finally:
        if retained.is_dir() and retained.name.startswith("atcap-runpod-state."):
            shutil.rmtree(retained)


def test_evidence_root_canonicalized_inside_repository_is_rejected(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[3]
    linked_root = tmp_path / "evidence-link"
    linked_root.symlink_to(repository, target_is_directory=True)

    result = subprocess.run(  # noqa: S603
        _live_command(linked_root),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert result.returncode == 2
    assert "outside the source repository" in result.stderr
