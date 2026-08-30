#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
original_args=("$@")

readonly ACCEPTANCE_PHRASE="I ACCEPT RUNPOD CHARGES"
readonly PRICING_URL="https://docs.runpod.io/serverless/pricing"
readonly CPU_TYPES_URL="https://docs.runpod.io/flash/configuration/cpu-types"
readonly CPU_INSTANCE_ID="cpu3g-4-16"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
example_dir="$(cd -- "${script_dir}/.." && pwd -P)"
repository_root="$(cd -- "${example_dir}/../.." && pwd -P)"
live_cli="${example_dir}/lab/live_cli.py"
compose_file="${repository_root}/compose.yaml"

worker_image=""
max_duration_minutes=""
confirm_cost=""
evidence_root=""
validate_only=0
supervised_fd=""

state_dir=""
trusted_state_dir=""
evidence_dir=""
template_id=""
endpoint_id=""
template_name=""
endpoint_name=""
cleanup_failed=0
compose_project=""
capability_ttl_seconds=0
template_create_attempted=0
endpoint_create_attempted=0
template_id_verified=0
endpoint_id_verified=0

run_local_controller() {
  PYTHONPATH="${example_dir}:${repository_root}/src" \
    uv run --frozen python -m lab.live_cli "$@"
}

usage() {
  cat <<'EOF'
Usage:
  run-live.sh --worker-image REGISTRY/REPOSITORY@sha256:DIGEST \
    --max-duration-minutes 5..30 \
    --evidence-root /absolute/dedicated/evidence/root \
    --confirm-cost 'I ACCEPT RUNPOD CHARGES'

  run-live.sh --validate-only \
    --worker-image REGISTRY/REPOSITORY@sha256:DIGEST \
    --max-duration-minutes 5..30

The live form creates a CPU Serverless template and endpoint, submits one real
job, then deletes both resources. It can incur Runpod charges. The validation
form performs local contract checks only and never contacts Runpod.
EOF
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --worker-image)
      (($# >= 2)) || fail "--worker-image needs a value"
      worker_image="$2"
      shift 2
      ;;
    --max-duration-minutes)
      (($# >= 2)) || fail "--max-duration-minutes needs a value"
      max_duration_minutes="$2"
      shift 2
      ;;
    --confirm-cost)
      (($# >= 2)) || fail "--confirm-cost needs a value"
      confirm_cost="$2"
      shift 2
      ;;
    --evidence-root)
      (($# >= 2)) || fail "--evidence-root needs a value"
      evidence_root="$2"
      shift 2
      ;;
    --validate-only)
      validate_only=1
      shift
      ;;
    --supervised-fd)
      (($# >= 2)) || fail "invalid internal supervisor handshake"
      supervised_fd="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ "$worker_image" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*/[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$ ]] \
  || fail "worker image must be an immutable registry/repository@sha256:<64 lowercase hex> reference"
[[ "$worker_image" != *":latest@"* ]] || fail "the mutable latest tag is forbidden"
[[ "$max_duration_minutes" =~ ^[0-9]+$ ]] \
  || fail "max duration must be an integer from 5 through 30"
((max_duration_minutes >= 5 && max_duration_minutes <= 30)) \
  || fail "max duration must be an integer from 5 through 30"
capability_ttl_seconds="$((max_duration_minutes * 60 + 300))"

if ((validate_only)); then
  [[ -z "$supervised_fd" && -z "${ATCAP_RUNPOD_SUPERVISION_SHA256:-}" ]] \
    || fail "supervisor handshake is not valid in no-Runpod-infrastructure mode"
  [[ -z "$confirm_cost" ]] \
    || fail "--confirm-cost is not accepted in no-Runpod-infrastructure validation mode"
  [[ -z "$evidence_root" ]] \
    || fail "--evidence-root is not accepted in no-Runpod-infrastructure validation mode"
  command -v uv >/dev/null 2>&1 || fail "uv is required for the fake worker check"
  ATCAP_SELF_TEST_WORKER_IMAGE="$worker_image" \
    uv run --frozen python "${example_dir}/self_test.py"
  declare -F run_local_controller >/dev/null \
    || fail "local controller runner function is unavailable"
  printf 'No-Runpod-infrastructure input and fake-worker contract validation passed.\n'
  exit 0
fi

[[ "$confirm_cost" == "$ACCEPTANCE_PHRASE" ]] \
  || fail "live execution requires --confirm-cost 'I ACCEPT RUNPOD CHARGES'"
[[ "$evidence_root" == /* && -d "$evidence_root" && -w "$evidence_root" ]] \
  || fail "--evidence-root must be an existing writable absolute directory"
evidence_root_real="$(cd -- "$evidence_root" && pwd -P)"
case "${evidence_root_real}/" in
  "${repository_root}/"*)
    fail "--evidence-root must be outside the source repository"
    ;;
esac
evidence_root="$evidence_root_real"

for required_command in curl docker python3 runpodctl sleep uv; do
  command -v "$required_command" >/dev/null 2>&1 \
    || fail "required command is missing: ${required_command}"
done
[[ -f "$live_cli" ]] || fail "local controller is missing: ${live_cli}"
command -v git >/dev/null 2>&1 || fail "git is required to bind a live run to exact source"
git -C "$repository_root" diff --quiet -- \
  || fail "live execution requires a clean tracked working tree"
git -C "$repository_root" diff --cached --quiet -- \
  || fail "live execution requires a clean staged index"
[[ -z "$(git -C "$repository_root" ls-files --others --exclude-standard)" ]] \
  || fail "live execution requires no untracked source files"
source_commit="$(git -C "$repository_root" rev-parse HEAD)"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || fail "could not resolve an exact source commit"

# A separate supervisor owns the deadline so Bash cannot defer it while waiting
# for a hung foreground Docker, curl, or runpodctl child. The supervised process
# group receives TERM at the execution deadline and has 120 seconds to run the
# normal cleanup trap before a final KILL. The child accepts only a per-run token
# delivered through a supervisor-owned pipe, so a pre-set environment cannot skip it.
if [[ -z "$supervised_fd" ]]; then
  [[ -z "${ATCAP_RUNPOD_SUPERVISION_SHA256:-}" ]] \
    || fail "invalid inherited Runpod supervisor state"
  exec python3 "${example_dir}/deadline_supervisor.py" \
    --limit-seconds "$((max_duration_minutes * 60))" \
    --cleanup-grace-seconds 120 \
    --append-handshake \
    -- "${script_dir}/run-live.sh" "${original_args[@]}"
fi
[[ "$supervised_fd" =~ ^[0-9]+$ ]] || fail "invalid internal supervisor descriptor"
expected_supervision_sha256="${ATCAP_RUNPOD_SUPERVISION_SHA256:-}"
[[ "$expected_supervision_sha256" =~ ^[0-9a-f]{64}$ ]] \
  || fail "invalid inherited Runpod supervisor state"
supervision_token=""
IFS= read -r supervision_token <&"$supervised_fd" \
  || fail "supervisor handshake was not readable"
eval "exec ${supervised_fd}<&-"
actual_supervision_sha256="$(
  printf '%s' "$supervision_token" | python3 -c \
    'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
unset supervision_token ATCAP_RUNPOD_SUPERVISION_SHA256
[[ "$actual_supervision_sha256" == "$expected_supervision_sha256" ]] \
  || fail "supervisor handshake did not verify"
unset expected_supervision_sha256 actual_supervision_sha256 supervised_fd

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
random_suffix="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
safe_suffix="${timestamp}-$$-${random_suffix}"
compose_project="atcap-runpod-$(date -u +%Y%m%d%H%M%S)-$$"
state_dir="$(python3 -c 'import tempfile; print(tempfile.mkdtemp(prefix="atcap-runpod-state."))')"
state_parent="$(dirname -- "$state_dir")"
chmod 0700 "$state_dir"
trusted_state_dir="${state_dir}/trusted-state"
mkdir -m 0700 "$trusted_state_dir"
evidence_dir="$(mktemp -d \
  "${evidence_root%/}/attested-capability-broker-runpod-live-${timestamp}.XXXXXX")"
chmod 0700 "$evidence_dir"
: >"${evidence_dir}/cleanup.log"
chmod 0600 "${evidence_dir}/cleanup.log"
template_name="atcap-holder-${safe_suffix}"
endpoint_name="atcap-holder-${safe_suffix}"

readonly PROVIDER_JSON_LIMIT_BYTES=1048576
readonly PROVIDER_STDERR_LIMIT_BYTES=262144
readonly WORKER_RESPONSE_LIMIT_BYTES=2097152
readonly REMOTE_DOCUMENT_LIMIT_BYTES=2097152
readonly COMPOSE_LOG_LIMIT_BYTES=16777216
readonly CLEANUP_COMMAND_TIMEOUT_SECONDS=3
readonly CLEANUP_DEADLINE_SECONDS=75
readonly CLEANUP_LIST_ATTEMPTS=12
readonly CLEANUP_ABSENCE_SNAPSHOTS=3
readonly CLEANUP_UNVERIFIED_ABSENCE_SNAPSHOTS=8
readonly CLEANUP_DELETE_ATTEMPTS=2
readonly CLEANUP_POLL_INTERVAL_SECONDS=2

compose_touched=0
cleanup_deadline=0
snapshot_exact_name_id=""
snapshot_id_present=0
state_retained=0

payload_file="${state_dir}/worker-payload.json"
response_file="${state_dir}/worker-response.json"
template_response="${state_dir}/template-create.json"
endpoint_response="${state_dir}/endpoint-create.json"
start_rfc3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

write_recovery() {
  {
    printf 'Runpod cleanup recovery\n'
    printf 'Created names are unique local values for this run.\n'
    printf 'Treat every provider response and identifier as untrusted.\n'
    printf 'Template name: %s\n' "$template_name"
    printf 'Endpoint name: %s\n' "$endpoint_name"
    printf 'Inspect the exact names with these commands:\n'
    printf '  runpodctl serverless list --output json\n'
    printf '  runpodctl template list --type user --output json\n'
    printf 'Delete only an identifier independently confirmed to have the exact name.\n'
    printf 'Provider raw output is never copied into this recovery file.\n'
    if ((state_retained)); then
      printf '\nPrivate state cleanup failed. This guarded path contains secrets:\n'
      printf '  %s\n' "$state_dir"
      printf 'After inspecting the exact path, remove only it with:\n'
      printf '  find %q -depth -delete\n' "$state_dir"
    fi
  } >"${evidence_dir}/RECOVERY.txt"
  chmod 0600 "${evidence_dir}/RECOVERY.txt"
}

capture_bounded() {
  local label="$1"
  local timeout_seconds="$2"
  local stdout_path="$3"
  local stdout_limit="$4"
  local stderr_path="$5"
  local stderr_limit="$6"
  local append="$7"
  shift 7
  [[ "$label" =~ ^[a-z0-9][a-z0-9._-]{0,95}$ ]] || return 126
  local result_path="${state_dir}/capture-${label}.result.json"
  local capture_arguments=(
    --stdout "$stdout_path"
    --stderr "$stderr_path"
    --result "$result_path"
    --stdout-limit-bytes "$stdout_limit"
    --stderr-limit-bytes "$stderr_limit"
    --timeout-seconds "$timeout_seconds"
  )
  if ((append)); then
    capture_arguments+=(--append)
  fi
  python3 "${example_dir}/bounded_capture.py" \
    "${capture_arguments[@]}" -- "$@"
}

snapshot_resource() {
  local kind="$1"
  local resource_name="$2"
  local resource_id="$3"
  local label="$4"
  local raw_path="${state_dir}/${label}.listing.raw.json"
  local stderr_path="${state_dir}/${label}.listing.stderr.raw.log"
  local observation_path="${state_dir}/${label}.listing.observation.json"
  if [[ "$kind" == "endpoint" ]]; then
    capture_bounded "$label" "$CLEANUP_COMMAND_TIMEOUT_SECONDS" \
      "$raw_path" "$PROVIDER_JSON_LIMIT_BYTES" \
      "$stderr_path" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
      runpodctl serverless list --output json || return 1
  else
    capture_bounded "$label" "$CLEANUP_COMMAND_TIMEOUT_SECONDS" \
      "$raw_path" "$PROVIDER_JSON_LIMIT_BYTES" \
      "$stderr_path" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
      runpodctl template list --type user --output json || return 1
  fi
  python3 "${example_dir}/provider_readback.py" listing \
    --json "$raw_path" \
    --result "$observation_path" \
    --resource-name "$resource_name" \
    --resource-id "$resource_id" || return 1
  snapshot_exact_name_id="$(python3 - "$observation_path" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
observed = value.get("exact_name_id")
print(observed if isinstance(observed, str) else "")
PY
)" || return 1
  snapshot_id_present="$(python3 - "$observation_path" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(1 if value.get("requested_id_present") is True else 0)
PY
)" || return 1
}

delete_resource() {
  local kind="$1"
  local resource_id="$2"
  local label="$3"
  if [[ "$kind" == "endpoint" ]]; then
    capture_bounded "$label" "$CLEANUP_COMMAND_TIMEOUT_SECONDS" \
      "${state_dir}/${label}.delete.stdout.raw.log" "$PROVIDER_JSON_LIMIT_BYTES" \
      "${state_dir}/${label}.delete.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
      runpodctl serverless delete "$resource_id"
  else
    capture_bounded "$label" "$CLEANUP_COMMAND_TIMEOUT_SECONDS" \
      "${state_dir}/${label}.delete.stdout.raw.log" "$PROVIDER_JSON_LIMIT_BYTES" \
      "${state_dir}/${label}.delete.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
      runpodctl template delete "$resource_id"
  fi
}

cleanup_resource() {
  local kind="$1"
  local resource_name="$2"
  local verified_id="$3"
  local create_attempted="$4"
  local iteration
  local consecutive_absent=0
  local delete_attempts=0
  local required_absent="$CLEANUP_ABSENCE_SNAPSHOTS"
  local target_id=""
  ((create_attempted)) || return 0
  if [[ -z "$verified_id" ]]; then
    # An ambiguous create may become visible only after the local command has
    # failed.  Require the longer, full absence horizon before declaring that
    # an attempted-but-unverified resource never appeared.
    required_absent="$CLEANUP_UNVERIFIED_ABSENCE_SNAPSHOTS"
  fi
  for ((iteration = 1; iteration <= CLEANUP_LIST_ATTEMPTS; iteration++)); do
    if ((SECONDS >= cleanup_deadline)); then
      printf 'Cleanup deadline reached while checking %s.\n' "$kind" \
        >>"${evidence_dir}/cleanup.log"
      return 1
    fi
    if ! snapshot_resource "$kind" "$resource_name" "$verified_id" \
      "cleanup-${kind}-list-${iteration}"; then
      printf 'Provider listing was incomplete while checking %s cleanup.\n' "$kind" \
        >>"${evidence_dir}/cleanup.log"
      return 1
    fi
    if [[ -n "$verified_id" && -n "$snapshot_exact_name_id" \
      && "$snapshot_exact_name_id" != "$verified_id" ]]; then
      printf 'Provider listing disagreed on the verified %s name and identifier.\n' \
        "$kind" >>"${evidence_dir}/cleanup.log"
      return 1
    fi
    target_id=""
    if [[ -n "$snapshot_exact_name_id" ]]; then
      target_id="$snapshot_exact_name_id"
    elif [[ -n "$verified_id" && "$snapshot_id_present" == 1 ]]; then
      target_id="$verified_id"
    fi
    if [[ -n "$target_id" ]]; then
      consecutive_absent=0
      required_absent="$CLEANUP_ABSENCE_SNAPSHOTS"
      if ((delete_attempts >= CLEANUP_DELETE_ATTEMPTS)); then
        printf 'Bounded delete attempts were exhausted for %s.\n' "$kind" \
          >>"${evidence_dir}/cleanup.log"
        return 1
      fi
      delete_attempts=$((delete_attempts + 1))
      if ! delete_resource "$kind" "$target_id" \
        "cleanup-${kind}-delete-${delete_attempts}"; then
        printf 'A bounded %s delete attempt did not succeed.\n' "$kind" \
          >>"${evidence_dir}/cleanup.log"
      fi
    else
      consecutive_absent=$((consecutive_absent + 1))
      if ((consecutive_absent >= required_absent)); then
        printf 'Verified %s identifier and exact unique name absent in %s consecutive snapshots.\n' \
          "$kind" "$required_absent" >>"${evidence_dir}/cleanup.log"
        return 0
      fi
    fi
    sleep "$CLEANUP_POLL_INTERVAL_SECONDS"
  done
  printf 'Could not establish consecutive absence for %s within bounded attempts.\n' \
    "$kind" >>"${evidence_dir}/cleanup.log"
  return 1
}

cleanup() {
  local original_status=$?
  local endpoint_id_digest=""
  local template_id_digest=""
  trap - EXIT
  set +e
  cleanup_deadline=$((SECONDS + CLEANUP_DEADLINE_SECONDS))
  write_recovery
  if ((compose_touched)); then
    if ! capture_bounded cleanup-compose-down 10 \
      "${state_dir}/cleanup-compose-down.stdout.raw.log" "$COMPOSE_LOG_LIMIT_BYTES" \
      "${state_dir}/cleanup-compose-down.stderr.raw.log" "$COMPOSE_LOG_LIMIT_BYTES" 0 \
      env -u RUNPOD_API_KEY \
      docker compose --project-name "$compose_project" --file "$compose_file" \
      down --volumes --remove-orphans; then
      cleanup_failed=1
    fi
  fi
  cleanup_resource endpoint "$endpoint_name" \
    "$([[ $endpoint_id_verified -eq 1 ]] && printf '%s' "$endpoint_id")" \
    "$endpoint_create_attempted" || cleanup_failed=1
  cleanup_resource template "$template_name" \
    "$([[ $template_id_verified -eq 1 ]] && printf '%s' "$template_id")" \
    "$template_create_attempted" || cleanup_failed=1
  if [[ -n "$state_dir" && -d "$state_dir" ]]; then
    if [[ "$state_dir" == "${state_parent}/atcap-runpod-state."* ]]; then
      if ! find "$state_dir" -depth -delete; then
        cleanup_failed=1
        state_retained=1
        write_recovery
        printf 'Private state deletion failed; retained exact state path: %s\n' \
          "$state_dir" >&2
      fi
    else
      printf 'Refusing to remove unexpected state path: %s\n' "$state_dir" >&2
      cleanup_failed=1
    fi
  fi
  if ((cleanup_failed)); then
    printf 'Cleanup was incomplete; use %s\n' "${evidence_dir}/RECOVERY.txt" >&2
    [[ $original_status -ne 0 ]] || original_status=1
  else
    printf 'Runpod endpoint and template cleanup completed.\n'
    if [[ -f "${evidence_dir}/RECOVERY.txt" ]]; then
      find "${evidence_dir}/RECOVERY.txt" -type f -delete 2>/dev/null || true
    fi
  fi
  printf 'cleanup_complete=%s\n' "$((cleanup_failed == 0))" \
    >"${evidence_dir}/cleanup-status.txt"
  if ((endpoint_id_verified)) && [[ -n "$endpoint_id" ]]; then
    endpoint_id_digest="$(
      printf '%s' "$endpoint_id" | python3 -c \
        'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
    )"
  fi
  if ((template_id_verified)) && [[ -n "$template_id" ]]; then
    template_id_digest="$(
      printf '%s' "$template_id" | python3 -c \
        'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
    )"
  fi
  if ! python3 "${example_dir}/evidence_manifest.py" \
    --root "$evidence_dir" \
    --worker-image "$worker_image" \
    --endpoint-id-sha256 "$endpoint_id_digest" \
    --template-id-sha256 "$template_id_digest" \
    --cleanup-complete "$([[ $cleanup_failed -eq 0 ]] && printf true || printf false)"; then
    cleanup_failed=1
    write_recovery
    printf 'cleanup_complete=0\n' >"${evidence_dir}/cleanup-status.txt"
    printf 'Evidence checksum/manifest generation failed.\n' >&2
    [[ $original_status -ne 0 ]] || original_status=1
  fi
  printf 'Local evidence (gitignored): %s\n' "$evidence_dir"
  exit "$original_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

runpodctl_version_path="${state_dir}/runpodctl-version.stdout.raw.log"
if ! capture_bounded runpodctl-version 5 \
  "$runpodctl_version_path" 4096 \
  "${state_dir}/runpodctl-version.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  runpodctl version; then
  fail "runpodctl version check failed"
fi
runpodctl_version="$(<"$runpodctl_version_path")"
if [[ "$runpodctl_version" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
  version_major="${BASH_REMATCH[1]}"
  version_minor="${BASH_REMATCH[2]}"
  version_patch="${BASH_REMATCH[3]}"
else
  fail "could not parse runpodctl version"
fi
((version_major == 2 && version_minor == 12 && version_patch == 0)) \
  || fail "the exact reviewed runpodctl 2.12.0 release is required"

# Authentication remains in runpodctl's local credential handling. This runner
# does not intentionally read, copy, or print the API key; runpodctl may use an
# inherited RUNPOD_API_KEY and necessarily sends its credential to Runpod.
if ! capture_bounded runpodctl-user 5 \
  "${state_dir}/runpodctl-user.stdout.raw.json" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/runpodctl-user.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  runpodctl user; then
  fail "runpodctl authentication check failed"
fi

# Discover only the local buildx executable, then expose that one plugin to a
# fresh mode-0700 Docker configuration containing no registry credentials. The
# --raw output is byte-for-byte hashed against the requested OCI digest.
docker_plugins_raw="${state_dir}/docker-plugins.stdout.raw.json"
if ! capture_bounded docker-plugin-discovery 5 \
  "$docker_plugins_raw" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/docker-plugins.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  env -u RUNPOD_API_KEY docker info --format '{{json .ClientInfo.Plugins}}'; then
  fail "could not discover the local Docker buildx plugin"
fi
buildx_plugin_path="$(python3 - "$docker_plugins_raw" <<'PY'
import json
import os
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(document, list):
    raise SystemExit(1)
matches = [item for item in document if isinstance(item, dict) and item.get("Name") == "buildx"]
if len(matches) != 1:
    raise SystemExit(1)
path = matches[0].get("Path")
if not isinstance(path, str) or not os.path.isabs(path):
    raise SystemExit(1)
candidate = pathlib.Path(path)
if not candidate.is_file() or not os.access(candidate, os.X_OK):
    raise SystemExit(1)
print(path)
PY
)" || fail "local Docker buildx plugin metadata was invalid"
anonymous_docker_config="${state_dir}/anonymous-docker-config"
mkdir -p "${anonymous_docker_config}/cli-plugins"
chmod 0700 "$anonymous_docker_config" "${anonymous_docker_config}/cli-plugins"
ln -s "$buildx_plugin_path" "${anonymous_docker_config}/cli-plugins/docker-buildx"
worker_manifest_raw="${state_dir}/worker-image-index.raw.json"
if ! capture_bounded anonymous-image-inspect 30 \
  "$worker_manifest_raw" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/worker-image-inspect.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  env -u RUNPOD_API_KEY -u DOCKER_AUTH_CONFIG -u REGISTRY_AUTH_FILE \
  DOCKER_CONFIG="$anonymous_docker_config" \
  docker buildx imagetools inspect --raw "$worker_image"; then
  fail "anonymous immutable worker-image inspection failed"
fi
python3 "${example_dir}/provider_readback.py" image \
  --json "$worker_manifest_raw" \
  --projection "${evidence_dir}/worker-image-manifest-projection.json" \
  --worker-image "$worker_image"

pricing_source_status="not_attempted"
cpu_types_source_status="not_attempted"
write_remote_source_status() {
  {
    printf 'schema_version=atcap-remote-source-capture/v1\n'
    printf 'max_bytes_each=%s\n' "$REMOTE_DOCUMENT_LIMIT_BYTES"
    printf 'pricing=%s\n' "$pricing_source_status"
    printf 'cpu_types=%s\n' "$cpu_types_source_status"
  } >"${evidence_dir}/remote-source-capture-status.txt"
}
write_remote_source_status
if capture_bounded pricing-source 30 \
  "${evidence_dir}/current-serverless-pricing.html" "$REMOTE_DOCUMENT_LIMIT_BYTES" \
  "${state_dir}/pricing-source.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  env -u RUNPOD_API_KEY curl --fail --show-error --silent --location \
  --proto '=https' --tlsv1.2 --max-time 30 "$PRICING_URL"; then
  pricing_source_status="received_bounded"
  write_remote_source_status
else
  pricing_source_status="failed_or_limited"
  write_remote_source_status
  fail "bounded pricing source retrieval failed"
fi
if capture_bounded cpu-types-source 30 \
  "${evidence_dir}/current-cpu-types.html" "$REMOTE_DOCUMENT_LIMIT_BYTES" \
  "${state_dir}/cpu-types-source.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  env -u RUNPOD_API_KEY curl --fail --show-error --silent --location \
  --proto '=https' --tlsv1.2 --max-time 30 "$CPU_TYPES_URL"; then
  cpu_types_source_status="received_bounded"
  write_remote_source_status
else
  cpu_types_source_status="failed_or_limited"
  write_remote_source_status
  fail "bounded CPU-type source retrieval failed"
fi
{
  printf 'queried_at=%s\n' "$start_rfc3339"
  printf 'pricing_url=%s\n' "$PRICING_URL"
  printf 'cpu_types_url=%s\n' "$CPU_TYPES_URL"
  printf 'worker_image=%s\n' "$worker_image"
  printf 'source_commit=%s\n' "$source_commit"
  printf 'compute_type=CPU\n'
  printf 'cpu_instance=%s\n' "$CPU_INSTANCE_ID"
  printf 'workers_min=0\nworkers_max=1\n'
  printf 'execution_timeout_seconds=120\nidle_timeout_seconds=5\n'
  printf 'whole_run_limit_minutes=%s\n' "$max_duration_minutes"
  printf 'capability_ttl_seconds=%s\n' "$capability_ttl_seconds"
  printf 'local_tpm_mode=real-swtpm\n'
  printf 'provider_submission_policy=at_most_one_attempt\n'
  printf 'provider_resubmission=forbidden\n'
} >"${evidence_dir}/run-configuration.txt"
printf 'Captured current official pricing/type sources; no price is hardcoded.\n'

compose_stdout_log="${evidence_dir}/local-swtpm-prepare.stdout.log"
compose_stderr_log="${evidence_dir}/local-swtpm-prepare.stderr.log"
compose_touched=1
capture_bounded compose-build 240 \
  "$compose_stdout_log" "$COMPOSE_LOG_LIMIT_BYTES" \
  "$compose_stderr_log" "$COMPOSE_LOG_LIMIT_BYTES" 1 \
  env -u RUNPOD_API_KEY \
  docker compose --project-name "$compose_project" --file "$compose_file" build --pull
capture_bounded compose-up 60 \
  "$compose_stdout_log" "$COMPOSE_LOG_LIMIT_BYTES" \
  "$compose_stderr_log" "$COMPOSE_LOG_LIMIT_BYTES" 1 \
  env -u RUNPOD_API_KEY \
  docker compose --project-name "$compose_project" --file "$compose_file" \
  up --detach --wait swtpm
capture_bounded compose-prepare 120 \
  "$compose_stdout_log" "$COMPOSE_LOG_LIMIT_BYTES" \
  "$compose_stderr_log" "$COMPOSE_LOG_LIMIT_BYTES" 1 \
  env -u RUNPOD_API_KEY \
  docker compose --project-name "$compose_project" --file "$compose_file" \
  run --rm --no-deps --user "$(id -u):$(id -g)" \
  --volume "${state_dir}:/runpod-state" \
  --env PYTHONPATH=/workspace/examples/runpod-untrusted-caller:/workspace/src \
  --env "ATCAP_LAB_COMMIT_SHA=${source_commit}" \
  verify \
  python -m lab.live_cli prepare \
    --worker-image "$worker_image" \
    --state-dir /runpod-state/trusted-state \
    --payload /runpod-state/worker-payload.json \
    --tpm-mode real-swtpm \
    --capability-ttl-seconds "$capability_ttl_seconds"
capture_bounded compose-down 20 \
  "$compose_stdout_log" "$COMPOSE_LOG_LIMIT_BYTES" \
  "$compose_stderr_log" "$COMPOSE_LOG_LIMIT_BYTES" 1 \
  env -u RUNPOD_API_KEY \
  docker compose --project-name "$compose_project" --file "$compose_file" \
  down --volumes --remove-orphans
compose_touched=0

if ! snapshot_resource template "$template_name" "" template-precreate; then
  fail "could not verify the unique template name before creation"
fi
if [[ -n "$snapshot_exact_name_id" ]]; then
  fail "refusing to create a template with a pre-existing unique name"
fi
set +e
template_create_attempted=1
capture_bounded template-create 15 \
  "$template_response" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/template-create.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  runpodctl template create \
  --name "$template_name" \
  --image "$worker_image" \
  --serverless \
  --container-disk-in-gb 5 \
  --volume-in-gb 0 \
  --output json
template_status=$?
set -e
template_id="$(python3 "${example_dir}/provider_readback.py" created-id \
  --json "$template_response" --kind template 2>/dev/null || true)"
[[ $template_status -eq 0 && -n "$template_id" ]] \
  || fail "template creation failed or returned no template ID; inspect local evidence/recovery"
[[ "$template_id" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] \
  || fail "template creation returned an invalid template ID"
write_recovery

template_verified="${state_dir}/template-readback.raw.json"
template_projection="${evidence_dir}/template-readback-projection.json"
capture_bounded template-get 15 \
  "$template_verified" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/template-get.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  runpodctl template get "$template_id" --output json
python3 "${example_dir}/provider_readback.py" template \
  --json "$template_verified" \
  --projection "$template_projection" \
  --template-id "$template_id" \
  --template-name "$template_name" \
  --worker-image "$worker_image"
template_id_verified=1
write_recovery

if ! snapshot_resource endpoint "$endpoint_name" "" endpoint-precreate; then
  fail "could not verify the unique endpoint name before creation"
fi
if [[ -n "$snapshot_exact_name_id" ]]; then
  fail "refusing to create an endpoint with a pre-existing unique name"
fi
set +e
endpoint_create_attempted=1
capture_bounded endpoint-create 15 \
  "$endpoint_response" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/endpoint-create.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  runpodctl serverless create \
  --name "$endpoint_name" \
  --template-id "$template_id" \
  --compute-type CPU \
  --instance-id "$CPU_INSTANCE_ID" \
  --workers-min 0 \
  --workers-max 1 \
  --scale-by requests \
  --scale-threshold 1 \
  --execution-timeout 120 \
  --idle-timeout 5 \
  --flash-boot=false \
  --output json
endpoint_status=$?
set -e
endpoint_id="$(python3 "${example_dir}/provider_readback.py" created-id \
  --json "$endpoint_response" --kind endpoint 2>/dev/null || true)"
[[ $endpoint_status -eq 0 && -n "$endpoint_id" ]] \
  || fail "endpoint creation failed or returned no endpoint ID; inspect local evidence/recovery"
[[ "$endpoint_id" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] \
  || fail "endpoint creation returned an invalid endpoint ID"
write_recovery

endpoint_verified="${state_dir}/endpoint-readback.raw.json"
endpoint_projection="${evidence_dir}/endpoint-readback-projection.json"
capture_bounded endpoint-get 15 \
  "$endpoint_verified" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/endpoint-get.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  runpodctl serverless get "$endpoint_id" --include-template --output json
python3 "${example_dir}/provider_readback.py" endpoint \
  --json "$endpoint_verified" \
  --projection "$endpoint_projection" \
  --endpoint-id "$endpoint_id" \
  --endpoint-name "$endpoint_name" \
  --template-id "$template_id" \
  --template-name "$template_name" \
  --instance-id "$CPU_INSTANCE_ID" \
  --worker-image "$worker_image"
endpoint_id_verified=1
write_recovery

capture_bounded serverless-run "$((max_duration_minutes * 60))" \
  "$response_file" "$WORKER_RESPONSE_LIMIT_BYTES" \
  "${state_dir}/serverless-run.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  runpodctl serverless run "$endpoint_id" \
  --input-file "$payload_file" \
  --wait "${max_duration_minutes}m" \
  --output json

capture_bounded local-finalize 60 \
  "${state_dir}/local-finalize.stdout.raw.log" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/local-finalize.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  env -u RUNPOD_API_KEY PYTHONPATH="${example_dir}:${repository_root}/src" \
  uv run --frozen python -m lab.live_cli finalize \
    --state-dir "$trusted_state_dir" \
    --worker-response "$response_file" \
    --endpoint-id "$endpoint_id" \
    --worker-image "$worker_image" \
    --evidence-dir "$evidence_dir"

end_rfc3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
endpoint_id_sha256="$(
  printf '%s' "$endpoint_id" | python3 -c \
    'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
raw_billing_response="${state_dir}/serverless-billing.raw.json"
set +e
capture_bounded serverless-billing 15 \
  "$raw_billing_response" "$PROVIDER_JSON_LIMIT_BYTES" \
  "${state_dir}/serverless-billing.stderr.raw.log" "$PROVIDER_STDERR_LIMIT_BYTES" 0 \
  runpodctl billing serverless \
  --start-time "$start_rfc3339" \
  --end-time "$end_rfc3339" \
  --endpoint-id "$endpoint_id" \
  --bucket-size hour \
  --output json
billing_status=$?
set -e
python3 "${example_dir}/billing_observation.py" \
  --raw "$raw_billing_response" \
  --output "${evidence_dir}/serverless-billing-observation.json" \
  --endpoint-id-sha256 "$endpoint_id_sha256" \
  --command-status "$([[ $billing_status -eq 0 ]] && printf success || printf failure)"

printf 'Live untrusted-holder experiment completed; cleanup will now run.\n'
