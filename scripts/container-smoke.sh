#!/bin/sh
set -eu

: "${ATCAP_SWTPM_TCTI:=swtpm:host=swtpm,port=2321}"
: "${TPM2TOOLS_TCTI:=${ATCAP_SWTPM_TCTI}}"
export ATCAP_SWTPM_TCTI TPM2TOOLS_TCTI

# This also fails early if the simulator is reachable but not usable as a TPM.
tpm2_getrandom 8 >/dev/null

uv sync --frozen --extra dev
./scripts/verify-coverage.sh
uv run --frozen pytest examples/runpod-untrusted-caller/tests
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy
uv run --frozen mypy --strict \
    examples/runpod-untrusted-caller/bounded_capture.py \
    examples/runpod-untrusted-caller/evidence_manifest.py \
    examples/runpod-untrusted-caller/deadline_supervisor.py \
    examples/runpod-untrusted-caller/billing_observation.py \
    examples/runpod-untrusted-caller/provider_readback.py \
    examples/runpod-untrusted-caller/lab \
    examples/runpod-untrusted-caller/handler.py \
    examples/runpod-untrusted-caller/handler_self_test.py \
    examples/runpod-untrusted-caller/self_test.py \
    examples/runpod-untrusted-caller/lab_test_support.py
uv run --frozen bandit -q -r src
uv run --frozen bandit -q scripts/verify-package.py
uv run --frozen bandit -q -r examples/runpod-untrusted-caller/lab
uv run --frozen bandit -q \
    examples/runpod-untrusted-caller/bounded_capture.py \
    examples/runpod-untrusted-caller/evidence_manifest.py \
    examples/runpod-untrusted-caller/deadline_supervisor.py \
    examples/runpod-untrusted-caller/billing_observation.py \
    examples/runpod-untrusted-caller/provider_readback.py \
    examples/runpod-untrusted-caller/handler.py \
    examples/runpod-untrusted-caller/handler_self_test.py \
    examples/runpod-untrusted-caller/self_test.py
package_dist_dir="$(mktemp -d)"
uv run --frozen python -m build --no-isolation --outdir "${package_dist_dir}"
uv run --frozen python scripts/verify-package.py --dist-dir "${package_dist_dir}"

echo "container smoke: PASS"
