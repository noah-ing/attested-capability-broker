#!/bin/sh
set -eu

: "${ATCAP_SWTPM_TCTI:=swtpm:host=swtpm,port=2321}"
: "${TPM2TOOLS_TCTI:=${ATCAP_SWTPM_TCTI}}"
export ATCAP_SWTPM_TCTI TPM2TOOLS_TCTI

# This also fails early if the simulator is reachable but not usable as a TPM.
tpm2_getrandom 8 >/dev/null

uv sync --frozen --extra dev
uv run --frozen pytest
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy
uv run --frozen bandit -q -r src
uv run --frozen python -m build --no-isolation

echo "container smoke: PASS"
