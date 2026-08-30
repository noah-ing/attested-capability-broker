#!/bin/sh
set -eu

# pyproject.toml is the single source of truth for branch measurement and the
# minimum. Arguments are passed to pytest so host runs can exclude the Linux-only
# swtpm profile while the container invokes the complete suite.
uv run --frozen coverage erase
uv run --frozen coverage run -m pytest "$@"
uv run --frozen coverage report
