# The tag documents the Python and Debian release. The digest pins the exact
# multi-platform image index returned by Docker Hub on 2026-08-29.
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/atcap-venv \
    PATH=/opt/atcap-venv/bin:${PATH}

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        libtss2-dev \
        pkg-config \
        swtpm \
        swtpm-tools \
        tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir uv==0.12.5

WORKDIR /workspace

COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --extra dev --no-install-project

COPY . .
RUN uv sync --frozen --extra dev

CMD ["./scripts/container-smoke.sh"]

