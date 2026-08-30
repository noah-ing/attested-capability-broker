# This exact multi-platform base index is the same reviewed Python 3.12.11
# Bookworm base used by the verification harness. Build and deploy linux/amd64.
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ARG TARGETPLATFORM

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/worker-venv/bin:${PATH}

RUN test "$TARGETPLATFORM" = "linux/amd64" \
    && groupadd --gid 10001 worker \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin worker \
    && python -m venv /opt/worker-venv \
    && chown -R worker:worker /opt/worker-venv

WORKDIR /opt/worker

COPY --chown=worker:worker requirements.lock ./requirements.lock
RUN test -s requirements.lock \
    && python -m pip install --no-cache-dir --require-hashes --requirement requirements.lock \
    && python -m pip check \
    && python -c 'import ca2a_runtime, cryptography, joserfc, pydantic, rfc8785, runpod'

COPY --chown=worker:worker handler.py handler_self_test.py self_test.py ./
COPY --chown=worker:worker \
    lab/__init__.py \
    lab/errors.py \
    lab/worker.py \
    lab/worker_wire.py \
    ./lab/

# Import the exact copied entrypoint and shared modules during the build. This
# makes a missing runtime dependency or malformed source a build failure rather
# than a worker that can never join the Runpod dispatcher.
RUN python -c 'import handler, lab.worker, lab.worker_wire'

USER 10001:10001

CMD ["python", "-u", "handler.py"]
