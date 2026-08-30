"""In-memory bytes transport used instead of live, billable infrastructure."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import rfc8785

from .errors import DuplicateRunIdError, LabProtocolError, LabTimeoutError
from .wire import WorkerRequest
from .worker import DisposableHolderWorker

ResponseMutator = Callable[[bytes, WorkerRequest], bytes]


class FakeWorkerTransport:
    """A deterministic transport with duplicate, corruption, and timeout faults."""

    def __init__(
        self,
        worker: DisposableHolderWorker,
        *,
        delays: dict[str, float] | None = None,
        corrupt_run_ids: set[str] | None = None,
        response_mutator: ResponseMutator | None = None,
    ) -> None:
        self.worker = worker
        self.delays = dict(delays or {})
        self.corrupt_run_ids = set(corrupt_run_ids or set())
        self.response_mutator = response_mutator
        self._seen_run_ids: set[str] = set()
        self._seen_lock = asyncio.Lock()

    async def submit(self, request: WorkerRequest, *, timeout_seconds: float) -> bytes:
        if timeout_seconds <= 0:
            raise ValueError("transport timeout must be positive")
        async with self._seen_lock:
            if request.run_id in self._seen_run_ids:
                raise DuplicateRunIdError("worker request run ID was already submitted")
            self._seen_run_ids.add(request.run_id)

        async def invoke() -> bytes:
            delay = self.delays.get(request.run_id, 0.0)
            if delay:
                await asyncio.sleep(delay)
            raw_request = rfc8785.dumps(request.model_dump(mode="json"))
            try:
                response = await asyncio.to_thread(self.worker.handle_bytes, raw_request)
            except Exception as exc:
                raise LabProtocolError("worker execution failed") from exc
            if request.run_id in self.corrupt_run_ids:
                response = b'{"corrupt":'
            if self.response_mutator is not None:
                response = self.response_mutator(response, request)
            return response

        try:
            return await asyncio.wait_for(invoke(), timeout=timeout_seconds)
        except TimeoutError as exc:
            raise LabTimeoutError("worker response deadline expired") from exc
