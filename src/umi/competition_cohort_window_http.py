"""Private scheduling RPC beside the existing authenticated admission owner."""

import httpx

from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .competition_cohort_window_owner import CohortWindowOwner, WindowOperation, WindowResult
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes

WINDOW_PATH = "/internal/cohorts/miner-windows"
MAX_WINDOW_REQUEST_BYTES = 16 * 1024**2 + 128 * 1024


class LocalWindowClient:
    maximum_bytes = 4096

    def __init__(self, owner: CohortWindowOwner, *, timeout_seconds=2400):
        self.owner, self.timeout_seconds = owner, timeout_seconds

    async def respond(self, request: WindowOperation) -> bytes:
        return canonical_json_bytes(await run_owned_thread(self.owner.apply, request))

    async def reserve(self, grant, request):
        return await self._apply(grant, request)

    async def retire(self, grant, request, receipt):
        return await self._apply(grant, request, receipt)

    async def _apply(self, grant, request, receipt=None):
        operation = WindowOperation(
            schema="umi-cohort-window-operation/1", grant=grant, request=request, retirement=receipt
        )
        return (await run_owned_thread(self.owner.apply, operation)).status


def window_routes(client: LocalWindowClient, *, token: str):
    return phase_review_routes(
        client,
        token=token,
        path=WINDOW_PATH,
        request_model=WindowOperation,
        maximum_request_bytes=MAX_WINDOW_REQUEST_BYTES,
        concurrency=8,
    )


class RemoteWindowClient:
    def __init__(self, client: httpx.AsyncClient, origin: str, *, token: str, timeout_seconds=2400):
        self.exchange = PhaseReviewHTTPClient(
            client,
            origin,
            token=token,
            path=WINDOW_PATH,
            maximum_bytes=4096,
            maximum_request_bytes=MAX_WINDOW_REQUEST_BYTES,
            timeout_seconds=timeout_seconds,
        )

    async def reserve(self, grant, request):
        return await self._apply(grant, request)

    async def retire(self, grant, request, receipt):
        return await self._apply(grant, request, receipt)

    async def _apply(self, grant, request, receipt=None):
        operation = WindowOperation(
            schema="umi-cohort-window-operation/1", grant=grant, request=request, retirement=receipt
        )
        raw = await self.exchange(operation)
        result = WindowResult.model_validate_json(raw)
        if canonical_json_bytes(result) != raw or result.operation_sha256 != digest(operation):
            raise ValueError("window owner response differs from the exact scheduling operation")
        if receipt is not None and result.status != "retired":
            raise ValueError("window owner did not retain the signed retirement")
        return result.status
