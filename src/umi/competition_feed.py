"""Hotkey-authenticated, reference-free assignment discovery; no dispatch or weights.

The HTTPS proxy is an operator deployment requirement. The local server exposes
only assignments already held in the journal. Video URLs are returned only in
an exact signed publication whose entire miner audience is the authenticated
caller. This service never signs publications or loads a wallet.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import Field, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response
from typing_extensions import Self

from .competition_authorization import (
    MAX_AUTHORIZATION_BYTES,
    SignedEndpointAuthorization,
    validate_publication,
)
from .competition_client import validate_intake_origin
from .competition_scheduling import AssignmentPublicationJournal
from .nonce import NonceStoreError, SQLiteNonceStore
from .open_competition import (
    CompetitionPolicy,
    Hex32,
    Hotkey,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .policy import ScoringPolicy
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_QUERY_BYTES = 4096
MAX_QUERY_AGE_NS = 30 * 1_000_000_000
MAX_QUERY_FUTURE_NS = 5 * 1_000_000_000


class AssignmentFeedQuery(StrictProtocolModel):
    schema_: Literal["umi-assignment-feed-query/1"] = Field(alias="schema")
    policy_sha256: Hex32
    miner_hotkey: Hotkey
    nonce_unix_ns: Annotated[str, Field(pattern=r"^[1-9][0-9]{0,18}$")]
    operation: Literal["list", "publication"]
    publication_sha256: Hex32 | None = None
    after: Hex32 | None = None
    limit: Annotated[int, Field(ge=1, le=100)] = 20
    include_history: bool = False

    @model_validator(mode="after")
    def parameters(self) -> Self:
        if self.operation == "publication":
            if self.publication_sha256 is None or self.after is not None or self.include_history:
                raise ValueError("publication retrieval needs only the exact publication digest")
        elif self.publication_sha256 is not None:
            raise ValueError("list query cannot name a publication")
        if int(self.nonce_unix_ns) > 2**63 - 1:
            raise ValueError("feed nonce exceeds its integer bound")
        return self


class SignedAssignmentFeedQuery(StrictProtocolModel):
    query: AssignmentFeedQuery
    signature: Signature

    @model_validator(mode="after")
    def authenticate(self) -> Self:
        if identity(self.query.miner_hotkey) != identity(self.signature.hotkey):
            raise ValueError("feed signer does not control the requested miner identity")
        verify_signature(self.query, self.signature)
        return self


def create_assignment_feed(
    journal: AssignmentPublicationJournal,
    *,
    nonce_path: Path,
    maximum_concurrent_reads: int = 8,
) -> FastAPI:
    if not isinstance(journal, AssignmentPublicationJournal):
        raise TypeError("assignment feed requires the durable scheduling journal")
    if type(maximum_concurrent_reads) is not int or not 1 <= maximum_concurrent_reads <= 32:
        raise ValueError("invalid assignment feed read capacity")
    # Membership is checked from published assignments before any replay state
    # is consumed. That audience grows through signed publications, so it is
    # intentionally not copied into a fixed policy-validator nonce allowlist.
    nonces = SQLiteNonceStore(
        nonce_path,
        retention_seconds=60,
        maximum_nonces_per_hotkey=32,
        maximum_total_nonces=8192,
        maximum_database_bytes=4 * 1024**2,
    )
    app = FastAPI(title="UMI assignment feed", docs_url=None, redoc_url=None, openapi_url=None)
    capacity = asyncio.Semaphore(maximum_concurrent_reads)

    def answer(signed):
        query = signed.query
        if query.policy_sha256 != digest(journal.policy):
            raise HTTPException(401, "assignment query rejected")
        nonce = int(query.nonce_unix_ns)
        now = time.time_ns()
        if not now - MAX_QUERY_AGE_NS <= nonce <= now + MAX_QUERY_FUTURE_NS:
            raise HTTPException(401, "assignment query rejected")
        account = identity(query.miner_hotkey)
        # The membership probe also checks persistent local-clock high-water.
        membership = journal.list_assignments(
            miner_hotkey=query.miner_hotkey,
            limit=1,
            include_history=True,
        )
        if not membership["items"]:
            raise HTTPException(401, "assignment query rejected")
        if not nonces.check_and_store(account, nonce):
            raise HTTPException(401, "assignment query rejected")
        publication = None
        if query.operation == "publication":
            try:
                publication = journal.publication(query.publication_sha256)
            except ValueError as error:
                raise HTTPException(404, "publication unavailable") from error
            audience = {identity(s.submission.hotkey) for s in publication.publication.submissions}
            if audience != {account}:
                raise HTTPException(404, "publication unavailable")
        if publication is not None:
            try:
                publication = journal.releasable_publication(query.publication_sha256)
            except ValueError as error:
                raise HTTPException(409, "publication has no currently releasable work") from error
            status = journal.publication_status(query.publication_sha256)
            # Retrieval never reopens an expired case or promises usable work.
            return {
                "publication": publication.model_dump(mode="json", by_alias=True),
                "status": status,
            }
        return journal.list_assignments(
            miner_hotkey=query.miner_hotkey,
            after=query.after,
            limit=query.limit,
            include_history=query.include_history,
        )

    @app.post("/v1/competition/assignments/query")
    async def query(request: Request):
        acquired = False
        try:
            try:
                await asyncio.wait_for(capacity.acquire(), timeout=0.1)
                acquired = True
            except asyncio.TimeoutError:
                raise HTTPException(503, "assignment feed busy") from None
            if (
                request.headers.get("content-encoding", "identity") != "identity"
                or request.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or sum(len(k) + len(v) for k, v in request.scope["headers"]) > 8192
            ):
                raise HTTPException(400, "assignment query rejected")

            async def read_body():
                chunks = bytearray()
                async for chunk in request.stream():
                    chunks.extend(chunk)
                    if len(chunks) > MAX_QUERY_BYTES:
                        raise HTTPException(413, "assignment query too large")
                return bytes(chunks)

            try:
                raw = await asyncio.wait_for(read_body(), timeout=2)
                signed = SignedAssignmentFeedQuery.model_validate_json(raw)
                if raw != canonical_json_bytes(signed):
                    raise ValueError("noncanonical query")
            except asyncio.TimeoutError:
                raise HTTPException(408, "assignment query timed out") from None
            except ValueError:
                raise HTTPException(401, "assignment query rejected") from None
            try:
                result = await run_in_threadpool(answer, signed)
            except NonceStoreError:
                raise HTTPException(503, "assignment feed replay store unavailable") from None
            except (OSError, ValueError, RuntimeError):
                raise HTTPException(503, "assignment feed unavailable") from None
            result["query_sha256"] = digest(signed.query)
            result["policy_sha256"] = digest(journal.policy)
            body = canonical_json_bytes(result)
            if len(body) > MAX_AUTHORIZATION_BYTES + 2 * 1024**2:
                raise HTTPException(503, "assignment reply exceeds its byte limit")
            return Response(
                body, media_type="application/json", headers={"Cache-Control": "no-store"}
            )
        finally:
            if acquired:
                capacity.release()

    @app.exception_handler(HTTPException)
    async def safe_error(_request, error):
        return JSONResponse(
            {"detail": error.detail},
            status_code=error.status_code,
            headers={"Cache-Control": "no-store"},
        )

    return app


async def query_assignment_feed(
    *,
    origin: str,
    signed: SignedAssignmentFeedQuery,
    policy: CompetitionPolicy,
    legacy_policy: ScoringPolicy,
    transport=None,
) -> dict:
    """Fetch once with an already signed query, verifying returned authorization.

    List entries are TLS-server status claims, not dispatch authority. Exact
    returned publications must also pass the independent signature/mapping gate.
    This function neither installs them into a miner nor sends a translation.
    """
    import httpx

    origin = validate_intake_origin(origin)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    signed = SignedAssignmentFeedQuery.model_validate_json(canonical_json_bytes(signed))
    if signed.query.policy_sha256 != digest(policy):
        raise ValueError("feed query policy mismatch")
    raw = canonical_json_bytes(signed)
    if len(raw) > MAX_QUERY_BYTES:
        raise ValueError("feed query byte limit exceeded")
    nonce = int(signed.query.nonce_unix_ns)
    now = time.time_ns()
    if not now - MAX_QUERY_AGE_NS <= nonce <= now + MAX_QUERY_FUTURE_NS:
        raise ValueError("feed query is not current")

    async def fetch():
        async with (
            httpx.AsyncClient(
                transport=transport,
                timeout=httpx.Timeout(10, connect=5),
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream(
                "POST",
                origin + "/v1/competition/assignments/query",
                content=raw,
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
            ) as response,
        ):
            if (
                response.status_code != 200
                or response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise ValueError("assignment feed rejected or unavailable")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(data) + len(chunk) > MAX_AUTHORIZATION_BYTES + 2 * 1024**2:
                    raise ValueError("assignment reply exceeds byte limit")
                data.extend(chunk)
            return bytes(data)

    try:
        response_bytes = await asyncio.wait_for(fetch(), timeout=15)
    except (httpx.HTTPError, asyncio.TimeoutError) as error:
        raise ValueError("assignment feed request failed") from error
    result = json.loads(response_bytes)
    if (
        not isinstance(result, dict)
        or canonical_json_bytes(result) != response_bytes
        or result.get("query_sha256") != digest(signed.query)
        or result.get("policy_sha256") != digest(policy)
    ):
        raise ValueError("assignment feed reply binding mismatch")
    if signed.query.operation == "publication":
        publication = validate_publication(
            SignedEndpointAuthorization.model_validate_json(
                canonical_json_bytes(result.get("publication"))
            ),
            policy,
            legacy_policy,
        )
        if digest(publication.publication) != signed.query.publication_sha256 or {
            identity(s.submission.hotkey) for s in publication.publication.submissions
        } != {identity(signed.query.miner_hotkey)}:
            raise ValueError("assignment publication digest or audience mismatch")
        status = result.get("status", {})
        if (
            not isinstance(status, dict)
            or status.get("chain_submission_authorized") is not False
            or status.get("publication_timing_proven") is not False
        ):
            raise ValueError("assignment feed claims unsupported authority")
    else:
        if (
            not isinstance(result.get("items"), list)
            or len(result["items"]) > signed.query.limit
            or result.get("chain_submission_authorized") is not False
            or result.get("publication_timing_proven") is not False
            or result.get("no_weight") is not True
        ):
            raise ValueError("assignment list is invalid")
    return result
