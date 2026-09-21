"""Authenticated post-cutoff discovery and settlement endorsement delivery."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from typing import Annotated, Literal

import httpx
from fastapi import HTTPException, Request
from pydantic import Field, model_validator
from starlette.responses import Response

from .competition_client import validate_intake_origin
from .competition_settlement_preparation import MAX_PREPARATION_BYTES, SettlementPreparation
from .competition_settlement_signing import IndependentSettlementSigner, SettlementEndorsement
from .nonce import SQLiteNonceStore
from .open_competition import Signature, digest, identity, sign_object, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

ROUTE = "/v1/competition/settlements"
MAX_REQUEST = 16 * 1024
MAX_REPLY = 4 * MAX_PREPARATION_BYTES + 8192


class SettlementQuery(StrictProtocolModel):
    schema_: Literal["umi-settlement-query/1"] = Field(alias="schema")
    policy_sha256: Hex32
    hotkey: str
    nonce_unix_ns: Annotated[str, Field(pattern=r"^[1-9][0-9]{0,18}$")]
    after: Annotated[int, Field(ge=0, le=2**53 - 1)] = 0
    vote: SettlementEndorsement | None = None

    @model_validator(mode="after")
    def parameters(self):
        identity(self.hotkey)
        if int(self.nonce_unix_ns) > 2**63 - 1 or (
            self.vote is not None
            and (self.after != 0 or identity(self.vote.signature.hotkey) != identity(self.hotkey))
        ):
            raise ValueError("settlement query parameters or vote signer differ")
        return self


class SignedSettlementQuery(StrictProtocolModel):
    query: SettlementQuery
    signature: Signature

    @model_validator(mode="after")
    def authenticate(self):
        if identity(self.query.hotkey) != identity(self.signature.hotkey):
            raise ValueError("settlement query signer differs")
        verify_signature(self.query, self.signature)
        return self


class SettlementReply(StrictProtocolModel):
    query_sha256: Hex32
    policy_sha256: Hex32
    cursor: Annotated[int, Field(ge=0, le=2**53 - 1)] = 0
    proposals: Annotated[tuple[SettlementPreparation, ...], Field(max_length=4)] = ()
    accepted_publication_sha256: Hex32 | None = None
    chain_submission_authorized: Literal[False] = False


def attach_settlement_route(app, queue):
    policy = queue.policy
    nonces = SQLiteNonceStore(
        queue.journal.root / "settlement-nonces.sqlite3",
        allowed_hotkeys=[e.hotkey for e in policy.evaluators],
        maximum_nonces_per_hotkey=256,
        maximum_total_nonces=256 * len(policy.evaluators),
        maximum_database_bytes=16 * 1024**2,
    )
    capacity = asyncio.Semaphore(2)

    @app.post(ROUTE)
    async def control(request: Request):
        acquired = False
        try:
            await asyncio.wait_for(capacity.acquire(), timeout=0.1)
            acquired = True
            if request.headers.get("content-encoding", "identity") != "identity" or (
                request.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or sum(len(k) + len(v) for k, v in request.scope["headers"]) > 8192
            ):
                raise HTTPException(400, "settlement request rejected")

            async def read():
                raw = bytearray()
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > MAX_REQUEST:
                        raise HTTPException(413, "settlement request byte limit")
                    raw.extend(chunk)
                return bytes(raw)

            raw = await asyncio.wait_for(read(), timeout=10)
            try:
                signed = SignedSettlementQuery.model_validate_json(raw)
            except ValueError:
                raise HTTPException(401, "settlement authentication rejected") from None
            q, now = signed.query, time.time_ns()
            if (
                raw != canonical_json_bytes(signed)
                or q.policy_sha256 != digest(policy)
                or identity(q.hotkey) not in {identity(e.hotkey) for e in policy.evaluators}
                or not now - 30_000_000_000 <= int(q.nonce_unix_ns) <= now + 5_000_000_000
                or not nonces.check_and_store(q.hotkey, int(q.nonce_unix_ns))
            ):
                raise HTTPException(401, "settlement authentication rejected")
            if q.vote is None:
                cursor, proposals = await asyncio.wait_for(
                    queue.pending(q.hotkey, after=q.after), timeout=25
                )
                reply = SettlementReply(
                    query_sha256=digest(q),
                    policy_sha256=digest(policy),
                    cursor=cursor,
                    proposals=proposals,
                )
            else:
                accepted = await asyncio.wait_for(queue.accept(q.vote), timeout=25)
                reply = SettlementReply(
                    query_sha256=digest(q),
                    policy_sha256=digest(policy),
                    accepted_publication_sha256=accepted,
                )
            body = canonical_json_bytes(reply)
            if len(body) > MAX_REPLY:
                raise ValueError("settlement reply exceeds its byte bound")
            return Response(
                body, media_type="application/json", headers={"Cache-Control": "no-store"}
            )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, "settlement queue unavailable or request rejected") from None
        finally:
            if acquired:
                capacity.release()


async def request_settlement(origin, signed, *, transport=None):
    origin = validate_intake_origin(origin)
    signed = SignedSettlementQuery.model_validate_json(canonical_json_bytes(signed))
    raw = canonical_json_bytes(signed)
    if len(raw) > MAX_REQUEST:
        raise ValueError("settlement query exceeds byte limit")

    async def fetch():
        async with (
            httpx.AsyncClient(
                transport=transport,
                timeout=httpx.Timeout(30, connect=5),
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream(
                "POST",
                origin + ROUTE,
                content=raw,
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
            ) as response,
        ):
            if response.status_code != 200 or (
                response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise ValueError("settlement request rejected")
            result = bytearray()
            async for chunk in response.aiter_bytes():
                if len(result) + len(chunk) > MAX_REPLY:
                    raise ValueError("settlement reply exceeds byte limit")
                result.extend(chunk)
            return bytes(result)

    try:
        raw = await asyncio.wait_for(fetch(), timeout=35)
    except (httpx.HTTPError, asyncio.TimeoutError):
        raise ValueError("settlement request failed") from None
    reply = SettlementReply.model_validate_json(raw)
    q = signed.query
    if (
        raw != canonical_json_bytes(reply)
        or reply.query_sha256 != digest(q)
        or reply.policy_sha256 != q.policy_sha256
    ):
        raise ValueError("settlement reply binding mismatch")
    if q.vote is None:
        if reply.accepted_publication_sha256 is not None or (
            reply.cursor < q.after
            or (reply.proposals and reply.cursor == q.after)
            or len({digest(p) for p in reply.proposals}) != len(reply.proposals)
            or any(
                not q.after < p.publication.round.sequence <= reply.cursor for p in reply.proposals
            )
        ):
            raise ValueError("settlement discovery cursor or reply kind mismatch")
    elif (
        reply.proposals
        or reply.cursor
        or reply.accepted_publication_sha256 != q.vote.publication_sha256
    ):
        raise ValueError("settlement endorsement acknowledgment mismatch")
    return reply


class SettlementSigningClient:
    def __init__(self, worker, origin, cutoff_journal, review_store, *, limits, transport=None):
        self.worker, self.origin = worker, validate_intake_origin(origin)
        self.transport = transport
        self.signer = IndependentSettlementSigner(
            worker, cutoff_journal, review_store, limits=limits
        )
        self.signer.journal.put("source", "origin", {"origin": self.origin})
        self.cursor = self.nonce = 0

    async def query(self, **fields):
        self.nonce = max(self.nonce + 1, time.time_ns())
        query = SettlementQuery(
            schema="umi-settlement-query/1",
            policy_sha256=digest(self.worker.policy),
            hotkey=self.worker.config.evaluator_hotkey,
            nonce_unix_ns=str(self.nonce),
            **fields,
        )
        return await request_settlement(
            self.origin,
            SignedSettlementQuery(query=query, signature=sign_object(query, self.worker.wallet)),
            transport=self.transport,
        )

    async def sync_once(self):
        counts = {"endorsed": 0, "held": 0}
        reply = await self.query(after=self.cursor)
        if not reply.proposals and reply.cursor == self.cursor and self.cursor:
            self.cursor = 0
            reply = await self.query(after=0)
        for prepared in reply.proposals:
            try:
                vote = await self.signer.endorse(prepared)
                await self.query(vote=vote)
                counts["endorsed"] += 1
            except (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError):
                counts["held"] += 1
        self.cursor = reply.cursor
        return counts
