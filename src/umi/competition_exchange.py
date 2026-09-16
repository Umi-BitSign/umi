"""Private hotkey-authenticated delivery of evaluator orders and retained evidence.

The relay has no wallet. Orders already require an independent quorum; reveals
are released only after an owned finalized boundary. TLS and durable cursors
provide transport, never independent publication timing or weight authority.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Annotated, Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import Field, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response

from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from .competition_client import validate_intake_origin
from .competition_endpoint_execution import EndpointPairedEvidence
from .competition_evaluator import (
    MAX_BYTES,
    Directory,
    EvaluationVote,
    SignedEvaluationOrder,
    SignedExecutionAnnouncement,
    _private,
    _publish,
    _read,
    order_job,
    validate_order,
)
from .competition_evidence import (
    IndependentEvaluationEvidence,
    replay_independent_evaluation,
    verify_evaluator_run,
)
from .competition_execution import execution_boundary, execution_key
from .competition_observations import execution_observations
from .competition_void import (
    AttestedEvaluationVoid,
    EvaluationVoidVote,
    VoidEvaluationEvidence,
    propose_evaluation_void,
    verify_evaluation_void,
)
from .nonce import SQLiteNonceStore
from .open_competition import (
    CompetitionPolicy,
    EvaluationSuite,
    Hex32,
    Hotkey,
    Signature,
    digest,
    identity,
    sign_object,
    verify_signature,
)
from .policy import scoring_policy_hash
from .protocol import StrictProtocolModel, canonical_json_bytes

Kind = Literal["order", "suite", "execution", "vote", "independent", "void_vote", "void"]
MODELS = {
    "order": SignedEvaluationOrder,
    "suite": EvaluationSuite,
    "execution": SignedExecutionAnnouncement,
    "vote": EvaluationVote,
    "independent": IndependentEvaluationEvidence,
    "void_vote": EvaluationVoidVote,
    "void": AttestedEvaluationVoid,
}
MAX_WIRE_BYTES = MAX_BYTES + 8192
ROUTE = "/v1/competition/evaluators/exchange"


class ExchangeConfig(StrictProtocolModel):
    schema_: Literal["umi-evaluator-exchange-config/1"] = Field(alias="schema")
    policy_sha256: Hex32
    chain: CompetitionChainConfig
    state_directory: Directory
    order_directory: Directory
    reveal_directory: Directory
    intake_directory: Directory | None = None
    legacy_policy_sha256: Hex32 | None = None
    maximum_orders: Annotated[int, Field(ge=1, le=65536)] = 1024
    maximum_events: Annotated[int, Field(ge=1, le=262144)] = 65536
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: Annotated[int, Field(ge=1024, le=65535)] = 8100
    no_weight: Literal[True] = True

    @model_validator(mode="after")
    def bindings(self):
        paths = [
            Path(p).resolve()
            for p in (
                self.state_directory,
                self.order_directory,
                self.reveal_directory,
                self.intake_directory,
                self.chain.state_directory,
            )
            if p is not None
        ]
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("exchange directories must not overlap")
        if (
            self.chain.policy_sha256 != self.policy_sha256
            or self.chain.collection_timeout_seconds > 15
        ):
            raise ValueError("exchange requires a matching bounded owned-finality provider")
        return self


class ExchangeQuery(StrictProtocolModel):
    schema_: Literal["umi-evaluator-exchange-query/1"] = Field(alias="schema")
    policy_sha256: Hex32
    hotkey: Hotkey
    nonce_unix_ns: Annotated[str, Field(pattern=r"^[1-9][0-9]{0,18}$")]
    operation: Literal["list", "item", "put"]
    after: Annotated[int, Field(ge=0, le=2**53 - 1)] = 0
    event: Annotated[int, Field(ge=1, le=2**53 - 1)] | None = None
    order_sha256: Hex32 | None = None
    kind: Literal["execution", "vote", "independent", "void_vote", "void"] | None = None
    payload_sha256: Hex32 | None = None

    @model_validator(mode="after")
    def parameters(self):
        if int(self.nonce_unix_ns) > 2**63 - 1:
            raise ValueError("exchange nonce exceeds integer bound")
        upload = (self.order_sha256, self.kind, self.payload_sha256)
        if self.operation == "put":
            valid = all(v is not None for v in upload) and self.event is None and self.after == 0
        elif self.operation == "item":
            valid = self.event is not None and self.after == 0 and all(v is None for v in upload)
        else:
            valid = self.event is None and all(v is None for v in upload)
        if not valid:
            raise ValueError("exchange query has mixed operation parameters")
        return self


class ExchangeRequest(StrictProtocolModel):
    query: ExchangeQuery
    signature: Signature
    payload: dict | None = None

    @model_validator(mode="after")
    def authenticate(self):
        if identity(self.query.hotkey) != identity(self.signature.hotkey):
            raise ValueError("exchange query signer mismatch")
        verify_signature(self.query, self.signature)
        if (self.payload is None) != (self.query.operation != "put"):
            raise ValueError("exchange payload does not match the operation")
        if self.payload is not None and digest(self.payload) != self.query.payload_sha256:
            raise ValueError("exchange payload digest mismatch")
        return self


class ExchangeEvent(StrictProtocolModel):
    event: Annotated[int, Field(ge=1, le=2**53 - 1)]
    order_sha256: Hex32
    kind: Kind
    author: Hex32 | None = None
    payload_sha256: Hex32
    observed_block: Annotated[int, Field(ge=0, le=2**53 - 1)]


class ExchangeReply(StrictProtocolModel):
    query_sha256: Hex32
    policy_sha256: Hex32
    items: Annotated[tuple[ExchangeEvent, ...], Field(max_length=16)] = ()
    payload: dict | None = None
    head: Annotated[int, Field(ge=0, le=2**53 - 1)]
    chain_submission_authorized: Literal[False] = False


def validate_payload(kind, payload, signed, author, suite, policy, legacy, block):
    """Replay uploads before storage; receiving clients repeat this check."""
    order = signed.order
    value = MODELS[kind].model_validate_json(canonical_json_bytes(payload))
    if kind in {"order", "suite"}:
        raise ValueError("network peers cannot publish orders or reveals")
    if author not in {identity(k) for k in order.evaluators}:
        raise ValueError("evidence author is not assigned this order")
    if not order.round.reveal_block <= block <= order.round.valid_through_block:
        raise ValueError("evidence transport outside the round window")
    if kind == "execution":
        body = value.announcement
        verify_signature(body, value.signature)
        if (
            body.order_sha256 != digest(order)
            or identity(body.evaluator_hotkey) != author
            or identity(value.signature.hotkey) != author
        ):
            raise ValueError("execution announcement binding mismatch")
        if isinstance(body.evidence, EndpointPairedEvidence) and (
            body.evidence.publication != order.publication or body.evidence.legacy_policy != legacy
        ):
            raise ValueError("execution changes the exact assigned endpoint publication")
        view = execution_observations(body.evidence, suite, policy, current_block=block)
        if view["job"] != order_job(order, body.evaluator_hotkey, policy, legacy):
            raise ValueError("execution differs from the authorized order")
    elif kind == "vote":
        verify_signature(value.result, value.result_signature)
        verify_evaluator_run(value.run)
        if (
            value.order_sha256 != digest(order)
            or identity(value.result_signature.hotkey) != author
            or identity(value.run.signature.hotkey) != author
            or value.result.round_sha256 != digest(order.round)
            or value.result.submission_sha256 != digest(order.submission.submission)
        ):
            raise ValueError("vote signer or result binding mismatch")
        # Agreement with retained execution is enforced by each evaluator.
    elif kind == "void_vote":
        verify_signature(value.void, value.signature)
        expected = propose_evaluation_void(
            signed_order=signed,
            observations=value.void.observations,
            suite=suite,
            policy=policy,
            legacy=legacy,
            current_block=block,
        )
        if identity(value.signature.hotkey) != author or value.void != expected:
            raise ValueError("void vote signer or observation binding mismatch")
    elif kind == "void":
        verify_evaluation_void(
            value,
            signed_order=signed,
            suite=suite,
            policy=policy,
            legacy=legacy,
            current_block=block,
        )
    else:
        replay_independent_evaluation(
            value, order.submission, order.round, suite, policy, current_block=block
        )
    return value


class ExchangeJournal:
    """Append-only event delivery with explicit byte/row ceilings and audiences."""

    def __init__(self, config, policy, legacy=None):
        self.config = ExchangeConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.legacy = legacy
        if (
            digest(policy) != config.policy_sha256
            or (legacy is None) != (config.legacy_policy_sha256 is None)
            or (legacy is not None and scoring_policy_hash(legacy) != config.legacy_policy_sha256)
        ):
            raise ValueError("exchange policy binding mismatch")
        root = Path(config.state_directory)
        _private(root)
        self.path = root / "exchange.sqlite3"
        self._check_files()
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS binding (body BLOB NOT NULL)")
            binding = canonical_json_bytes(
                config.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude={"maximum_orders", "maximum_events", "maximum_bytes", "port", "host"},
                )
            )
            old = db.execute("SELECT body FROM binding").fetchall()
            if old and (len(old) != 1 or bytes(old[0][0]) != binding):
                raise ValueError("exchange configuration changed")
            if not old:
                db.execute("INSERT INTO binding VALUES (?)", (binding,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "order_id TEXT NOT NULL, kind TEXT NOT NULL, author TEXT NOT NULL, "
                "sha TEXT NOT NULL, body BLOB NOT NULL, block INTEGER NOT NULL, "
                "UNIQUE(order_id,kind,author,sha))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS audience (order_id TEXT NOT NULL, "
                "account TEXT NOT NULL, PRIMARY KEY(order_id,account))"
            )
            db.execute("CREATE TABLE IF NOT EXISTS collected (event INTEGER PRIMARY KEY)")
            db.execute("CREATE TABLE IF NOT EXISTS highwater (block INTEGER NOT NULL)")
        self._seen = set()
        self._cursor = ""
        self._collect_cursor = 0

    def _check_files(self):
        _private(self.path.parent)
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = Path(str(self.path) + suffix)
            if path.is_symlink():
                raise ValueError("exchange database symlink")
            if path.exists():
                info = path.stat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                ):
                    raise ValueError("exchange database must be private and owned")

    @contextmanager
    def transaction(self):
        self._check_files()
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "PRAGMA max_page_count=" + str((self.config.maximum_bytes + 64 * 1024**2) // 4096)
            )
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def observe(self, block):
        with self.transaction() as db:
            prior = db.execute("SELECT block FROM highwater").fetchall()
            if (
                type(block) is not int
                or not self.policy.valid_from_block <= block <= self.policy.valid_through_block
                or (prior and (len(prior) != 1 or block < prior[0][0]))
            ):
                raise ValueError("exchange finalized boundary is invalid or regressed")
            db.execute("DELETE FROM highwater")
            db.execute("INSERT INTO highwater VALUES (?)", (block,))

    def append(self, order, kind, author, value, block):
        raw, sha = canonical_json_bytes(value), digest(value)
        with self.transaction() as db:
            old = db.execute(
                "SELECT id FROM events WHERE order_id=? AND kind=? AND author=? AND sha=?",
                (order, kind, author or "", sha),
            ).fetchone()
            if old:
                return old[0]
            count, size = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0) FROM events"
            ).fetchone()
            if (
                count >= self.config.maximum_events
                or size + len(raw) > self.config.maximum_bytes
                or len(raw) > MAX_BYTES
            ):
                raise ValueError("exchange retention capacity exhausted")
            if kind == "order":
                if (
                    db.execute("SELECT COUNT(*) FROM events WHERE kind='order'").fetchone()[0]
                    >= self.config.maximum_orders
                ):
                    raise ValueError("exchange order capacity exhausted")
                # A protected suite cannot be scheduled again after its first
                # reveal. Distinct submissions in the same round share it.
                for (old_body,) in db.execute("SELECT body FROM events WHERE kind='order'"):
                    old_round = SignedEvaluationOrder.model_validate_json(old_body).order.round
                    if (
                        old_round.suite_sha256 == value.order.round.suite_sha256
                        and old_round != value.order.round
                    ):
                        raise ValueError("protected suite cannot be reused across rounds")
                db.executemany(
                    "INSERT OR IGNORE INTO audience VALUES (?,?)",
                    ((order, identity(k)) for k in value.order.evaluators),
                )
            row = db.execute(
                "INSERT INTO events(order_id,kind,author,sha,body,block) VALUES (?,?,?,?,?,?)",
                (order, kind, author or "", sha, raw, block),
            )
            return row.lastrowid

    def object(self, order, kind):
        with self.transaction() as db:
            rows = db.execute(
                "SELECT body FROM events WHERE order_id=? AND kind=? ORDER BY id LIMIT 2",
                (order, kind),
            ).fetchall()
        if len(rows) != 1:
            raise ValueError("exchange object absent or ambiguous")
        return MODELS[kind].model_validate_json(rows[0][0])

    def ingest(self, block):
        """Bounded local input discovery; withheld reveals never consume a cursor."""
        root = Path(self.config.order_directory)
        _private(root)
        with os.scandir(root) as entries:
            names = []
            for entry in entries:
                if len(names) >= self.config.maximum_orders:
                    raise ValueError("exchange order inbox exceeds its capacity")
                names.append(entry.name)
        pending = sorted(n for n in names if n.endswith(".json") and n not in self._seen)
        for name in ([n for n in pending if n > self._cursor] or pending)[:4]:
            self._cursor = name
            try:
                signed = validate_order(
                    _read(root / name, SignedEvaluationOrder), self.policy, self.legacy
                )
                if name != digest(signed.order) + ".json":
                    raise ValueError("order filename mismatch")
                self.append(digest(signed.order), "order", None, signed, block)
                self._seen.add(name)
            except (OSError, ValueError):
                # A broken new file cannot prevent existing orders advancing.
                continue
        with self.transaction() as db:
            orders = db.execute(
                "SELECT order_id,body FROM events e WHERE kind='order' AND NOT EXISTS "
                "(SELECT 1 FROM events s WHERE s.order_id=e.order_id AND s.kind='suite') "
                "ORDER BY id LIMIT ?",
                (self.config.maximum_orders,),
            ).fetchall()
        released = 0
        for order_id, raw in orders:
            order = SignedEvaluationOrder.model_validate_json(raw).order
            if block < order.round.reveal_block:
                continue
            if released >= 4:
                break
            try:
                suite = _read(
                    Path(self.config.reveal_directory) / (order.round.suite_sha256 + ".json"),
                    EvaluationSuite,
                )
                if (
                    digest(suite) != order.round.suite_sha256
                    or suite.policy_sha256 != digest(self.policy)
                    or tuple((c.case_id, c.video_sha256, c.stratum) for c in suite.cases)
                    != tuple((c.case_id, c.video_sha256, c.stratum) for c in order.cases)
                ):
                    raise ValueError("reveal differs from the committed case suite")
                self.append(order_id, "suite", None, suite, block)
                released += 1
            except (OSError, ValueError):
                continue

    def delivery(self, query):
        with self.transaction() as db:
            head = db.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
            if query.after > head:
                raise ValueError("exchange cursor exceeds retained history")
            sql = (
                "SELECT e.id,e.order_id,e.kind,e.author,e.sha,e.block,e.body FROM events e "
                "JOIN audience a ON a.order_id=e.order_id WHERE a.account=? "
            )
            if query.operation == "item":
                rows = db.execute(
                    sql + "AND e.id=?", (identity(query.hotkey), query.event)
                ).fetchall()
                if len(rows) != 1:
                    raise ValueError("exchange item unavailable")
            else:
                rows = db.execute(
                    sql + "AND e.id>? ORDER BY e.id LIMIT 16", (identity(query.hotkey), query.after)
                ).fetchall()
        items = tuple(
            ExchangeEvent(
                event=r[0],
                order_sha256=r[1],
                kind=r[2],
                author=r[3] or None,
                payload_sha256=r[4],
                observed_block=r[5],
            )
            for r in rows
        )
        return ExchangeReply(
            query_sha256=digest(query),
            policy_sha256=digest(self.policy),
            items=items,
            head=head,
            payload=json.loads(rows[0][6]) if query.operation == "item" else None,
        )

    def upload(self, request, block):
        query = request.query
        order = self.object(query.order_sha256, "order")
        suite = self.object(query.order_sha256, "suite")
        with self.transaction() as db:
            prior = db.execute(
                "SELECT block FROM events WHERE order_id=? AND kind=? AND author=? AND sha=?",
                (query.order_sha256, query.kind, identity(query.hotkey), query.payload_sha256),
            ).fetchone()
        # An uncertain HTTP response may be retried after expiry. A previously
        # retained identical upload keeps its original observation, never a new
        # result or renewed round authority.
        original_block = block if prior is None else prior[0]
        value = validate_payload(
            query.kind,
            request.payload,
            order,
            identity(query.hotkey),
            suite,
            self.policy,
            self.legacy,
            original_block,
        )
        event = self.append(
            query.order_sha256, query.kind, identity(query.hotkey), value, original_block
        )
        return self.delivery(
            ExchangeQuery(
                schema="umi-evaluator-exchange-query/1",
                policy_sha256=query.policy_sha256,
                hotkey=query.hotkey,
                nonce_unix_ns=query.nonce_unix_ns,
                operation="item",
                event=event,
            )
        ).model_copy(update={"query_sha256": digest(query), "payload": None})

    def collect(self, store, *, observed_block):
        """Repair delivery to an already admitted/closed coordinator round."""
        with self.transaction() as db:
            rows = db.execute(
                "SELECT id,order_id,body,kind FROM events WHERE kind IN ('independent','void') "
                "AND id NOT IN (SELECT event FROM collected) AND id>? ORDER BY id LIMIT 16",
                (self._collect_cursor,),
            ).fetchall()
            if not rows and self._collect_cursor:
                self._collect_cursor = 0
                return
        for event, order_id, raw, kind in rows:
            self._collect_cursor = event
            try:
                signed = self.object(order_id, "order")
                suite = self.object(order_id, "suite")
                # The relay's earlier receipt is not the coordinator's receipt.
                # Delayed collection must retain its actual owned arrival block.
                if kind == "void":
                    store.record_void_evaluation(
                        evidence=VoidEvaluationEvidence(
                            schema="umi-competition-void-evidence/1",
                            order=signed,
                            certificate=AttestedEvaluationVoid.model_validate_json(raw),
                            legacy_policy=self.legacy,
                        ),
                        suite=suite,
                        observed_block=observed_block,
                    )
                else:
                    store.record_independent_evaluation(
                        signed=signed.order.submission,
                        evidence=IndependentEvaluationEvidence.model_validate_json(raw),
                        round_=signed.order.round,
                        suite=suite,
                        observed_block=observed_block,
                    )
            except ValueError:
                continue
            with self.transaction() as db:
                db.execute("INSERT OR IGNORE INTO collected VALUES (?)", (event,))


def create_exchange_app(
    config, policy, *, legacy=None, provider_factory=FinalizedRegistrationProvider
):
    config = ExchangeConfig.model_validate_json(canonical_json_bytes(config))
    journal = ExchangeJournal(config, policy, legacy)
    policy = journal.policy
    provider = provider_factory(config.chain, policy)
    nonces = SQLiteNonceStore(
        Path(config.state_directory) / "nonces.sqlite3",
        allowed_hotkeys=[e.hotkey for e in policy.evaluators],
        maximum_nonces_per_hotkey=256,
        maximum_total_nonces=256 * len(policy.evaluators),
        maximum_database_bytes=16 * 1024**2,
    )
    store = None
    if config.intake_directory is not None:
        from .competition_store import CompetitionStore

        store = CompetitionStore(Path(config.intake_directory), policy)

    @asynccontextmanager
    async def lifespan(_app):
        try:
            await provider.start()
            yield
        finally:
            await provider.aclose()

    app = FastAPI(
        title="UMI evaluator exchange",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.finality_providers = (provider,)
    capacity = asyncio.Semaphore(2)
    serial = asyncio.Lock()

    @app.post(ROUTE)
    async def exchange(request: Request):
        acquired = False
        try:
            try:
                await asyncio.wait_for(capacity.acquire(), timeout=0.1)
                acquired = True
            except asyncio.TimeoutError:
                raise HTTPException(503, "exchange busy") from None
            if (
                request.headers.get("content-encoding", "identity") != "identity"
                or request.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or sum(len(k) + len(v) for k, v in request.scope["headers"]) > 8192
            ):
                raise HTTPException(400, "exchange request rejected")

            async def read_body():
                raw = bytearray()
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > MAX_WIRE_BYTES:
                        raise HTTPException(413, "exchange byte limit")
                    raw.extend(chunk)
                return bytes(raw)

            raw = await asyncio.wait_for(read_body(), timeout=10)
            try:
                signed = ExchangeRequest.model_validate_json(raw)
            except ValueError:
                raise HTTPException(401, "exchange authentication rejected") from None
            if raw != canonical_json_bytes(signed):
                raise HTTPException(401, "exchange request rejected")
            q = signed.query
            now = time.time_ns()
            if (
                q.policy_sha256 != digest(policy)
                or identity(q.hotkey) not in {identity(e.hotkey) for e in policy.evaluators}
                or not now - 30_000_000_000 <= int(q.nonce_unix_ns) <= now + 5_000_000_000
            ):
                raise HTTPException(401, "exchange authentication rejected")
            if not await run_in_threadpool(nonces.check_and_store, q.hotkey, int(q.nonce_unix_ns)):
                raise HTTPException(401, "exchange nonce rejected")
            async with serial:
                block = execution_boundary(
                    await asyncio.wait_for(provider.collect(), timeout=20)
                ).block
                await run_in_threadpool(journal.observe, block)
                await run_in_threadpool(journal.ingest, block)
                result = (
                    await run_in_threadpool(journal.upload, signed, block)
                    if q.operation == "put"
                    else await run_in_threadpool(journal.delivery, q)
                )
                if store is not None:
                    await run_in_threadpool(journal.collect, store, observed_block=block)
            body = canonical_json_bytes(result)
            if len(body) > MAX_WIRE_BYTES:
                raise ValueError("exchange reply too large")
            return Response(
                body, media_type="application/json", headers={"Cache-Control": "no-store"}
            )
        except HTTPException:
            raise
        except Exception:
            # Neither wallet data nor private model responses enter HTTP errors.
            raise HTTPException(503, "exchange unavailable or request rejected") from None
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


class ExchangeUnavailableError(ValueError):
    """A transport failure can be retried without changing retained work."""


async def request_exchange(origin, signed, *, transport=None):
    origin = validate_intake_origin(origin)
    signed = ExchangeRequest.model_validate_json(canonical_json_bytes(signed))
    raw = canonical_json_bytes(signed)
    if len(raw) > MAX_WIRE_BYTES:
        raise ValueError("exchange request too large")

    async def fetch():
        async with (
            httpx.AsyncClient(
                transport=transport,
                timeout=httpx.Timeout(45, connect=5),
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
            if (
                response.status_code != 200
                or response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise ValueError("exchange request rejected")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(data) + len(chunk) > MAX_WIRE_BYTES:
                    raise ValueError("exchange reply too large")
                data.extend(chunk)
            return bytes(data)

    try:
        raw = await asyncio.wait_for(fetch(), timeout=50)
    except asyncio.TimeoutError:
        raise ExchangeUnavailableError("exchange request timed out") from None
    except httpx.HTTPError:
        raise ExchangeUnavailableError("exchange transport unavailable") from None
    reply = ExchangeReply.model_validate_json(raw)
    if (
        raw != canonical_json_bytes(reply)
        or reply.query_sha256 != digest(signed.query)
        or reply.policy_sha256 != signed.query.policy_sha256
    ):
        raise ValueError("exchange reply binding mismatch")
    return reply


class EvaluatorExchangeClient:
    """Attached to one evaluator; immutable journal entries precede cursor advance."""

    def __init__(self, worker, origin, *, transport=None):
        self.worker, self.origin, self.transport = worker, validate_intake_origin(origin), transport
        with worker.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS exchange_delivery "
                "(name TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            old = db.execute("SELECT value FROM exchange_delivery WHERE name='origin'").fetchone()
            if old and old[0] != self.origin:
                raise ValueError("evaluator exchange origin changed")
            db.execute(
                "INSERT OR IGNORE INTO exchange_delivery VALUES ('origin',?)", (self.origin,)
            )
        self._upload_cursor = ""
        self._upload_audit_cursor = ""
        self._nonce = 0

    async def query(self, operation, *, payload=None, **fields):
        w = self.worker
        self._nonce = max(time.time_ns(), self._nonce + 1)
        q = ExchangeQuery(
            schema="umi-evaluator-exchange-query/1",
            policy_sha256=digest(w.policy),
            hotkey=w.config.evaluator_hotkey,
            nonce_unix_ns=str(self._nonce),
            operation=operation,
            **fields,
        )
        signed = ExchangeRequest(query=q, signature=sign_object(q, w.wallet), payload=payload)
        return await request_exchange(self.origin, signed, transport=self.transport)

    async def sync_once(self):
        w = self.worker
        with w.journal.transaction() as db:
            row = db.execute("SELECT value FROM exchange_delivery WHERE name='cursor'").fetchone()
            cursor = int(row[0]) if row else 0
        listing = await self.query("list", after=cursor)
        if (
            listing.payload is not None
            or listing.head < cursor
            or any(e.event <= cursor or e.event > listing.head for e in listing.items)
            or [e.event for e in listing.items] != sorted(set(e.event for e in listing.items))
        ):
            raise ValueError("exchange list cursor mismatch")
        for event in listing.items[: w.config.page_size]:
            reply = await self.query("item", event=event.event)
            if (
                reply.items != (event,)
                or reply.payload is None
                or digest(reply.payload) != event.payload_sha256
            ):
                raise ValueError("exchange event payload mismatch")
            await self.install(event, reply.payload)
            with w.journal.transaction() as db:
                db.execute(
                    "INSERT OR REPLACE INTO exchange_delivery VALUES ('cursor',?)",
                    (str(event.event),),
                )
        uploaded = await self.upload_once()
        return {"received": min(len(listing.items), w.config.page_size), "uploaded": uploaded}

    async def install(self, event, payload):
        w = self.worker
        value = MODELS[event.kind].model_validate_json(canonical_json_bytes(payload))
        if event.kind == "order":
            signed = validate_order(value, w.policy, w.legacy)
            if (
                digest(signed.order) != event.order_sha256
                or identity(w.config.evaluator_hotkey)
                not in {identity(k) for k in signed.order.evaluators}
                or event.author is not None
            ):
                raise ValueError("delivered order identity mismatch")
            slot = execution_key(
                order_job(signed.order, w.config.evaluator_hotkey, w.policy, w.legacy)
            )
            try:
                w.journal.admit(signed, slot)
            except ValueError:
                # A valid conflicting order is retained by admit and held.
                with w.journal.transaction() as db:
                    held = db.execute(
                        "SELECT conflict FROM orders WHERE slot=?", (slot,)
                    ).fetchone()
                if held != (1,):
                    raise
            _publish(Path(w.config.order_directory) / (event.order_sha256 + ".json"), signed)
            if w.config.assignment_directory is not None and signed.order.publication is not None:
                publication = signed.order.publication
                _publish(
                    Path(w.config.assignment_directory)
                    / (digest(publication.publication) + ".json"),
                    publication,
                )
            return
        signed = _read(
            Path(w.config.order_directory) / (event.order_sha256 + ".json"), SignedEvaluationOrder
        )
        slot = execution_key(order_job(signed.order, w.config.evaluator_hotkey, w.policy, w.legacy))
        if event.kind == "suite":
            if (
                event.author is not None
                or digest(value) != signed.order.round.suite_sha256
                or value.policy_sha256 != digest(w.policy)
            ):
                raise ValueError("delivered reveal digest mismatch")
            if (await w.boundary()).block < signed.order.round.reveal_block:
                raise ValueError("delivered reveal is premature")
            _publish(Path(w.config.reveal_directory) / (digest(value) + ".json"), value)
            return
        suite = _read(
            Path(w.config.reveal_directory) / (signed.order.round.suite_sha256 + ".json"),
            EvaluationSuite,
        )
        # The relay's observed block is a transport claim. Current owned state
        # independently gates new signatures in the evaluator, not this cursor.
        value = validate_payload(
            event.kind,
            payload,
            signed,
            event.author,
            suite,
            w.policy,
            w.legacy,
            event.observed_block,
        )
        if event.kind in {"independent", "void"}:
            return
        try:
            w.journal.put(slot, "peer_" + event.kind + ":" + event.author, value)
        except ValueError:
            with w.journal.transaction() as db:
                held = db.execute("SELECT conflict FROM orders WHERE slot=?", (slot,)).fetchone()
            if held != (1,):
                raise
            return
        _publish(
            Path(w.config.peer_directory)
            / f"{event.order_sha256}.{event.author}.{event.kind}.json",
            value,
        )

    async def upload_once(self):
        w = self.worker
        root = Path(w.config.outbox_directory)
        names = []
        with os.scandir(root) as entries:
            for entry in entries:
                if len(names) >= w.config.maximum_orders * 3 + 1:
                    raise ValueError("evaluator outbox capacity exceeded")
                names.append(entry.name)
        names = sorted(n for n in names if n.endswith(".json"))
        with w.journal.transaction() as db:
            markers = db.execute(
                "SELECT name FROM exchange_delivery WHERE name LIKE 'sent:%' LIMIT ?",
                (w.config.maximum_orders * 3 + 1,),
            ).fetchall()
        if len(markers) > w.config.maximum_orders * 3:
            raise ValueError("evaluator delivery marker capacity exceeded")
        delivered = {row[0][5:] for row in markers}
        pending = [name for name in names if name not in delivered]
        retained = [name for name in names if name in delivered]
        # Old acknowledgments must not consume the new-evidence upload budget.
        # Audit a separate bounded page so modified retained files still fail.
        candidates = ([name for name in pending if name > self._upload_cursor] or pending)[
            : w.config.page_size
        ]
        candidates += ([name for name in retained if name > self._upload_audit_cursor] or retained)[
            : w.config.page_size
        ]
        uploaded = 0
        for name in candidates:
            if name in delivered:
                self._upload_audit_cursor = name
            else:
                self._upload_cursor = name
            parts = name.split(".")
            if (
                len(parts) != 4
                or parts[1] != identity(w.config.evaluator_hotkey)
                or parts[2] not in {"execution", "vote", "independent", "void_vote", "void"}
            ):
                raise ValueError("unexpected evaluator outbox name")
            value = _read(root / name, MODELS[parts[2]])
            marker = "sent:" + name
            with w.journal.transaction() as db:
                sent = db.execute(
                    "SELECT value FROM exchange_delivery WHERE name=?", (marker,)
                ).fetchone()
            if sent:
                if sent[0] != digest(value):
                    raise ValueError("previously delivered evaluator output changed")
                continue
            if name in delivered:
                raise ValueError("previously delivered evaluator marker disappeared")
            reply = await self.query(
                "put",
                payload=value.model_dump(mode="json", by_alias=True),
                order_sha256=parts[0],
                kind=parts[2],
                payload_sha256=digest(value),
            )
            if len(reply.items) != 1 or (
                reply.items[0].order_sha256,
                reply.items[0].kind,
                reply.items[0].author,
                reply.items[0].payload_sha256,
            ) != (parts[0], parts[2], parts[1], digest(value)):
                raise ValueError("exchange upload acknowledgment mismatch")
            with w.journal.transaction() as db:
                db.execute("INSERT INTO exchange_delivery VALUES (?,?)", (marker, digest(value)))
            uploaded += 1
        return uploaded


def serve_exchange(config, policy, *, legacy=None):
    from .competition_service_supervision import serve_with_finality_supervision

    app = create_exchange_app(config, policy, legacy=legacy)
    serve_with_finality_supervision(
        app, host=config.host, port=config.port, workers=1, access_log=False, log_level="warning"
    )
