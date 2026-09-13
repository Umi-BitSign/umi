"""Continuous endpoint dispatch from a signed journal; no chain weight capability.

Only a durable claim permits fresh request signing. After a claim, cancellation
or an unrecorded result stays uncertain and is never transmitted again. Retained
transport evidence requires independent replay after the protected suite reveal.
"""

from __future__ import annotations

import asyncio
import os
import signal
import stat
import time
from collections import OrderedDict
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .chain_evidence import FinalizedSnapshotRef
from .competition_authorization import (
    MAX_AUTHORIZATION_BYTES,
    SignedEndpointAuthorization,
    validate_publication,
)
from .competition_chain import CompetitionChainConfig
from .competition_endpoint import prepare_endpoint_case
from .competition_origin import EndpointOriginCapture, FinalizedEndpointProvider, public_ip_origin
from .competition_scheduling import AssignmentPublicationJournal, assignment_key
from .config import Limits
from .open_competition import CompetitionPolicy, Hotkey, digest, identity
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator import prepare_request_attempt, send_prepared_request
from .validator_plans import VerifiedFinalizedBlock


class EndpointDispatchConfig(StrictProtocolModel):
    schema_: Literal["umi-endpoint-dispatch-config/1"] = Field(alias="schema")
    policy_sha256: Hex32
    legacy_policy_sha256: Hex32
    chain: CompetitionChainConfig
    journal_directory: Annotated[str, Field(min_length=1, max_length=4096)]
    publication_directory: Annotated[str, Field(min_length=1, max_length=4096)]
    evaluator_hotkey: Hotkey
    wallet_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    hotkey_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    wallet_path: Annotated[str, Field(min_length=1, max_length=4096)]
    poll_seconds: Annotated[int, Field(ge=1, le=30)] = 5
    discovery_grace_seconds: Annotated[int, Field(ge=5, le=60)] = 10
    maximum_concurrency: Annotated[int, Field(ge=1, le=8)] = 4
    page_size: Annotated[int, Field(ge=1, le=100)] = 32
    request_timeout_seconds: Annotated[int, Field(ge=1, le=600)] = 180
    no_weight: Literal[True] = True

    @field_validator("journal_directory", "publication_directory", "wallet_path")
    @classmethod
    def absolute_paths(cls, value):
        path = Path(value)
        if not path.is_absolute() or path == Path(path.anchor) or "\x00" in value:
            raise ValueError("dispatch paths must be explicit non-root absolute paths")
        if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("dispatch paths must not traverse symlinks or parents")
        return value

    @model_validator(mode="after")
    def separate_state(self):
        paths = [
            Path(self.journal_directory).resolve(),
            Path(self.publication_directory).resolve(),
            Path(self.chain.state_directory).resolve(),
            Path(self.wallet_path).resolve(),
        ]
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError(
                "publication, journal, origin verifier and wallet directories must be separate"
            )
        if self.chain.policy_sha256 != self.policy_sha256:
            raise ValueError("dispatch chain configuration belongs to another policy")
        return self

    def check_policies(self, policy, legacy):
        if (
            digest(policy) != self.policy_sha256
            or scoring_policy_hash(legacy) != self.legacy_policy_sha256
        ):
            raise ValueError("dispatch policy binding mismatch")
        pins = legacy.implementation_pins
        if (
            pins.live_chain != self.chain.chain_pin
            or pins.finality_verifier != self.chain.finality_pin
        ):
            raise ValueError("dispatch and transport finality pins must agree")
        evaluator = identity(self.evaluator_hotkey)
        if evaluator not in {identity(e.hotkey) for e in policy.evaluators} or evaluator not in {
            identity(e.validator_hotkey) for e in legacy.validator_registry
        }:
            raise ValueError("dispatch signer must be an evaluator in both policies")
        if self.discovery_grace_seconds >= legacy.clock.issue_allowance_seconds:
            raise ValueError("discovery grace must leave a usable issue window")


@dataclass(frozen=True, slots=True)
class DispatchOrigin:
    capture: EndpointOriginCapture
    observed: VerifiedFinalizedBlock
    issuance: VerifiedFinalizedBlock


class DispatchFinalityProvider(FinalizedEndpointProvider):
    """One owned observer, explicitly bound to the signed transport policy.

    Registration and Axon proofs still use the competition policy. The observer
    creates transport-bound attestations itself; no JSON or relabeled block is
    accepted as a replacement for a verified block.
    """

    def __init__(self, config, policy, legacy_policy, **test_ports):
        self.legacy_policy = ScoringPolicy.model_validate_json(canonical_json_bytes(legacy_policy))
        pins = self.legacy_policy.implementation_pins
        if pins.live_chain != config.chain_pin or pins.finality_verifier != config.finality_pin:
            raise ValueError("origin and transport verifier pins differ")
        super().__init__(config, policy, **test_ports)

    def _finality_policy_hash(self):
        return scoring_policy_hash(self.legacy_policy)

    def _cache_binding_hash(self):
        return digest(
            {"chain": digest(self.config), "transport_policy": self._finality_policy_hash()}
        )

    async def verified_blocks(self, heights=()):
        if (
            not isinstance(heights, tuple)
            or len(heights) > 256
            or any(type(h) is not int or not 1 <= h <= 2**53 - 1 for h in heights)
        ):
            raise ValueError("dispatch requires bounded exact block heights")

        async def collect():
            async with self._lock:
                if self._closed or (self._owned and (self._task is None or self._task.done())):
                    raise ValueError("owned dispatch observer is not running")
                ref = await self._proofs.finalized_snapshot()
                if (
                    not isinstance(ref, FinalizedSnapshotRef)
                    or ref.block_number < self.config.minimum_finalized_block
                    or (self._owned and ref.block_number <= self._startup_floor)
                ):
                    raise ValueError("waiting for a current owned finalized head")
                head = await self._finality.verified_block_at(ref.block_number)
                self._check_finality(ref, head)
                self._fresh(head.timestamp_ms)
                if any(h > head.height for h in heights):
                    raise ValueError("requested issuance has not finalized")
                blocks = []
                for height in heights:
                    block = await self._finality.verified_block_at(height)
                    # Same process-owned source, same pins; old issuance need not be fresh.
                    if not isinstance(block, VerifiedFinalizedBlock) or block.height != height:
                        raise ValueError("owned issuance is unavailable")
                    self._check_finality_context(block)
                    if block.timestamp_ms > head.timestamp_ms:
                        raise ValueError("issuance is newer than the verified head")
                    blocks.append(block)
                return head, tuple(blocks)

        return await asyncio.wait_for(collect(), timeout=self.config.collection_timeout_seconds)

    async def dispatch_origin(self, signed, issued_block):
        capture = await self.collect_origin(signed)
        head, blocks = await self.verified_blocks((capture.block, issued_block))
        observed, issuance = blocks
        if (observed.block_hash, observed.state_root, observed.timestamp_ms) != (
            capture.block_hash,
            capture.state_root,
            capture.timestamp_ms,
        ) or head.height - observed.height > self.policy.maximum_snapshot_age_blocks:
            raise ValueError("dispatch origin proof differs from the owned observation")
        self._fresh(observed.timestamp_ms)
        return DispatchOrigin(capture, observed, issuance)


class EndpointDispatcher:
    def __init__(self, config, journal, provider, wallet, *, transport=None):
        import bittensor as bt

        self.config = EndpointDispatchConfig.model_validate_json(canonical_json_bytes(config))
        self.config.check_policies(journal.policy, journal.legacy_policy)
        if Path(config.journal_directory).resolve() != journal.path.parent.resolve():
            raise ValueError("dispatcher journal path mismatch")
        if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
            config.evaluator_hotkey
        ):
            raise ValueError("dispatcher wallet does not hold the configured evaluator hotkey")
        self.journal, self.provider, self.wallet, self.transport = (
            journal,
            provider,
            wallet,
            transport,
        )
        self.limits = Limits.from_policy(journal.legacy_policy)
        self._cursor = None
        self._ready_since = OrderedDict()
        self._tasks = {}
        self._counts = {"completed": 0, "held": 0, "uncertain": 0}
        self._publications = set()
        self._publication_cursor = None

    async def ingest_once(self):
        """Read one immutable quorum-signed inbox file; errors never retime work.

        The inbox is operator-owned and private. Temporary files are ignored;
        publish by atomically renaming complete bytes to <body-digest>.json.
        It is not an unauthenticated network upload directory.
        """
        directory = Path(self.config.publication_directory)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("publication inbox must be owned and private")
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    if len(names) >= 1024:
                        raise ValueError("publication inbox exceeds its file capacity")
                    names.append(entry.name)
            pending = sorted(
                n for n in names if n.endswith(".json") and n not in self._publications
            )
            after = [
                n
                for n in pending
                if self._publication_cursor is None or n > self._publication_cursor
            ]
            if not pending:
                return "idle"
            name = (after or pending)[0]
            self._publication_cursor = name
            key = name[:-5]
            if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
                raise ValueError("publication filename must be its body digest")
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(file_fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                ):
                    raise ValueError("publication must be an owned private regular file")
                if not 1 <= info.st_size <= MAX_AUTHORIZATION_BYTES:
                    raise ValueError("publication exceeds its byte capacity")
                raw = stream.read(MAX_AUTHORIZATION_BYTES + 1)
            if len(raw) != info.st_size:
                raise ValueError("publication size changed during read")
        finally:
            os.close(fd)
        publication = validate_publication(
            SignedEndpointAuthorization.model_validate_json(raw),
            self.journal.policy,
            self.journal.legacy_policy,
        )
        if canonical_json_bytes(publication) != raw or digest(publication.publication) != key:
            raise ValueError("publication filename or canonical bytes mismatch")
        clock = self.journal.legacy_policy.clock
        activation = self.journal.legacy_policy.activation_block
        announcements = tuple(
            sorted(
                {
                    activation
                    + ((a.request.issued_block - activation) // clock.window_stride_blocks)
                    * clock.window_stride_blocks
                    for a in publication.publication.assignments
                }
            )
        )
        head, blocks = await self.provider.verified_blocks(announcements)
        self.journal.publish(publication, observed=head, announcements=blocks)
        # The journal reserves all outcome space before this file is accepted.
        self._publications.add(name)
        return "retained"

    async def dispatch_one(self, key):
        claimed = False
        try:
            status = self.journal.status(key)
            if status["state"] != "published":
                return "held"
            publication = self.journal.publication(status["publication_sha256"])
            body = publication.publication
            assignment = next(a for a in body.assignments if assignment_key(publication, a) == key)
            if identity(assignment.evaluator_hotkey) != identity(self.config.evaluator_hotkey):
                raise ValueError("assignment belongs to another evaluator")
            heights = tuple(sorted({a.request.issued_block for a in body.assignments}))
            head, issuances = await self.provider.verified_blocks(heights)
            self.journal.observe(observed=head, issuances=issuances)
            # Start grace only when this entire signed publication is retrievable.
            self.journal.releasable_publication(status["publication_sha256"])
            now = time.time_ns() // 1_000_000
            pubkey = status["publication_sha256"]
            if pubkey not in self._ready_since:
                if len(self._ready_since) >= 1024:
                    self._ready_since.popitem(last=False)
                self._ready_since[pubkey] = now
            if now < self._ready_since[pubkey] + self.config.discovery_grace_seconds * 1000:
                return "held"
            signed = next(
                s for s in body.submissions if digest(s.submission) == assignment.submission_sha256
            )
            origin = await self.provider.dispatch_origin(signed, assignment.request.issued_block)
            if not isinstance(origin, DispatchOrigin) or (
                origin.capture.submission_sha256 != digest(signed.submission)
                or identity(origin.capture.hotkey) != identity(signed.submission.hotkey)
                or origin.capture.origin != public_ip_origin(signed.submission.endpoint_url)
            ):
                raise ValueError("dispatch origin binding mismatch")
            claim = self.journal.claim(key, observed=origin.observed, issuance=origin.issuance)
            if claim is None:
                return "held"
            claimed = True
            prepared = prepare_request_attempt(
                assignment.request,
                wallet=self.wallet,
                miner_hotkey=claim.miner_hotkey,
                nonce_ns=time.time_ns(),
            )
            case = next(c for c in body.cases if digest(c) == assignment.case_sha256)
            prepare_endpoint_case(
                prepared,
                policy=self.journal.policy,
                round_=body.round,
                signed=signed,
                case_id=case.case_id,
                expected_transport_policy_sha256=self.config.legacy_policy_sha256,
                limits=self.limits,
            )
            started = str(time.time_ns())
            outcome = await asyncio.wait_for(
                send_prepared_request(
                    prepared,
                    miner_url=origin.capture.origin,
                    limits=self.limits,
                    timeout_seconds=self.config.request_timeout_seconds,
                    transport=self.transport,
                    maximum_request_transmissions=1,
                    maximum_response_bodies=1,
                ),
                timeout=self.config.request_timeout_seconds,
            )
            evidence = canonical_json_bytes(
                {
                    "schema": "umi-endpoint-dispatch-transcript/1",
                    "assignment_key": key,
                    "publication_sha256": claim.publication_sha256,
                    "case_id": case.case_id,
                    "origin_evidence_sha256": origin.capture.evidence_sha256,
                    "origin_block": origin.capture.block,
                    "request_hex": prepared.request_bytes.hex(),
                    "auth_headers": outcome.auth_headers,
                    "limits": asdict(self.limits),
                    "started_at_unix_ns": started,
                    "finished_at_unix_ns": str(time.time_ns()),
                    "received_at_unix_ns": outcome.received_at_unix_ns,
                    "envelope_hex": None
                    if outcome.envelope_bytes is None
                    else outcome.envelope_bytes.hex(),
                    "response_signature": outcome.response_signature,
                    "received_body_prefix_hex": None
                    if outcome.received_body_prefix is None
                    else outcome.received_body_prefix.hex(),
                    "received_bytes_sha256": outcome.received_bytes_sha256,
                    "failure_code": outcome.failure_code,
                    "no_weight": True,
                    "evidence_verified": False,
                    "chain_submission_authorized": False,
                }
            )
            self.journal.complete(claim, evidence=evidence)
            return "completed"
        except Exception:
            # No endpoint, wallet path, auth header or provider exception in public status.
            return "uncertain" if claimed else "held"

    async def poll_once(self):
        for key, (task, _miner) in tuple(self._tasks.items()):
            if task.done():
                self._counts[task.result()] += 1
                del self._tasks[key]
        try:
            ingestion = await self.ingest_once()
        except Exception:
            ingestion = "held"
        page = self.journal.pending_dispatches(
            evaluator_hotkey=self.config.evaluator_hotkey,
            after=self._cursor,
            limit=self.config.page_size,
        )
        busy = {miner for _task, miner in self._tasks.values()}
        for item in page["items"]:
            if len(self._tasks) >= self.config.maximum_concurrency:
                break
            key, miner = item["assignment_key"], item["miner_account"]
            if key in self._tasks or miner in busy:
                continue
            self._tasks[key] = (asyncio.create_task(self.dispatch_one(key)), miner)
            busy.add(miner)
        # Holds cannot starve later pages. A wrapped scan revisits skipped work.
        self._cursor = page["next_cursor"]
        return {
            "schema": "umi-endpoint-dispatch-status/1",
            **self._counts,
            "in_flight": len(self._tasks),
            "publication_intake": ingestion,
            "no_weight": True,
            "chain_submission_authorized": False,
        }

    async def drain(self):
        if self._tasks:
            await asyncio.gather(*(task for task, _ in self._tasks.values()))

    async def aclose(self):
        tasks = [task for task, _ in self._tasks.values()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()


async def run_dispatch(config, policy, legacy_policy, *, once=False, report=None):
    """CLI construction has no injected transport, proof source or coldkey access."""
    import bittensor as bt

    config = EndpointDispatchConfig.model_validate_json(canonical_json_bytes(config))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    legacy = ScoringPolicy.model_validate_json(canonical_json_bytes(legacy_policy))
    config.check_policies(policy, legacy)
    wallet = bt.Wallet(name=config.wallet_name, hotkey=config.hotkey_name, path=config.wallet_path)
    # Check the hotkey before opening an observer, journal or network connection.
    if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
        config.evaluator_hotkey
    ):
        raise ValueError("dispatcher wallet does not hold the configured evaluator hotkey")
    journal = AssignmentPublicationJournal(Path(config.journal_directory), policy, legacy)
    provider = DispatchFinalityProvider(config.chain, policy, legacy)
    dispatcher = None
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    handlers = []
    try:
        dispatcher = EndpointDispatcher(config, journal, provider, wallet)
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
            handlers.append(sig)
        await provider.start()
        while not stop.is_set():
            status = await dispatcher.poll_once()
            if report is not None:
                report(status)
            if once:
                await dispatcher.drain()
                # Harvest only. A second poll could schedule a new batch.
                for task, _ in dispatcher._tasks.values():
                    dispatcher._counts[task.result()] += 1
                return {**status, **dispatcher._counts, "in_flight": 0}
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=config.poll_seconds)
        return {"status": "stopped", "no_weight": True, "chain_submission_authorized": False}
    finally:
        if dispatcher is not None:
            await dispatcher.aclose()
        await provider.aclose()
        for sig in handlers:
            loop.remove_signal_handler(sig)
