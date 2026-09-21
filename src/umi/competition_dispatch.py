"""Continuous endpoint dispatch from a signed journal; no chain weight capability.

Only a durable claim permits fresh request signing. After a claim, cancellation
or an unrecorded result stays uncertain and is never transmitted again. Retained
transport evidence requires independent replay after the protected suite reveal.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import stat
import time
from collections import OrderedDict
from contextlib import closing, suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .chain_evidence import FinalizedSnapshotRef
from .competition_authorization import (
    MAX_AUTHORIZATION_BYTES,
    SignedEndpointAuthorization,
    validate_publication,
    validate_transport_cohort,
)
from .competition_chain import CompetitionChainConfig
from .competition_dispatch_capacity import (
    DispatchTimingBudget,
    DispatchTimingLimits,
    timing_profile_sha256,
)
from .competition_dispatch_inbox import publication_names
from .competition_endpoint import prepare_endpoint_case
from .competition_origin import (
    EndpointOriginCapture,
    FinalizedEndpointProvider,
    public_https_origin,
)
from .competition_policy_lineage import admitted_policy_sha256s
from .competition_scheduling import AssignmentPublicationJournal, SchedulingCapacity, assignment_key
from .concurrency import await_owned_task
from .config import Limits
from .finalized_ancestry import MAXIMUM_DISTANCE, HeaderPathCache, recover_header_path
from .open_competition import CompetitionPolicy, Hotkey, digest, identity
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import lock_private_file
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator import prepare_request_attempt, send_prepared_request
from .validator_chain import StorageReadSpec
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
    maximum_concurrency: Annotated[int, Field(ge=1, le=128)] = 4
    page_size: Annotated[int, Field(ge=1, le=100)] = 32
    request_timeout_seconds: Annotated[int, Field(ge=1, le=600)] = 180
    scheduling_capacity: SchedulingCapacity = Field(default_factory=SchedulingCapacity)
    timing_budget: DispatchTimingBudget | None = None
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
        validate_transport_cohort(policy, legacy)
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
        self._ancestry_headers = HeaderPathCache()

    def _finality_policy_hash(self):
        return scoring_policy_hash(self.legacy_policy)

    def _cache_binding_hash(self):
        return digest(
            {
                "chain": self._config_binding_hash(self.config),
                "transport_policy": self._finality_policy_hash(),
            }
        )

    def _acceptable_cache_bindings(self):
        accepted = {self._cache_binding_hash()}
        for policy_sha256 in admitted_policy_sha256s(self.policy):
            legacy = self.config.model_copy(update={"policy_sha256": policy_sha256})
            accepted.add(
                digest({"chain": digest(legacy), "transport_policy": self._finality_policy_hash()})
            )
        return frozenset(accepted)

    async def _recover_historical_block(self, height, head):
        if not self._owned or self._registration_rpc is None:
            raise ValueError("owned issuance is unavailable")
        if height < self.config.minimum_finalized_block:
            raise ValueError("historical issuance precedes configured minimum")
        anchor = await self._finality.verified_block_after(
            height, maximum_distance=MAXIMUM_DISTANCE
        )
        if anchor is None or anchor.height > head.height:
            raise ValueError("historical issuance lacks an owned finalized anchor")
        self._check_finality_context(anchor)
        ref, headers = await recover_header_path(
            anchor, height, self._registration_rpc.request, cache=self._ancestry_headers
        )
        runtime = await self._runtime_context(ref)
        if runtime.snapshot != ref or runtime.pin != self._runtime_pin:
            raise ValueError("historical timestamp runtime binding mismatch")
        batch = await self._read(runtime, (StorageReadSpec("Timestamp", "Now"),))
        timestamp = batch.reads[0].decoded_value
        if type(timestamp) is not int or not 0 < timestamp <= anchor.timestamp_ms:
            raise ValueError("historical timestamp is invalid or newer than its anchor")
        evidence = canonical_json_bytes(
            {
                "schema": "umi-owned-finalized-ancestor/1",
                "evidence_class": "verified_finalized_ancestry",
                "offline_finality_proof": False,
                "scoring_policy_hash": anchor.scoring_policy_hash,
                "chain_observation": anchor.chain_observation.model_dump(mode="json"),
                "finality_verifier_sha256": anchor.finality_verifier_sha256,
                "block": ref.block_number,
                "block_hash": ref.block_hash,
                "anchor": json.loads(anchor.finality_evidence),
                "anchor_sha256": anchor.finality_evidence_sha256,
                "headers": headers,
                "metadata_sha256": runtime.metadata_sha256,
                "storage_proof_verifier_sha256": self.config.proof_binary_sha256,
                "state_root": batch.evidence.verified_state_root,
                "claims": [
                    {
                        "key": "0x" + c.storage_key.hex(),
                        "value": None if c.value is None else "0x" + c.value.hex(),
                    }
                    for c in batch.evidence.claims
                ],
                "proof": ["0x" + node.hex() for node in batch.evidence.proof],
                "timestamp_ms": timestamp,
            }
        )
        block = VerifiedFinalizedBlock(
            height=ref.block_number,
            block_hash=ref.block_hash,
            state_root=ref.state_root,
            timestamp_ms=timestamp,
            scoring_policy_hash=anchor.scoring_policy_hash,
            chain_observation=anchor.chain_observation,
            finality_verifier_sha256=anchor.finality_verifier_sha256,
            finality_evidence=evidence,
            finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )
        # Retain the derivation separately. Never insert a synthetic observer row
        # or local acceptance time. Cache reads do not substitute for verification.
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT body FROM artifacts WHERE digest=?", (block.finality_evidence_sha256,)
            ).fetchone()
            if prior is not None and prior[0] != evidence:
                raise ValueError("historical evidence digest conflict")
            if prior is None:
                used = db.execute("SELECT COALESCE(SUM(length(body)),0) FROM artifacts").fetchone()[
                    0
                ]
                used += db.execute(
                    "SELECT COALESCE(SUM(length(evidence)),0) FROM captures"
                ).fetchone()[0]
                if used + len(evidence) > self.config.maximum_cache_bytes:
                    raise ValueError("historical evidence cache capacity exhausted")
                db.execute(
                    "INSERT INTO artifacts VALUES (?,?)", (block.finality_evidence_sha256, evidence)
                )
            db.commit()
        return block

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
                    if block is None:
                        block = await self._recover_historical_block(height, head)
                    else:
                        self._check_finality_context(block)
                    # Same process-owned source, same pins; old issuance need not be fresh.
                    if not isinstance(block, VerifiedFinalizedBlock) or block.height != height:
                        raise ValueError("owned issuance is unavailable")
                    if block.timestamp_ms > head.timestamp_ms:
                        raise ValueError("issuance is newer than the verified head")
                    blocks.append(block)
                # Network recovery may take time. Return a fresh owned head, and
                # never reinterpret historical proof as historical receipt timing.
                newest = await self._proofs.finalized_snapshot()
                if (
                    not isinstance(newest, FinalizedSnapshotRef)
                    or newest.block_number < ref.block_number
                    or (newest.block_number == ref.block_number and newest != ref)
                ):
                    raise ValueError("dispatch finalized head rolled back or changed")
                head = await self._finality.verified_block_at(newest.block_number)
                self._check_finality(newest, head)
                self._fresh(head.timestamp_ms)
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
        # Always check actual runtime limits, including legacy starts with no
        # budget. Omitting the optional field cannot bypass a retained profile.
        self.journal = journal
        self._configure_timing()
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
        # Queue before the provider starts its bounded proof-collection timer.
        # HTTP requests may overlap; one owned observer collects proofs at a time.
        self._proof_gate = asyncio.Lock()

    def _configure_timing(self):
        limits = DispatchTimingLimits(
            **{name: getattr(self.config, name) for name in DispatchTimingLimits.model_fields}
        )
        self.journal.configure_dispatch(
            evaluator_hotkey=self.config.evaluator_hotkey,
            limits=limits,
            budget=self.config.timing_budget,
            publication_directory=self.config.publication_directory,
        )
        return (
            None
            if self.config.timing_budget is None
            else timing_profile_sha256(limits, self.config.timing_budget)
        )

    async def _verified_blocks(self, heights):
        async with self._proof_gate:
            return await self.provider.verified_blocks(heights)

    async def ingest_once(self):
        """Read one immutable quorum-signed inbox file; errors never retime work.

        The inbox is operator-owned and private. Temporary files are ignored;
        publish by atomically renaming complete bytes to <body-digest>.json.
        It is not an unauthenticated network upload directory.
        """
        directory = Path(self.config.publication_directory)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            names = publication_names(fd)
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
        head, blocks = await self._verified_blocks(announcements)
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
            head, issuances = await self._verified_blocks(heights)
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
            async with self._proof_gate:
                origin = await self.provider.dispatch_origin(
                    signed, assignment.request.issued_block
                )
            if not isinstance(origin, DispatchOrigin) or (
                origin.capture.submission_sha256 != digest(signed.submission)
                or identity(origin.capture.hotkey) != identity(signed.submission.hotkey)
                or origin.capture.origin != public_https_origin(signed.submission.endpoint_url)
            ):
                raise ValueError("dispatch origin binding mismatch")
            resolver = origin.capture.transport_resolver()
            expected_profile = self._configure_timing()
            claim = self.journal.claim(
                key,
                observed=origin.observed,
                issuance=origin.issuance,
                expected_dispatch_profile=expected_profile,
            )
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
            # The transport owns its deadline and retains any partial response
            # when it expires. An equal outer deadline races that retention and
            # leaves an ordinary timeout permanently uncertain in the journal.
            outcome = await send_prepared_request(
                prepared,
                miner_url=origin.capture.origin,
                limits=self.limits,
                timeout_seconds=self.config.request_timeout_seconds,
                transport=self.transport,
                resolver=resolver,
                maximum_request_transmissions=1,
                maximum_response_bodies=1,
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
        self._configure_timing()
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
    journal = AssignmentPublicationJournal(
        Path(config.journal_directory), policy, legacy, **config.scheduling_capacity.model_dump()
    )
    provider = dispatcher = None
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    handlers = []
    # Per-miner serialization and task limits are process-local. Keep one
    # production dispatcher per evaluator/journal, including during shutdown.
    lease = lock_private_file(
        Path(config.journal_directory) / f".dispatch-{identity(config.evaluator_hotkey)}.lock"
    )
    try:
        provider = DispatchFinalityProvider(config.chain, policy, legacy)
        dispatcher = EndpointDispatcher(config, journal, provider, wallet)
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
            handlers.append(sig)
        await provider.start()
        while not stop.is_set():
            provider.ensure_observer_running()
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

        async def cleanup():
            try:
                try:
                    if dispatcher is not None:
                        await dispatcher.aclose()
                finally:
                    if provider is not None:
                        await provider.aclose()
            finally:
                try:
                    for sig in handlers:
                        loop.remove_signal_handler(sig)
                finally:
                    os.close(lease)

        # Repeated cancellation must not release the service lease while old
        # HTTP/proof tasks still run. Cleanup owns the descriptor until drained.
        await await_owned_task(asyncio.create_task(cleanup()))
