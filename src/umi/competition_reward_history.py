"""Resumable complete control-block history with durable native block results.

The selected start block is part of the owner's binding. Every intervening block
is proved, including unchanged or empty slots; there is no last-update shortcut.
Raw records are only hints until natively verified. Shared metadata/code bytes are
deduplicated by the existing lossless recipe format. Capacity exhaustion retains
the verified prefix for retry after provisioning; it never completes a cohort.

A complete interval grants no reward authority. The decision reader must choose
the correct admission boundary, interpret all writes and reject unresolved
effects. Execution still requires fresh current control and recipient proofs.
"""

from __future__ import annotations

import asyncio
import secrets
import sqlite3
from contextlib import suppress
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import _hotkey, _uint
from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    checked_digest,
    decode_evidence,
    decode_evidence_for_reuse,
    encode_evidence,
    encode_evidence_for_reuse,
)
from .competition_history_source_externalization import (
    JournalSourceExternalizer,
    source_journal_version,
)
from .competition_reward_control_archive import (
    MAX_CONTROL_ARCHIVE_BYTES,
    MAX_CONTROL_METADATA_BYTES,
    HistoricalRewardControlProvider,
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .competition_reward_control_writes import (
    MAX_WRITE_EVIDENCE_BYTES,
    OwnedRewardControlWrites,
    capture_control_writes,
    validate_control_writes,
)
from .competition_reward_history_checkpoint import (
    SOURCE_KINDS,
    HistoryCheckpointRepairRequired,
    HistoryCheckpoints,
)
from .competition_reward_history_parallel import advance_parallel_locked
from .competition_reward_history_progress import HistoryProgress
from .competition_reward_history_workers import HistoryVerificationProfile
from .competition_reward_proof_archive import RewardProofArchive, history_archive_key
from .competition_reward_write_archive import review_control_writes
from .competition_round_journal import RoundJournal
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import digest

_ISSUER = object()
_MAX_FRAME_OBJECTS = 128
_MAX_FRAME_OBJECT_BYTES = MAX_EVIDENCE_BYTES
MAX_HISTORY_BYTES = 512 * 1024**3
_FIELDS = {
    "slot_evidence": MAX_CONTROL_ARCHIVE_BYTES,
    "slot_metadata": MAX_CONTROL_METADATA_BYTES,
    "evidence": MAX_WRITE_EVIDENCE_BYTES,
}


class _HistoryJournal(RoundJournal):
    """History grows by charged bytes, independently of round counts.

    Every canonical record consumes at least one logical byte. The byte budget
    therefore also bounds total records without an earlier fixed count limit.
    Per-kind and per-call limits, accounting and reservation formats are shared
    with ordinary round journals; their operational envelopes are unchanged.
    """

    MAXIMUM_BYTES = MAX_HISTORY_BYTES

    def __init__(self, *args, remote_store=None, **kwargs):
        self.remote_store = remote_store
        super().__init__(*args, **kwargs)

    def _version(self, db):
        try:
            return source_journal_version(
                db,
                remote_namespace=None
                if self.remote_store is None
                else self.remote_store.namespace_sha256,
            )
        except ValueError as error:
            raise HistoryCheckpointRepairRequired(str(error)) from error

    def _enable_reservations(self, db):
        if db.execute("PRAGMA user_version").fetchone()[0] == 3:
            raise ValueError("remote history cannot transition to reservation generation")
        return super()._enable_reservations(db)

    @property
    def maximum_records(self) -> int:
        return self.maximum_bytes


@dataclass(frozen=True, slots=True)
class HistoricalControlWrite:
    block_number: int
    extrinsic_index: int
    decision_sha256: str


@dataclass(frozen=True, slots=True)
class OwnedRewardControlHistory:
    first_block: int
    tip: FinalizedSnapshotRef
    control_hotkey: str
    chain_config_sha256: str
    writes: tuple[HistoricalControlWrite, ...]
    unresolved_blocks: tuple[int, ...]
    evidence_sha256: str
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value: OwnedRewardControlHistory) -> str:
    return digest(
        {
            "first": value.first_block,
            "tip": [
                value.tip.block_number,
                value.tip.block_hash,
                value.tip.parent_hash,
                value.tip.state_root,
            ],
            "hotkey": value.control_hotkey,
            "config": value.chain_config_sha256,
            "writes": [
                [w.block_number, w.extrinsic_index, w.decision_sha256] for w in value.writes
            ],
            "unresolved": list(value.unresolved_blocks),
            "evidence": value.evidence_sha256,
        }
    )


def validate_control_history(
    value: OwnedRewardControlHistory,
    *,
    first_block: int,
    tip: FinalizedSnapshotRef,
    control_hotkey: str,
    chain_config_sha256: str,
) -> None:
    if (
        type(value) is not OwnedRewardControlHistory
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or (value.first_block, value.tip, value.control_hotkey, value.chain_config_sha256)
        != (first_block, tip, control_hotkey, chain_config_sha256)
    ):
        raise ValueError("control history lacks the complete selected native interval")


@dataclass(frozen=True, slots=True)
class ControlHistoryProgress:
    next_block: int
    target_block: int
    history: OwnedRewardControlHistory | None


@dataclass(frozen=True, slots=True)
class _HistoryTip:
    snapshot: FinalizedSnapshotRef
    control_sha256: str | None
    committed_at_block: int | None


@dataclass(slots=True)
class _HistoryPreparation:
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    observation: OwnedRewardControlWrites | dict | None = None
    task: asyncio.Task | None = None


class RewardControlHistoryReader:
    """One private owner captures or replays a bounded amount of work per call.

    Per-call work limits do not expire the retained interval. On restart the
    reader restores owned successful block results and fresh tip finality before
    fetching missing blocks. Legacy raw records receive one native verification
    pass. Missing or changed completed results require explicit scoped repair.
    """

    def __init__(
        self,
        root: Path,
        *,
        control_hotkey: str,
        chain_config_sha256: str,
        first_block: int,
        maximum_bytes: int = 4 * 1024**3,
        archive: RewardProofArchive | None = None,
        export_archive: RewardProofArchive | None = None,
        repair_record_capacity: bool = False,
        verification_profile: HistoryVerificationProfile | None = None,
        remote_store=None,
    ) -> None:
        _uint(first_block, 2**53 - 1)
        if first_block == 0:
            raise ValueError("control block history requires a parent block")
        self.hotkey = _hotkey(control_hotkey)
        self.config_sha256 = checked_digest(chain_config_sha256)
        self.first_block = first_block
        self.verification_profile = verification_profile
        self._field_bounds = _FIELDS
        self.archive = archive
        self.export_archive = export_archive
        self.remote_store = (
            remote_store if remote_store is not None else getattr(export_archive, "remote", None)
        )
        binding = {
            "schema": "umi-reward-control-history/1",
            "control_hotkey": self.hotkey,
            "chain_config_sha256": self.config_sha256,
            "first_block": first_block,
        }
        self.journal = _HistoryJournal(
            root,
            binding,
            maximum_rounds=65536,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=2 * MAX_EVIDENCE_BYTES + 1024,
            repair_record_capacity=repair_record_capacity,
            remote_store=self.remote_store,
        )
        self.checkpoints = HistoryCheckpoints(self.journal, binding)
        self.remote_sources = JournalSourceExternalizer(
            self.journal,
            self.checkpoints,
            self.remote_store,
            source_kinds=SOURCE_KINDS,
            repair_error=HistoryCheckpointRepairRequired,
        )
        self.checkpoints.remote_sources = self.remote_sources
        self._source_tokens = {}
        self._prepared_encodings = {}
        self.progress = HistoryProgress(first_block)
        self.progress.remote_export_selected = getattr(export_archive, "remote", None) is not None
        self._repair_reason = None
        self._repair_id = None
        self._advance_lock = asyncio.Lock()
        self._lock = asyncio.Lock()
        self._next = first_block
        self._tip: _HistoryTip | None = None
        self._writes: list[HistoricalControlWrite] = []
        self._unresolved: list[int] = []
        self._initial_evidence_sha256 = digest(binding)
        self._evidence_sha256 = self._initial_evidence_sha256
        # Only entries verified or restored by this owner enter this index. Keep a tip,
        # proof digest and list lengths, not a copy of the growing write list.
        self._prefixes: dict[int, tuple[FinalizedSnapshotRef, str, int, int]] = {}

    def _prefix(self, height: int) -> OwnedRewardControlHistory:
        saved = self._prefixes.get(height)
        if saved is None:
            raise ValueError("control history prefix has not been natively verified")
        tip, evidence, writes, unresolved = saved
        history = OwnedRewardControlHistory(
            self.first_block,
            tip,
            self.hotkey,
            self.config_sha256,
            tuple(self._writes[:writes]),
            tuple(self._unresolved[:unresolved]),
            evidence,
            _issuer=_ISSUER,
        )
        object.__setattr__(history, "_binding", _binding(history))
        return history

    async def verified_prefix(self, height: int) -> OwnedRewardControlHistory:
        """Reuse an already replayed prefix for an older coverage endpoint.

        Reopening clears this index. advance() restores bound successful results
        with current owned tip finality before issuing history.
        """
        _uint(height, 2**53 - 1)
        async with self._lock:
            return self._prefix(height)

    async def review_control(
        self, provider: HistoricalRewardControlProvider, height: int
    ) -> OwnedHistoricalRewardControl:
        """Replay the retained slot at an already verified history boundary.

        This uses the original proof bytes, including after a restart where
        historical state RPC is unavailable. It cannot skip history replay.
        """
        if (
            not isinstance(provider, HistoricalRewardControlProvider)
            or digest(provider.config) != self.config_sha256
        ):
            raise ValueError("control history provider differs from selected chain")
        async with self._lock:
            prefix = self._prefix(height)
            with self.journal.locked():
                try:
                    saved = await run_owned_thread(self._load, height)
                finally:
                    self._prepared_encodings.pop(height, None)
                    self._source_tokens.pop(height, None)
                if saved is None:
                    raise ValueError("verified control history lost its retained frame")
                control = await provider.review_control(
                    saved["slot_evidence"], saved["slot_metadata"]
                )
                validate_historical_reward_control(
                    control,
                    expected_control_hotkey=self.hotkey,
                    expected_chain_config_sha256=self.config_sha256,
                )
                if control.snapshot != prefix.tip:
                    raise ValueError("retained control differs from verified history boundary")
                return control

    def _save(self, observation: OwnedRewardControlWrites) -> None:
        self._save_fields(
            observation.slot.snapshot.block_number,
            {
                "slot_evidence": observation.slot.evidence,
                "slot_metadata": observation.slot.metadata,
                "evidence": observation.evidence,
            },
        )

    def _save_fields(self, height: int, fields: dict[str, bytes]) -> None:
        records = []
        refs = {}
        prepared = {}
        for name, raw in fields.items():
            refs[name] = []
            prepared[name] = []
            for offset in range(0, len(raw), MAX_EVIDENCE_BYTES):
                part = raw[offset : offset + MAX_EVIDENCE_BYTES]
                if self.export_archive is None:
                    encoded = encode_evidence(part, kind="proof")
                else:
                    encoding = encode_evidence_for_reuse(part, kind="proof")
                    encoded = encoding.for_bytes(part, kind="proof")
                    prepared[name].append(encoding)
                records.extend(
                    ("control_history_object", sha, {"hex": value.hex()})
                    for sha, value in encoded.objects.items()
                )
                records.append(
                    (
                        "control_history_chunk",
                        encoded.sha256,
                        {
                            "length": encoded.expanded_bytes,
                            "recipe_hex": encoded.recipe.hex(),
                        },
                    )
                )
                refs[name].append(encoded.sha256)
        records.append(("control_history_block", str(height), refs))
        # The complete frame and all of its objects commit together. A lost
        # acknowledgement is an exact immutable retry, never another decision.
        source_tokens = []

        def index(db):
            source_tokens.extend(
                self.checkpoints.sources(((kind, key) for kind, key, _ in records), db)
            )
            self._source_tokens[height] = source_tokens

        self.journal.put_many(self.remote_sources.filter_records(records), index=index)
        self.progress.record("captured", height)
        if self.export_archive is not None:
            self._prepared_encodings[height] = prepared

    def _object(self, sha: str, size: int, *, db: sqlite3.Connection) -> bytes:
        value = self.remote_sources.get("control_history_object", sha, db=db)
        if (
            type(value) is not dict
            or set(value) != {"hex"}
            or type(value["hex"]) is not str
            or len(value["hex"]) != 2 * size
        ):
            raise ValueError("control history object is missing or oversized")
        raw = bytes.fromhex(value["hex"])
        if raw.hex() != value["hex"]:
            raise ValueError("control history object is not canonical")
        return raw

    def _load(self, height: int) -> dict[str, bytes] | None:
        # A frame and all its chunks commit together. Read that same snapshot
        # without opening another database connection for every proof object.
        with self.journal.read_transaction() as db:
            return self._load_frame(height, db=db)

    def _load_frame(self, height: int, *, db: sqlite3.Connection) -> dict[str, bytes] | None:
        source_keys = [("control_history_block", str(height))]
        frame = self.remote_sources.get("control_history_block", str(height), db=db)
        if frame is None:
            return None
        if type(frame) is not dict or set(frame) != set(_FIELDS):
            raise ValueError("control history frame has invalid fields")
        objects = {}
        object_bytes = 0

        def resolve(sha, size):
            nonlocal object_bytes
            key = sha, size
            if key not in objects:
                source_keys.append(("control_history_object", sha))
                raw = self._object(sha, size, db=db)
                if (
                    len(objects) < _MAX_FRAME_OBJECTS
                    and object_bytes + len(raw) <= _MAX_FRAME_OBJECT_BYTES
                ):
                    objects[key] = raw
                    object_bytes += len(raw)
                return raw
            return objects[key]

        result = {}
        prepared = {}
        for name, maximum in _FIELDS.items():
            refs = frame[name]
            if (
                type(refs) is not list
                or not 0 < len(refs) <= (maximum + MAX_EVIDENCE_BYTES - 1) // MAX_EVIDENCE_BYTES
            ):
                raise ValueError("control history frame exceeds its chunk bound")
            parts = []
            prepared[name] = []
            total = 0
            for sha in refs:
                checked_digest(sha)
                source_keys.append(("control_history_chunk", sha))
                chunk = self.remote_sources.get("control_history_chunk", sha, db=db)
                if type(chunk) is not dict or set(chunk) != {"length", "recipe_hex"}:
                    raise ValueError("control history chunk is missing or malformed")
                if (
                    type(chunk["length"]) is not int
                    or not 0 < chunk["length"] <= MAX_EVIDENCE_BYTES
                ):
                    raise ValueError("control history chunk length exceeds its bound")
                total += chunk["length"]
                if total > maximum:
                    raise ValueError("control history frame expansion exceeds its bound")
                recipe = chunk["recipe_hex"]
                if type(recipe) is not str or len(recipe) > 8 * 1024**2:
                    raise ValueError("control history recipe exceeds its bound")
                raw_recipe = bytes.fromhex(recipe)
                if raw_recipe.hex() != recipe:
                    raise ValueError("control history recipe is not canonical")
                decode = (
                    decode_evidence if self.export_archive is None else decode_evidence_for_reuse
                )
                decoded = decode(
                    raw_recipe,
                    sha256=sha,
                    expanded_bytes=chunk["length"],
                    kind="proof",
                    resolve=resolve,
                )
                if self.export_archive is None:
                    parts.append(decoded)
                else:
                    parts.append(decoded.raw)
                    prepared[name].append(decoded)
            result[name] = b"".join(parts)
        self._source_tokens[height] = self.checkpoints.sources(source_keys, db)
        if self.export_archive is not None:
            self._prepared_encodings[height] = prepared
        return result

    async def _prepare(self, provider: HistoricalRewardControlProvider, height: int):
        """Prepare one exact frame without publishing it or changing the prefix."""
        try:
            completed = await run_owned_thread(self.checkpoints.load, height)
        except HistoryCheckpointRepairRequired:
            self.progress.invalidate(height)
            if not self._repair_reason:
                raise
            completed = None
        if completed is not None:
            return completed, True
        saved = await run_owned_thread(self._load, height)
        retained = saved is not None
        self.progress.native_start(retained=retained, repair=bool(self._repair_reason))
        if not retained and self.archive is not None:
            try:
                context, saved = await run_owned_thread(
                    partial(
                        self.archive.read,
                        "history",
                        history_archive_key(self.config_sha256, self.hotkey, height),
                        bounds=_FIELDS,
                    ),
                )
            except FileNotFoundError:
                saved = None
            else:
                if context != self._archive_context(height):
                    raise ValueError("imported history changes its requested domain")
        observation = (
            await capture_control_writes(provider, self.hotkey, height)
            if saved is None
            else await review_control_writes(provider, **saved)
        )
        return observation, retained

    def _start_preparation(self, provider, height):
        prepared = _HistoryPreparation()
        prepared.task = asyncio.create_task(self._prepare_durable(provider, height, prepared))
        return prepared

    async def _prepare_durable(self, provider, height, prepared):
        # One owned task spans native verification through durable success. The
        # caller may cancel or fail publication, but must drain this task before
        # releasing ownership. A successful prefetched check is never discarded.
        try:
            observation, retained = await self._prepare(provider, height)
            if isinstance(observation, dict):
                prepared.observation = observation
                prepared.ready.set()
                return observation
            validate_control_writes(
                observation,
                expected_control_hotkey=self.hotkey,
                expected_chain_config_sha256=self.config_sha256,
            )
            if observation.slot.snapshot.block_number != height:
                raise ValueError("control history has a gap or a different parent")
            prepared.observation = observation
            prepared.ready.set()
            save_error = None
            if not retained:
                try:
                    await run_owned_thread(self._save, observation)
                except Exception as error:
                    # A publication can commit and lose its acknowledgement.
                    # The transaction's captured identities let us persist the
                    # already successful native result before propagating that
                    # original error. remember() rechecks committed identities.
                    if height not in self._source_tokens:
                        raise
                    save_error = error
            value = self.checkpoints.capture(observation, self._source_tokens[height])
            if self._repair_reason:
                value["repair"] = {"reason": self._repair_reason, "operation": self._repair_id}
            try:
                await run_owned_thread(
                    partial(self.checkpoints.remember, value, repair_reason=self._repair_reason)
                )
            except Exception:
                if save_error is not None:
                    raise save_error from None
                raise
            self.progress.native_finished(height)
            if save_error is not None:
                raise save_error
            return value
        finally:
            # Also wake the owner on failure before native observation exists.
            prepared.ready.set()

    def _validate_advance(self, provider, through_block, maximum_blocks):
        _uint(through_block, 2**53 - 1)
        if type(maximum_blocks) is not int or not 1 <= maximum_blocks <= 4096:
            raise ValueError("control history work count exceeds its bound")
        if (
            not isinstance(provider, HistoricalRewardControlProvider)
            or digest(provider.config) != self.config_sha256
        ):
            raise ValueError("control history provider differs from selected chain")
        if through_block < self.first_block or through_block < self._next - 1:
            raise ValueError("control history target regressed")

    async def _advance(
        self,
        provider: HistoricalRewardControlProvider,
        *,
        through_block: int,
        maximum_blocks: int = 64,
    ) -> ControlHistoryProgress:
        self._validate_advance(provider, through_block, maximum_blocks)
        async with self._lock:
            if through_block < self.first_block or through_block < self._next - 1:
                raise ValueError("control history target regressed")
            with self.journal.locked():
                last = min(through_block, self._next + maximum_blocks - 1)
                pending = following = None
                try:
                    await self.progress.inventory(self)
                    if self.verification_profile is not None:
                        await advance_parallel_locked(self, provider, last)
                        history = (
                            self._prefix(through_block) if self._next == through_block + 1 else None
                        )
                        return ControlHistoryProgress(self._next, through_block, history)
                    await self._restore_prefix(provider, last)
                    if self._next <= last:
                        pending = self._start_preparation(provider, self._next)
                    while self._next <= last:
                        await pending.ready.wait()
                        observation = pending.observation
                        if observation is None:
                            # Propagate the original preparation failure. No
                            # subsequent block may start before this validation.
                            await await_owned_task(pending.task)
                            raise RuntimeError("history preparation produced no result")
                        if isinstance(observation, dict):
                            snapshot = FinalizedSnapshotRef(**observation["snapshot"])
                        else:
                            snapshot = observation.slot.snapshot
                        if snapshot.block_number != self._next or (
                            self._tip is not None
                            and snapshot.parent_hash != self._tip.snapshot.block_hash
                        ):
                            raise ValueError("control history has a gap or a different parent")
                        if self._next < last:
                            # Native proof work may overlap persistence/export.
                            # Each child owns its own success checkpoint, even
                            # if its predecessor fails or this caller cancels.
                            following = self._start_preparation(provider, self._next + 1)
                        value = await await_owned_task(pending.task)
                        if isinstance(observation, dict):
                            # A following native worker may already be active.
                            # Keep its timer running across this cheap restore;
                            # restored blocks never enter the rate numerator.
                            await self._validate_checkpoint_tip(provider, value)
                            if await run_owned_thread(self.checkpoints.load, self._next) != value:
                                raise HistoryCheckpointRepairRequired(
                                    "checkpoint changed during finality"
                                )
                            value = await self._ensure_checkpoint_export(value)
                            self.progress.restored_completed += 1
                        elif self.export_archive is not None:
                            await run_owned_thread(self._export, observation, self.export_archive)
                            value = {**value, "exports": [self._export_identity()]}
                            await run_owned_thread(
                                partial(
                                    self.checkpoints.remember,
                                    value,
                                    repair_reason="new_export_destination",
                                )
                            )
                        if self.export_archive is not None:
                            self.progress.record("exported", self._next)
                        self._apply_checkpoint(value)
                        pending, following = following, None
                finally:
                    for prepared in (pending, following):
                        if prepared is not None:
                            # Drain complete native+checkpoint ownership. A
                            # secondary failure cannot replace the caller's
                            # publication error or cancellation. Retrieving a
                            # completed failure with result() again would
                            # replace its original traceback with this cleanup.
                            with suppress(asyncio.CancelledError, Exception):
                                if not prepared.task.done():
                                    await await_owned_task(prepared.task)
                                elif not prepared.task.cancelled():
                                    prepared.task.exception()
                    self._source_tokens.clear()
                    self._prepared_encodings.clear()
                history = None
                if self._next == through_block + 1:
                    history = self._prefix(through_block)
                return ControlHistoryProgress(self._next, through_block, history)

    def _apply_checkpoint(self, value):
        self.progress.record("verified", value["snapshot"]["block_number"])
        self.progress.applied(value["snapshot"]["block_number"])
        slot = _HistoryTip(
            FinalizedSnapshotRef(**value["snapshot"]),
            value["control_sha256"],
            value["committed_at_block"],
        )
        if slot.snapshot.block_number != self._next or (
            self._tip is not None and slot.snapshot.parent_hash != self._tip.snapshot.block_hash
        ):
            raise ValueError("control history has a gap or a different parent")
        unresolved = bool(value["unresolved_extrinsics"])
        if (
            self._tip is not None
            and not value["writes"]
            and (slot.control_sha256, slot.committed_at_block)
            != (self._tip.control_sha256, self._tip.committed_at_block)
        ):
            unresolved = True
        if unresolved:
            self._unresolved.append(self._next)
        self._writes.extend(
            HistoricalControlWrite(self._next, i, key) for i, key in value["writes"]
        )
        self._evidence_sha256 = digest(
            {
                "prior": self._evidence_sha256,
                "block": self._next,
                "slot": value["slot_evidence_sha256"],
                "writes": value["write_evidence_sha256"],
            }
        )
        self._tip = slot
        self._prefixes[self._next] = (
            slot.snapshot,
            self._evidence_sha256,
            len(self._writes),
            len(self._unresolved),
        )
        self._source_tokens.pop(self._next, None)
        self._next += 1
        self.progress.report(self, "running")

    async def _validate_checkpoint_tip(self, provider, value):
        async with provider._lock:
            if provider._closed or not provider._owned:
                raise ValueError("checkpoint restore requires the running owned provider")
            await provider._resolve_control_header(
                FinalizedSnapshotRef(**value["snapshot"]), value["header"]
            )

    async def _restore_prefix(self, provider, last):
        self.progress.native_stop()
        values = []
        for height in range(self._next, last + 1):
            try:
                value = await run_owned_thread(self.checkpoints.load, height)
            except HistoryCheckpointRepairRequired:
                self.progress.invalidate(height)
                if not self._repair_reason:
                    raise
                break
            if value is None:
                break
            values.append(value)
        if not values:
            return
        self.progress.report(self, "restoring_checkpoint")
        await self._validate_checkpoint_tip(provider, values[-1])
        # Recheck source identities after asynchronous finality, before issuing
        # any prefix. Unchanged proof payloads are never read or hashed here.
        for value in values:
            current = await run_owned_thread(
                self.checkpoints.load, value["snapshot"]["block_number"]
            )
            if current != value:
                raise HistoryCheckpointRepairRequired("checkpoint changed during owned restore")
        for value in values:
            value = await self._ensure_checkpoint_export(value)
            self.progress.restored_completed += 1
            self._apply_checkpoint(value)

    def _export_identity(self):
        root = self.export_archive.root
        try:
            stat = root.stat()
        except FileNotFoundError:
            return None
        value = {"path": str(root.resolve()), "identity": [stat.st_dev, stat.st_ino, stat.st_uid]}
        remote = getattr(self.export_archive, "remote", None)
        if remote is not None:
            value["remote_namespace_sha256"] = remote.namespace_sha256
        return digest(value)

    async def _ensure_checkpoint_export(self, value):
        if self.export_archive is None:
            return value
        identity = self._export_identity()
        if identity in value["exports"]:
            self.progress.record("exported", value["snapshot"]["block_number"])
            return value
        # A new destination needs its first copy, but no new native proof check.
        # Retain the old successful result and bind the new delivery fact to the
        # same original source identities in the atomic checkpoint transaction.
        height = value["snapshot"]["block_number"]
        self.progress.stage = "checkpoint_export"
        self.progress.report(self, "running", force=True)
        fields = await run_owned_thread(self._load, height)
        if fields is None:
            raise HistoryCheckpointRepairRequired("verified history lost export source")
        await run_owned_thread(self._export_fields, height, fields, self.export_archive)
        identity = self._export_identity()
        updated = {**value, "exports": [*value["exports"], identity]}
        await run_owned_thread(
            partial(self.checkpoints.remember, updated, repair_reason="new_export_destination")
        )
        self.progress.record("exported", height)
        return updated

    async def advance(self, provider, *, through_block, maximum_blocks=64):
        async with self._advance_lock:
            result = await self._observed_advance(
                provider, through_block=through_block, maximum_blocks=maximum_blocks
            )
            if result.history is not None:
                self._repair_reason = self._repair_id = None
            return result

    def _externalize_sources(self, maximum_records):
        if type(maximum_records) is not int or not 1 <= maximum_records <= 4096:
            raise ValueError("history source replication requires a bounded record batch")
        with self.journal.locked():
            return self._externalize_sources_locked(maximum_records)

    def _externalize_sources_locked(self, maximum_records):
        keys = []
        with self.journal.read_transaction() as db:
            # Bound index traversal as well as payload work. A mixed-direction
            # ORDER BY across all kinds requires a temporary sort of the whole
            # first kind even when the requested batch is small.
            for kind in reversed(SOURCE_KINDS):
                keys.extend(
                    db.execute(
                        "SELECT kind,id FROM records WHERE kind=? ORDER BY id LIMIT ?",
                        (kind, maximum_records - len(keys)),
                    ).fetchall()
                )
                if len(keys) == maximum_records:
                    break
        result = self.remote_sources.externalize_many(keys)
        with self.journal.read_transaction() as db:
            result["remaining_local_records"] = db.execute(
                "SELECT COALESCE(SUM(number),0) FROM round_record_capacity_kinds "
                "WHERE kind IN (?,?,?)",
                SOURCE_KINDS,
            ).fetchone()[0]
        self.progress.local_release = result
        return result

    async def externalize_history_sources(self, *, maximum_records=256):
        """Explicit bounded upgrade/repair entrypoint under this reader's ownership."""
        async with self._advance_lock, self._lock:
            return await run_owned_thread(self._externalize_sources, maximum_records)

    async def _observed_advance(self, provider, *, through_block, maximum_blocks):
        stop = asyncio.Event()
        # Preserve native argument rejection before starting diagnostics.
        self._validate_advance(provider, through_block, maximum_blocks)
        self.progress.start(through_block, self._next, repair=bool(self._repair_reason))
        self.progress.report(self, "running", force=True)
        monitor = asyncio.create_task(self.progress.monitor(self, stop))
        failed = False
        try:
            if self.remote_store is not None:
                self.progress.stage = "history_source_replication"
                self.progress.report(self, "running", force=True)
                async with self._lock:
                    await run_owned_thread(self._externalize_sources, 256)
            result = await self._advance(
                provider, through_block=through_block, maximum_blocks=maximum_blocks
            )
            if self.remote_store is not None:
                self.progress.stage = "history_source_replication"
                self.progress.report(self, "running", force=True)
                async with self._lock:
                    await run_owned_thread(self._externalize_sources, 256)
            self.progress.report(self, "completed" if result.history is not None else "pending")
            return result
        except BaseException as error:
            failed = True
            self.progress.report(
                self,
                "repair_required"
                if isinstance(error, HistoryCheckpointRepairRequired)
                else "retrying",
                error_type=type(error).__name__,
            )
            raise
        finally:
            stop.set()
            self.progress.finish()
            # Diagnostic failures never mask native errors or abandon native
            # cancellation cleanup; the monitor owns no protocol work.
            if failed:
                with suppress(Exception, asyncio.CancelledError):
                    await await_owned_task(monitor)
            else:
                # A new caller cancellation remains a cancellation, including
                # when it arrives after the native result but during cleanup.
                with suppress(Exception):
                    await await_owned_task(monitor)

    async def repair_checkpoints(self, provider, *, through_block, reason, maximum_blocks=64):
        """Explicitly recheck affected native blocks; preserve unaffected receipts.

        Existing raw /1 journals need no reset. Blocks with no successful receipt
        follow the ordinary native first pass, checkpointed one block at a time.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("history checkpoint repair requires an explicit reason")
        async with self._advance_lock:
            if self._repair_reason is None:
                # Rebuild the cheap ordered reducer from the beginning. Good
                # independent block results survive; only affected blocks replay
                # their native proofs. Continued bounded repair calls retain this
                # cursor and reason until the selected interval is complete.
                async with self._lock:
                    self._next = self.first_block
                    self._tip = None
                    self._writes.clear()
                    self._unresolved.clear()
                    self._prefixes.clear()
                    self._evidence_sha256 = self._initial_evidence_sha256
                self._repair_reason = reason
                self._repair_id = secrets.token_hex(16)
            elif self._repair_reason != reason:
                raise ValueError("history checkpoint repair already has a different reason")
            result = await self._observed_advance(
                provider, through_block=through_block, maximum_blocks=maximum_blocks
            )
            if result.history is not None:
                self._repair_reason = self._repair_id = None
            return result

    def _archive_context(self, height):
        return {
            "chain_config_sha256": self.config_sha256,
            "control_hotkey": self.hotkey,
            "block": height,
        }

    def _export(self, observation: OwnedRewardControlWrites, archive: RewardProofArchive) -> None:
        # advance() has verified and durably retained these exact bytes. Reloading
        # the frame here only decodes the same large proof objects a second time.
        height = observation.slot.snapshot.block_number
        self._export_fields(
            height,
            {
                "slot_evidence": observation.slot.evidence,
                "slot_metadata": observation.slot.metadata,
                "evidence": observation.evidence,
            },
            archive,
        )

    def _export_fields(self, height, fields, archive):
        archive.write(
            "history",
            history_archive_key(self.config_sha256, self.hotkey, height),
            context=self._archive_context(height),
            fields=fields,
            prepared_encodings=self._prepared_encodings.pop(height, None),
        )
