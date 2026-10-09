"""Resumable complete control-block history, with native replay after restart.

The selected start block is part of the owner's binding. Every intervening block
is proved, including unchanged or empty slots; there is no last-update shortcut.
Storage records are only hints until replayed. Shared metadata/code bytes are
deduplicated by the existing lossless recipe format. Capacity exhaustion retains
the verified prefix for retry after provisioning; it never completes a cohort.

A complete interval grants no reward authority. The decision reader must choose
the correct admission boundary, interpret all writes and reject unresolved
effects. Execution still requires fresh current control and recipient proofs.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import _hotkey, _uint
from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    checked_digest,
    decode_evidence,
    encode_evidence,
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
from .competition_reward_proof_archive import RewardProofArchive, history_archive_key
from .competition_reward_write_archive import review_control_writes
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread
from .open_competition import digest

_ISSUER = object()
_FIELDS = {
    "slot_evidence": MAX_CONTROL_ARCHIVE_BYTES,
    "slot_metadata": MAX_CONTROL_METADATA_BYTES,
    "evidence": MAX_WRITE_EVIDENCE_BYTES,
}


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


class RewardControlHistoryReader:
    """One private owner captures or replays a bounded amount of work per call.

    Per-call work limits do not expire the retained interval. On restart the
    reader replays retained proofs before fetching missing blocks. No cursor or
    stored summary is accepted as proof that a block has been checked.
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
    ) -> None:
        _uint(first_block, 2**53 - 1)
        if first_block == 0:
            raise ValueError("control block history requires a parent block")
        self.hotkey = _hotkey(control_hotkey)
        self.config_sha256 = checked_digest(chain_config_sha256)
        self.first_block = first_block
        self.archive = archive
        self.export_archive = export_archive
        binding = {
            "schema": "umi-reward-control-history/1",
            "control_hotkey": self.hotkey,
            "chain_config_sha256": self.config_sha256,
            "first_block": first_block,
        }
        self.journal = RoundJournal(
            root,
            binding,
            maximum_rounds=65536,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=2 * MAX_EVIDENCE_BYTES + 1024,
        )
        self._lock = asyncio.Lock()
        self._next = first_block
        self._tip: OwnedRewardControlWrites | None = None
        self._writes: list[HistoricalControlWrite] = []
        self._unresolved: list[int] = []
        self._evidence_sha256 = digest(binding)
        # Only entries verified in this process enter this index. Keep a tip,
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

        Reopening clears this index. Retained records do not issue history until
        advance() has natively replayed every intervening block again.
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
                saved = await run_owned_thread(self._load, height)
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
        records = []
        refs = {}
        for name, raw in (
            ("slot_evidence", observation.slot.evidence),
            ("slot_metadata", observation.slot.metadata),
            ("evidence", observation.evidence),
        ):
            refs[name] = []
            for offset in range(0, len(raw), MAX_EVIDENCE_BYTES):
                encoded = encode_evidence(raw[offset : offset + MAX_EVIDENCE_BYTES], kind="proof")
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
        records.append(("control_history_block", str(observation.slot.snapshot.block_number), refs))
        # The complete frame and all of its objects commit together. A lost
        # acknowledgement is an exact immutable retry, never another decision.
        self.journal.put_many(records)

    def _object(self, sha: str, size: int, *, db: sqlite3.Connection) -> bytes:
        value = self.journal.get("control_history_object", sha, db=db)
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
        frame = self.journal.get("control_history_block", str(height), db=db)
        if frame is None:
            return None
        if type(frame) is not dict or set(frame) != set(_FIELDS):
            raise ValueError("control history frame has invalid fields")
        result = {}
        for name, maximum in _FIELDS.items():
            refs = frame[name]
            if (
                type(refs) is not list
                or not 0 < len(refs) <= (maximum + MAX_EVIDENCE_BYTES - 1) // MAX_EVIDENCE_BYTES
            ):
                raise ValueError("control history frame exceeds its chunk bound")
            parts = []
            total = 0
            for sha in refs:
                checked_digest(sha)
                chunk = self.journal.get("control_history_chunk", sha, db=db)
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
                parts.append(
                    decode_evidence(
                        raw_recipe,
                        sha256=sha,
                        expanded_bytes=chunk["length"],
                        kind="proof",
                        resolve=partial(self._object, db=db),
                    )
                )
            result[name] = b"".join(parts)
        return result

    async def advance(
        self,
        provider: HistoricalRewardControlProvider,
        *,
        through_block: int,
        maximum_blocks: int = 64,
    ) -> ControlHistoryProgress:
        _uint(through_block, 2**53 - 1)
        if type(maximum_blocks) is not int or not 1 <= maximum_blocks <= 4096:
            raise ValueError("control history work count exceeds its bound")
        if (
            not isinstance(provider, HistoricalRewardControlProvider)
            or digest(provider.config) != self.config_sha256
        ):
            raise ValueError("control history provider differs from selected chain")
        async with self._lock:
            if through_block < self.first_block or through_block < self._next - 1:
                raise ValueError("control history target regressed")
            with self.journal.locked():
                for _ in range(maximum_blocks):
                    if self._next > through_block:
                        break
                    saved = await run_owned_thread(self._load, self._next)
                    retained = saved is not None
                    if not retained and self.archive is not None:
                        try:
                            context, saved = await run_owned_thread(
                                partial(
                                    self.archive.read,
                                    "history",
                                    history_archive_key(
                                        self.config_sha256, self.hotkey, self._next
                                    ),
                                    bounds=_FIELDS,
                                ),
                            )
                        except FileNotFoundError:
                            saved = None
                        else:
                            if context != self._archive_context(self._next):
                                raise ValueError("imported history changes its requested domain")
                    observation = (
                        await capture_control_writes(provider, self.hotkey, self._next)
                        if saved is None
                        else await review_control_writes(provider, **saved)
                    )
                    validate_control_writes(
                        observation,
                        expected_control_hotkey=self.hotkey,
                        expected_chain_config_sha256=self.config_sha256,
                    )
                    slot = observation.slot
                    if slot.snapshot.block_number != self._next or (
                        self._tip is not None
                        and slot.snapshot.parent_hash != self._tip.slot.snapshot.block_hash
                    ):
                        raise ValueError("control history has a gap or a different parent")
                    if not retained:
                        await run_owned_thread(self._save, observation)
                    unresolved = bool(observation.unresolved_extrinsics)
                    if self._tip is not None and not observation.writes:
                        prior = self._tip.slot
                        if (slot.control_sha256, slot.committed_at_block) != (
                            prior.control_sha256,
                            prior.committed_at_block,
                        ):
                            # A cleared slot or an unattributed effect must be
                            # resolved by a future native decoder, never skipped.
                            unresolved = True
                    if self.export_archive is not None:
                        # Retain original bytes before advancing the replay cursor.
                        # A failed export leaves this block retryable after restart.
                        await run_owned_thread(self._export, observation, self.export_archive)
                    if unresolved:
                        self._unresolved.append(self._next)
                    self._writes.extend(
                        HistoricalControlWrite(self._next, w.extrinsic_index, w.decision_sha256)
                        for w in observation.writes
                    )
                    self._evidence_sha256 = digest(
                        {
                            "prior": self._evidence_sha256,
                            "block": self._next,
                            "slot": slot.evidence_sha256,
                            "writes": hashlib.sha256(observation.evidence).hexdigest(),
                        }
                    )
                    self._tip = observation
                    self._prefixes[self._next] = (
                        slot.snapshot,
                        self._evidence_sha256,
                        len(self._writes),
                        len(self._unresolved),
                    )
                    self._next += 1
                history = None
                if self._next == through_block + 1:
                    history = self._prefix(through_block)
                return ControlHistoryProgress(self._next, through_block, history)

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
        archive.write(
            "history",
            history_archive_key(self.config_sha256, self.hotkey, height),
            context=self._archive_context(height),
            fields={
                "slot_evidence": observation.slot.evidence,
                "slot_metadata": observation.slot.metadata,
                "evidence": observation.evidence,
            },
        )
