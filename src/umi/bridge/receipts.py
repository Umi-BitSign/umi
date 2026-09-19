"""Read exact bridge transaction outcomes from owned finalized history.

The reader never submits or changes a journal. It hashes backwards from an
owned head, verifies the body root, and decodes proven child events with the
parent's proven runtime. A missing result is uncertainty, not proof of absence.
Completed ancestry/body work survives a timeout in this process. Only one
attempt's eight-block era is retained; a long outage does not grow the cache.
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass
from datetime import datetime
from functools import partial

from ..bootstrap_weight_operator import BootstrapExtrinsicReference
from ..chain_evidence import FinalizedSnapshotRef
from ..concurrency import await_owned_task, run_owned_thread
from ..encoding import datetime_to_unix_ms
from ..finalized_ancestry import MAXIMUM_HEADER_BYTES, encode_rpc_header
from ..grandpa_finality import _decode_header
from ..protocol import canonical_json_bytes
from ..runtime_metadata import MAX_CODE_BYTES, RuntimeMetadataExecutor, collect_executed_runtime
from ..substrate_proof import SubprocessStorageProofVerifier
from ..validator_chain import FinalizedProofCollector, ProofCollectionLimits, RawJsonRpc
from ..validator_chain_scan import _extrinsic_statuses
from .policy import _require
from .signing import BridgeFinality, _SnapshotPort
from .transactions import RegistrationBridgeTransactionJournal, evolve_journal, parse_bridge_journal

_HEX = re.compile(r"0x(?:[0-9a-f]{2})+")
_MAX_BODY_BYTES = 64 * 1024**2
_MAX_EXTRINSIC_BYTES = 16 * 1024**2
_MAX_EXTRINSICS = 4096


@dataclass(frozen=True)
class VerifiedBridgeReceipt:
    receipt: BootstrapExtrinsicReference
    successful: bool
    signed_extrinsic_hash: str
    owned_head: FinalizedSnapshotRef


@dataclass(frozen=True)
class _Header:
    snapshot: FinalizedSnapshotRef
    extrinsics_root: str


def retain_verified_receipt(journal, proven: VerifiedBridgeReceipt, *, now: datetime):
    """Build one transition from a local reader result, never an RPC receipt.

    Receipt inclusion settles transaction uncertainty. A successful call still
    needs the separate current-row check before the journal becomes applied.
    """
    journal = parse_bridge_journal(canonical_json_bytes(journal))
    _require(
        type(journal) is RegistrationBridgeTransactionJournal
        and journal.phase in {"submitting", "outcome_unknown", "receipt_returned"}
        and type(proven) is VerifiedBridgeReceipt
        and proven.signed_extrinsic_hash == journal.signed_extrinsic_hash,
        "bridge_receipt_attempt_mismatch",
    )
    receipt, anchor = proven.receipt, proven.owned_head
    _require(
        journal.attempt.preflight_block < receipt.block_number < journal.attempt.era_death
        and receipt.block_number <= anchor.block_number
        and type(proven.successful) is bool,
        "bridge_receipt_position_invalid",
    )
    _require(
        journal.weight_call is None or (proven.successful and journal.weight_call == receipt),
        "bridge_receipt_conflict",
    )
    updates = dict(updated_at_unix_ms=datetime_to_unix_ms(now))
    if anchor.block_number >= journal.last_observed_block:
        _require(
            anchor.block_number != journal.last_observed_block
            or anchor.block_hash == journal.last_observed_block_hash,
            "bridge_receipt_finality_equivocation",
        )
        updates.update(
            last_observed_block=anchor.block_number, last_observed_block_hash=anchor.block_hash
        )
    if proven.successful:
        updates.update(phase="receipt_returned", weight_call=receipt)
    else:
        updates.update(phase="failed", failed_call=receipt)
    return evolve_journal(journal, **updates)


class BridgeReceiptReader:
    """One owner retains bounded progress until an attempt is resolved.

    A caller must retain this reader across iterations to preserve progress.
    Progress is not loaded from operator JSON or accepted as finality evidence.
    After process restart the ancestry is authenticated again. The caller still
    checks the current row and policy before allowing another submission.
    """

    def __init__(
        self,
        *,
        finality: BridgeFinality,
        rpc: RawJsonRpc,
        verifier: SubprocessStorageProofVerifier,
        runtime_executor: RuntimeMetadataExecutor,
        timeout_seconds: float = 60,
    ):
        if (
            type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 120
        ):
            raise ValueError("receipt collection timeout must be in (0, 120]")
        self._finality, self._rpc, self._verifier = finality, rpc, verifier
        self._executor, self._timeout = runtime_executor, timeout_seconds
        self._lock = asyncio.Lock()
        # storage_evidence operates only at snapshots authenticated below.
        snapshots = _SnapshotPort(finality, rpc)
        self._proofs = FinalizedProofCollector(
            rpc,
            finality=snapshots,
            verifier=verifier,
            limits=ProofCollectionLimits(
                maximum_storage_keys=1,
                maximum_storage_value_bytes=16 * 1024**2,
                maximum_storage_values_bytes=16 * 1024**2,
                maximum_proof_node_bytes=16 * 1024**2,
                maximum_proof_bytes=32 * 1024**2,
            ),
        )
        self._code_proofs = FinalizedProofCollector(
            rpc,
            finality=snapshots,
            verifier=verifier,
            limits=ProofCollectionLimits(
                maximum_storage_keys=1,
                maximum_storage_value_bytes=MAX_CODE_BYTES,
                maximum_storage_values_bytes=MAX_CODE_BYTES,
                maximum_proof_node_bytes=MAX_CODE_BYTES,
                maximum_proof_bytes=MAX_CODE_BYTES + 1024**2,
            ),
        )
        self._identity: tuple[str, str] | None = None
        self._anchor: _Header | None = None
        self._cursor: _Header | None = None
        self._era: dict[int, _Header] = {}
        self._checked: set[int] = set()
        self._found: VerifiedBridgeReceipt | None = None

    async def find(
        self, journal: RegistrationBridgeTransactionJournal
    ) -> VerifiedBridgeReceipt | None:
        journal = parse_bridge_journal(canonical_json_bytes(journal))
        _require(
            type(journal) is RegistrationBridgeTransactionJournal
            and journal.phase in {"submitting", "outcome_unknown", "receipt_returned", "applied"}
            and journal.signed_extrinsic is not None,
            "bridge_receipt_signed_attempt_required",
        )
        task = asyncio.create_task(asyncio.wait_for(self._find(journal), self._timeout))
        return await await_owned_task(task, on_cancel=task.cancel)

    async def _header(self, block_hash: str, number: int, raw=None) -> _Header:
        raw = await self._rpc.request("chain_getHeader", (block_hash,)) if raw is None else raw
        encoded = encode_rpc_header(raw)
        decoded = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        _require(
            decoded["hash"] == block_hash and decoded["number"] == number,
            "bridge_receipt_header_mismatch",
        )
        return _Header(
            FinalizedSnapshotRef(number, block_hash, decoded["parent_hash"], decoded["state_root"]),
            decoded["extrinsics_root"],
        )

    async def _find(self, journal):
        async with self._lock:
            identity = (journal.attempt.attempt_id, journal.signed_extrinsic_hash)
            if identity != self._identity:
                self._identity = identity
                self._anchor = self._cursor = self._found = None
                self._era.clear()
                self._checked.clear()
            if self._found is not None:
                return self._found
            attempt = journal.attempt
            birth, last = attempt.preflight_block, attempt.era_death - 1
            _require(last - birth == 7, "bridge_receipt_era_unsupported")
            # Refresh only after completing the available part of a live era.
            # A timeout midway through an old path resumes that path instead.
            if self._cursor is None or (
                self._cursor.snapshot.block_number == birth
                and self._anchor.snapshot.block_number < last
            ):
                owned = await self._finality.read_finalized_identity()
                _require(
                    type(owned.number) is int and owned.number > birth,
                    "bridge_receipt_not_yet_finalized",
                )
                anchor = await self._header(owned.block_hash, owned.number)
                if self._anchor is not None:
                    _require(
                        anchor.snapshot.block_number >= self._anchor.snapshot.block_number,
                        "bridge_receipt_finality_rollback",
                    )
                    _require(
                        anchor.snapshot.block_number != self._anchor.snapshot.block_number
                        or anchor == self._anchor,
                        "bridge_receipt_finality_equivocation",
                    )
                self._anchor = self._cursor = anchor
            while self._cursor.snapshot.block_number > birth:
                current = self._cursor
                number = current.snapshot.block_number
                if number <= last:
                    self._remember(current)
                parent = await self._header(current.snapshot.parent_hash, number - 1)
                if parent.snapshot.block_number <= last:
                    self._remember(parent)
                if parent.snapshot.block_number == birth:
                    _require(
                        parent.snapshot.block_hash == attempt.preflight_block_hash,
                        "bridge_receipt_preflight_ancestry_mismatch",
                    )
                self._cursor = parent  # Retain only after hash/height validation.
            encoded = bytes.fromhex(journal.signed_extrinsic)
            for number in sorted(self._era):
                if number == birth or number in self._checked:
                    continue
                header = self._era[number]
                body = await self._body(header)
                indices = [index for index, raw in enumerate(body) if raw == encoded]
                _require(len(indices) <= 1, "bridge_receipt_duplicate_transaction")
                if indices:
                    result = await self._outcome(
                        journal, header, self._era[number - 1], body, indices[0]
                    )
                    self._found = result
                    return result
                self._checked.add(number)
            return None

    def _remember(self, header):
        number = header.snapshot.block_number
        prior = self._era.get(number)
        _require(prior is None or prior == header, "bridge_receipt_ancestry_equivocation")
        self._era[number] = header
        _require(len(self._era) <= 8, "bridge_receipt_era_cache_invalid")

    async def _body(self, header: _Header) -> tuple[bytes, ...]:
        reply = await self._rpc.request("chain_getBlock", (header.snapshot.block_hash,))
        _require(
            isinstance(reply, dict) and isinstance(reply.get("block"), dict),
            "bridge_receipt_body_invalid",
        )
        block = reply["block"]
        _require(isinstance(block.get("header"), dict), "bridge_receipt_body_header_missing")
        _require(
            await self._header(
                header.snapshot.block_hash, header.snapshot.block_number, block.get("header")
            )
            == header,
            "bridge_receipt_body_header_mismatch",
        )
        items = block.get("extrinsics")
        _require(
            isinstance(items, list) and len(items) <= _MAX_EXTRINSICS, "bridge_receipt_body_invalid"
        )
        total, body = 0, []
        for item in items:
            _require(
                isinstance(item, str)
                and len(item) <= 2 + 2 * _MAX_EXTRINSIC_BYTES
                and _HEX.fullmatch(item) is not None,
                "bridge_receipt_extrinsic_invalid",
            )
            total += (len(item) - 2) // 2
            _require(total <= _MAX_BODY_BYTES, "bridge_receipt_body_limit")
            body.append(bytes.fromhex(item[2:]))
        body = tuple(body)
        _require(
            await run_owned_thread(
                partial(
                    self._verifier.verify_extrinsics_root,
                    expected_root=bytes.fromhex(header.extrinsics_root[2:]),
                    extrinsics=body,
                    state_version=1,
                )
            )
            is True,
            "bridge_receipt_body_root_invalid",
        )
        return body

    async def _outcome(self, journal, header, parent, body, index):
        runtime = await collect_executed_runtime(self._code_proofs, self._executor, parent.snapshot)
        key = runtime.storage_key("System", "Events")
        evidence = await self._proofs.storage_evidence(header.snapshot, key)
        events = runtime.decode_storage("System", "Events", evidence.value)
        _require(
            isinstance(events, list)
            and len(events) <= 65536
            and all(isinstance(event, dict) for event in events),
            "bridge_receipt_events_invalid",
        )
        statuses = _extrinsic_statuses(events, len(body))
        number = header.snapshot.block_number
        return VerifiedBridgeReceipt(
            BootstrapExtrinsicReference(
                extrinsic_id=f"{number}-{index:04d}",
                block_number=number,
                extrinsic_index=index,
                block_hash=header.snapshot.block_hash,
            ),
            statuses[index],
            journal.signed_extrinsic_hash,
            self._anchor.snapshot,
        )
