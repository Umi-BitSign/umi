"""Read exact mortal transaction outcomes from owned finalized ancestry.

This reader never signs, submits, retries or establishes reward authority. A
query's claimed era must come from independently checked encoding. No match is
uncertainty, never proof of non-inclusion or permission to reuse a nonce.
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass
from functools import partial
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .bootstrap_weight_operator import BootstrapExtrinsicReference
from .bridge.signing import BridgeFinality, _SnapshotPort
from .chain_evidence import FinalizedSnapshotRef
from .concurrency import await_owned_task, run_owned_thread
from .finalized_ancestry import MAXIMUM_HEADER_BYTES, encode_rpc_header
from .grandpa_finality import _decode_header
from .open_competition import digest
from .protocol import BlockHash, StrictProtocolModel
from .runtime_metadata import MAX_CODE_BYTES, RuntimeMetadataExecutor, collect_executed_runtime
from .signed_extrinsic import MAX_SIGNED_EXTRINSIC_BYTES, exact_signed_extrinsic
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_chain import FinalizedProofCollector, ProofCollectionLimits, RawJsonRpc
from .validator_chain_scan import _extrinsic_statuses

_HEX = re.compile(r"0x(?:[0-9a-f]{2})+")
_MAX_BODY_BYTES = 64 * 1024**2
_MAX_EXTRINSIC_BYTES = 16 * 1024**2
_MAX_EXTRINSICS = 4096


class MortalReceiptError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _require(condition, reason):
    if not condition:
        raise MortalReceiptError(reason)


class MortalReceiptQuery(StrictProtocolModel):
    """Exact retained bytes and search bounds, not signing or retry authority."""

    schema_: Literal["umi-mortal-receipt-query/1"] = Field(alias="schema")
    birth_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    birth_hash: BlockHash
    mortality_period: Annotated[int, Field(ge=4, le=4096)]
    signed_extrinsic: Annotated[
        str,
        Field(
            min_length=2,
            max_length=2 * MAX_SIGNED_EXTRINSIC_BYTES,
            pattern=r"^(?:[0-9a-f]{2})+$",
        ),
    ]

    @model_validator(mode="after")
    def bounds(self):
        if self.mortality_period & (self.mortality_period - 1):
            raise ValueError("receipt query needs an exact power-of-two mortal era")
        if self.birth_block + self.mortality_period > 2**53 - 1:
            raise ValueError("receipt query exceeds the block bound")
        return self

    @property
    def signed_extrinsic_hash(self) -> str:
        return exact_signed_extrinsic(bytes.fromhex(self.signed_extrinsic)).extrinsic_hash


@dataclass(frozen=True)
class VerifiedMortalReceipt:
    receipt: BootstrapExtrinsicReference
    successful: bool
    signed_extrinsic_hash: str
    owned_head: FinalizedSnapshotRef


@dataclass(frozen=True)
class _Header:
    snapshot: FinalizedSnapshotRef
    extrinsics_root: str


class MortalReceiptReader:
    """One owner resumes hash walks and body checks across interrupted polls.

    Retain the reader across polls. Only one bounded era's headers and checked
    body identities are cached. Cold start verifies ancestry again, and every
    returned outcome uses proved child events with the parent's proved runtime.
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
        self._found: VerifiedMortalReceipt | None = None
        self._expiry_result = None

    @property
    def progress(self) -> tuple:
        """Opaque in-process progress marker, not a proof or persisted cursor."""
        return (
            self._identity,
            self._anchor,
            self._cursor,
            frozenset(self._checked),
            self._found is not None,
            self._expiry_result is not None,
        )

    async def find(self, query: MortalReceiptQuery) -> VerifiedMortalReceipt | None:
        if type(query) is not MortalReceiptQuery:
            raise ValueError("receipt query type is invalid")
        # Copies can bypass model validation. Validate their original Python
        # values before canonicalization can normalize an invalid field type.
        query = MortalReceiptQuery.model_validate(
            query.model_dump(mode="python", by_alias=True, warnings=False)
        )
        task = asyncio.create_task(asyncio.wait_for(self._find(query), self._timeout))
        return await await_owned_task(task, on_cancel=task.cancel)

    async def _header(self, block_hash: str, number: int, raw=None) -> _Header:
        raw = await self._rpc.request("chain_getHeader", (block_hash,)) if raw is None else raw
        encoded = encode_rpc_header(raw)
        decoded = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        _require(
            decoded["hash"] == block_hash and decoded["number"] == number,
            "mortal_receipt_header_mismatch",
        )
        return _Header(
            FinalizedSnapshotRef(number, block_hash, decoded["parent_hash"], decoded["state_root"]),
            decoded["extrinsics_root"],
        )

    async def _find(self, query):
        async with self._lock:
            birth, last = query.birth_block, query.birth_block + query.mortality_period - 1
            identity = (digest(query), query.signed_extrinsic_hash)
            self._era_period = query.mortality_period
            if identity != self._identity:
                # A stopped handoff visits attempts newest first. The cursor
                # already authenticates the prefix from its owned head; keep
                # that prefix when the entire next era is below the cursor.
                # Newer or overlapping eras start with a new owned head.
                earlier_era = (
                    self._anchor is not None
                    and self._cursor is not None
                    and last <= self._cursor.snapshot.block_number
                )
                self._identity = identity
                if not earlier_era:
                    self._anchor = self._cursor = None
                self._found = None
                self._expiry_result = None
                self._era.clear()
                self._checked.clear()
            if self._found is not None:
                return self._found
            # Refresh only after completing the available part of a live era.
            # A timeout midway through an old path resumes that path instead.
            if self._cursor is None or (
                self._cursor.snapshot.block_number == birth
                and self._anchor.snapshot.block_number < last
            ):
                owned = await self._finality.read_finalized_identity()
                _require(
                    type(owned.number) is int and owned.number > birth,
                    "mortal_receipt_not_yet_finalized",
                )
                anchor = await self._header(owned.block_hash, owned.number)
                if self._anchor is not None:
                    _require(
                        anchor.snapshot.block_number >= self._anchor.snapshot.block_number,
                        "mortal_receipt_finality_rollback",
                    )
                    _require(
                        anchor.snapshot.block_number != self._anchor.snapshot.block_number
                        or anchor == self._anchor,
                        "mortal_receipt_finality_equivocation",
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
                        parent.snapshot.block_hash == query.birth_hash,
                        "mortal_receipt_preflight_ancestry_mismatch",
                    )
                self._cursor = parent  # Retain only after hash/height validation.
            encoded = bytes.fromhex(query.signed_extrinsic)
            for number in sorted(self._era):
                if number == birth or number in self._checked:
                    continue
                header = self._era[number]
                body = await self._body(header)
                indices = [index for index, raw in enumerate(body) if raw == encoded]
                _require(len(indices) <= 1, "mortal_receipt_duplicate_transaction")
                if indices:
                    result = await self._outcome(
                        query, header, self._era[number - 1], body, indices[0]
                    )
                    self._found = result
                    return result
                self._checked.add(number)
            return None

    def _remember(self, header):
        number = header.snapshot.block_number
        prior = self._era.get(number)
        _require(prior is None or prior == header, "mortal_receipt_ancestry_equivocation")
        self._era[number] = header
        _require(len(self._era) <= self._era_period, "mortal_receipt_era_cache_invalid")

    async def _body(self, header: _Header) -> tuple[bytes, ...]:
        reply = await self._rpc.request("chain_getBlock", (header.snapshot.block_hash,))
        _require(
            isinstance(reply, dict) and isinstance(reply.get("block"), dict),
            "mortal_receipt_body_invalid",
        )
        block = reply["block"]
        _require(isinstance(block.get("header"), dict), "mortal_receipt_body_header_missing")
        _require(
            await self._header(
                header.snapshot.block_hash, header.snapshot.block_number, block.get("header")
            )
            == header,
            "mortal_receipt_body_header_mismatch",
        )
        items = block.get("extrinsics")
        _require(
            isinstance(items, list) and len(items) <= _MAX_EXTRINSICS, "mortal_receipt_body_invalid"
        )
        total, body = 0, []
        for item in items:
            _require(
                isinstance(item, str)
                and len(item) <= 2 + 2 * _MAX_EXTRINSIC_BYTES
                and _HEX.fullmatch(item) is not None,
                "mortal_receipt_extrinsic_invalid",
            )
            total += (len(item) - 2) // 2
            _require(total <= _MAX_BODY_BYTES, "mortal_receipt_body_limit")
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
            "mortal_receipt_body_root_invalid",
        )
        return body

    async def _outcome(self, query, header, parent, body, index):
        runtime = await collect_executed_runtime(self._code_proofs, self._executor, parent.snapshot)
        key = runtime.storage_key("System", "Events")
        evidence = await self._proofs.storage_evidence(header.snapshot, key)
        events = runtime.decode_storage("System", "Events", evidence.value)
        _require(
            isinstance(events, list)
            and len(events) <= 65536
            and all(isinstance(event, dict) for event in events),
            "mortal_receipt_events_invalid",
        )
        statuses = _extrinsic_statuses(events, len(body))
        number = header.snapshot.block_number
        return VerifiedMortalReceipt(
            BootstrapExtrinsicReference(
                extrinsic_id=f"{number}-{index:04d}",
                block_number=number,
                extrinsic_index=index,
                block_hash=header.snapshot.block_hash,
            ),
            statuses[index],
            query.signed_extrinsic_hash,
            self._anchor.snapshot,
        )
