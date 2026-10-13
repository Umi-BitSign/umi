"""Shared native archive proof kernel, with no finality or history ownership.

The caller independently authenticates the child header and timestamp ceiling.
These compact facts grant no capability and never create an Owned observation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .competition_chain import _uint
from .competition_reward_control import _control_value
from .competition_reward_history_effects import checked_control_effects
from .competition_reward_runtime import validate_weight_runtime
from .competition_reward_write_evidence import _ArchivePort
from .runtime_metadata import RuntimeMetadataExecutor, collect_executed_runtime
from .validator_chain import (
    FinalizedProofCollector,
    FinalizedRuntimePin,
    StorageReadSpec,
    VerifiedStorageBatch,
)
from .validator_chain_scan import FinalizedBlockScanner


@dataclass(frozen=True, slots=True)
class HistoryProofTools:
    proofs: FinalizedProofCollector
    runtime_proofs: FinalizedProofCollector | None
    executor: RuntimeMetadataExecutor | None
    pin: FinalizedRuntimePin
    storage_codec: bool
    executor_sha256: str | None

    def validate(self, runtime, snapshot):
        validate_weight_runtime(runtime, snapshot, self.pin, self.executor_sha256)


async def verify_slot_archive(archive, tools: HistoryProofTools, *, timestamp, ceiling):
    ref = archive.snapshot
    collector = tools.proofs.with_evidence_rpc(archive)
    if tools.executor is not None:
        execution = archive.body["runtime_execution"]
        if not isinstance(execution, dict) or execution["executor_sha256"] != (
            tools.executor_sha256
        ):
            raise ValueError("reward archive runtime executor differs from selection")
        runtime = await collect_executed_runtime(
            tools.runtime_proofs.with_evidence_rpc(archive), tools.executor, ref
        )
    else:
        runtime = (
            await collector.storage_codec_runtime(ref, tools.pin, archive.metadata)
            if tools.storage_codec
            else await collector.pinned_runtime(ref, tools.pin)
        )
    tools.validate(runtime, ref)
    if (
        runtime.storage_codec_mode != archive.body["storage_codec_mode"]
        or runtime.metadata_sha256 != archive.body["runtime_metadata_sha256"]
        or json.loads(runtime.runtime_version_bytes) != archive.body["runtime_version"]
    ):
        raise ValueError("replayed runtime differs from archived control evidence")
    specs = (
        StorageReadSpec("Timestamp", "Now"),
        StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
        StorageReadSpec("Commitments", "CommitmentOf", (78, archive.hotkey)),
    )
    batch = await collector.storage_reads(runtime, specs)
    if (
        not isinstance(batch, VerifiedStorageBatch)
        or batch.runtime != runtime
        or len(batch.reads) != len(specs)
        or {read.spec for read in batch.reads} != set(specs)
    ):
        raise ValueError("historical control proof binding or coverage differs")
    values = {r.spec: r.decoded_value for r in batch.reads}
    actual_time = _uint(values[specs[0]], 2**53 - 1)
    if (
        not 0 < actual_time <= ceiling
        or (timestamp is not None and actual_time != timestamp)
        or values[specs[1]] is not True
    ):
        raise ValueError("historical control timestamp or subnet differs")
    control, committed = _control_value(values[specs[2]], ref.block_number)
    if (control, committed) != (
        archive.body["control_sha256"],
        archive.body["committed_at_block"],
    ):
        raise ValueError("historical control digest differs from proved storage")
    archive.consumed()
    return runtime, actual_time, control, committed


async def verify_write_archive(archive, tools, identity, *, hotkey, control, committed):
    archive.bind_parent(identity.parent_snapshot, tools.executor_sha256)
    if tools.executor is None:
        runtime = await tools.proofs.with_evidence_rpc(archive).pinned_runtime(
            identity.parent_snapshot, tools.pin
        )
    else:
        runtime = await collect_executed_runtime(
            tools.runtime_proofs.with_evidence_rpc(archive),
            tools.executor,
            identity.parent_snapshot,
        )
    tools.validate(runtime, identity.parent_snapshot)
    if (
        runtime.metadata_bytes != archive.metadata
        or runtime.runtime_version_bytes != archive.version_bytes
    ):
        raise ValueError("control write archive runtime differs from native replay")
    verifier = tools.proofs._verifier
    scanner = FinalizedBlockScanner(
        _ArchivePort(archive, identity, runtime),
        extrinsics_root_verifier=verifier.verify_extrinsics_root,
        event_proof_verifier=verifier,
        supported_runtime_pins=(runtime.pin,),
    )
    block, bindings = await scanner.decode_block_commitments(identity)
    archive.consumed()
    return checked_control_effects(
        identity.snapshot,
        hotkey,
        control,
        committed,
        block,
        bindings,
    )
