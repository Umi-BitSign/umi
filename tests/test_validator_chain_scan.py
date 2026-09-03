from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

import bittensor_core
import pytest

from umi.chain_evidence import FinalizedSnapshotRef, assert_shadow_no_weight_interval
from umi.validator_chain import FinalizedRuntimePin, PinnedRuntimeContext
from umi.validator_chain_scan import (
    FinalityAttestationReplayBinding,
    FinalizedBlockScanner,
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    ScanLimits,
    ValidatorChainScanError,
    VerifiedFinalizedBlockIdentity,
    finalized_block_body_sha256,
)

VALIDATOR = b"v" * 32
OTHER = b"o" * 32
SIGNATORY = b"s" * 32
METADATA = b"pinned-runtime-metadata"
PIN = FinalizedRuntimePin(
    metadata_sha256=hashlib.sha256(METADATA).hexdigest(),
    spec_version=449,
    transaction_version=1,
)


def block_hash(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def snapshot(height: int) -> FinalizedSnapshotRef:
    return FinalizedSnapshotRef(
        block_number=height,
        block_hash=block_hash(1_000 + height),
        parent_hash=block_hash(999 + height),
        state_root=block_hash(10_000 + height),
    )


def identity(height: int) -> VerifiedFinalizedBlockIdentity:
    return VerifiedFinalizedBlockIdentity(
        snapshot=snapshot(height),
        parent_snapshot=snapshot(height - 1),
        extrinsics_root=block_hash(20_000 + height),
        finality_verifier_sha256=(b"f" * 32).hex(),
        finality_evidence_sha256=(b"e" * 32).hex(),
    )


def arg(name: str, value: Any, type_name: str = "Any") -> dict[str, Any]:
    return {"name": name, "type": type_name, "value": value}


def call(
    module: str,
    function: str,
    args: list[dict[str, Any]] | None = None,
    *,
    marker: int = 1,
) -> dict[str, Any]:
    return {
        "call_index": "0x0000",
        "call_module": module,
        "call_function": function,
        "call_args": [] if args is None else args,
        "call_hash": block_hash(30_000 + marker),
    }


def extrinsic(raw: bytes, decoded_call: dict[str, Any], signer: bytes | None = None):
    value: dict[str, Any] = {
        "extrinsic_hash": "0x" + hashlib.blake2b(raw, digest_size=32).hexdigest(),
        "extrinsic_length": len(raw),
        "call": decoded_call,
    }
    if signer is not None:
        value["address"] = signer
    return value


def event(
    module: str,
    name: str,
    attributes: Any,
    *,
    extrinsic_index: int | None = 0,
) -> dict[str, Any]:
    phase = "ApplyExtrinsic" if extrinsic_index is not None else "Finalization"
    nested = {
        "event_index": "0000",
        "module_id": module,
        "event_id": name,
        "attributes": attributes,
    }
    return {
        "phase": phase,
        "extrinsic_idx": extrinsic_index,
        "event": nested,
        "event_index": 0,
        "module_id": module,
        "event_id": name,
        "attributes": attributes,
        "topics": [],
    }


def success(index: int = 0) -> dict[str, Any]:
    return event("System", "ExtrinsicSuccess", {}, extrinsic_index=index)


class Entry:
    modifier = "Default"
    default_bytes = b"\x00"
    value_type = "Vec<EventRecord>"


class FakeRuntime:
    def __init__(
        self,
        decoded_extrinsics: dict[bytes, dict[str, Any]],
        decoded_events: dict[bytes, list[dict[str, Any]]],
    ) -> None:
        self.decoded_extrinsics = decoded_extrinsics
        self.decoded_events = decoded_events

    def storage_key(self, pallet: str, item: str, params: list[Any]) -> bytes:
        assert (pallet, item, params) == ("System", "Events", [])
        return b"system-events-key"

    def storage_entry(self, pallet: str, item: str) -> Entry:
        assert (pallet, item) == ("System", "Events")
        return Entry()

    def decode(self, type_name: str, encoded: bytes, strict: bool = True) -> Any:
        assert type_name == "Vec<EventRecord>"
        assert strict is True
        return self.decoded_events[encoded]

    def decode_extrinsic(self, raw: bytes, strict: bool = True) -> dict[str, Any]:
        assert strict is True
        return self.decoded_extrinsics[raw]


def context(
    ref: FinalizedSnapshotRef,
    decoded_extrinsics: dict[bytes, dict[str, Any]],
    decoded_events: dict[bytes, list[dict[str, Any]]],
    *,
    pin: FinalizedRuntimePin = PIN,
    metadata: bytes = METADATA,
) -> PinnedRuntimeContext:
    return PinnedRuntimeContext(
        snapshot=ref,
        pin=pin,
        metadata_bytes=metadata,
        runtime_version_bytes=b"runtime-version",
        _runtime=FakeRuntime(decoded_extrinsics, decoded_events),
    )


class FakePort:
    def __init__(self) -> None:
        self.bodies: dict[int, RawFinalizedBlockBody | None] = {}
        self.events: dict[int, RawFinalizedEventStorage | None] = {}
        self.runtimes: dict[int, PinnedRuntimeContext | None] = {}

    async def block_body_at(self, item):
        return self.bodies.get(item.snapshot.block_number)

    async def event_storage_at(self, item, storage_key):
        assert storage_key == b"system-events-key"
        return self.events.get(item.snapshot.block_number)

    async def execution_runtime_at(self, item):
        return self.runtimes.get(item.snapshot.block_number)


def add_block(
    port: FakePort,
    item: VerifiedFinalizedBlockIdentity,
    decoded_calls: list[dict[str, Any]],
    decoded_events: list[dict[str, Any]],
    *,
    signers: list[bytes | None] | None = None,
    pin: FinalizedRuntimePin = PIN,
    metadata: bytes = METADATA,
) -> None:
    raw_extrinsics = tuple(
        b"extrinsic-" + item.snapshot.block_number.to_bytes(2, "big") + index.to_bytes(2, "big")
        for index in range(len(decoded_calls))
    )
    event_bytes = b"events-" + item.snapshot.block_number.to_bytes(2, "big")
    signer_values = signers or [None] * len(decoded_calls)
    decoded_extrinsics = {
        raw: extrinsic(raw, decoded_call, signer)
        for raw, decoded_call, signer in zip(
            raw_extrinsics, decoded_calls, signer_values, strict=True
        )
    }
    port.bodies[item.snapshot.block_number] = RawFinalizedBlockBody(
        block_hash=item.snapshot.block_hash,
        parent_hash=item.snapshot.parent_hash,
        state_root=item.snapshot.state_root,
        extrinsics_root=item.extrinsics_root,
        extrinsics=raw_extrinsics,
        body_sha256=finalized_block_body_sha256(raw_extrinsics),
    )
    port.events[item.snapshot.block_number] = RawFinalizedEventStorage(
        block_hash=item.snapshot.block_hash,
        state_root=item.snapshot.state_root,
        storage_key=b"system-events-key",
        value=event_bytes,
        proof=(b"proof-" + item.snapshot.block_number.to_bytes(2, "big"),),
        value_sha256=hashlib.sha256(event_bytes).hexdigest(),
    )
    port.runtimes[item.snapshot.block_number] = context(
        item.parent_snapshot,
        decoded_extrinsics,
        {event_bytes: decoded_events},
        pin=pin,
        metadata=metadata,
    )


def scanner(port: FakePort, **kwargs: Any) -> FinalizedBlockScanner:
    return FinalizedBlockScanner(
        port,
        extrinsics_root_verifier=lambda **_values: True,
        event_proof_verifier=lambda **_values: True,
        supported_runtime_pins=(PIN,),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_exact_complete_interval_returns_records_accepted_by_section_10_scan() -> None:
    port = FakePort()
    identities = (identity(40), identity(41))
    for item in identities:
        add_block(
            port,
            item,
            [call("Timestamp", "set", [arg("now", 123)], marker=item.snapshot.block_number)],
            [success()],
        )

    result = await scanner(port).decode_no_weight_interval(
        identities,
        start_block=40,
        end_block=41,
        validator_account=VALIDATOR,
    )

    assert result.scan.scanned_blocks == 2
    assert result.scan.scanned_calls == 2
    assert result.scan.scanned_events == 2
    assert [block.snapshot.block_number for block in result.blocks] == [40, 41]
    assert_shadow_no_weight_interval(
        result.blocks,
        start_block=40,
        end_block=41,
        validator_account=VALIDATOR,
    )


@pytest.mark.asyncio
async def test_capture_retains_every_exact_replay_input_and_binds_finality_bytes() -> None:
    attestations = (b"smoldot-attestation-80", b"smoldot-attestation-81")
    identities = tuple(
        replace(
            identity(height),
            finality_evidence_sha256=hashlib.sha256(attestation).hexdigest(),
        )
        for height, attestation in zip((80, 81), attestations, strict=True)
    )
    port = FakePort()
    for item in identities:
        add_block(
            port,
            item,
            [call("Timestamp", "set", [arg("now", 123)], marker=item.snapshot.block_number)],
            [success()],
        )

    result = await scanner(port).capture_no_weight_interval(
        identities,
        finality_attestations=attestations,
        finality_replay_bindings=tuple(
            FinalityAttestationReplayBinding(
                minimum_finalized_block=height,
                maximum_records=1,
                startup_timeout_seconds=60,
                expected_sequence=0,
                previous_number=None,
                previous_timestamp_ms=None,
            )
            for height in (80, 81)
        ),
        start_block=80,
        end_block=81,
        validator_account=VALIDATOR,
    )

    assert tuple(item.identity for item in result.evidence) == identities
    assert tuple(item.finality_attestation for item in result.evidence) == attestations
    assert tuple(item.body for item in result.evidence) == (port.bodies[80], port.bodies[81])
    assert tuple(item.event_storage for item in result.evidence) == (
        port.events[80],
        port.events[81],
    )
    assert tuple(item.decoded_block for item in result.evidence) == result.blocks

    with pytest.raises(ValidatorChainScanError, match="finality_evidence_mismatch"):
        await scanner(port).capture_no_weight_interval(
            identities,
            finality_attestations=(b"tampered", attestations[1]),
            finality_replay_bindings=tuple(
                item.finality_replay_binding for item in result.evidence
            ),
            start_block=80,
            end_block=81,
            validator_account=VALIDATOR,
        )


@pytest.mark.asyncio
async def test_generic_capture_retains_exact_root_sha256_commitment_binding() -> None:
    attestation = b"smoldot-attestation-82"
    item = replace(
        identity(82),
        finality_evidence_sha256=hashlib.sha256(attestation).hexdigest(),
    )
    root = "12" * 32
    port = FakePort()
    add_block(
        port,
        item,
        [
            call(
                "Commitments",
                "set_commitment",
                [
                    arg("netuid", 78),
                    arg("info", {"fields": [{"Sha256": "0x" + root}]}),
                ],
                marker=82,
            )
        ],
        [success()],
        signers=[VALIDATOR],
    )
    binding = FinalityAttestationReplayBinding(
        minimum_finalized_block=82,
        maximum_records=1,
        startup_timeout_seconds=60,
        expected_sequence=0,
        previous_number=None,
        previous_timestamp_ms=None,
    )

    result = await scanner(port).capture_blocks(
        (item,),
        finality_attestations=(attestation,),
        finality_replay_bindings=(binding,),
        start_block=82,
        end_block=82,
    )

    assert result.blocks == (result.evidence[0].decoded_block,)
    assert result.evidence[0].commitment_calls[0].extrinsic_index == 0
    assert result.evidence[0].commitment_calls[0].netuid == 78
    assert result.evidence[0].commitment_calls[0].field_sha256 == root


def weight_call(marker: int = 7) -> dict[str, Any]:
    return call(
        "SubtensorModule",
        "commit_timelocked_mechanism_weights",
        [arg("netuid", 78), arg("mecid", 0), arg("commit", b"x")],
        marker=marker,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("wrapper", ["batch", "proxy", "multisig", "sudo", "dispatch_as"])
async def test_hidden_nested_weight_calls_are_rejected_for_all_dispatch_origins(
    wrapper: str,
) -> None:
    port = FakePort()
    item = identity(50)
    inner = weight_call()
    signer = OTHER
    validator = VALIDATOR
    if wrapper == "batch":
        outer = call("Utility", "batch", [arg("calls", [inner])], marker=11)
        signer = validator
    elif wrapper == "proxy":
        outer = call(
            "Proxy",
            "proxy",
            [arg("real", validator), arg("force_proxy_type", None), arg("call", inner)],
            marker=12,
        )
    elif wrapper == "multisig":
        outer = call(
            "Multisig",
            "as_multi",
            [
                arg("threshold", 2),
                arg("other_signatories", [SIGNATORY]),
                arg("maybe_timepoint", None),
                arg("call", inner),
            ],
            marker=13,
        )
        validator, _ = bittensor_core.multisig_account_id([OTHER, SIGNATORY], 2)
    elif wrapper == "sudo":
        outer = call(
            "Sudo",
            "sudo_as",
            [arg("who", validator), arg("call", inner)],
            marker=14,
        )
    else:
        outer = call(
            "Utility",
            "dispatch_as",
            [arg("as_origin", {"system": {"Signed": validator}}), arg("call", inner)],
            marker=15,
        )
    add_block(port, item, [outer], [success()], signers=[signer])

    with pytest.raises(ValidatorChainScanError, match="shadow_no_weight_assertion_failed"):
        await scanner(port).decode_no_weight_interval(
            (item,),
            start_block=50,
            end_block=50,
            validator_account=validator,
        )


@pytest.mark.asyncio
async def test_sudo_root_weight_call_is_fail_closed_even_without_account_attribution() -> None:
    port = FakePort()
    item = identity(51)
    outer = call("Sudo", "sudo", [arg("call", weight_call())], marker=20)
    add_block(port, item, [outer], [success()], signers=[OTHER])

    with pytest.raises(ValidatorChainScanError, match="shadow_no_weight_assertion_failed"):
        await scanner(port).decode_no_weight_interval(
            (item,), start_block=51, end_block=51, validator_account=VALIDATOR
        )


@pytest.mark.asyncio
async def test_proxy_and_multisig_effective_origins_are_derived_exactly() -> None:
    port = FakePort()
    item = identity(52)
    nested = call("System", "remark", [arg("remark", b"x")], marker=22)
    proxy = call(
        "Proxy",
        "proxy",
        [arg("real", VALIDATOR), arg("force_proxy_type", None), arg("call", nested)],
        marker=23,
    )
    add_block(port, item, [proxy], [success()], signers=[OTHER])
    block = await scanner(port).decode_block(item)
    assert block.calls[0].children[0].effective_origin_account_id32 == VALIDATOR

    item2 = identity(53)
    multi = call(
        "Multisig",
        "as_multi_threshold_1",
        [arg("other_signatories", [SIGNATORY]), arg("call", nested)],
        marker=24,
    )
    add_block(port, item2, [multi], [success()], signers=[OTHER])
    block2 = await scanner(port).decode_block(item2)
    expected, _ = bittensor_core.multisig_account_id([OTHER, SIGNATORY], 1)
    assert block2.calls[0].children[0].effective_origin_account_id32 == expected


@pytest.mark.asyncio
async def test_batch_weight_target_cannot_hide_sn78_in_a_multi_target_list() -> None:
    port = FakePort()
    item = identity(54)
    batch = call(
        "SubtensorModule",
        "batch_commit_weights",
        [arg("netuids", [2, 78, 99]), arg("commit_hashes", [b"a", b"b", b"c"])],
        marker=25,
    )
    add_block(port, item, [batch], [success()], signers=[VALIDATOR])
    block = await scanner(port).decode_block(item)
    assert block.calls[0].netuid == 78
    assert block.calls[0].mechanism_id == 0
    with pytest.raises(ValidatorChainScanError, match="shadow_no_weight_assertion_failed"):
        await scanner(port).decode_no_weight_interval(
            (item,), start_block=54, end_block=54, validator_account=VALIDATOR
        )


@pytest.mark.asyncio
async def test_weights_batch_revealed_event_is_not_ignored_by_legacy_event_set() -> None:
    port = FakePort()
    item = identity(55)
    generic = call("Timestamp", "set", [arg("now", 1)], marker=26)
    revealed = event(
        "SubtensorModule",
        "WeightsBatchRevealed",
        [VALIDATOR, 78, [block_hash(1)]],
    )
    add_block(port, item, [generic], [revealed, success()])

    with pytest.raises(ValidatorChainScanError, match="shadow_interval_weight_event"):
        await scanner(port).decode_no_weight_interval(
            (item,), start_block=55, end_block=55, validator_account=VALIDATOR
        )


@pytest.mark.asyncio
async def test_weights_set_event_without_account_is_attributed_from_nested_call_origin() -> None:
    port = FakePort()
    item = identity(551)
    inner = call(
        "SubtensorModule",
        "set_mechanism_weights",
        [arg("netuid", 78), arg("mecid", 0), arg("dests", [1]), arg("weights", [1])],
        marker=261,
    )
    outer = call(
        "Proxy",
        "proxy",
        [arg("real", VALIDATOR), arg("force_proxy_type", None), arg("call", inner)],
        marker=262,
    )
    weights_set = event("SubtensorModule", "WeightsSet", [78, 7])
    add_block(port, item, [outer], [weights_set, success()], signers=[OTHER])

    block = await scanner(port).decode_block(item)
    assert block.events[0].account_id32 == VALIDATOR
    assert block.events[0].netuid == 78
    assert block.events[0].mechanism_id == 0
    with pytest.raises(ValidatorChainScanError, match="shadow_no_weight_assertion_failed"):
        await scanner(port).decode_no_weight_interval(
            (item,), start_block=551, end_block=551, validator_account=VALIDATOR
        )


@pytest.mark.asyncio
async def test_unknown_or_incomplete_wrapper_decode_fails_closed() -> None:
    port = FakePort()
    item = identity(56)
    hidden = call(
        "UnknownPallet",
        "dispatch",
        [arg("opaque", {"nested": weight_call()})],
        marker=27,
    )
    add_block(port, item, [hidden], [success()], signers=[VALIDATOR])
    with pytest.raises(ValidatorChainScanError, match="unknown_dispatch_wrapper"):
        await scanner(port).decode_block(item)

    raw = port.bodies[56].extrinsics[0]  # type: ignore[union-attr]
    runtime = port.runtimes[56]
    assert runtime is not None
    runtime._runtime.decoded_extrinsics[raw]["call"]["call_args"] = "not-a-complete-decode"
    with pytest.raises(ValidatorChainScanError, match="call_args_invalid"):
        await scanner(port).decode_block(item)


@pytest.mark.asyncio
async def test_missing_body_and_block_identity_mismatch_fail_closed() -> None:
    port = FakePort()
    item = identity(57)
    port.runtimes[57] = context(item.parent_snapshot, {}, {})
    with pytest.raises(ValidatorChainScanError, match="block_body_missing"):
        await scanner(port).decode_block(item)

    add_block(port, item, [call("Timestamp", "set", [arg("now", 1)])], [success()])
    body = port.bodies[57]
    assert body is not None
    port.bodies[57] = replace(body, block_hash=block_hash(123))
    with pytest.raises(ValidatorChainScanError, match="block_body_identity_mismatch"):
        await scanner(port).decode_block(item)


@pytest.mark.asyncio
async def test_extrinsic_hash_and_root_mismatch_fail_closed() -> None:
    port = FakePort()
    item = identity(58)
    add_block(port, item, [call("Timestamp", "set", [arg("now", 1)])], [success()])
    body = port.bodies[58]
    runtime = port.runtimes[58]
    assert body is not None and runtime is not None
    runtime._runtime.decoded_extrinsics[body.extrinsics[0]]["extrinsic_hash"] = block_hash(9)
    with pytest.raises(ValidatorChainScanError, match="extrinsic_hash_mismatch"):
        await scanner(port).decode_block(item)

    bad_root_scanner = FinalizedBlockScanner(
        port,
        extrinsics_root_verifier=lambda **_values: False,
        event_proof_verifier=lambda **_values: True,
        supported_runtime_pins=(PIN,),
    )
    with pytest.raises(ValidatorChainScanError, match="extrinsics_root_verification_failed"):
        await bad_root_scanner.decode_block(item)


@pytest.mark.asyncio
async def test_event_proof_and_event_count_fail_closed() -> None:
    port = FakePort()
    item = identity(59)
    add_block(port, item, [call("Timestamp", "set", [arg("now", 1)])], [success()])
    bad_proof = FinalizedBlockScanner(
        port,
        extrinsics_root_verifier=lambda **_values: True,
        event_proof_verifier=lambda **_values: False,
        supported_runtime_pins=(PIN,),
    )
    with pytest.raises(ValidatorChainScanError, match="event_proof_verification_failed"):
        await bad_proof.decode_block(item)

    runtime = port.runtimes[59]
    raw_events = port.events[59]
    assert runtime is not None and raw_events is not None and raw_events.value is not None
    runtime._runtime.decoded_events[raw_events.value].append(
        event("System", "CodeUpdated", None, extrinsic_index=None)
    )
    with pytest.raises(ValidatorChainScanError, match="event_count_limit"):
        await scanner(port, limits=ScanLimits(maximum_events_per_block=1)).decode_block(item)


@pytest.mark.asyncio
async def test_bounds_and_unsupported_runtime_fail_closed() -> None:
    port = FakePort()
    item = identity(60)
    calls = [
        call("Timestamp", "set", [arg("now", 1)], marker=30),
        call("System", "remark", [arg("remark", b"x")], marker=31),
    ]
    add_block(port, item, calls, [success(0), success(1)])
    with pytest.raises(ValidatorChainScanError, match="extrinsic_count_limit"):
        await scanner(port, limits=ScanLimits(maximum_extrinsics_per_block=1)).decode_block(item)

    other_metadata = b"other-runtime"
    other_pin = FinalizedRuntimePin(
        metadata_sha256=hashlib.sha256(other_metadata).hexdigest(),
        spec_version=450,
        transaction_version=1,
    )
    add_block(port, item, calls, [success(0), success(1)], pin=other_pin, metadata=other_metadata)
    with pytest.raises(ValidatorChainScanError, match="execution_runtime_unsupported"):
        await scanner(port).decode_block(item)


@pytest.mark.asyncio
async def test_interval_gap_duplicate_and_parent_mismatch_fail_before_fetch() -> None:
    port = FakePort()
    first = identity(70)
    third = identity(72)
    with pytest.raises(ValidatorChainScanError, match="scan_interval_incomplete"):
        await scanner(port).decode_blocks((first, third), start_block=70, end_block=72)
    with pytest.raises(ValidatorChainScanError, match="scan_interval_incomplete"):
        await scanner(port).decode_blocks((first, first), start_block=70, end_block=71)

    second = identity(71)
    alternate_parent = replace(snapshot(70), state_root=block_hash(99_999))
    wrong_parent = replace(second, parent_snapshot=alternate_parent)
    with pytest.raises(ValidatorChainScanError, match="scan_parent_identity_mismatch"):
        await scanner(port).decode_blocks((first, wrong_parent), start_block=70, end_block=71)


def test_raw_body_and_event_digests_bind_exact_bytes() -> None:
    digest = finalized_block_body_sha256((b"a", b"bc"))
    assert digest != finalized_block_body_sha256((b"ab", b"c"))
    with pytest.raises(ValueError, match="body digest"):
        RawFinalizedBlockBody(
            block_hash=block_hash(1),
            parent_hash=block_hash(0),
            state_root=block_hash(2),
            extrinsics_root=block_hash(3),
            extrinsics=(b"one",),
            body_sha256="00" * 32,
        )
    with pytest.raises(ValueError, match="storage digest"):
        RawFinalizedEventStorage(
            block_hash=block_hash(1),
            state_root=block_hash(2),
            storage_key=b"events",
            value=b"one",
            proof=(b"node",),
            value_sha256="00" * 32,
        )
