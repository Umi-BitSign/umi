from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

import umi.chain_evidence as chain_evidence
from umi.chain_evidence import (
    CoreObservation,
    CorePin,
    FinalizedBlockRecord,
    FinalizedCallRecord,
    FinalizedEventRecord,
    FinalizedSnapshotRef,
    RuntimeSpecObservation,
    RuntimeSpecPin,
    StorageEvidence,
    WeightScheduleSnapshot,
    assert_shadow_no_weight_interval,
    build_crv4_weight_commit,
    build_sha256_commitment_call,
    require_core_pin,
    require_runtime_spec_pin,
)


def block_hash(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def digest(value: int) -> str:
    return value.to_bytes(32, "big").hex()


def snapshot(height: int) -> FinalizedSnapshotRef:
    return FinalizedSnapshotRef(
        block_number=height,
        block_hash=block_hash(height + 1),
        parent_hash=block_hash(height),
        state_root=block_hash(10_000 + height),
    )


def schedule() -> WeightScheduleSnapshot:
    return WeightScheduleSnapshot(
        block_number=1_000,
        block_hash=block_hash(1_001),
        tempo=360,
        last_epoch_block=900,
        pending_epoch_at=0,
        subnet_epoch_index=23,
        blocks_since_last_step=100,
        reveal_period_epochs=1,
        block_time=12.0,
    )


def generic_call(ref: FinalizedSnapshotRef, index: int = 0) -> FinalizedCallRecord:
    return FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=index,
        call_hash=block_hash(ref.block_number * 10 + index + 1),
        module="Timestamp",
        function="set",
        successful=True,
        recursive_decode_complete=True,
        declared_child_count=0,
        call_path=(),
    )


def block_record(ref: FinalizedSnapshotRef) -> FinalizedBlockRecord:
    return FinalizedBlockRecord(
        snapshot=ref,
        extrinsic_count=1,
        event_count=0,
        calls=(generic_call(ref),),
        events=(),
    )


def weight_call_node(
    ref: FinalizedSnapshotRef,
    *,
    path: tuple[int, ...],
    origin: bytes | None,
    value: int = 700,
    complete: bool = True,
) -> FinalizedCallRecord:
    return FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(value),
        module="SubtensorModule",
        function="commit_timelocked_mechanism_weights",
        successful=False,
        recursive_decode_complete=complete,
        declared_child_count=0,
        call_path=path,
        effective_origin_account_id32=origin,
        netuid=78,
        mechanism_id=0,
    )


def wrapped_block(ref: FinalizedSnapshotRef, root: FinalizedCallRecord) -> FinalizedBlockRecord:
    return FinalizedBlockRecord(
        snapshot=ref,
        extrinsic_count=1,
        event_count=0,
        calls=(root,),
        events=(),
    )


def test_finalized_snapshot_is_strict_and_immutable() -> None:
    ref = snapshot(10)
    with pytest.raises(FrozenInstanceError):
        ref.block_number = 11  # type: ignore[misc]
    with pytest.raises(ValueError, match="0x-prefixed"):
        replace(ref, state_root="ab" * 32)
    with pytest.raises(ValueError, match="cannot name itself"):
        replace(ref, parent_hash=ref.block_hash)


def test_storage_evidence_requires_proof_verification_and_matching_root() -> None:
    ref = snapshot(10)
    observed: dict[str, object] = {}

    def verifier(**kwargs):
        observed.update(kwargs)
        return bytes.fromhex(ref.state_root[2:])

    evidence = StorageEvidence(
        snapshot=ref,
        storage_key=b"\x12key",
        value=None,
        proof=(b"node-one", b"node-two"),
        verifier=verifier,
    )
    assert evidence.verified_state_root == ref.state_root
    assert evidence.proof == (b"node-one", b"node-two")
    assert observed == {
        "block_hash": ref.block_hash,
        "storage_key": b"\x12key",
        "expected_value": None,
        "proof": (b"node-one", b"node-two"),
    }
    with pytest.raises(FrozenInstanceError):
        evidence.value = b"replacement"  # type: ignore[misc]

    with pytest.raises(ValueError, match="does not match"):
        StorageEvidence(
            snapshot=ref,
            storage_key=b"key",
            value=b"value",
            proof=(b"node",),
            verifier=lambda **_kwargs: block_hash(999),
        )
    with pytest.raises(ValueError, match="must return"):
        StorageEvidence(
            snapshot=ref,
            storage_key=b"key",
            value=b"value",
            proof=(b"node",),
            verifier=lambda **_kwargs: True,
        )
    with pytest.raises(TypeError, match="verifier"):
        StorageEvidence(  # type: ignore[call-arg]
            snapshot=ref,
            storage_key=b"key",
            value=b"value",
            proof=(b"node",),
        )


def test_storage_evidence_wraps_verifier_failure() -> None:
    def failed_verifier(**_kwargs):
        raise RuntimeError("invalid trie proof")

    with pytest.raises(ValueError, match="verification failed") as error:
        StorageEvidence(
            snapshot=snapshot(2),
            storage_key=b"key",
            value=b"value",
            proof=(b"node",),
            verifier=failed_verifier,
        )
    assert isinstance(error.value.__cause__, RuntimeError)


def test_crv4_builder_uses_exactly_one_schedule_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    schedule_ref = schedule()
    captured: dict[str, object] = {}

    def fake_encrypt(**kwargs):
        captured.update(kwargs)
        return b"ciphertext", 123_456

    monkeypatch.setattr(chain_evidence.bittensor_core, "get_encrypted_commit_v2", fake_encrypt)
    built = build_crv4_weight_commit(
        schedule=schedule_ref,
        uids=(3, 7),
        weights=(65_535, 12_345),
        weights_version_key=91,
        hotkey_public_key=b"h" * 32,
    )

    assert captured == {
        "uids": [3, 7],
        "weights": [65_535, 12_345],
        "version_key": 91,
        "last_epoch_block": schedule_ref.last_epoch_block,
        "pending_epoch_at": schedule_ref.pending_epoch_at,
        "subnet_epoch_index": schedule_ref.subnet_epoch_index,
        "tempo": schedule_ref.tempo,
        "blocks_since_last_step": schedule_ref.blocks_since_last_step,
        "current_block": schedule_ref.block_number,
        "subnet_reveal_period_epochs": schedule_ref.reveal_period_epochs,
        "block_time": schedule_ref.block_time,
        "hotkey": b"h" * 32,
    }
    assert built.schedule is schedule_ref
    assert built.ciphertext == b"ciphertext"
    assert built.reveal_round == 123_456
    assert built.raw_call.module == "SubtensorModule"
    assert built.raw_call.function == "commit_timelocked_mechanism_weights"
    assert built.raw_call.params == {
        "netuid": 78,
        "mecid": 0,
        "commit": b"ciphertext",
        "reveal_round": 123_456,
        "commit_reveal_version": 4,
    }


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"uids": (), "weights": ()}, "non-empty parallel"),
        ({"uids": (1, 1), "weights": (1, 2)}, "unique"),
        ({"uids": (1,), "weights": (0,)}, "must be positive"),
        ({"uids": (65_536,), "weights": (1,)}, "out of range"),
        ({"hotkey_public_key": b"short"}, "exactly 32 bytes"),
        ({"netuid": 1}, "pinned to SN78"),
    ],
)
def test_crv4_builder_fails_before_encryption_on_invalid_input(
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, object],
    message: str,
) -> None:
    monkeypatch.setattr(
        chain_evidence.bittensor_core,
        "get_encrypted_commit_v2",
        lambda **_kwargs: pytest.fail("invalid input reached the ciphertext builder"),
    )
    arguments = {
        "schedule": schedule(),
        "uids": (1,),
        "weights": (1,),
        "weights_version_key": 1,
        "hotkey_public_key": b"h" * 32,
    }
    arguments.update(changes)
    with pytest.raises(ValueError, match=message):
        build_crv4_weight_commit(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "core_result",
    [
        (b"", 12),
        (bytearray(b"cipher"), 12),
        (b"cipher", 0),
        (b"cipher", True),
    ],
)
def test_crv4_builder_rejects_invalid_core_output(
    monkeypatch: pytest.MonkeyPatch,
    core_result: tuple[object, object],
) -> None:
    monkeypatch.setattr(
        chain_evidence.bittensor_core,
        "get_encrypted_commit_v2",
        lambda **_kwargs: core_result,
    )
    with pytest.raises((TypeError, ValueError)):
        build_crv4_weight_commit(
            schedule=schedule(),
            uids=(1,),
            weights=(1,),
            weights_version_key=1,
            hotkey_public_key=b"h" * 32,
        )


def test_sha256_commitment_builder_has_one_typed_field() -> None:
    raw_digest = bytes(range(32))
    call = build_sha256_commitment_call(raw_digest)
    assert call.module == "Commitments"
    assert call.function == "set_commitment"
    assert call.params == {
        "netuid": 78,
        "info": {"fields": [{"Sha256": raw_digest}]},
    }
    assert build_sha256_commitment_call(raw_digest.hex()) == call
    with pytest.raises(ValueError, match="pinned to SN78"):
        build_sha256_commitment_call(raw_digest, netuid=1)


def test_complete_shadow_interval_passes_and_reports_counts() -> None:
    blocks = tuple(block_record(snapshot(height)) for height in range(10, 13))
    result = assert_shadow_no_weight_interval(
        blocks,
        start_block=10,
        end_block=12,
        validator_account=b"v" * 32,
    )
    assert result.start_snapshot == blocks[0].snapshot
    assert result.end_snapshot == blocks[-1].snapshot
    assert result.scanned_blocks == 3
    assert result.scanned_calls == 3
    assert result.scanned_events == 0


def test_shadow_scan_rejects_height_gap_and_parent_fork() -> None:
    blocks = (block_record(snapshot(10)), block_record(snapshot(12)))
    with pytest.raises(ValueError, match="incomplete"):
        assert_shadow_no_weight_interval(
            blocks,
            start_block=10,
            end_block=12,
            validator_account=b"v" * 32,
        )

    first = block_record(snapshot(10))
    forked_ref = replace(snapshot(11), parent_hash=block_hash(999))
    with pytest.raises(ValueError, match="contiguous"):
        assert_shadow_no_weight_interval(
            (first, block_record(forked_ref)),
            start_block=10,
            end_block=11,
            validator_account=b"v" * 32,
        )


def test_finalized_block_record_requires_complete_call_and_event_indexes() -> None:
    ref = snapshot(10)
    with pytest.raises(ValueError, match="every outer extrinsic"):
        FinalizedBlockRecord(
            snapshot=ref,
            extrinsic_count=2,
            event_count=0,
            calls=(generic_call(ref, 0),),
            events=(),
        )
    event = FinalizedEventRecord(
        snapshot=ref,
        event_index=1,
        payload_sha256=digest(1),
        module="System",
        event="ExtrinsicSuccess",
        extrinsic_index=0,
    )
    with pytest.raises(ValueError, match="every event"):
        FinalizedBlockRecord(
            snapshot=ref,
            extrinsic_count=1,
            event_count=1,
            calls=(generic_call(ref),),
            events=(event,),
        )


def test_finalized_block_allows_identical_calls_in_distinct_extrinsics() -> None:
    ref = snapshot(10)
    first = generic_call(ref, 0)
    second = replace(generic_call(ref, 1), call_hash=first.call_hash)
    block = FinalizedBlockRecord(
        snapshot=ref,
        extrinsic_count=2,
        event_count=0,
        calls=(first, second),
        events=(),
    )
    scan = assert_shadow_no_weight_interval(
        (block,),
        start_block=10,
        end_block=10,
        validator_account=b"v" * 32,
    )
    assert scan.scanned_calls == 2


def test_shadow_scan_rejects_even_a_failed_weight_call() -> None:
    ref = snapshot(10)
    weight_call = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(500),
        module="SubtensorModule",
        function="commit_timelocked_mechanism_weights",
        successful=False,
        recursive_decode_complete=True,
        declared_child_count=0,
        call_path=(),
        signer_account_id32=b"v" * 32,
        netuid=78,
        mechanism_id=0,
    )
    block = FinalizedBlockRecord(
        snapshot=ref,
        extrinsic_count=1,
        event_count=0,
        calls=(weight_call,),
        events=(),
    )
    with pytest.raises(ValueError, match="weight call"):
        assert_shadow_no_weight_interval(
            (block,),
            start_block=10,
            end_block=10,
            validator_account=b"v" * 32,
        )


def test_shadow_scan_traverses_failed_utility_batch_children() -> None:
    ref = snapshot(10)
    nested_weight = weight_call_node(ref, path=(0,), origin=b"v" * 32)
    utility_batch = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(701),
        module="Utility",
        function="batch",
        successful=False,
        recursive_decode_complete=True,
        declared_child_count=1,
        call_path=(),
        signer_account_id32=b"v" * 32,
        children=(nested_weight,),
    )
    with pytest.raises(ValueError, match="weight call"):
        assert_shadow_no_weight_interval(
            (wrapped_block(ref, utility_batch),),
            start_block=10,
            end_block=10,
            validator_account=b"v" * 32,
        )


def test_shadow_scan_uses_proxy_effective_origin_not_outer_signer() -> None:
    ref = snapshot(10)
    proxied_weight = weight_call_node(ref, path=(0,), origin=b"v" * 32, value=702)
    proxy_call = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(703),
        module="Proxy",
        function="proxy",
        successful=False,
        recursive_decode_complete=True,
        declared_child_count=1,
        call_path=(),
        signer_account_id32=b"d" * 32,
        effective_origin_account_id32=b"d" * 32,
        children=(proxied_weight,),
    )
    with pytest.raises(ValueError, match="weight call"):
        assert_shadow_no_weight_interval(
            (wrapped_block(ref, proxy_call),),
            start_block=10,
            end_block=10,
            validator_account=b"v" * 32,
        )


def test_shadow_scan_traverses_deep_multisig_and_custom_call_trees() -> None:
    ref = snapshot(10)
    nested_weight = weight_call_node(ref, path=(0, 0), origin=b"v" * 32, value=704)
    custom_wrapper = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(705),
        module="ExampleWrapper",
        function="dispatch_nested",
        successful=False,
        recursive_decode_complete=True,
        declared_child_count=1,
        call_path=(0,),
        effective_origin_account_id32=b"v" * 32,
        children=(nested_weight,),
    )
    multisig = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(706),
        module="Multisig",
        function="as_multi",
        successful=False,
        recursive_decode_complete=True,
        declared_child_count=1,
        call_path=(),
        signer_account_id32=b"p" * 32,
        effective_origin_account_id32=b"m" * 32,
        children=(custom_wrapper,),
    )
    with pytest.raises(ValueError, match="weight call"):
        assert_shadow_no_weight_interval(
            (wrapped_block(ref, multisig),),
            start_block=10,
            end_block=10,
            validator_account=b"v" * 32,
        )


def test_shadow_scan_rejects_incomplete_recursive_decode_at_any_depth() -> None:
    ref = snapshot(10)
    incomplete_child = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(707),
        module="Proxy",
        function="proxy",
        successful=False,
        recursive_decode_complete=False,
        declared_child_count=0,
        call_path=(0,),
        effective_origin_account_id32=b"v" * 32,
    )
    outer = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(708),
        module="Utility",
        function="batch_all",
        successful=False,
        recursive_decode_complete=True,
        declared_child_count=1,
        call_path=(),
        signer_account_id32=b"v" * 32,
        children=(incomplete_child,),
    )
    with pytest.raises(ValueError, match="incomplete recursive decoding"):
        assert_shadow_no_weight_interval(
            (wrapped_block(ref, outer),),
            start_block=10,
            end_block=10,
            validator_account=b"v" * 32,
        )


@pytest.mark.parametrize(
    ("module", "function"),
    [
        ("Utility", "batch"),
        ("Proxy", "proxy"),
        ("Multisig", "as_multi"),
        ("Sudo", "sudo"),
        ("Scheduler", "schedule"),
    ],
)
def test_known_dispatch_wrapper_cannot_claim_a_complete_empty_tree(
    module: str,
    function: str,
) -> None:
    ref = snapshot(10)
    omitted_children = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(799),
        module=module,
        function=function,
        successful=False,
        recursive_decode_complete=True,
        declared_child_count=0,
        call_path=(),
        signer_account_id32=b"v" * 32,
    )
    with pytest.raises(ValueError, match="lacks recursively decoded"):
        assert_shadow_no_weight_interval(
            (wrapped_block(ref, omitted_children),),
            start_block=10,
            end_block=10,
            validator_account=b"v" * 32,
        )


def test_shadow_scan_rejects_unresolved_nested_weight_origin() -> None:
    ref = snapshot(10)
    unresolved_weight = weight_call_node(ref, path=(0,), origin=None, value=709)
    outer = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(710),
        module="Utility",
        function="as_derivative",
        successful=False,
        recursive_decode_complete=True,
        declared_child_count=1,
        call_path=(),
        signer_account_id32=b"v" * 32,
        children=(unresolved_weight,),
    )
    with pytest.raises(ValueError, match="effective origin"):
        assert_shadow_no_weight_interval(
            (wrapped_block(ref, outer),),
            start_block=10,
            end_block=10,
            validator_account=b"v" * 32,
        )


def test_call_tree_rejects_missing_children_wrong_paths_and_nested_signers() -> None:
    ref = snapshot(10)
    child = weight_call_node(ref, path=(0,), origin=b"o" * 32, value=711)
    common = {
        "snapshot": ref,
        "extrinsic_index": 0,
        "call_hash": block_hash(712),
        "module": "Utility",
        "function": "batch",
        "successful": False,
        "recursive_decode_complete": True,
        "call_path": (),
    }
    with pytest.raises(ValueError, match="declared_child_count"):
        FinalizedCallRecord(**common, declared_child_count=2, children=(child,))

    wrong_path = weight_call_node(ref, path=(1,), origin=b"o" * 32, value=713)
    with pytest.raises(ValueError, match="position-derived"):
        FinalizedCallRecord(**common, declared_child_count=1, children=(wrong_path,))

    signed_child = replace(child, signer_account_id32=b"o" * 32)
    with pytest.raises(ValueError, match="only the outer"):
        FinalizedCallRecord(**common, declared_child_count=1, children=(signed_child,))


def test_nested_non_validator_weight_is_counted_but_allowed() -> None:
    ref = snapshot(10)
    other_weight = weight_call_node(ref, path=(0,), origin=b"o" * 32, value=714)
    outer = FinalizedCallRecord(
        snapshot=ref,
        extrinsic_index=0,
        call_hash=block_hash(715),
        module="Utility",
        function="batch",
        successful=True,
        recursive_decode_complete=True,
        declared_child_count=1,
        call_path=(),
        signer_account_id32=b"o" * 32,
        children=(other_weight,),
    )
    result = assert_shadow_no_weight_interval(
        (wrapped_block(ref, outer),),
        start_block=10,
        end_block=10,
        validator_account=b"v" * 32,
    )
    assert result.scanned_calls == 2


def test_shadow_scan_rejects_weight_event_and_allows_another_validator() -> None:
    ref = snapshot(10)

    def block_with_event(account: bytes) -> FinalizedBlockRecord:
        event = FinalizedEventRecord(
            snapshot=ref,
            event_index=0,
            payload_sha256=digest(2),
            module="SubtensorModule",
            event="TimelockedWeightsCommitted",
            extrinsic_index=0,
            account_id32=account,
            netuid=78,
            mechanism_id=0,
        )
        return FinalizedBlockRecord(
            snapshot=ref,
            extrinsic_count=1,
            event_count=1,
            calls=(generic_call(ref),),
            events=(event,),
        )

    other_validator = block_with_event(b"o" * 32)
    assert_shadow_no_weight_interval(
        (other_validator,),
        start_block=10,
        end_block=10,
        validator_account=b"v" * 32,
    )
    with pytest.raises(ValueError, match="weight event"):
        assert_shadow_no_weight_interval(
            (block_with_event(b"v" * 32),),
            start_block=10,
            end_block=10,
            validator_account=b"v" * 32,
        )


def test_runtime_and_core_guards_require_exact_pins() -> None:
    ref = snapshot(10)
    runtime_pin = RuntimeSpecPin(
        spec_version=449,
        metadata_sha256=digest(1),
    )
    runtime = RuntimeSpecObservation(
        snapshot=ref,
        spec_version=449,
        metadata_sha256=digest(1),
        mechanism_count=1,
        commit_reveal_enabled=True,
        commit_reveal_version=4,
    )
    require_runtime_spec_pin(runtime, runtime_pin)

    for changed in (
        replace(runtime, spec_version=450),
        replace(runtime, metadata_sha256=digest(2)),
        replace(runtime, mechanism_count=2),
        replace(runtime, commit_reveal_enabled=False),
        replace(runtime, commit_reveal_version=3),
    ):
        with pytest.raises(ValueError):
            require_runtime_spec_pin(changed, runtime_pin)

    core_pin = CorePin(revision="core-1", content_sha256=digest(3))
    core = CoreObservation(revision="core-1", content_sha256=digest(3))
    require_core_pin(core, core_pin)
    with pytest.raises(ValueError, match="does not match"):
        require_core_pin(replace(core, revision="core-2"), core_pin)
    with pytest.raises(ValueError, match="does not match"):
        require_core_pin(replace(core, content_sha256=digest(4)), core_pin)


def test_runtime_pin_cannot_weaken_mechanism_or_crv4() -> None:
    with pytest.raises(ValueError, match="exactly one mechanism"):
        RuntimeSpecPin(spec_version=449, metadata_sha256=digest(1), mechanism_count=2)
    with pytest.raises(ValueError, match="version 4"):
        RuntimeSpecPin(
            spec_version=449,
            metadata_sha256=digest(1),
            commit_reveal_version=3,
        )
