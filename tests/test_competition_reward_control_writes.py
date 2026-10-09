"""Native block/slot consumers with synthetic RPC, trie and codec ports."""

import asyncio
import json
import threading
from contextlib import suppress
from dataclasses import replace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_reward_control_writes import capture_control_writes, validate_control_writes
from umi.encoding import account_id32
from umi.finalized_ancestry import encode_rpc_header
from umi.grandpa_finality import _decode_header
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_chain import PinnedRuntimeContext
from umi.validator_chain_scan import FinalizedBlockScanner, ScanLimits

from . import test_competition_reward_control_archive as archive_tests
from .test_competition_reward_control import commitment
from .test_competition_reward_control_capture import (
    capture_source,
)
from .test_competition_reward_control_capture import (
    chain as chain,
)
from .test_competition_reward_control_capture import (
    chain_config as chain_config,
)
from .test_competition_reward_control_capture import (
    control as control,
)
from .test_competition_reward_control_capture import (
    historical as historical,
)
from .test_competition_reward_control_capture import (
    policy as policy,
)
from .test_competition_reward_control_capture import (
    series_case as series_case,
)
from .test_finalized_ancestry import make_headers
from .test_validator_chain_scan import arg, call, context, event, extrinsic, success


def commit(value, netuid=78):
    return call(
        "Commitments",
        "set_commitment",
        [arg("netuid", netuid), arg("info", {"fields": [{"Sha256": "0x" + value}]})],
    )


@pytest.fixture
async def block_case(historical, monkeypatch):
    h = historical
    # Include an authenticated parent whose runtime executes the target block.
    monkeypatch.setattr(
        archive_tests, "make_headers", lambda start, end: make_headers(start - 1, end)
    )
    h.item.rpc.values[h.item.spec] = commitment("bb" * 32, h.old.height)
    source = await capture_source(h, monkeypatch)
    h.source = source
    block_header = source.w.headers[source.w.original.block_hash]
    parent = source.w.headers[block_header["parentHash"]]
    decoded = _decode_header(encode_rpc_header(parent), maximum_bytes=1024**2)
    parent_ref = FinalizedSnapshotRef(
        decoded["number"], decoded["hash"], decoded["parent_hash"], decoded["state_root"]
    )
    raw = (b"first-write", b"second-write")
    calls = [commit("aa" * 32), commit("bb" * 32)]
    events = [success(0), success(1)]
    h.body_calls = calls
    h.events = events
    h.event_bytes = b"events"
    h.raw = raw
    h.fault = None
    h.parent_ref = parent_ref
    h.signers = [account_id32(h.item.hotkey)] * 2
    h.runtime_change = lambda runtime: runtime
    h.block_started = asyncio.Event()
    h.block_release = None
    original_runtime = h.item.provider._runtime_context

    async def runtime(ref):
        if ref != parent_ref:
            return await original_runtime(ref)
        selected = context(
            ref,
            {
                encoded: extrinsic(encoded, c, signer)
                for encoded, c, signer in zip(raw, calls, h.signers, strict=True)
            },
            {h.event_bytes: events},
            pin=h.item.provider._runtime_pin,
            metadata=h.metadata,
        )
        pin = selected.pin
        return h.runtime_change(
            replace(
                selected,
                runtime_version_bytes=canonical_json_bytes(
                    {
                        "specVersion": pin.spec_version,
                        "transactionVersion": pin.transaction_version,
                        "stateVersion": pin.state_version,
                    }
                ),
            )
        )

    monkeypatch.setattr(h.item.provider, "_runtime_context", runtime)

    async def request(method, params):
        if method == "chain_getBlock":
            assert params == (source.w.original.block_hash,)
            h.block_started.set()
            if h.block_release is not None:
                await h.block_release.wait()
            header = dict(block_header)
            if h.fault == "header":
                header["parentHash"] = "0x" + "99" * 32
            return {"block": {"header": header, "extrinsics": ["0x" + v.hex() for v in raw]}}
        if method == "state_getStorageAt" and params[0] == "0x" + b"system-events-key".hex():
            assert params[1] == source.w.original.block_hash
            return "0x" + h.event_bytes.hex()
        if method == "state_getReadProof" and tuple(params[0]) == (
            "0x" + b"system-events-key".hex(),
        ):
            return {"at": source.w.original.block_hash, "proof": ["0x" + b"event-proof".hex()]}
        return await source.request(method, params)

    monkeypatch.setattr(h.item.provider._registration_rpc, "request", request)
    h.capture_request = request
    # The proof collector uses the same endpoint with its native bounds.
    monkeypatch.setattr(h.item.proofs._rpc, "request", request)

    def verify_body(**kw):
        assert kw["expected_root"] == bytes.fromhex(block_header["extrinsicsRoot"][2:])
        assert kw["extrinsics"] == raw and kw["state_version"] == 0
        return h.fault != "body"

    monkeypatch.setattr(h.item.verifier, "verify_extrinsics_root", verify_body, raising=False)
    old_verify = type(h.item.verifier).__call__

    def verify_events(self, **kw):
        if kw["storage_key"] == b"system-events-key":
            return (
                h.fault != "events"
                and kw["state_root"] == bytes.fromhex(block_header["stateRoot"][2:])
                and kw["expected_value"] == h.event_bytes
                and kw["proof"] == (b"event-proof",)
            )
        return old_verify(self, **kw)

    monkeypatch.setattr(type(h.item.verifier), "__call__", verify_events)
    return h


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_preserves_each_successful_write_in_block_order(block_case):
    h = block_case
    result = await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)
    validate_control_writes(
        result,
        expected_control_hotkey=h.item.hotkey,
        expected_chain_config_sha256=digest(h.item.config),
    )
    assert [(w.extrinsic_index, w.decision_sha256) for w in result.writes] == [
        (0, "aa" * 32),
        (1, "bb" * 32),
    ]
    assert not result.unresolved_extrinsics
    evidence = json.loads(result.evidence)
    assert evidence["finality_provenance"] == "owned_finalized_ancestry"
    assert not evidence["chain_submission_authorized"]
    assert evidence["runtime_metadata"] == h.metadata.hex()
    with pytest.raises(ValueError):
        validate_control_writes(
            replace(result, writes=()),
            expected_control_hotkey=h.item.hotkey,
            expected_chain_config_sha256=digest(h.item.config),
        )


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("fault", ["body", "events", "header"])
async def test_rejects_corrupt_body_header_or_event_proof(block_case, fault):
    h = block_case
    h.fault = fault
    expected = {
        "body": "extrinsics_root_verification_failed",
        "events": "event_storage_fetch_failed",
        "header": "block_body_fetch_failed",
    }
    with pytest.raises(RuntimeError, match=expected[fault]):
        await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_failed_direct_write_does_not_count_as_revocation(block_case):
    h = block_case
    h.events[0] = event("System", "ExtrinsicFailed", {}, extrinsic_index=0)
    result = await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)
    assert [(w.extrinsic_index, w.decision_sha256) for w in result.writes] == [(1, "bb" * 32)]


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_wrapped_write_is_unresolved_even_with_outer_success(block_case):
    h = block_case
    h.body_calls[0] = call("Utility", "batch", [arg("calls", [commit("aa" * 32)])])
    result = await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)
    assert result.unresolved_extrinsics == (0,)
    assert [(w.extrinsic_index, w.decision_sha256) for w in result.writes] == [(1, "bb" * 32)]


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_last_write_must_match_independent_post_state(block_case):
    h = block_case
    h.body_calls[1] = commit("cc" * 32)
    with pytest.raises(ValueError, match="post-state"):
        await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("foreign", ["signer", "subnet"])
async def test_other_control_accounts_and_subnets_do_not_change_this_history(block_case, foreign):
    h = block_case
    if foreign == "signer":
        h.signers[0] = b"other-control".ljust(32, b"!")
    else:
        h.body_calls[0] = commit("aa" * 32, netuid=1)
    result = await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)
    assert [(w.extrinsic_index, w.decision_sha256) for w in result.writes] == [(1, "bb" * 32)]
    assert not result.unresolved_extrinsics


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_malformed_or_uninterpreted_commitment_is_not_silently_omitted(block_case):
    h = block_case
    h.body_calls[0] = call(
        "Commitments",
        "set_commitment",
        [arg("netuid", 78), arg("info", {"fields": [{"Raw0": None}]})],
    )
    result = await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)
    assert result.unresolved_extrinsics == (0,)


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("changed", ["parent", "storage_only"])
async def test_execution_uses_actual_parent_runtime(block_case, changed):
    h = block_case

    class StorageOnly(PinnedRuntimeContext):
        @property
        def storage_codec_mode(self):
            return "reviewed_storage_codec/1"

    if changed == "parent":
        h.runtime_change = lambda r: replace(
            r, snapshot=replace(r.snapshot, state_root="0x" + "ab" * 32)
        )
    else:
        h.runtime_change = lambda r: StorageOnly(
            r.snapshot, r.pin, r.metadata_bytes, r.runtime_version_bytes, r._runtime
        )
    with pytest.raises(ValueError, match="runtime"):
        await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_missing_extrinsic_outcome_leaves_block_unproven(block_case):
    h = block_case
    h.events.pop()
    with pytest.raises(RuntimeError, match="extrinsic_status_coverage_invalid"):
        await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_close_waits_for_owned_capture_and_cancellation_releases_lock(block_case):
    h = block_case
    h.block_release = asyncio.Event()
    capture = asyncio.create_task(
        capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)
    )
    await asyncio.wait_for(h.block_started.wait(), 5)
    closing = asyncio.create_task(h.item.provider.aclose())
    await asyncio.sleep(0)
    assert not closing.done() and h.item.provider._lock.locked()
    capture.cancel()
    with pytest.raises(asyncio.CancelledError):
        await capture
    await asyncio.wait_for(closing, 5)
    assert not h.item.provider._lock.locked()


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_large_events_do_not_enlarge_ordinary_weight_proof_limits(block_case):
    h = block_case
    h.item.proofs._limits = replace(h.item.proofs._limits, maximum_storage_value_bytes=65536)
    original_limits = h.item.proofs._limits
    h.event_bytes = b"e" * (65536 + 1)
    result = await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)
    assert len(result.writes) == 2
    assert bytes.fromhex(json.loads(result.evidence)["events"]["value"]) == h.event_bytes
    assert h.item.proofs._limits == original_limits


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_event_collection_still_enforces_its_own_limit(block_case, monkeypatch):
    import umi.competition_reward_control_writes as module

    h = block_case
    monkeypatch.setattr(module, "ScanLimits", lambda: ScanLimits(maximum_event_storage_bytes=5))
    with pytest.raises(RuntimeError, match="event_storage_fetch_failed"):
        await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("stage", ["body", "events", "decode"])
async def test_slow_block_work_keeps_loop_responsive_and_drains_on_close(
    block_case, monkeypatch, stage
):
    h = block_case
    started, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()

    def wait():
        loop.call_soon_threadsafe(started.set)
        assert release.wait(5), "proof thread was abandoned or blocked the event loop"

    if stage == "body":
        original = h.item.verifier.verify_extrinsics_root

        def verify(**kw):
            wait()
            return original(**kw)

        monkeypatch.setattr(h.item.verifier, "verify_extrinsics_root", verify)
    elif stage == "events":
        original = type(h.item.verifier).__call__
        calls = 0

        def verify(self, **kw):
            nonlocal calls
            if kw["storage_key"] == b"system-events-key":
                calls += 1
                if calls == 2:  # The scanner re-verifies the collected event proof.
                    wait()
            return original(self, **kw)

        monkeypatch.setattr(type(h.item.verifier), "__call__", verify)
    else:
        original = FinalizedBlockScanner._decode_verified_block

        def decode(self, *args):
            wait()
            return original(self, *args)

        monkeypatch.setattr(FinalizedBlockScanner, "_decode_verified_block", decode)

    task = asyncio.create_task(capture_control_writes(h.item.provider, h.item.hotkey, h.old.height))
    closing = None
    try:
        await asyncio.wait_for(started.wait(), 3)
        task.cancel()
        closing = asyncio.create_task(h.item.provider.aclose())
        for _ in range(3):
            await asyncio.sleep(0)
            task.cancel()
        assert not task.done() and not closing.done()
        assert h.item.provider._lock.locked()
    finally:
        release.set()
        with suppress(asyncio.CancelledError):
            await task
        if closing is not None:
            await asyncio.wait_for(closing, 3)
    assert not h.item.provider._lock.locked()
