"""Retained block replay through native consumers and synthetic chain codecs."""

import asyncio
import hashlib
import json
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_control_writes import capture_control_writes, validate_control_writes
from umi.competition_reward_write_archive import review_control_writes
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.runtime_metadata import RuntimeMetadataExecutor
from umi.validator_chain import FinalizedProofCollector

from .test_competition_chain import _Runtime
from .test_competition_reward_control_writes import (
    block_case as block_case,
)
from .test_competition_reward_control_writes import (
    chain as chain,
)
from .test_competition_reward_control_writes import (
    chain_config as chain_config,
)
from .test_competition_reward_control_writes import (
    control as control,
)
from .test_competition_reward_control_writes import (
    historical as historical,
)
from .test_competition_reward_control_writes import (
    policy as policy,
)
from .test_competition_reward_control_writes import (
    series_case as series_case,
)
from .test_validator_chain_scan import Entry, arg, call, extrinsic


@pytest.fixture(params=["exact_runtime", "executed_runtime"])
async def archived(block_case, monkeypatch, tmp_path, request):
    h = block_case
    h.executed = request.param == "executed_runtime"
    h.code_checks, h.executions = [], []
    metadata = {b"parent-code": (b"meta-parent", 452), b"child-code": (b"meta-child", 453)}

    # Only the low-level SCALE codec is synthetic. The replay collector still
    # checks the approved metadata hash, runtime versions and every trie proof.
    class Codec(_Runtime):
        def __init__(self, raw, spec, transaction, *, ss58_format):
            if h.executed:
                assert (raw, spec) in metadata.values()
                assert (transaction, ss58_format) == (1, 42)
                self.spec_version, self.transaction_version = spec, transaction
            else:
                super().__init__(raw, spec, transaction, ss58_format=ss58_format)

        def storage_key(self, pallet, item, params):
            if (pallet, item) == ("System", "Events"):
                assert not params
                return b"system-events-key"
            return super().storage_key(pallet, item, params)

        def storage_entry(self, pallet, item):
            if (pallet, item) == ("System", "Events"):
                return Entry()
            return super().storage_entry(pallet, item)

        def decode(self, value_type, data, *, strict):
            if value_type == "Vec<EventRecord>":
                assert strict and data == b"events"
                return h.events
            return super().decode(value_type, data, strict=strict)

        def decode_extrinsic(self, raw, strict=True):
            assert strict
            index = h.raw.index(raw)
            return extrinsic(raw, h.body_calls[index], h.signers[index])

    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", Codec)
    if h.executed:
        h.item.config = h.item.provider.config = h.item.config.model_copy(
            update={
                "runtime_metadata_binary": str(tmp_path / "executor"),
                "runtime_metadata_binary_sha256": "ab" * 32,
            }
        )
        code_at = {
            h.parent_ref.block_hash: (h.parent_ref.state_root, b"parent-code"),
            h.source.w.original.block_hash: (h.source.w.original.state_root, b"child-code"),
        }

        async def code_request(method, params):
            if params[-1] in code_at:
                if method == "state_getStorageAt" and params[0] == "0x3a636f6465":
                    return "0x" + code_at[params[-1]][1].hex()
                if method == "state_getReadProof" and tuple(params[0]) == ("0x3a636f6465",):
                    return {"at": params[-1], "proof": ["0x" + b"code-proof".hex()]}
            return await h.capture_request(method, params)

        def code_verifier(**kw):
            h.code_checks.append(kw)
            return (
                kw["storage_key"] == b":code"
                and kw["proof"] == (b"code-proof",)
                and (
                    (kw["state_root"], kw["expected_value"])
                    in {(bytes.fromhex(root[2:]), code) for root, code in code_at.values()}
                )
            )

        def invoke(self, code):
            h.executions.append(code)
            value, spec = metadata[code]
            return (
                canonical_json_bytes(
                    {
                        "schema": "umi-runtime-metadata-execution/1",
                        "runtime_code_sha256": hashlib.sha256(code).hexdigest(),
                        "metadata_sha256": hashlib.sha256(value).hexdigest(),
                        "metadata_hex": value.hex(),
                        "spec_version": spec,
                        "transaction_version": 1,
                        "state_version": 1,
                        "chain_submission_authorized": False,
                    }
                )
                + b"\n"
            )

        monkeypatch.setattr(h.item.rpc, "request", code_request)
        h.item.provider._registration_rpc.request = code_request
        monkeypatch.setattr(RuntimeMetadataExecutor, "_invoke", invoke)
        monkeypatch.delattr(h.item.provider, "_runtime_context")

        def configure(provider):
            provider._runtime_executor = RuntimeMetadataExecutor(
                binary_path=tmp_path / "executor", expected_sha256="ab" * 32
            )
            provider._runtime_proofs = FinalizedProofCollector(
                h.item.rpc, finality=h.item.finality, verifier=code_verifier
            )

        configure(h.item.provider)
    h.captured = await capture_control_writes(h.item.provider, h.item.hotkey, h.old.height)
    await h.item.provider.aclose()
    h.item.provider = h.source.own(h.reopen())
    if h.executed:
        configure(h.item.provider)
    h.code_checks.clear()
    h.executions.clear()
    h.replay_rpc = []

    async def head_only(method, params):
        h.replay_rpc.append((method, tuple(params)))
        assert (method, tuple(params)) in {
            ("chain_getHeader", (h.source.w.head.block_hash,)),
            ("chain_getBlockHash", (h.source.w.head.height,)),
        }, "old state and block RPCs are unavailable"
        return await h.source.request(method, params)

    monkeypatch.setattr(h.item.rpc, "request", head_only)
    h.item.provider._registration_rpc = SimpleNamespace(request=head_only, aclose=h.source.close)
    return h


async def replay(h, evidence=None):
    return await review_control_writes(
        h.item.provider,
        slot_evidence=h.captured.slot.evidence,
        slot_metadata=h.captured.slot.metadata,
        evidence=h.captured.evidence if evidence is None else evidence,
    )


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_replays_every_write_after_restart_without_old_rpc(archived):
    h = archived
    result = await replay(h)
    validate_control_writes(
        result,
        expected_control_hotkey=h.item.hotkey,
        expected_chain_config_sha256=digest(h.item.provider.config),
    )
    assert result == h.captured
    assert [w.decision_sha256 for w in result.writes] == ["aa" * 32, "bb" * 32]
    assert h.replay_rpc and all(m.startswith("chain_") for m, _ in h.replay_rpc)
    assert not json.loads(result.evidence)["chain_submission_authorized"]
    if h.executed:
        assert h.executions == [b"child-code", b"parent-code"]
        assert len(h.code_checks) == 2
        assert result.slot.metadata == b"meta-child"
        assert bytes.fromhex(json.loads(result.evidence)["runtime_metadata"]) == b"meta-parent"
    with pytest.raises(ValueError, match="native block proof"):
        validate_control_writes(
            replace(result, unresolved_extrinsics=(0,)),
            expected_control_hotkey=h.item.hotkey,
            expected_chain_config_sha256=digest(h.item.provider.config),
        )


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "slot",
        "child",
        "parent",
        "order",
        "omission",
        "event_key",
        "event_value",
        "event_proof",
        "metadata",
        "version",
        "authority",
        "extra",
        "noncanonical",
        "provenance",
        "runtime_execution",
        "invalid_hex",
        "null_body",
    ],
)
async def test_changed_archive_cannot_recreate_an_owned_observation(archived, fault):
    h = archived
    body = json.loads(h.captured.evidence)
    if fault == "slot":
        body["slot_evidence_sha256"] = "00" * 32
    elif fault == "child":
        body["header"] = body["parent_header"]
    elif fault == "parent":
        body["parent_header"] = body["header"]
    elif fault == "order":
        body["extrinsics"].reverse()
    elif fault == "omission":
        body["extrinsics"].pop()
    elif fault == "event_key":
        body["events"]["key"] = b"wrong-key".hex()
    elif fault == "event_value":
        body["events"]["value"] = b"changed".hex()
    elif fault == "event_proof":
        body["events"]["proof"] = [b"changed-proof".hex()]
    elif fault == "metadata":
        body["runtime_metadata"] = b"changed-metadata".hex()
    elif fault == "version":
        body["runtime_version"] = b'{"specVersion":99}'.hex()
    elif fault == "authority":
        body["chain_submission_authorized"] = True
    elif fault == "extra":
        body["writes"] = []
    elif fault == "provenance":
        body["finality_provenance"] = "rpc_report"
    elif fault == "runtime_execution":
        body["runtime_execution"] = {}
    elif fault == "invalid_hex":
        body["extrinsics"][0] = "0x00"
    elif fault == "null_body":
        body = None
    raw = canonical_json_bytes(body)
    if fault == "noncanonical":
        raw += b"\n"
    with pytest.raises((ValueError, RuntimeError)):
        await replay(h, raw)


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_wrapped_effect_stays_unresolved_after_archive_replay(archived):
    h = archived
    # The synthetic byte codec now decodes a wrapper; native origin/effect
    # analysis must preserve its ambiguity rather than infer inner success.
    h.body_calls[0] = call("Utility", "batch", [arg("calls", [h.body_calls[0]])])
    result = await replay(h)
    assert result.unresolved_extrinsics == (0,)
    assert [w.decision_sha256 for w in result.writes] == ["bb" * 32]


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_closed_owner_cannot_replay_stale_bytes(archived):
    h = archived
    await h.item.provider.aclose()
    with pytest.raises(ValueError, match="closed"):
        await replay(h)


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("archived", ["executed_runtime"], indirect=True)
@pytest.mark.parametrize("fault", ["code", "proof", "executor", "child_runtime", "block_type"])
async def test_parent_runtime_needs_its_own_proof_and_selected_executor(archived, fault):
    h = archived
    body = json.loads(h.captured.evidence)
    execution = body["runtime_execution"]
    if fault == "code":
        execution["value"] = "0x" + b"changed-code".hex()
    elif fault == "proof":
        execution["proof"] = ["0x" + b"changed-proof".hex()]
    elif fault == "executor":
        execution["executor_sha256"] = "cc" * 32
    elif fault == "child_runtime":
        body["runtime_execution"] = json.loads(h.captured.slot.evidence)["runtime_execution"]
    elif fault == "block_type":
        execution["block"] = True
    with pytest.raises((ValueError, RuntimeError)):
        await replay(h, canonical_json_bytes(body))
    # The separately archived child was replayed. Unproved parent code never
    # reaches the executor, and no live old-state RPC can rescue the archive.
    assert h.executions == [b"child-code"]


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("archived", ["executed_runtime"], indirect=True)
async def test_cancellation_drains_parent_execution_before_provider_close(archived, monkeypatch):
    h = archived
    started, release = threading.Event(), threading.Event()
    invoke = RuntimeMetadataExecutor._invoke

    def blocked(executor, code):
        if code == b"parent-code":
            started.set()
            assert release.wait(10)
        return invoke(executor, code)

    monkeypatch.setattr(RuntimeMetadataExecutor, "_invoke", blocked)
    task = asyncio.create_task(replay(h))
    closing = None
    try:

        async def wait_started():
            while not started.is_set():
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_started(), 5)
        task.cancel()
        closing = asyncio.create_task(h.item.provider.aclose())
        await asyncio.sleep(0.02)
        assert not task.done() and not closing.done()
        assert h.item.provider._lock.locked()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        if closing is not None:
            await asyncio.wait_for(closing, 5)
    assert not h.item.provider._lock.locked()
