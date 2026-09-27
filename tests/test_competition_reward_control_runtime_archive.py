"""Native executed-runtime archive replay with synthetic execution and proof ports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_control import validate_owned_reward_control
from umi.competition_reward_control_archive import (
    HistoricalRewardControlProvider,
    validate_historical_reward_control,
)
from umi.finalized_ancestry import encode_rpc_header
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.runtime_metadata import ExecutedRuntimeContext, RuntimeMetadataExecutor
from umi.validator_chain import ValidatorChainError

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_historical_registration import change_block
from .test_competition_reward_control import commitment
from .test_competition_weights import executed_weight_case as executed_weight_case
from .test_competition_weights import package_case as package_case
from .test_competition_weights import package_limits as package_limits
from .test_competition_weights import release_identity as release_identity
from .test_competition_weights import replay_limits as replay_limits
from .test_competition_weights import weight_case as weight_case
from .test_competition_weights import worker_capacity as worker_capacity
from .test_open_competition import policy as policy


@pytest.fixture
async def runtime_archive(executed_weight_case, chain_config, monkeypatch, tmp_path):
    item = executed_weight_case
    config = item.config.model_copy(
        update={
            "state_directory": str(tmp_path / "runtime-control-archive"),
            "minimum_finalized_block": chain_config.minimum_finalized_block,
        }
    )
    providers = []

    def reopen():
        provider = HistoricalRewardControlProvider(
            config,
            item.policy,
            historical_header_directory=tmp_path / "control-history",
            finality=item.finality,
            proofs=item.proofs,
            now_ms=lambda: item.clock.now,
        )
        providers.append(provider)
        # Construction enforces the production checkpoint floor. Only this
        # synthetic chain uses small heights, as in the current-control test.
        provider.config = config.model_copy(update={"minimum_finalized_block": 100})
        provider._runtime_proofs = item.provider._runtime_proofs
        return provider

    original_at = item.finality.verified_block_at

    async def finalized(height, receipt):
        encoded = change_block(item, height)
        block = await original_at(height)
        raw = canonical_json_bytes(
            {
                **json.loads(block.finality_evidence),
                "block": {"scale_header": encoded},
                "request_id": receipt,
            }
        )
        return replace(
            block,
            finality_evidence=raw,
            finality_evidence_sha256=hashlib.sha256(raw).hexdigest(),
        )

    try:
        old = await finalized(item.finality.ref.block_number, "runtime-control-capture")
        blocks = {old.height: old}
        looked_up = []

        async def at(height):
            looked_up.append(height)
            return blocks.get(height)

        monkeypatch.setattr(item.finality, "verified_block_at", at)
        code_checks, executions = [], []
        original_verify = item.provider._runtime_proofs._verifier
        original_invoke = RuntimeMetadataExecutor._invoke

        def verify_code(**kwargs):
            code_checks.append(kwargs)
            # The shared fixture recognizes a synthetic proof node. Bind that
            # node to its exact value/root so a changed Wasm reaches rejection
            # in the native collector, before the synthetic executor runs.
            return original_verify(**kwargs) and (
                kwargs["state_root"] == bytes.fromhex(old.state_root[2:])
                and kwargs["storage_key"] == b":code"
                and kwargs["expected_value"] == item.code
            )

        def invoke(executor, code):
            executions.append(code)
            return original_invoke(executor, code)

        monkeypatch.setattr(item.provider._runtime_proofs, "_verifier", verify_code)
        monkeypatch.setattr(RuntimeMetadataExecutor, "_invoke", invoke)
        provider = reopen()
        item.rpc.values[("Commitments", "CommitmentOf", (78, item.hotkey))] = commitment()
        captured = await provider.collect_control(item.hotkey)
        validate_owned_reward_control(
            captured,
            expected_control_hotkey=item.hotkey,
            expected_chain_config_sha256=digest(provider.config),
        )
        assert type(captured.runtime) is ExecutedRuntimeContext
        assert executions == [item.code]
        assert len(code_checks) == 1

        item.clock.now += 10 * 60 * 60 * 1000
        fresh = await finalized(old.height + 3000, "runtime-control-review")
        blocks[fresh.height] = fresh
        item.rpc.values[("Commitments", "CommitmentOf", (78, item.hotkey))] = commitment(
            "bb" * 32, fresh.height
        )
        original_request = item.rpc.request
        rpc_calls = []

        async def current_only(method, params):
            rpc_calls.append((method, tuple(params)))
            if method == "chain_getBlockHash":
                assert tuple(params) == (fresh.height,), "old header RPC is unavailable"
            else:
                assert params[-1] == fresh.block_hash, "old state RPC is unavailable"
            return await original_request(method, params)

        monkeypatch.setattr(item.rpc, "request", current_only)
        code_checks.clear()
        executions.clear()
        looked_up.clear()
        yield SimpleNamespace(
            item=item,
            provider=provider,
            reopen=reopen,
            captured=captured,
            raw=captured.evidence,
            metadata=captured.runtime.metadata_bytes,
            old=old,
            fresh=fresh,
            blocks=blocks,
            looked_up=looked_up,
            code_checks=code_checks,
            executions=executions,
            rpc_calls=rpc_calls,
        )
    finally:
        for provider in reversed(providers):
            await provider.aclose()
        await item.provider.aclose()


def check_replay(h, result):
    validate_historical_reward_control(
        result,
        expected_control_hotkey=h.item.hotkey,
        expected_chain_config_sha256=digest(h.provider.config),
    )
    assert result.snapshot == h.captured.snapshot
    assert result.control_sha256 == "aa" * 32
    assert result.committed_at_block == 100
    assert result.evidence_sha256 == hashlib.sha256(h.raw).hexdigest()
    assert result.metadata_sha256 == hashlib.sha256(h.metadata).hexdigest()
    assert h.looked_up == [h.fresh.height, h.old.height]
    assert h.rpc_calls == [
        ("chain_getHeader", (h.fresh.block_hash,)),
        ("chain_getBlockHash", (h.fresh.height,)),
    ]
    assert h.executions == [h.item.code]
    assert len(h.code_checks) == 1
    assert h.code_checks[0]["state_root"] == bytes.fromhex(h.old.state_root[2:])


async def test_native_executed_archive_replays_old_control_after_restart(runtime_archive):
    h = runtime_archive
    body = json.loads(h.raw)
    assert len(h.raw) < 16 * 1024 and len(h.metadata) < 1024
    assert body["storage_codec_mode"] == "executed_runtime/1"
    assert body["chain_submission_authorized"] is False
    assert body["runtime_execution"]["value"] == "0x" + h.item.code.hex()
    assert body["runtime_execution"]["proof"] == ["0x" + b"proof".hex()]
    assert body["finality"]["block"] == json.loads(h.old.finality_evidence)["block"]
    assert h.item.clock.now - h.captured.timestamp_ms > h.provider.config.maximum_head_age_ms
    assert h.fresh.height - h.old.height > h.item.policy.maximum_snapshot_age_blocks
    await h.provider.aclose()
    h.provider = h.reopen()
    checked = len(h.item.verifier.checked)

    result = await h.provider.review_control(h.raw, h.metadata)

    check_replay(h, result)
    assert len(h.item.verifier.checked) == checked + 1
    proved = h.item.verifier.checked[-1]
    assert proved["state_root"] == bytes.fromhex(h.old.state_root[2:])
    assert len(proved["items"]) == 3


async def test_changed_live_runtime_needs_no_old_rpc_or_live_metadata(runtime_archive, monkeypatch):
    h = runtime_archive
    current_only = h.item.rpc.request
    live_runtime = {
        "state_getMetadata": "0x" + b"meta\x0e-upgraded-live-runtime".hex(),
        "state_getRuntimeVersion": {"specVersion": 999, "transactionVersion": 9, "stateVersion": 1},
    }

    async def upgraded(method, params):
        if method in live_runtime or (
            method == "state_getStorageAt" and params[0] == "0x3a636f6465"
        ):
            h.rpc_calls.append((method, tuple(params)))
            assert params[-1] == h.fresh.block_hash, "old runtime RPC is unavailable"
            if method in live_runtime:
                return live_runtime[method]
            return "0x" + b"upgraded live wasm".hex()
        return await current_only(method, params)

    monkeypatch.setattr(h.item.rpc, "request", upgraded)
    result = await h.provider.review_control(h.raw, h.metadata)
    check_replay(h, result)


@pytest.mark.parametrize("field", ["value", "proof"])
async def test_changed_archived_code_or_proof_fails_before_execution(runtime_archive, field):
    h = runtime_archive
    body = json.loads(h.raw)
    changed = "0x" + b"altered".hex()
    body["runtime_execution"][field] = changed if field == "value" else [changed]
    checked = len(h.item.verifier.checked)

    with pytest.raises(ValidatorChainError, match="storage_proof_verification_failed"):
        await h.provider.review_control(canonical_json_bytes(body), h.metadata)

    assert len(h.code_checks) == 1
    assert h.executions == []
    assert len(h.item.verifier.checked) == checked


async def test_changed_archived_executor_fails_before_proof_or_execution(runtime_archive):
    h = runtime_archive
    body = json.loads(h.raw)
    body["runtime_execution"]["executor_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="runtime executor differs from selection"):
        await h.provider.review_control(canonical_json_bytes(body), h.metadata)
    assert h.code_checks == h.executions == []


@pytest.mark.parametrize("rebind_digest", [False, True])
async def test_changed_metadata_cannot_replace_executed_metadata(runtime_archive, rebind_digest):
    h = runtime_archive
    body = json.loads(h.raw)
    metadata = b"meta\x0e-altered-archive"
    if rebind_digest:
        body["runtime_metadata_sha256"] = hashlib.sha256(metadata).hexdigest()
    reason = (
        "replayed runtime differs from archived control evidence"
        if rebind_digest
        else "not exact native evidence"
    )
    with pytest.raises(ValueError, match=reason):
        await h.provider.review_control(canonical_json_bytes(body), metadata)
    assert h.executions == ([h.item.code] if rebind_digest else [])


@pytest.mark.parametrize("field", ["specVersion", "transactionVersion", "stateVersion"])
async def test_archived_runtime_versions_must_equal_executed_versions(runtime_archive, field):
    h = runtime_archive
    body = json.loads(h.raw)
    body["runtime_version"][field] += 1
    checked = len(h.item.verifier.checked)
    with pytest.raises(ValueError, match="replayed runtime differs from archived control evidence"):
        await h.provider.review_control(canonical_json_bytes(body), h.metadata)
    assert h.executions == [h.item.code]
    assert len(h.item.verifier.checked) == checked


@pytest.mark.parametrize(
    "field,value",
    [
        ("block", 171),
        ("block_hash", "0x" + "ab" * 32),
        ("parent_hash", "0x" + "ab" * 32),
        ("state_root", "0x" + "ab" * 32),
        ("key", "0x3a6f74686572"),
    ],
)
async def test_runtime_execution_header_fields_must_bind_archive(runtime_archive, field, value):
    h = runtime_archive
    body = json.loads(h.raw)
    body["runtime_execution"][field] = value
    with pytest.raises(ValueError, match="runtime execution binds a different block or key"):
        await h.provider.review_control(canonical_json_bytes(body), h.metadata)
    assert h.rpc_calls == h.code_checks == h.executions == []


@pytest.mark.parametrize(
    "field,value",
    [("block", 171), ("block_hash", "0x" + "ab" * 32), ("state_root", "0x" + "ab" * 32)],
)
async def test_archive_fields_must_equal_scale_header(runtime_archive, field, value):
    h = runtime_archive
    body = json.loads(h.raw)
    body[field] = value
    with pytest.raises(ValueError, match="archive differs from its header"):
        await h.provider.review_control(canonical_json_bytes(body), h.metadata)
    assert h.rpc_calls == h.code_checks == h.executions == []


async def test_consistently_rewritten_scale_header_still_needs_owned_history(runtime_archive):
    h = runtime_archive
    body = json.loads(h.raw)
    parent = "0x" + "ab" * 32
    encoded = encode_rpc_header(
        {
            "number": hex(h.old.height),
            "parentHash": parent,
            "stateRoot": h.old.state_root,
            "extrinsicsRoot": "0x" + "33" * 32,
            "digest": {"logs": []},
        }
    )
    block_hash = "0x" + hashlib.blake2b(bytes.fromhex(encoded[2:]), digest_size=32).hexdigest()
    body["finality"]["block"]["scale_header"] = encoded
    body["block_hash"] = body["runtime_execution"]["block_hash"] = block_hash
    body["runtime_execution"]["parent_hash"] = parent

    with pytest.raises(ValueError, match="owned finality snapshot binding mismatch"):
        await h.provider.review_control(canonical_json_bytes(body), h.metadata)
    assert h.looked_up == [h.fresh.height, h.old.height]
    assert h.code_checks == h.executions == []


async def test_executed_archive_requires_retained_owned_header(runtime_archive):
    h = runtime_archive
    del h.blocks[h.old.height]
    with pytest.raises(FileNotFoundError, match="owned reward admission header is unavailable"):
        await h.provider.review_control(h.raw, h.metadata)
    assert h.code_checks == h.executions == []


async def test_historical_capture_uses_owned_executed_runtime(runtime_archive, monkeypatch):
    from umi.competition_reward_control_archive import _Archive
    from umi.grandpa_finality import _decode_header

    h = runtime_archive
    archive = _Archive(h.raw, h.metadata)
    header = _decode_header(archive.encoded, maximum_bytes=1024 * 1024)
    original_request = h.item.rpc.request

    async def request(method, params):
        if method == "chain_getBlockHash" and params == (h.old.height,):
            return h.old.block_hash
        if method == "chain_getHeader" and params == (h.old.block_hash,):
            return {
                "number": hex(h.old.height),
                "parentHash": header["parent_hash"],
                "stateRoot": header["state_root"],
                "extrinsicsRoot": header["extrinsics_root"],
                "digest": {"logs": []},
            }
        if params[-1] == h.old.block_hash:
            return await archive.request(method, params)
        return await original_request(method, params)

    async def close():
        pass

    monkeypatch.setattr(h.item.rpc, "request", request)
    h.provider._owned = True
    h.provider._registration_rpc = SimpleNamespace(request=request, aclose=close)
    captured = await h.provider.capture_control_at(h.item.hotkey, h.old.height)
    validate_historical_reward_control(
        captured,
        expected_control_hotkey=h.item.hotkey,
        expected_chain_config_sha256=digest(h.provider.config),
    )
    assert captured.control_sha256 == json.loads(h.raw)["control_sha256"]
    body = json.loads(captured.evidence)
    assert body["runtime_execution"] == json.loads(h.raw)["runtime_execution"]
    assert body["finality"]["evidence_class"] == "owned_finalized_ancestry"
    assert h.executions and all(code == h.item.code for code in h.executions)
    assert h.code_checks
