"""C4 drain evidence with real signatures and saved native weight archives.

Finality and trie proof ports are synthetic and bind exact fixture bytes. These
tests do not stop an installed writer or authorize C5 activation.
"""

import asyncio
import hashlib
import json
import threading
from dataclasses import replace
from pathlib import Path

import bittensor as bt
import pytest

from umi.competition_reward_legacy_recovery import (
    LegacyWeightExpiry,
    review_legacy_weight_expiry,
    validate_legacy_weight_expiry,
)
from umi.competition_weights import _WeightAttempt
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.runtime_metadata import RuntimeMetadataExecutor
from umi.validator_chain import FinalizedProofCollector, ValidatorChainError

from .test_competition_reward_transaction_outcome import at
from .test_competition_reward_transaction_recovery import chain_config as chain_config
from .test_competition_reward_transaction_recovery import native_encoding as native_encoding
from .test_competition_reward_transaction_recovery import original as original
from .test_competition_reward_transaction_recovery import policy as policy


def inputs(t, phase="signed"):
    i = t.intent
    attempt = _WeightAttempt(
        schema="umi-competition-weight-attempt/1",
        authorization_id="01" * 32,
        authorization_sha256="02" * 32,
        validator_hotkey=t.hotkey,
        recovery_checkpoint_sha256="03" * 32,
        chain_config_sha256=i.chain_config_sha256,
        phase=phase,
        preflight_block=i.block,
        preflight_hash=i.block_hash,
        prior_last_update=i.prior_last_update,
        nonce=i.nonce,
        era_death=i.block + i.mortality_period,
        chain_evidence_sha256=i.chain_evidence_sha256,
        publication_journal_status_sha256="04" * 32,
        signed_extrinsic="0x" + t.encoded.hex(),
    )
    return dict(
        attempt=canonical_json_bytes(attempt),
        chain=t.chain.evidence,
        metadata=t.chain.runtime.metadata_bytes,
        validator_hotkey=t.hotkey,
    )


@pytest.mark.parametrize(
    "phase", ["signed", "applied", "recovered_effect", "unknown", "expired_unconsumed_nonce"]
)
@pytest.mark.parametrize("offset", [127, 128, 3000])
async def test_native_expiry_ignores_local_outcome_and_needs_no_old_state_rpc(
    original, phase, offset
):
    t = original
    at(t, offset)
    args = inputs(t, phase)
    before = t.journal.recovery_inputs()
    result = await review_legacy_weight_expiry(t.provider, **args)
    if offset == 127:
        assert result is None
    else:
        validate_legacy_weight_expiry(
            result,
            attempt=args["attempt"],
            chain_config_sha256=digest(t.provider.config),
            validator_hotkey=t.hotkey,
        )
        assert result.death_block == t.old.height + 128
        assert result.finalized.block_number == t.old.height + offset
        assert (
            result.signed_extrinsic_hash
            == "0x" + hashlib.blake2b(t.encoded, digest_size=32).hexdigest()
        )
        assert not result.chain_submission_authorized
    assert len(t.checked) == len(json.loads(t.chain.evidence)["storage_batches"])
    assert {method for method, _ in t.calls} == {"chain_getHeader", "chain_getBlockHash"}
    assert t.journal.recovery_inputs() == before


@pytest.mark.parametrize(
    "change",
    [
        "nonce",
        "death",
        "last_update",
        "config",
        "hotkey",
        "signature",
        "absent_bytes",
        "header",
        "metadata",
        "storage_value",
        "storage_proof",
        "genesis",
    ],
)
async def test_changed_original_context_cannot_manufacture_expiry(original, change):
    t = original
    args = inputs(t)
    attempt, chain = json.loads(args["attempt"]), json.loads(args["chain"])
    if change == "nonce":
        attempt["nonce"] += 1
    elif change == "death":
        attempt["era_death"] -= 64
    elif change == "last_update":
        attempt["prior_last_update"] -= 1
    elif change == "config":
        attempt["chain_config_sha256"] = "ff" * 32
    elif change == "hotkey":
        attempt["validator_hotkey"] = bt.sp_core.Keypair.from_uri("//Bob").ss58_address
    elif change == "signature":
        attempt["signed_extrinsic"] = "0x" + (t.encoded[:-1] + b"\xff").hex()
    elif change == "absent_bytes":
        attempt.update(phase="unknown", signed_extrinsic=None)
    elif change == "header":
        chain["block_hash"] = "0x" + "ff" * 32
    elif change == "metadata":
        args["metadata"] += b"\0"
    elif change == "storage_value":
        chain["storage_batches"][0]["claims"][0]["value"] = "0x00"
    elif change == "storage_proof":
        chain["storage_batches"][0]["proof"] = ["0x00"]
    else:
        chain["finality"]["genesis_hash"] = "0x" + "ff" * 32
    args["chain"] = canonical_json_bytes(chain)
    attempt["chain_evidence_sha256"] = hashlib.sha256(args["chain"]).hexdigest()
    args["attempt"] = canonical_json_bytes(attempt)
    with pytest.raises((ValueError, ValidatorChainError)):
        await review_legacy_weight_expiry(t.provider, **args)


@pytest.mark.parametrize("change", ["copy", "snapshot", "death", "attempt", "config", "hotkey"])
async def test_native_result_cannot_be_rebound_to_another_inventory_entry(original, change):
    t = original
    args = inputs(t)
    value = await review_legacy_weight_expiry(t.provider, **args)
    binding = dict(
        attempt=args["attempt"],
        chain_config_sha256=digest(t.provider.config),
        validator_hotkey=t.hotkey,
    )
    if change == "copy":
        value = LegacyWeightExpiry(
            value.attempt_sha256,
            value.chain_config_sha256,
            value.validator_hotkey,
            value.signed_extrinsic_hash,
            value.birth_block,
            value.death_block,
            value.finalized,
        )
    elif change == "snapshot":
        value = replace(value, finalized=replace(value.finalized, block_hash="0x" + "ff" * 32))
    elif change == "death":
        value = replace(value, death_block=value.death_block - 1)
    elif change == "attempt":
        binding["attempt"] += b" "
    elif change == "config":
        binding["chain_config_sha256"] = "ff" * 32
    else:
        binding["validator_hotkey"] = bt.sp_core.Keypair.from_uri("//Bob").ss58_address
    with pytest.raises(ValueError, match="matching native provenance"):
        validate_legacy_weight_expiry(value, **binding)


@pytest.mark.parametrize("fault", ["missing", "wrong_root", "wrong_verifier"])
async def test_expiry_requires_owned_current_finality(original, fault):
    t = original
    height = t.finality.ref.block_number
    if fault == "missing":
        t.blocks.pop(height)
    elif fault == "wrong_root":
        t.blocks[height] = replace(t.blocks[height], state_root="0x" + "ff" * 32)
    else:
        t.blocks[height] = replace(t.blocks[height], finality_verifier_sha256="ff" * 32)
    with pytest.raises(ValueError):
        await review_legacy_weight_expiry(t.provider, **inputs(t))


async def test_restart_replays_original_evidence_without_a_saved_capability(original):
    t = original
    args = inputs(t)
    first = await review_legacy_weight_expiry(t.provider, **args)
    await t.provider.aclose()
    t.provider = t.reopen()
    second = await review_legacy_weight_expiry(t.provider, **args)
    assert second == first and second is not first
    assert not any(m in {"state_getStorageAt", "chain_getBlock"} for m, _ in t.calls)


@pytest.mark.parametrize("change", [None, "code", "proof", "executor", "context", "metadata"])
async def test_executed_original_runtime_checks_real_signature_after_runtime_change(
    original, monkeypatch, change
):
    # Only the Wasm executor and proof ports are synthetic. Native collection,
    # runtime binding, SCALE call reconstruction and sr25519 verification run.
    t = original
    args = inputs(t)
    body = json.loads(args["chain"])
    code, proof, executor = b"original-runtime-wasm", b"original-code-proof", "ab" * 32
    t.provider.config = t.provider.config.model_copy(
        update={
            "runtime_metadata_binary": "/synthetic/runtime-executor",
            "runtime_metadata_binary_sha256": executor,
        }
    )
    body["config_sha256"] = digest(t.provider.config)
    body["storage_codec_mode"] = "executed_runtime/1"
    body["runtime_execution"] = {
        "executor_sha256": executor,
        "block": t.old.height,
        "block_hash": t.old.block_hash,
        "parent_hash": t.chain.snapshot.parent_hash,
        "state_root": t.old.state_root,
        "key": "0x3a636f6465",
        "value": "0x" + code.hex(),
        "proof": ["0x" + proof.hex()],
    }
    calls, checks = [], []

    def invoke(self, data):
        calls.append(data)
        assert data == code
        pin = t.chain.runtime.pin
        return (
            canonical_json_bytes(
                {
                    "schema": "umi-runtime-metadata-execution/1",
                    "runtime_code_sha256": hashlib.sha256(code).hexdigest(),
                    "metadata_sha256": hashlib.sha256(args["metadata"]).hexdigest(),
                    "metadata_hex": args["metadata"].hex(),
                    "spec_version": pin.spec_version,
                    "transaction_version": pin.transaction_version,
                    "state_version": 1,
                    "chain_submission_authorized": False,
                }
            )
            + b"\n"
        )

    def verify(**kwargs):
        checks.append(kwargs)
        return (
            kwargs["state_root"] == bytes.fromhex(t.old.state_root[2:])
            and kwargs["storage_key"] == b":code"
            and kwargs["expected_value"] == code
            and kwargs["proof"] == (proof,)
        )

    monkeypatch.setattr(RuntimeMetadataExecutor, "_invoke", invoke)
    t.provider._runtime_executor = RuntimeMetadataExecutor(
        binary_path=Path("/synthetic/runtime-executor"),
        expected_sha256=executor,
    )
    t.provider._runtime_proofs = FinalizedProofCollector(
        t.rpc,
        finality=t.finality,
        verifier=verify,
    )
    if change == "code":
        body["runtime_execution"]["value"] = "0x01"
    elif change == "proof":
        body["runtime_execution"]["proof"] = ["0x01"]
    elif change == "executor":
        body["runtime_execution"]["executor_sha256"] = "ff" * 32
    elif change == "context":
        body["runtime_execution"]["block"] += 1
    elif change == "metadata":
        body["runtime_metadata_sha256"] = "ff" * 32
    args["chain"] = canonical_json_bytes(body)
    attempt = json.loads(args["attempt"])
    attempt["chain_evidence_sha256"] = hashlib.sha256(args["chain"]).hexdigest()
    attempt["chain_config_sha256"] = digest(t.provider.config)
    args["attempt"] = canonical_json_bytes(attempt)
    if change is not None:
        with pytest.raises((ValueError, ValidatorChainError)):
            await review_legacy_weight_expiry(t.provider, **args)
    else:
        result = await review_legacy_weight_expiry(t.provider, **args)
        validate_legacy_weight_expiry(
            result,
            attempt=args["attempt"],
            chain_config_sha256=digest(t.provider.config),
            validator_hotkey=t.hotkey,
        )
        assert calls == [code] and len(checks) == 1
        assert result.death_block == t.old.height + 128
        assert not any(m.startswith("state_") for m, _ in t.calls)


async def test_cancelled_crypto_replay_drains_before_releasing_provider(original, monkeypatch):
    t = original
    from umi import competition_reward_legacy_recovery as module

    entered, release = threading.Event(), threading.Event()
    real_verify = module.verify_mortal_call

    def delayed(*args, **kwargs):
        entered.set()
        if not release.wait(10):
            raise AssertionError("test failed to release signing replay")
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(module, "verify_mortal_call", delayed)
    task = asyncio.create_task(review_legacy_weight_expiry(t.provider, **inputs(t)))
    closer = None
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        closer = asyncio.create_task(t.provider.aclose())
        await asyncio.sleep(0)
        assert t.provider._lock.locked() and not closer.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        if closer is not None:
            await closer
    assert t.provider._closed
