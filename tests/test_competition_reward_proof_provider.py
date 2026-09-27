"""Standing provider integration over real TLS with synthetic chain/trie facts."""

from __future__ import annotations

import json

import pytest

from umi.competition_chain_state import validate_owned_weight_observation
from umi.competition_reward_control import (
    FinalizedRewardControlProvider,
    validate_owned_reward_control,
)
from umi.competition_weight_rpc import WeightProofRpc
from umi.open_competition import digest
from umi.validator_chain import FinalizedProofCollector, ProofCollectionLimits, ValidatorChainError

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_proof_rpc import wire as wire
from .test_competition_proof_rpc import with_fallback
from .test_competition_reward_control import commitment
from .test_competition_reward_registrations import (
    base_policy as base_policy,
)
from .test_competition_reward_registrations import (
    key,
)
from .test_competition_reward_registrations import (
    policy as policy,
)
from .test_competition_reward_registrations import (
    registered_case as registered_case,
)


@pytest.fixture
async def standing(registered_case, wire):
    item = registered_case
    await item.provider.aclose()
    config = with_fallback(item.config)
    rpc = WeightProofRpc(config)
    provider = FinalizedRewardControlProvider(
        config,
        item.policy,
        finality=item.finality,
        proofs=FinalizedProofCollector(
            rpc,
            finality=item.finality,
            verifier=item.verifier,
            limits=ProofCollectionLimits(
                maximum_storage_value_bytes=64 * 1024,
                maximum_storage_values_bytes=1024 * 1024,
            ),
        ),
        now_ms=lambda: item.clock.now,
    )
    # Production owns this transport. Keep it present so accidentally entering
    # the legacy prefetch branch is observable through the real wire.
    provider._weight_rpc = rpc
    item.provider = provider
    item.wire = wire[0]
    item.control_hotkey = key("Ferdie")
    item.control_spec = ("Commitments", "CommitmentOf", (78, item.control_hotkey))
    item.rpc.values[item.control_spec] = commitment(block=item.finality.ref.block_number - 10)
    try:
        yield item
    finally:
        await provider.aclose()


def storage_reads(item):
    return [
        (path, method, params)
        for path, method, params in item.wire.reads
        if method in {"state_getReadProof", "state_getStorageAt", "state_queryStorageAt"}
    ]


@pytest.mark.parametrize("second_backup", [False, True])
async def test_control_and_complete_weights_need_five_proof_batches(standing, second_backup):
    item = standing
    item.wire.fallback_rpc_error = second_backup
    control = await item.provider.collect_control(item.control_hotkey)
    validate_owned_reward_control(
        control,
        expected_control_hotkey=item.control_hotkey,
        expected_chain_config_sha256=digest(item.provider.config),
    )
    weights = await item.provider.collect_registered_weights(item.hotkey, at=control.snapshot)
    validate_owned_weight_observation(weights)
    assert weights.snapshot == control.snapshot
    assert weights.registrations_complete and len(weights.registrations) == 4
    assert weights.validator_row == ((0, 19661), (1, 20000), (2, 25874))
    assert len(json.loads(weights.evidence)["storage_batches"]) == 4
    reads = storage_reads(item)
    # Block-specific unavailable-state errors are tried again for each batch;
    # they cannot quarantine that provider's reads at unrelated blocks.
    assert len(reads) == (10 if second_backup else 5)
    assert {method for _, method, _ in reads} == {"state_getReadProof"}
    assert {params[1] for _, _, params in reads} == {control.snapshot.block_hash}
    selected = "/second-backup" if second_backup else "/fallback"
    assert len([r for r in reads if r[0] == selected]) == 5
    assert len(item.verifier.checked) == 5
    assert not any(method.startswith("author_") for _, method, _ in item.wire.reads)


async def test_proven_absence_stays_absent_after_prior_discovery(standing):
    item = standing
    assert (await item.provider.collect_control(item.control_hotkey)).control_sha256 == "aa" * 32
    del item.rpc.values[item.control_spec]
    current = await item.provider.collect_control(item.control_hotkey)
    assert current.control_sha256 is None
    assert current.committed_at_block is None
    assert len(storage_reads(item)) == 2
    assert {m for _, m, _ in storage_reads(item)} == {"state_getReadProof"}


@pytest.mark.parametrize("fault", ["old-helper", "invalid-proof", "reader-error", "wrong-block"])
async def test_no_claim_or_alternate_provider_fallback_on_verification_failure(
    standing, monkeypatch, fault
):
    item = standing
    if fault == "old-helper":
        monkeypatch.setattr(item.verifier, "read_many", None)
    elif fault == "invalid-proof":
        item.rpc.bad_proof = True
    elif fault == "reader-error":

        def fail(**kwargs):
            raise RuntimeError("fixture helper failure")

        monkeypatch.setattr(item.verifier, "read_many", fail)
    else:
        original = item.rpc.request

        async def wrong_block(method, params):
            value = await original(method, params)
            if method == "state_getReadProof":
                value["at"] = "0x" + "ff" * 32
            return value

        monkeypatch.setattr(item.rpc, "request", wrong_block)
    with pytest.raises(ValidatorChainError):
        await item.provider.collect_control(item.control_hotkey)
    assert len(storage_reads(item)) == (0 if fault == "old-helper" else 1)
    assert not {m for _, m, _ in storage_reads(item)} - {"state_getReadProof"}
    assert "/second-backup" not in item.wire.handshakes
    assert not item.verifier.checked


@pytest.mark.parametrize("limit", ["individual", "aggregate"])
async def test_provider_keeps_its_value_limits_before_decoding(standing, monkeypatch, limit):
    item = standing
    original = item.verifier.read_many

    def oversized(**kwargs):
        assert kwargs["maximum_value_bytes"] == 64 * 1024
        assert kwargs["maximum_total_value_bytes"] == 1024 * 1024
        values = original(**kwargs)
        if limit == "individual":
            return tuple((k, b"x" * (64 * 1024 + 1)) for k, _ in values)
        return tuple((k, b"x" * (64 * 1024)) for k, _ in values)

    monkeypatch.setattr(item.verifier, "read_many", oversized)
    with pytest.raises(ValidatorChainError, match="storage_proof_verification_failed"):
        # The complete base weight batch has more than 16 keys.
        await item.provider.collect_registered_weights(item.hotkey)
    assert len(storage_reads(item)) == 1
    assert not item.verifier.checked
