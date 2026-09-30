"""Unsigned signing-state recovery through the executed-runtime proof adapter.

The code executor, chain/finality and SCALE/storage verifier ports are synthetic;
the real SCALE/signature integration has its own recovery tests.
"""

import hashlib
import json

import pytest

from umi.competition_cohort_reward_allocation import CohortRewardProjection
from umi.competition_reward_transaction_recovery import review_standing_transaction
from umi.competition_reward_transactions import StandingWeightIntent, StandingWeightJournal
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_chain import ValidatorChainError

from .test_competition_reward_control_runtime_archive import chain as chain
from .test_competition_reward_control_runtime_archive import chain_config as chain_config
from .test_competition_reward_control_runtime_archive import (
    executed_weight_case as executed_weight_case,
)
from .test_competition_reward_control_runtime_archive import package_case as package_case
from .test_competition_reward_control_runtime_archive import package_limits as package_limits
from .test_competition_reward_control_runtime_archive import policy as policy
from .test_competition_reward_control_runtime_archive import release_identity as release_identity
from .test_competition_reward_control_runtime_archive import replay_limits as replay_limits
from .test_competition_reward_control_runtime_archive import runtime_archive as runtime_archive
from .test_competition_reward_control_runtime_archive import weight_case as weight_case
from .test_competition_reward_control_runtime_archive import worker_capacity as worker_capacity

pytestmark = pytest.mark.parametrize("runtime_archive", [True], indirect=True)


@pytest.mark.parametrize("change", [None, "code", "proof", "executor", "context"])
async def test_original_runtime_and_weight_proofs_survive_a_later_runtime(
    runtime_archive, tmp_path, change
):
    h = runtime_archive
    chain = h.weights
    raw = json.loads(chain.evidence)
    if change == "code":
        raw["runtime_execution"]["value"] = "0x0001"
    elif change == "proof":
        raw["runtime_execution"]["proof"] = ["0x0001"]
    elif change == "executor":
        raw["runtime_execution"]["executor_sha256"] = "ff" * 32
    elif change == "context":
        raw["runtime_execution"]["block_hash"] = "0x" + "ff" * 32
    raw = canonical_json_bytes(raw)
    intent = StandingWeightIntent(
        schema="umi-standing-weight-intent/1",
        series_sha256="11" * 32,
        activation_sha256="22" * 32,
        decision_sha256=h.captured.control_sha256,
        chain_config_sha256=digest(h.provider.config),
        validator_hotkey=h.item.hotkey,
        block=chain.block,
        block_hash=chain.block_hash,
        prior_last_update=chain.validator_last_update,
        nonce=chain.validator_nonce,
        mortality_period=128,
        weights_version_key=chain.weights_version_key,
        destinations=(0, 1),
        weights=(0, 65535),
        projection=CohortRewardProjection(
            schema="umi-cohort-reward-projection/1",
            allocation_sha256="33" * 32,
            snapshot_sha256="44" * 32,
            recipients=(),
            uids=(1,),
            weights=(65535,),
        ),
        chain_evidence_sha256=hashlib.sha256(raw).hexdigest(),
        control_evidence_sha256=h.captured.evidence_sha256,
        metadata_sha256=chain.runtime.metadata_sha256,
    )
    store = StandingWeightJournal(
        tmp_path / "standing",
        series_sha256=intent.series_sha256,
        validator_hotkey=h.item.hotkey,
        chain_config_sha256=digest(h.provider.config),
        maximum_bytes=8 * 1024**2,
    )
    store.reserve(intent, chain=raw, control=h.raw, metadata=h.metadata)
    before = store.recovery_inputs()
    await h.provider.aclose()
    h.provider = h.reopen()
    if change is not None:
        with pytest.raises((ValueError, ValidatorChainError)):
            await review_standing_transaction(h.provider, store, control_hotkey=h.item.hotkey)
    else:
        result = await review_standing_transaction(h.provider, store, control_hotkey=h.item.hotkey)
        assert result.query is None and result.pending == before.pending
        assert h.executions == [h.item.code]
        assert len(h.code_checks) == 2  # Control execution and original weight code proof.
        assert all(
            row["state_root"] == bytes.fromhex(h.old.state_root[2:]) for row in h.code_checks
        )
        assert {method for method, _ in h.rpc_calls} == {"chain_getHeader", "chain_getBlockHash"}
    assert store.recovery_inputs() == before
