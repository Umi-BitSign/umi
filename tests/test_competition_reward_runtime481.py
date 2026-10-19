"""Exact481 qualification preserves old profiles and refuses code drift safely."""

import json
from pathlib import Path

import pytest

from umi.competition_reward_coverage_collector import _log_retry
from umi.competition_reward_eligibility import (
    RewardEligibilityRuntime,
    RewardRuntimeCodeMismatch,
    collect_reward_eligibility,
    validate_qualified_reward_runtime,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_eligibility import chain as chain
from .test_competition_reward_eligibility import chain_config as chain_config
from .test_competition_reward_eligibility import eligibility_case as eligibility_case
from .test_competition_reward_eligibility import policy as policy
from .test_competition_reward_eligibility import registered_case as registered_case

FIXTURE = Path(__file__).parent / "fixtures/reward-eligibility/runtime481-qualification.json"


def profile():
    data = json.loads(FIXTURE.read_bytes())
    return RewardEligibilityRuntime(
        schema=data["profile_schema"],
        netuid=78,
        genesis_hash="2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03",
        runtime_code_sha256=data["runtime_code_sha256"],
        epoch_source_revision=data["epoch_source_revision"],
    )


def test_exact481_pair_and_original479_bytes_remain_supported():
    value = profile()
    validate_qualified_reward_runtime(value)
    for name in ["runtime479-qualification.json", "runtime481-qualification.json"]:
        data = json.loads(FIXTURE.with_name(name).read_bytes())
        selected = value.model_copy(
            update={
                "runtime_code_sha256": data["runtime_code_sha256"],
                "epoch_source_revision": data["epoch_source_revision"],
            }
        )
        raw = canonical_json_bytes(selected)
        validate_qualified_reward_runtime(selected)
        assert canonical_json_bytes(RewardEligibilityRuntime.model_validate_json(raw)) == raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime_code_sha256", "fe" * 32),
        ("epoch_source_revision", "f4786f9087cac84cfab37cbdf1e01c399042653a"),
    ],
)
def test481_code_cannot_relabel_unknown_or_old_source(field, value):
    with pytest.raises(ValueError):
        validate_qualified_reward_runtime(profile().model_copy(update={field: value}))


def test_original_schema_cannot_select481_semantics():
    with pytest.raises(ValueError):
        RewardEligibilityRuntime.model_validate_json(
            canonical_json_bytes(
                profile().model_copy(update={"schema_": "umi-reward-eligibility-runtime/1"})
            )
        )


@pytest.mark.asyncio
async def test_native_current_code_drift_reports_hashes_before_eligibility(eligibility_case):
    t = eligibility_case
    # Fixture is synthetic native chain/trie execution, never Finney qualification.
    changed = t.profile.model_copy(update={"runtime_code_sha256": "ff" * 32})
    chain = await t.provider.collect_registered_weights(t.hotkey)
    with pytest.raises(RewardRuntimeCodeMismatch) as caught:
        await collect_reward_eligibility(
            t.provider, chain, changed, expected_runtime_profile_sha256=digest(changed)
        )
    assert caught.value.expected_runtime_code_sha256 == "ff" * 32
    assert caught.value.observed_runtime_code_sha256 == t.profile.runtime_code_sha256


def test_nested_code_drift_retry_logs_safe_numeric_identity_only(caplog):
    code = RewardRuntimeCodeMismatch(expected="ee" * 32, observed="aa" * 32)
    error = ValueError("wss://provider.invalid/?api_key=never-log-this")
    error.__cause__ = code
    with caplog.at_level("INFO", logger="umi.competition_reward_coverage_collector"):
        _log_retry(error, phase="fresh", operation="capture", block=123)
    assert "reward_eligibility_runtime_code_mismatch" in caplog.text
    assert "ee" * 32 in caplog.text and "aa" * 32 in caplog.text
    assert "never-log-this" not in caplog.text and "provider.invalid" not in caplog.text
