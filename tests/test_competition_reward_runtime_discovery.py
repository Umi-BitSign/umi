"""Runtime discovery through native online and retained-proof consumers."""

import hashlib

import pytest

from umi.competition_reward_eligibility import (
    RewardEligibilityRuntime,
    UnsupportedRewardEpochConsensus,
    validate_qualified_reward_runtime,
)
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.runtime_metadata import RuntimeMetadataExecutor

from . import test_competition_reward_runtime479 as legacy_runtime
from .test_competition_historical_registration import change_block
from .test_competition_reward_runtime479 import base_policy as base_policy
from .test_competition_reward_runtime479 import chain as chain
from .test_competition_reward_runtime479 import chain_config as chain_config
from .test_competition_reward_runtime479 import policy as policy
from .test_competition_reward_runtime479 import registered_case as registered_case
from .test_competition_reward_runtime479 import retained as retained

native_case = legacy_runtime.eligibility_case


def discovered_profile():
    return RewardEligibilityRuntime(
        schema="umi-reward-eligibility-runtime/3",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        runtime_binding="native_finalized_executed_code/1",
        epoch_semantics="umi-yuma-eligibility/1",
    )


@pytest.fixture
def yuma_source():
    # The fixture's original profile is historical; the discovery consumer below
    # deliberately has no qualified-code registry or source revision.
    return "f4786f9087cac84cfab37cbdf1e01c399042653a"


@pytest.fixture
async def eligibility_case(native_case, monkeypatch):
    native_case.profile = discovered_profile()
    monkeypatch.setattr("umi.competition_reward_eligibility._QUALIFIED_YUMA_RUNTIMES", frozenset())
    return native_case


def test_discovery_profile_has_explicit_semantics_and_no_code_or_release_allowlist():
    profile = discovered_profile()
    raw = canonical_json_bytes(profile)
    assert b"runtime_code_sha256" not in raw and b"epoch_source_revision" not in raw
    assert canonical_json_bytes(RewardEligibilityRuntime.model_validate_json(raw)) == raw
    validate_qualified_reward_runtime(profile)
    for change in (
        {"runtime_code_sha256": None},
        {"epoch_source_revision": None},
        {"runtime_code_sha256": "ff" * 32},
        {"epoch_source_revision": "f4786f9087cac84cfab37cbdf1e01c399042653a"},
        {"runtime_binding": None},
        {"epoch_semantics": None},
        {"epoch_semantics": "unrecognized"},
    ):
        with pytest.raises(ValueError):
            RewardEligibilityRuntime.model_validate_json(
                canonical_json_bytes(profile.model_dump(by_alias=True) | change)
            )


@pytest.mark.parametrize("field", ["runtime_binding", "epoch_semantics"])
def test_historical_profile_still_refuses_new_fields_even_when_null(field):
    value = {
        "schema": "umi-reward-eligibility-runtime/1",
        "genesis_hash": FINNEY_GENESIS_HASH,
        "netuid": 78,
        "runtime_code_sha256": "a9" * 32,
        "epoch_source_revision": "c004cebf360f4088187ee49d851dfb1a1eaaf710",
        field: None,
    }
    with pytest.raises(ValueError):
        RewardEligibilityRuntime.model_validate_json(canonical_json_bytes(value))


async def test_native_runtime_change_keeps_profile_and_binds_each_new_code_proof(
    eligibility_case, monkeypatch
):
    t = eligibility_case
    first = await t.capture()
    old_code = first.chain.runtime.code_evidence.value
    invoke = RuntimeMetadataExecutor._invoke

    def next_metadata(self, code):
        import json

        value = json.loads(invoke(self, code))
        value["spec_version"] = 999999
        return canonical_json_bytes(value) + b"\n"

    monkeypatch.setattr(RuntimeMetadataExecutor, "_invoke", next_metadata)

    def next_codec(self, metadata, spec_version, transaction_version, *, ss58_format):
        assert metadata == b"metadata"
        assert (spec_version, transaction_version, ss58_format) == (999999, 1, 42)
        self.spec_version = spec_version
        self.transaction_version = transaction_version

    monkeypatch.setattr(legacy_runtime._Runtime, "__init__", next_codec)
    t.code = b"a later finalized runtime with compatible proved state"
    change_block(t, first.chain.block + 1)
    second = await t.capture()
    assert first.eligible and second.eligible
    assert second.runtime_profile_sha256 == first.runtime_profile_sha256 == digest(t.profile)
    assert second.chain.runtime.code_evidence.value == t.code != old_code
    assert second.chain.runtime.pin.spec_version == 999999
    assert second.chain.snapshot != first.chain.snapshot
    assert (
        hashlib.sha256(second.chain.evidence).digest()
        != hashlib.sha256(first.chain.evidence).digest()
    )


@pytest.mark.parametrize("mode", ["Null", "unknown", 0, {"Yuma": None}])
async def test_runtime_discovery_does_not_accept_unsupported_epoch_semantics(
    eligibility_case, mode
):
    t = eligibility_case
    t.rpc.values["SubtensorModule", "SubnetEpochConsensus", (78,)] = mode
    with pytest.raises(UnsupportedRewardEpochConsensus):
        await t.capture()


async def test_runtime_discovery_keeps_native_proof_guard(eligibility_case):
    t = eligibility_case
    t.rpc.bad_proof = True
    with pytest.raises((ValueError, RuntimeError)):
        await t.capture()


async def test_discovered_profile_and_original_evidence_survive_offline_restart(retained):
    h = retained
    first = await h.review()
    await h.t.provider.aclose()
    h.t.provider = h.reopen()
    second = await h.review()
    assert first.eligible and second.eligible
    assert second.subject == first.subject
    assert second.runtime_profile_sha256 == first.runtime_profile_sha256
    assert second.eligibility_evidence == first.eligibility_evidence
    assert {p.name: p.read_bytes() for p in h.archive.iterdir()} == h.before
