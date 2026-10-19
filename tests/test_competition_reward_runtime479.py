"""Versioned eligibility with native proof consumers and synthetic chain ports.

These fixtures qualify proof/selection behavior, not a deployed runtime build.
"""

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_reward_control_archive import HistoricalRewardControlProvider
from umi.competition_reward_coverage_capture import capture_reward_eligibility
from umi.competition_reward_eligibility import (
    RewardEligibilityRuntime,
    UnsupportedRewardEligibilityRuntime,
    UnsupportedRewardEpochConsensus,
    collect_reward_eligibility,
    validate_qualified_reward_runtime,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_chain import ValidatorChainError

from .test_competition_chain import _Runtime
from .test_competition_historical_registration import change_block
from .test_competition_reward_eligibility import chain as chain
from .test_competition_reward_eligibility import chain_config as chain_config
from .test_competition_reward_eligibility import configure_eligibility
from .test_competition_reward_eligibility import registered_case as registered_case
from .test_competition_reward_eligibility_archive import base_policy as base_policy
from .test_competition_reward_eligibility_archive import policy as policy
from .test_competition_reward_eligibility_archive import retained as retained

CONSENSUS = ("SubtensorModule", "SubnetEpochConsensus", (78,))
LEGACY_REVISION = "c004cebf360f4088187ee49d851dfb1a1eaaf710"
YUMA_REVISION = "f4786f9087cac84cfab37cbdf1e01c399042653a"


def test_reviewed_runtime_pair_is_qualified_without_authorizing_other_code():
    from umi.grandpa_finality import FINNEY_GENESIS_HASH

    provenance = json.loads(
        (
            Path(__file__).parent / "fixtures/reward-eligibility/runtime479-qualification.json"
        ).read_text()
    )
    profile = RewardEligibilityRuntime(
        schema="umi-reward-eligibility-runtime/2",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        runtime_code_sha256=provenance["runtime_code_sha256"],
        epoch_source_revision=provenance["epoch_source_revision"],
    )
    validate_qualified_reward_runtime(profile)
    assert provenance["scope"] == "same-root Yuma pre-consensus row eligibility"
    for code in (provenance["public_ci_candidate_sha256"], "00" * 32, "ff" * 32):
        with pytest.raises(UnsupportedRewardEligibilityRuntime):
            validate_qualified_reward_runtime(
                profile.model_copy(update={"runtime_code_sha256": code})
            )
    with pytest.raises(UnsupportedRewardEligibilityRuntime):
        validate_qualified_reward_runtime(
            profile.model_copy(
                update={
                    "schema_": "umi-reward-eligibility-runtime/1",
                    "epoch_source_revision": LEGACY_REVISION,
                }
            )
        )


@pytest.fixture(params=[YUMA_REVISION, "6a972693ae9580541225bd37696ac2fee26b8ae9"])
def yuma_source(request):
    return request.param


@pytest.fixture
async def eligibility_case(registered_case, monkeypatch, tmp_path, request, yuma_source):
    t = await configure_eligibility(registered_case, monkeypatch, tmp_path)
    t.profile = RewardEligibilityRuntime.model_validate_json(
        canonical_json_bytes(
            {
                **t.profile.model_dump(mode="json", by_alias=True),
                "schema": "umi-reward-eligibility-runtime/2",
                "epoch_source_revision": yuma_source,
            }
        )
    )
    # Synthetic runtime bytes are authorized only inside this fixture. The
    # production qualification registry never accepts them or arbitrary hashes.
    monkeypatch.setattr(
        "umi.competition_reward_eligibility._QUALIFIED_YUMA_RUNTIMES",
        frozenset({(t.profile.runtime_code_sha256, t.profile.epoch_source_revision)}),
    )
    t.rpc.values[CONSENSUS] = getattr(request, "param", "Yuma")
    entry = _Runtime.storage_entry

    def storage_entry(self, pallet, item):
        if (pallet, item) == CONSENSUS[:2]:
            return SimpleNamespace(modifier="Default", default_bytes=b'"Yuma"', value_type="json")
        return entry(self, pallet, item)

    monkeypatch.setattr(_Runtime, "storage_entry", storage_entry)
    try:
        yield t
    finally:
        await t.provider.aclose()


def consensus_claim(body):
    key = "0x" + canonical_json_bytes(CONSENSUS).hex()
    claims = [c for batch in body["storage_batches"] for c in batch["claims"] if c["key"] == key]
    assert len(claims) == 1
    return claims[0]


async def test_profile_versions_preserve_old_bytes_and_refuse_mixed_semantics(eligibility_case):
    profile = eligibility_case.profile.model_dump(mode="json", by_alias=True)
    legacy = {
        **profile,
        "schema": "umi-reward-eligibility-runtime/1",
        "epoch_source_revision": LEGACY_REVISION,
    }
    original = canonical_json_bytes(legacy)
    parsed = RewardEligibilityRuntime.model_validate_json(original)
    assert canonical_json_bytes(parsed) == original
    assert not parsed.requires_epoch_consensus_proof
    with pytest.raises(UnsupportedRewardEligibilityRuntime):
        validate_qualified_reward_runtime(parsed)
    assert eligibility_case.profile.requires_epoch_consensus_proof
    for changed in (
        {**legacy, "epoch_source_revision": YUMA_REVISION},
        {**profile, "epoch_source_revision": LEGACY_REVISION},
        {**profile, "epoch_source_revision": "00" * 20},
    ):
        with pytest.raises(ValueError):
            RewardEligibilityRuntime.model_validate_json(canonical_json_bytes(changed))


@pytest.mark.parametrize("eligibility_case", ["Yuma", None], indirect=True)
async def test_current_endpoint_proves_membership_or_metadata_default_at_its_root(eligibility_case):
    t = eligibility_case
    result = await t.capture()
    assert result.eligible
    body = json.loads(result.evidence)
    claim = consensus_claim(body)
    assert claim["value"] == (None if t.rpc.values[CONSENSUS] is None else "0x" + b'"Yuma"'.hex())
    assert body["runtime_profile_sha256"] == digest(t.profile)
    assert {b["state_root"] for b in body["storage_batches"]} == {result.chain.snapshot.state_root}


@pytest.mark.parametrize("eligibility_case", ["Null", "unknown", 0, {"Yuma": None}], indirect=True)
async def test_unsupported_or_malformed_epoch_mode_holds_instead_of_credit(eligibility_case):
    with pytest.raises(UnsupportedRewardEpochConsensus, match="proved Yuma") as caught:
        await eligibility_case.capture()
    assert caught.value.reason_code == "reward_epoch_consensus_unsupported"


@pytest.mark.parametrize("default", [None, "Null"])
async def test_absence_uses_executed_metadata_and_never_a_local_yuma_default(
    eligibility_case, monkeypatch, default
):
    t = eligibility_case
    t.rpc.values[CONSENSUS] = None
    entry = _Runtime.storage_entry

    def storage_entry(self, pallet, item):
        if (pallet, item) == CONSENSUS[:2]:
            return SimpleNamespace(
                modifier="Optional" if default is None else "Default",
                default_bytes=json.dumps(default).encode(),
                value_type="json",
            )
        return entry(self, pallet, item)

    monkeypatch.setattr(_Runtime, "storage_entry", storage_entry)
    with pytest.raises(UnsupportedRewardEpochConsensus):
        await t.capture()


async def test_epoch_mode_is_reproved_after_root_change_without_runtime_change(eligibility_case):
    t = eligibility_case
    first = await t.capture()
    t.finality.ref = replace(t.finality.ref, state_root="0x" + "77" * 32)
    change_block(t, first.chain.block + 1)
    t.rpc.values[CONSENSUS] = "Null"
    with pytest.raises(UnsupportedRewardEpochConsensus):
        await t.capture()
    t.rpc.values[CONSENSUS] = "Yuma"
    latest = await t.capture()
    assert latest.eligible and latest.chain.snapshot != first.chain.snapshot
    assert latest.runtime_profile_sha256 == first.runtime_profile_sha256
    assert latest.chain.runtime.code_evidence.value == first.chain.runtime.code_evidence.value


async def test_new_semantics_retain_exact_code_and_native_proof_guards(
    eligibility_case, monkeypatch
):
    t = eligibility_case
    chain = await t.provider.collect_registered_weights(t.hotkey)
    wrong = t.profile.model_copy(update={"runtime_code_sha256": "ff" * 32})
    with pytest.raises(UnsupportedRewardEligibilityRuntime):
        validate_qualified_reward_runtime(wrong)
    monkeypatch.setattr(
        "umi.competition_reward_eligibility._QUALIFIED_YUMA_RUNTIMES",
        frozenset((p.runtime_code_sha256, p.epoch_source_revision) for p in (t.profile, wrong)),
    )
    with pytest.raises(ValueError, match="qualified runtime"):
        await collect_reward_eligibility(
            t.provider, chain, wrong, expected_runtime_profile_sha256=digest(wrong)
        )
    with pytest.raises(ValueError, match="selected profile"):
        await collect_reward_eligibility(
            t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(wrong)
        )
    t.rpc.bad_proof = True
    with pytest.raises((ValueError, RuntimeError)):
        await collect_reward_eligibility(
            t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
        )


@pytest.mark.parametrize("eligibility_case", ["Yuma", None], indirect=True)
async def test_original_mode_proof_survives_offline_restart_and_repeated_archive_review(retained):
    h = retained
    first = await h.review()
    assert first.eligible and consensus_claim(json.loads(first.eligibility_evidence))
    await h.t.provider.aclose()
    h.t.provider = h.reopen()
    second = await h.review()
    assert second.subject == first.subject
    assert second.runtime_profile_sha256 == first.runtime_profile_sha256
    assert second.eligibility_evidence == first.eligibility_evidence
    assert set(h.calls) <= {"chain_getHeader", "chain_getBlockHash"}
    assert {p.name: p.read_bytes() for p in h.archive.iterdir()} == h.before


@pytest.mark.parametrize("change", ["missing", "null", "root", "proof", "code"])
async def test_historical_mode_evidence_cannot_be_removed_changed_or_rebound(retained, change):
    h = retained
    body = json.loads(h.before["eligibility"])
    claim = consensus_claim(body)
    batch = next(b for b in body["storage_batches"] if claim in b["claims"])
    options = {}
    if change == "missing":
        batch["claims"].remove(claim)
    elif change == "null":
        claim["value"] = "0x" + b'"Null"'.hex()
    elif change == "root":
        batch["state_root"] = "0x" + "cc" * 32
    elif change == "proof":
        batch["proof"] = ["0x00"]
    else:
        profile = h.t.profile.model_copy(update={"runtime_code_sha256": "ef" * 32})
        options = {"profile": profile, "expected_runtime_profile_sha256": digest(profile)}
    with pytest.raises((ValueError, ValidatorChainError)):
        await h.review(eligibility=canonical_json_bytes(body), **options)
    assert (await h.review()).eligible


@pytest.mark.parametrize("eligibility_case", ["Yuma", None, "Null"], indirect=True)
async def test_historical_capture_and_replay_use_the_same_mode_rule(
    eligibility_case, tmp_path, monkeypatch
):
    t = eligibility_case
    previous = t.provider
    original_at = t.finality.verified_block_at

    async def finalized(height):
        header = change_block(t, height)
        block = await original_at(height)
        raw = canonical_json_bytes(
            {**json.loads(block.finality_evidence), "block": {"scale_header": header}}
        )
        return replace(
            block, finality_evidence=raw, finality_evidence_sha256=hashlib.sha256(raw).hexdigest()
        )

    await finalized(t.finality.ref.block_number)
    monkeypatch.setattr(t.finality, "verified_block_at", finalized)
    await previous.aclose()
    t.provider = HistoricalRewardControlProvider(
        t.config,
        t.policy,
        finality=t.finality,
        proofs=t.proofs,
        now_ms=lambda: t.clock.now,
        historical_header_directory=tmp_path / "capture-headers",
    )
    t.provider._runtime_proofs = previous._runtime_proofs
    from .test_competition_reward_control import commitment

    t.rpc.values[("Commitments", "CommitmentOf", (78, t.hotkey))] = commitment(
        "ab" * 32, t.finality.ref.block_number - 1
    )
    current_control = await t.provider.collect_control(t.hotkey)
    control = await t.provider.review_control(
        current_control.evidence, current_control.runtime.metadata_bytes
    )

    async def capture():
        return await capture_reward_eligibility(
            t.provider,
            control,
            validator_hotkey=t.hotkey,
            control_hotkey=t.hotkey,
            profile=t.profile,
            expected_runtime_profile_sha256=digest(t.profile),
        )

    if t.rpc.values[CONSENSUS] == "Null":
        with pytest.raises(UnsupportedRewardEpochConsensus):
            await capture()
    else:
        result = await capture()
        assert result.eligible
        assert consensus_claim(json.loads(result.eligibility_evidence))["value"] == (
            None if t.rpc.values[CONSENSUS] is None else "0x" + b'"Yuma"'.hex()
        )
