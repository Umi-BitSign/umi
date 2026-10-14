"""Explicit bootstrap adoption, immutable admission and retained signed bytes."""

import json
from types import SimpleNamespace

import pytest

from umi.bootstrap_weights import (
    build_bootstrap_eligibility_manifest,
    sign_bootstrap_eligibility_manifest,
)
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
    initial_reward_boundary,
    verify_adoption_selection,
)
from umi.competition_reward_bootstrap import BootstrapRewardPredecessor
from umi.competition_reward_decisions import RewardControlDecision, verify_reward_decisions
from umi.competition_reward_files import StandingRewardFiles
from umi.competition_reward_publication import retain_standing_reward_inputs
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .factories import dev_wallet
from .test_bootstrap_weights import _entry, _policy
from .test_competition_reward_adoption import adoption_case, revised, transition
from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_competition_reward_decisions import signatures, signed, successor_series


def bootstrap_case(c):
    coordinator, miner = dev_wallet("//BootstrapCoordinator"), dev_wallet("//BootstrapMiner")
    policy = _policy(coordinator)
    manifest = build_bootstrap_eligibility_manifest(
        policy,
        [_entry(policy, miner, pilot_byte="2", uid=2)],
        frozen_at_block=125,
        frozen_at_block_hash="0x" + "12" * 32,
    )
    anchor = BootstrapRewardPredecessor(
        schema="umi-bootstrap-reward-predecessor/1",
        signed_manifest=sign_bootstrap_eligibility_manifest(manifest, wallet=coordinator),
        control_hotkey=c.series.control_hotkey,
        committed_at_block=130,
    )
    original, old = adoption_case(c, revisions=1)
    body = RewardModelAdoption.model_validate(
        {
            **old.adoptions[0].adoption.model_dump(by_alias=True),
            "schema": "umi-standing-model-reward-adoption/3",
            "bootstrap_predecessor": anchor,
            "issued_at_block": max(181, c.series.recovery.authority.issued_at_block),
        }
    )
    adoption = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    selection = RewardAdoptionSelection(schema=old.schema_, adoptions=(adoption,))
    genesis = signed(
        RewardControlDecision(
            schema="umi-reward-control-decision/4",
            series_sha256=digest(c.series),
            sequence=0,
            predecessor_sha256=anchor.control_sha256,
            kind="admit_series",
            observed_at_block=max(200, c.series.recovery.authority.issued_at_block),
            activation=None,
            admission_adoption_sha256=digest(body),
            admission_predecessor_committed_at_block=anchor.committed_at_block,
        )
    )
    return SimpleNamespace(
        anchor=anchor, adoption=adoption, selection=selection, genesis=genesis, original=original
    )


def test_historical_signer_and_control_key_are_distinct_and_expiry_is_not_renewed(series_case):
    c, b = series_case, bootstrap_case(series_case)
    assert b.anchor.signed_manifest.coordinator_hotkey != c.series.control_hotkey
    assert verify_adoption_selection(b.selection, c.series, c.control.policy) == b.selection
    assert initial_reward_boundary(c.series, b.selection) == (
        b.anchor.control_sha256,
        130,
        digest(b.adoption.adoption),
    )
    assert verify_reward_decisions(
        c.series, c.control.policy, (b.genesis,), reward_adoptions=b.selection
    ) == (b.genesis,)


@pytest.mark.parametrize(
    "field,value",
    [
        ("predecessor_sha256", "ff" * 32),
        ("admission_adoption_sha256", "ee" * 32),
        ("admission_predecessor_committed_at_block", 131),
        ("observed_at_block", 180),
    ],
)
def test_genesis_must_bind_exact_timely_signed_adoption(series_case, field, value):
    c, b = series_case, bootstrap_case(series_case)
    body = b.genesis.decision.model_copy(update={field: value})
    with pytest.raises(ValueError):
        verify_reward_decisions(
            c.series, c.control.policy, (signed(body),), reward_adoptions=b.selection
        )


def test_bootstrap_cannot_reinterpret_original_genesis_or_standing_successor(series_case):
    c, b = series_case, bootstrap_case(series_case)
    with pytest.raises(ValueError):
        verify_reward_decisions(
            c.series, c.control.policy, (c.genesis,), reward_adoptions=b.selection
        )
    with pytest.raises(ValueError):
        verify_reward_decisions(c.series, c.control.policy, (b.genesis,))
    with pytest.raises(ValueError, match="boundary"):
        b.anchor.check_series(successor_series(c.series))


@pytest.mark.parametrize(
    "field,value",
    [
        ("committed_at_block", 150),
        ("committed_at_block", 124),
        ("control_hotkey", dev_wallet("//WrongControl").hotkey.ss58_address),
    ],
)
def test_bootstrap_must_predate_authority_and_match_control(series_case, field, value):
    b = bootstrap_case(series_case)
    with pytest.raises(ValueError, match="boundary"):
        b.anchor.model_copy(update={field: value}).check_series(series_case.series)


def test_recommit_and_wrong_slot_are_rejected(series_case):
    b = bootstrap_case(series_case)
    fields = dict(
        control_hotkey=b.anchor.control_hotkey,
        control_sha256=b.anchor.control_sha256,
        committed_at_block=130,
    )
    b.anchor.check_control(SimpleNamespace(**fields))
    for update in ({"committed_at_block": 131}, {"control_sha256": "ff" * 32}):
        with pytest.raises(ValueError, match="native control"):
            b.anchor.check_control(SimpleNamespace(**(fields | update)))


def test_unsigned_anchor_and_invalid_historical_signature_are_rejected(series_case):
    c, b = series_case, bootstrap_case(series_case)
    for anchor in (
        b.anchor.model_copy(update={"committed_at_block": 131}),
        b.anchor.model_copy(
            update={
                "signed_manifest": b.anchor.signed_manifest.model_copy(
                    update={"signature": "00" * 64}
                )
            }
        ),
    ):
        body = b.adoption.adoption.model_copy(update={"bootstrap_predecessor": anchor})
        bad = b.selection.model_copy(
            update={"adoptions": (b.adoption.model_copy(update={"adoption": body}),)}
        )
        with pytest.raises(ValueError):
            verify_adoption_selection(bad, c.series, c.control.policy)


async def test_native_reader_restart_follows_bootstrap_genesis_and_adopted_activation(series_case):
    c, b = series_case, bootstrap_case(series_case)
    active = transition(
        c,
        (b.genesis,),
        "activate",
        revised(b.original.decision.activation, b.adoption),
        observed=201,
    )
    for value in (b.genesis, active):
        c.objects[digest(value.decision)] = canonical_json_bytes(value)
    c.reader = c.reopen(reward_adoptions=b.selection)
    first = c.reader.select(await c.observe(active, block=201), c.source)
    assert first.state == "selected"
    assert b.anchor.control_sha256 not in c.fetches
    c.reader = c.reopen(reward_adoptions=b.selection)
    assert c.reader.select(await c.observe(active, block=201), lambda _: None) == first


def test_delivery_retains_adoption_before_genesis_and_retries_exactly(series_case, tmp_path):
    c, b = series_case, bootstrap_case(series_case)
    files = StandingRewardFiles(
        tmp_path / "publication", maximum_package_bytes=1000000, maximum_witness_bytes=1000000
    )
    for _ in range(2):
        assert retain_standing_reward_inputs(
            files,
            c.series,
            c.control.policy,
            (b.genesis,),
            lambda _: pytest.fail("no package"),
            reward_adoptions=b.selection,
        ) == digest(b.genesis.decision)
        assert files.adoption(digest(b.adoption.adoption)) == b.adoption
        assert files.decision(digest(b.genesis.decision)) == canonical_json_bytes(b.genesis)


def test_original_signed_schema_bytes_omit_new_fields(series_case):
    c = series_case
    _, old = adoption_case(c, revisions=1)
    for value in (c.genesis.decision, old.adoptions[0].adoption):
        raw = canonical_json_bytes(value)
        assert not any("bootstrap" in k or "admission_" in k for k in json.loads(raw))
        assert canonical_json_bytes(type(value).model_validate_json(raw)) == raw


def test_economic_revision_retains_immutable_initial_adoption(series_case):
    c, b = series_case, bootstrap_case(series_case)
    body = b.adoption.adoption.model_copy(
        update={
            "revision": 2,
            "predecessor_adoption_sha256": digest(b.adoption.adoption),
            "issued_at_block": 190,
        }
    )
    second = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    selection = b.selection.model_copy(update={"adoptions": (b.adoption, second)})
    verify_adoption_selection(selection, c.series, c.control.policy)
    assert initial_reward_boundary(c.series, selection)[2] == digest(b.adoption.adoption)
    changed = body.model_copy(
        update={"bootstrap_predecessor": b.anchor.model_copy(update={"committed_at_block": 131})}
    )
    selection = selection.model_copy(
        update={
            "adoptions": (
                b.adoption,
                SignedRewardModelAdoption(adoption=changed, signatures=signatures(changed)),
            )
        }
    )
    with pytest.raises(ValueError, match="original bootstrap"):
        verify_adoption_selection(selection, c.series, c.control.policy)
