"""Real signed control/allocation approval with synthetic native chain ports.

These cases do not qualify deployed publication or external validator adoption.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_decisions import RewardActivation
from umi.open_competition import digest
from umi.translation_reference_policy import reference_policy_sha256, verify_reference_policy
from umi.translation_reference_publication import TranslationReferenceApprovalPublisher
from umi.weight_storage import subtensor_stored_weights

from .test_competition_chain import chain, chain_config
from .test_competition_cohort_reward_allocation import allocation, key
from .test_competition_reward_control import control
from .test_competition_reward_decisions import series_case
from .test_competition_reward_registrations import base_policy, policy, set_members
from .test_open_competition import wallet

__all__ = ["base_policy", "chain", "chain_config", "control", "policy", "series_case"]


@pytest.fixture
async def publication_case(series_case, tmp_path):
    c, item = series_case, series_case.control
    reward = allocation(item.policy)
    activation = RewardActivation(
        cohort_sha256=digest(c.series.cohorts[0]),
        allocation_sha256=digest(reward),
        package_sha256="ab" * 32,
        recovery_tip_sha256="bc" * 32,
        prior_opportunity_sha256="cd" * 32,
    )
    tip = c.decision(c.genesis, 5, activation=activation)
    set_members(item, [key(n) for n in ("Burn", "Alice", "Bob")])
    stored = list(enumerate(subtensor_stored_weights((19661, 20000, 25874))))
    values = dict(
        ValidatorPermit=[False, True, False],
        LastUpdate=[0, item.finality.ref.block_number - 5, 0],
        MechanismCountCurrent=1,
        CommitRevealWeightsEnabled=False,
        WeightsVersionKey=2**32,
        MinAllowedWeights=1,
        MaxAllowedUids=256,
        MaxWeightsLimit=65535,
        WeightsSetRateLimit=10,
        SubnetOwnerHotkey=key("Burn"),
        RecycleOrBurn="Burn",
    )
    item.rpc.values.update({("SubtensorModule", k, (78,)): v for k, v in values.items()})
    item.rpc.values[("SubtensorModule", "Weights", (78, 1))] = stored
    item.rpc.values[("System", "Account", (key("Alice"),))] = {"nonce": 10}
    calls, objects, events = [], {}, []

    def signer():
        calls.append("signer")
        return wallet("Charlie").hotkey

    def publish(name, raw):
        calls.append((name, raw))
        if name in objects:
            assert objects[name] == raw
        objects[name] = raw

    def reopen(**changes):
        options = dict(
            reference_hotkey=key("Alice"),
            signer_loader=signer,
            publish_immutable=publish,
            maximum_bytes=8 * 1024**2,
            progress=events.append,
            authority_hotkey=key("Charlie"),
        )
        options.update(changes)
        return TranslationReferenceApprovalPublisher(tmp_path / "approvals", c.reader, **options)

    async def inputs(selected=tip):
        observed = await c.observe(selected)
        native = await item.provider.collect_registered_weights(key("Alice"), at=observed.snapshot)
        return dict(
            control=observed,
            source=c.source,
            allocation=reward,
            chain=native,
            chain_config=item.config,
        )

    return SimpleNamespace(
        c=c,
        item=item,
        reward=reward,
        activation=activation,
        tip=tip,
        stored=tuple(stored),
        calls=calls,
        objects=objects,
        events=events,
        reopen=reopen,
        inputs=inputs,
    )


async def test_signed_current_allocation_and_native_projection_approve_exact_entire_row(
    publication_case,
):
    c = publication_case
    publisher = c.reopen()
    body = publisher.step(**await c.inputs())
    assert body.expected_row_sha256 == digest(c.stored)
    raw = next(iter(c.objects.values()))
    assert (
        verify_reference_policy(
            raw,
            expected_policy_sha256=reference_policy_sha256(body),
            expected_authority_hotkey=key("Charlie"),
        )
        == body
    )
    assert not body.independent_cohort_certification_claimed
    assert c.calls.count("signer") == 1 and len(c.objects) == 1
    # A newer reference refresh must not re-sign or re-upload the same approval.
    c.item.rpc.values[("SubtensorModule", "LastUpdate", (78,))][1] += 1
    assert c.reopen().step(**await c.inputs()) == body
    assert len(c.calls) == 2
    assert c.events[-1]["completed"] == 1 and c.events[-1]["eta_seconds"] == 0
    assert "channel selection" in c.events[-1]["eta_basis"]


async def test_lost_upload_acknowledgement_retries_exact_retained_signature(publication_case):
    c = publication_case
    received = []

    def lost_ack(name, raw):
        received.append((name, raw))
        raise ConnectionError("lost acknowledgement after durable creation")

    with pytest.raises(ConnectionError):
        c.reopen(publish_immutable=lost_ack).step(**await c.inputs())
    assert c.events[-1]["retrying"]
    c.reopen().step(**await c.inputs())
    assert c.calls.count("signer") == 1
    assert c.objects[received[0][0]] == received[0][1]


@pytest.mark.parametrize(
    "damage", ["allocation", "row", "old_update", "permit", "proof", "snapshot"]
)
async def test_unapproved_or_unproven_input_refuses_before_signer_or_upload(
    publication_case, damage
):
    c = publication_case
    if damage == "row":
        c.item.rpc.values[("SubtensorModule", "Weights", (78, 1))] = [(0, 65535)]
    elif damage == "old_update":
        c.item.rpc.values[("SubtensorModule", "LastUpdate", (78,))][1] = 1
    elif damage == "permit":
        c.item.rpc.values[("SubtensorModule", "ValidatorPermit", (78,))][1] = False
    inputs = await c.inputs()
    if damage == "allocation":
        inputs["allocation"] = c.reward.model_copy(update={"quality_manifest_sha256": "ee" * 32})
    elif damage == "proof":
        inputs["chain"] = replace(inputs["chain"], validator_row=((0, 65535),))
    elif damage == "snapshot":
        inputs["control"] = replace(
            inputs["control"], snapshot=replace(inputs["control"].snapshot, block_number=1)
        )
    with pytest.raises(ValueError):
        c.reopen().step(**inputs)
    assert not c.calls and not c.objects


@pytest.mark.parametrize("kind", ["revoke", "admit_series"])
async def test_revoked_or_not_activated_series_cannot_publish(publication_case, kind):
    c = publication_case
    selected = c.c.genesis if kind == "admit_series" else c.c.decision(c.tip, kind="revoke")
    with pytest.raises(ValueError, match="effective native selection"):
        c.reopen().step(**await c.inputs(selected))
    assert not c.calls


async def test_wrong_release_authority_cannot_publish(publication_case):
    c = publication_case
    with pytest.raises(ValueError, match="signer differs"):
        c.reopen(signer_loader=lambda: wallet("Dave").hotkey).step(**await c.inputs())
    assert not c.objects


async def test_new_cohort_gets_new_approval_without_replaying_previous_payloads(publication_case):
    c = publication_case
    first = c.reopen().step(**await c.inputs())
    next_activation = c.activation.model_copy(
        update={"cohort_sha256": digest(c.c.series.cohorts[1])}
    )
    successor = c.c.decision(c.tip, 6, activation=next_activation)
    second = c.reopen().step(**await c.inputs(successor))
    assert (first.first_cohort_sequence, second.first_cohort_sequence) == (5, 6)
    assert first.expected_row_sha256 == second.expected_row_sha256
    assert reference_policy_sha256(first) != reference_policy_sha256(second)
    assert len(c.objects) == 2 and c.calls.count("signer") == 2
    assert all(not method.startswith("author_") for method, _ in c.item.rpc.calls)


async def test_missing_retained_signed_bytes_requires_restoration(publication_case):
    c = publication_case
    publisher = c.reopen()
    policy = publisher.step(**await c.inputs())
    with publisher.journal.transaction() as db:
        db.execute(
            "DELETE FROM records WHERE kind='reference_approval' AND id=?",
            (reference_policy_sha256(policy),),
        )
    with pytest.raises(ValueError, match="restoration of signed bytes"):
        c.reopen().step(**await c.inputs())
    assert c.calls.count("signer") == 1


async def test_publication_owner_mutex_excludes_another_instance(publication_case):
    c = publication_case
    one, two = c.reopen(), c.reopen()
    inputs = await c.inputs()
    with one.journal.locked(), pytest.raises(BlockingIOError):
        two.step(**inputs)
    assert not c.calls


async def test_pending_activation_fence_does_not_publish(publication_case):
    c = publication_case
    inputs = await c.inputs()
    inputs["control"] = await c.c.observe(c.tip, block=c.item.finality.ref.block_number)
    with pytest.raises(ValueError, match="effective native selection"):
        c.reopen().step(**inputs)
    assert not c.calls


async def test_signed_forward_adoption_uses_effective_allocation(publication_case):
    from umi.competition_geometric_rewards import GeometricRewardParameters
    from umi.competition_reward_adoption import (
        RewardAdoptionSelection,
        RewardModelAdoption,
        SignedRewardModelAdoption,
    )

    from .test_competition_reward_decisions import signatures, signed

    c = publication_case
    original = c.activation.model_copy(update={"allocation_sha256": "ef" * 32})
    adoption = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256=digest(c.c.series),
        policy_sha256=c.c.series.policy_sha256,
        cohort_sha256=original.cohort_sha256,
        authority_sha256=digest(c.c.series.recovery.authority),
        package_sha256=original.package_sha256,
        allocation_sha256=original.allocation_sha256,
        service_certificate_sha256=c.reward.service_certificate_sha256,
        quality_manifest_sha256=c.reward.quality_manifest_sha256,
        effective_allocation_sha256=digest(c.reward),
        parameters=GeometricRewardParameters(),
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=180,
        lifetime="until_first_verified_live_reward_then_locked",
    )
    selected = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=(SignedRewardModelAdoption(adoption=adoption, signatures=signatures(adoption)),),
    )
    c.c.reader = c.c.reopen(reward_adoptions=selected)
    active = original.model_copy(
        update={
            "reward_adoption_sha256": digest(adoption),
            "effective_allocation_sha256": digest(c.reward),
        }
    )
    body = c.tip.decision.model_copy(
        update={
            "schema_": "umi-reward-control-decision/3",
            "observed_at_block": 200,
            "activation": active,
        }
    )
    tip = signed(body)
    from umi.protocol import canonical_json_bytes

    c.c.objects[digest(body)] = canonical_json_bytes(tip)
    inputs = await c.inputs(tip)
    inputs["control"] = await c.c.observe(tip, block=210)
    approved = c.reopen().step(**inputs)
    assert approved.expected_row_sha256 == digest(c.stored)
    assert c.calls.count("signer") == 1
