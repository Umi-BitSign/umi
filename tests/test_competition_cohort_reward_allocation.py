"""Fixed entitlements survive UID reuse, absence, rejoin and target expiry."""

import pytest

from umi.competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    project_reward_allocation,
)
from umi.competition_cohort_service_allocation import ServiceRecipientAmount
from umi.competition_settlement import PromotionHeadBinding
from umi.open_competition import BurnDestination, RegistrationSnapshot, digest, identity

from .test_open_competition import policy as policy
from .test_open_competition import wallet


def key(name):
    return wallet(name).hotkey.ss58_address


def allocation(policy):
    return CohortRewardAllocation(
        schema="umi-cohort-reward-allocation/1",
        policy_sha256=digest(policy),
        round_sha256="ab" * 32,
        service_certificate_sha256="cd" * 32,
        quality_manifest_sha256="ef" * 32,
        promotion_head=PromotionHeadBinding(
            sequence=0,
            promotion_sha256="12" * 32,
            model_sha256="34" * 32,
            contributor_hotkey=None,
        ),
        recipients=tuple(
            sorted(
                [
                    ServiceRecipientAmount(hotkey=key("Alice"), raw_weight=20000),
                    ServiceRecipientAmount(hotkey=key("Bob"), raw_weight=25874),
                ],
                key=lambda r: identity(r.hotkey),
            )
        ),
        burn_weight=19661,
    )


def snapshot(*members, block=1000000, burn_uid=0):
    return RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=block,
        block_hash="0x" + "12" * 32,
        registrations=tuple(
            {"uid": uid, "hotkey": key(name)} for uid, name in [(burn_uid, "Burn"), *members]
        ),
        burn_destination=BurnDestination(uid=burn_uid, hotkey=key("Burn")),
    )


def row(a, s, policy, **changes):
    p = project_reward_allocation(a, s, policy, current_block=changes.get("current_block", s.block))
    assert sum(p.weights) == 65535
    assert not p.chain_submission_authorized
    return dict(zip(p.uids, p.weights, strict=True))


def test_fixed_shares_survive_uid_reuse_absence_and_rejoin_after_old_deadlines(policy):
    a = allocation(policy)
    before = digest(a)
    assert row(a, snapshot((6, "Alice"), (9, "Bob")), policy) == {0: 19661, 6: 20000, 9: 25874}
    # A new occupant gets nothing. Bob's allocation is not inflated.
    assert row(a, snapshot((6, "Eve"), (9, "Bob")), policy) == {0: 39661, 9: 25874}
    assert row(a, snapshot((6, "Eve"), (9, "Bob"), (247, "Alice")), policy) == {
        0: 19661,
        9: 25874,
        247: 20000,
    }
    assert row(a, snapshot((6, "Eve")), policy) == {0: 65535}
    assert digest(a) == before


def test_current_burn_destination_can_move_without_changing_allocation(policy):
    a = allocation(policy)
    assert row(a, snapshot((6, "Alice"), burn_uid=15), policy) == {6: 20000, 15: 45535}


@pytest.mark.parametrize("age", [-1, 11])
def test_fixed_allocations_still_require_fresh_registration(policy, age):
    s = snapshot((6, "Alice"))
    with pytest.raises(ValueError, match="stale or from the future"):
        row(allocation(policy), s, policy, current_block=s.block + age)


@pytest.mark.parametrize(
    "damage",
    ["missing_burn", "wrong_burn", "duplicate_uid", "duplicate_hotkey", "policy"],
)
def test_projection_rejects_unproved_shape_or_unrelated_authority(policy, damage):
    a, s = allocation(policy), snapshot((6, "Alice"), (9, "Bob"))
    if damage == "missing_burn":
        s = s.model_copy(update={"burn_destination": None})
    elif damage == "wrong_burn":
        s = s.model_copy(update={"burn_destination": BurnDestination(uid=0, hotkey=key("Eve"))})
    elif damage in ("duplicate_uid", "duplicate_hotkey"):
        r = s.registrations[1].model_copy(
            update={"hotkey": key("Eve")} if damage == "duplicate_uid" else {"uid": 13}
        )
        s = s.model_copy(update={"registrations": (*s.registrations, r)})
    elif damage == "policy":
        a = a.model_copy(update={"policy_sha256": "ff" * 32})
    with pytest.raises(ValueError):
        row(a, s, policy)


def test_recipient_becoming_burn_destination_does_not_hold_other_recipients(policy):
    a = allocation(policy)
    s = snapshot((6, "Alice"), (9, "Bob"))
    s = s.model_copy(update={"burn_destination": BurnDestination(uid=6, hotkey=key("Alice"))})
    p = project_reward_allocation(a, s, policy, current_block=s.block)
    assert dict(zip(p.uids, p.weights, strict=True)) == {6: 39661, 9: 25874}
    assert next(r for r in p.recipients if r.hotkey == key("Alice")).reason == "burn_destination"


@pytest.mark.parametrize("damage", ["duplicate", "nonconserving", "zero"])
def test_invalid_fixed_budget_is_never_projected(policy, damage):
    a = allocation(policy)
    if damage == "duplicate":
        a = a.model_copy(update={"recipients": (*a.recipients, a.recipients[0])})
    elif damage == "nonconserving":
        a = a.model_copy(update={"burn_weight": 0})
    else:
        a = a.model_copy(
            update={
                "recipients": (
                    a.recipients[0].model_copy(update={"raw_weight": 0}),
                    *a.recipients[1:],
                )
            }
        )
    with pytest.raises(ValueError):
        row(a, snapshot((6, "Alice")), policy)
