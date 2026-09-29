"""Arithmetic attack cases; native evidence replay is covered by grant tests."""

import random
from fractions import Fraction
from functools import cache

import pytest

from umi.competition_cohort_quality import exact_quality
from umi.competition_cohort_service_allocation import (
    allocate_service_quality,
    apportion_work_budget,
)
from umi.competition_cohort_service_quality import (
    ClosedServiceQuality,
    ServiceTerms,
    ServiceWorkQuality,
)
from umi.open_competition import digest, identity

from .test_open_competition import wallet


@cache
def hotkey(n):
    return wallet("ServiceCredit" + str(n)).hotkey.ss58_address


def terms(**changes):
    return ServiceTerms(
        schema="umi-cohort-service-terms/1",
        policy_sha256="aa" * 32,
        transport_policy_sha256="bb" * 32,
        service_pool_bps=5000,
        stratum_weights={"fingerspelling": 3, "continuous": 10},
    ).model_copy(update=changes)


def work(n, recipient, score=Fraction(1), stratum="fingerspelling"):
    return ServiceWorkQuality(
        work_sha256=f"{n:064x}",
        terminal_sha256="cc" * 32,
        reference_sha256="dd" * 32,
        recipient_hotkey=recipient,
        stratum=stratum,
        status="ok",
        reason_code=None,
        hypothesis_sha256="ee" * 32,
        quality=exact_quality(score),
        credit=exact_quality(score),
    )


def allocate(items, selected=None):
    selected = selected or terms()
    quality = ClosedServiceQuality(
        schema="umi-cohort-service-quality/1",
        terms_sha256=digest(selected),
        request_closure_sha256="ab" * 32,
        reference_reveal_sha256="cd" * 32,
        work=tuple(items),
    )
    return allocate_service_quality(quality, selected)


def amounts(result):
    assert (
        sum(r.raw_weight for r in result.recipients) + result.burn_weight == result.service_budget
    )
    assert result.service_budget + result.model_budget == 65535
    return {identity(r.hotkey): r.raw_weight for r in result.recipients}


def test_work_is_rounded_before_recipients_across_random_alias_partitions():
    rng = random.Random(78)
    aliases, other = [hotkey(n) for n in range(1, 50)], hotkey(70)
    for _ in range(100):
        jobs = [
            work(
                n,
                aliases[0],
                Fraction(rng.randrange(11), 10),
                "continuous" if n % 2 else "fingerspelling",
            )
            for n in range(1, 85)
        ]
        rivals = [
            work(n, other, Fraction(3, 5), "continuous" if n % 2 else "fingerspelling")
            for n in range(85, 115)
        ]
        original = amounts(allocate(jobs + rivals))
        split = [w.model_copy(update={"recipient_hotkey": rng.choice(aliases)}) for w in jobs]
        shuffled = split + rivals
        rng.shuffle(shuffled)
        divided = amounts(allocate(shuffled))
        assert sum(divided.get(identity(k), 0) for k in aliases) == original.get(
            identity(aliases[0]), 0
        )
        assert divided.get(identity(other), 0) == original.get(identity(other), 0)


def test_work_identity_breaks_ties_without_recipient_or_input_order():
    assert apportion_work_budget(2, {"c": Fraction(1), "b": Fraction(1), "a": Fraction(1)}) == {
        "a": 1,
        "b": 1,
        "c": 0,
    }
    jobs = [work(n, hotkey(n)) for n in range(1, 4)]
    first = allocate(jobs)
    assert first == allocate(reversed(jobs)).model_copy(
        update={"quality_sha256": first.quality_sha256}
    )
    assert amounts(first)[identity(hotkey(1))] == 2521
    assert amounts(first)[identity(hotkey(2))] == 2521
    assert amounts(first)[identity(hotkey(3))] == 2520


def test_zero_credit_stratum_burns_its_fixed_budget():
    result = allocate([work(1, hotkey(1), Fraction(0)), work(2, hotkey(2), stratum="continuous")])
    assert amounts(result) == {identity(hotkey(2)): 25205}
    assert result.burn_weight == 7562
    empty = allocate([])
    assert amounts(empty) == {} and empty.burn_weight == 32767


def test_linear_quality_does_not_reward_variance_or_uid_average():
    a, b = hotkey(1), hotkey(2)
    result = allocate(
        [
            work(1, a, Fraction(0)),
            work(2, a),
            work(3, b, Fraction(1, 2)),
            work(4, b, Fraction(1, 2)),
        ]
    )
    assert amounts(result) == {identity(a): 3781, identity(b): 3781}


@pytest.mark.parametrize("bps,service,model", [(5000, 32767, 32768), (7000, 45874, 19661)])
def test_selected_pools_conserve_budget_with_deterministic_rounding(bps, service, model):
    selected = terms(service_pool_bps=bps)
    result = allocate([work(1, hotkey(1)), work(2, hotkey(2), stratum="continuous")], selected)
    assert result.terms_sha256 == digest(selected)
    assert (result.service_budget, result.model_budget) == (service, model)
    assert result.burn_weight == 0
    amounts(result)


@pytest.mark.parametrize(
    "damage", ["duplicate", "conflicting_recipient", "credit", "failure_score"]
)
def test_credit_cannot_be_copied_changed_or_granted_to_a_signed_error(damage):
    item = work(1, hotkey(1))
    items = [item]
    if damage == "duplicate":
        items.append(item)
    elif damage == "conflicting_recipient":
        items.append(item.model_copy(update={"recipient_hotkey": hotkey(2)}))
    elif damage == "credit":
        items = [item.model_copy(update={"credit": exact_quality(Fraction(1, 2))})]
    else:
        items = [item.model_copy(update={"status": "miner_failure"})]
    with pytest.raises(ValueError, match="duplicate or inconsistent"):
        allocate(items)


@pytest.mark.parametrize("bps", [0, 10000])
def test_explicit_pool_extremes_keep_the_budget(bps):
    result = allocate([work(1, hotkey(1))], terms(service_pool_bps=bps))
    amounts(result)
    assert result.service_budget == (65535 if bps else 0)
    assert result.model_budget == (0 if bps else 65535)
