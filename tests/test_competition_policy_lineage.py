"""Deal-preserving policy lineage: operational successors carry submissions forward."""

from __future__ import annotations

import pytest

from umi.competition_policy_lineage import (
    DEAL_FIELDS,
    OPERATIONAL_FIELDS,
    PolicyLineage,
    deal_digest,
    operational_successor_of,
    policy_admits,
    validate_operational_successor,
)
from umi.open_competition import CompetitionPolicy, Evaluator, digest
from umi.protocol import canonical_json_bytes

from .test_open_competition import wallet


def policy() -> CompetitionPolicy:
    # Test fixture allocations and identities only, never release defaults.
    return CompetitionPolicy(
        schema="umi-open-competition-policy/1",
        network="finney",
        netuid=78,
        sequence=1,
        predecessor_sha256=None,
        valid_from_block=100,
        valid_through_block=1000,
        endpoint_reward_bps=7000,
        model_reward_bps=3000,
        minimum_score_bps=1000,
        promotion_margin_bps=100,
        minimum_cases_per_stratum=1,
        maximum_inference_ms=1000,
        maximum_output_bytes=100,
        maximum_bundle_bytes=10_000,
        maximum_bundle_files=20,
        minimum_submission_interval_blocks=5,
        maximum_submission_lifetime_blocks=900,
        maximum_snapshot_age_blocks=10,
        maximum_uids=256,
        evaluators=(
            Evaluator(hotkey=wallet("Charlie").hotkey.ss58_address, control_group="c"),
            Evaluator(hotkey=wallet("Dave").hotkey.ss58_address, control_group="d"),
        ),
        required_evaluator_groups=2,
        contribution_terms_sha256="a1" * 32,
        accepted_model_licenses=("CC-BY-SA-4.0",),
        evaluation_runtime_sha256="a2" * 32,
    )


def successor(prior: CompetitionPolicy, **changes) -> CompetitionPolicy:
    body = prior.model_dump(mode="json", by_alias=True)
    body.update(sequence=prior.sequence + 1, predecessor_sha256=digest(prior), **changes)
    return CompetitionPolicy.model_validate_json(canonical_json_bytes(body))


def test_every_policy_field_is_classified_exactly_once() -> None:
    names = {info.alias or name for name, info in CompetitionPolicy.model_fields.items()}
    assert DEAL_FIELDS | OPERATIONAL_FIELDS == names
    assert not DEAL_FIELDS & OPERATIONAL_FIELDS


def test_deal_digest_ignores_operational_fields_only() -> None:
    base = policy()
    assert deal_digest(base) == deal_digest(
        successor(base, maximum_inference_ms=2000, evaluation_runtime_sha256="9" * 64)
    )
    assert deal_digest(base) != deal_digest(successor(base, contribution_terms_sha256="a" * 64))
    assert deal_digest(base) != deal_digest(successor(base, endpoint_reward_bps=6000, model_reward_bps=4000))
    assert deal_digest(base) != deal_digest(successor(base, maximum_bundle_bytes=20_000))


@pytest.mark.parametrize(
    "changes",
    [
        {"maximum_inference_ms": 240_000},
        {"evaluation_runtime_sha256": "f" * 64},
        {"minimum_cases_per_stratum": 3},
        {"maximum_snapshot_age_blocks": 120},
        {"minimum_score_bps": 2000, "promotion_margin_bps": 200},
        {"required_evaluator_groups": 1},
    ],
)
def test_operational_successor_admits_predecessor_submissions(changes) -> None:
    prior = policy()
    live = successor(prior, **changes)
    validate_operational_successor(live, prior)
    assert operational_successor_of(live, prior)
    lineage = PolicyLineage(live, [prior])
    assert lineage.admitted_policy_sha256s == (digest(live), digest(prior))
    assert lineage.admits(digest(prior))
    assert lineage.admits(digest(live))
    assert policy_admits(live, digest(prior), [prior])
    assert lineage.policy(digest(prior)) == prior


@pytest.mark.parametrize(
    "changes",
    [
        {"contribution_terms_sha256": "b" * 64},
        {"endpoint_reward_bps": 6000, "model_reward_bps": 4000},
        {"maximum_bundle_bytes": 5_000},
        {"maximum_submission_lifetime_blocks": 450},
        {"accepted_model_licenses": ("MIT",)},
        {"valid_through_block": 2000},
    ],
)
def test_deal_change_does_not_carry_predecessor_submissions(changes) -> None:
    prior = policy()
    live = successor(prior, **changes)
    assert not operational_successor_of(live, prior)
    with pytest.raises(ValueError, match="changes deal fields without re-consent"):
        validate_operational_successor(live, prior)
    lineage = PolicyLineage(live, [prior])
    assert lineage.admitted_policy_sha256s == (digest(live),)
    assert not lineage.admits(digest(prior))
    assert not policy_admits(live, digest(prior), [prior])


def test_change_and_revert_cannot_launder_a_stale_consent() -> None:
    p1 = policy()
    p2 = successor(p1, contribution_terms_sha256="c" * 64)  # terms changed
    p3 = successor(p2, contribution_terms_sha256=p1.contribution_terms_sha256)  # restored
    assert deal_digest(p1) == deal_digest(p3)  # endpoints agree...
    lineage = PolicyLineage(p3, [p2, p1])
    # ...but the hop p3 -> p2 is a deal change, so nothing behind it is honored.
    assert lineage.admitted_policy_sha256s == (digest(p3),)
    assert not lineage.admits(digest(p1))


def test_lineage_walks_several_operational_hops() -> None:
    p1 = policy()
    p2 = successor(p1, maximum_inference_ms=2000)
    p3 = successor(p2, evaluation_runtime_sha256="d" * 64)
    p4 = successor(p3, minimum_cases_per_stratum=2)
    lineage = PolicyLineage(p4, [p3, p2, p1])
    assert lineage.admitted_policy_sha256s == tuple(digest(p) for p in (p4, p3, p2, p1))


def test_lineage_rejects_a_non_contiguous_chain() -> None:
    p1 = policy()
    p2 = successor(p1, maximum_inference_ms=2000)
    p3 = successor(p2, maximum_inference_ms=3000)
    with pytest.raises(ValueError, match="not a contiguous predecessor chain"):
        PolicyLineage(p3, [p1])  # skipped p2
    unrelated = successor(policy(), maximum_uids=128)
    with pytest.raises(ValueError, match="not a contiguous predecessor chain"):
        PolicyLineage(p2, [unrelated])


def test_successor_must_immediately_follow() -> None:
    p1 = policy()
    skipped = successor(successor(p1, maximum_inference_ms=2000), maximum_inference_ms=3000)
    with pytest.raises(ValueError, match="does not immediately follow"):
        validate_operational_successor(skipped, p1)


def test_root_policy_lineage_admits_only_itself() -> None:
    root = policy()
    lineage = PolicyLineage(root)
    assert lineage.admitted_policy_sha256s == (digest(root),)
    assert lineage.deal_sha256 == deal_digest(root)
