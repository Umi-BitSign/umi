"""Immutable service/model amounts and fresh registration projection.

The owner selects a verified local promotion once. These records still need a
settlement certificate and standing chain authority before any transaction.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_chain_state import (
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_cohort_quality import ClosedQualityReview
from .competition_cohort_quality_signing import CohortQualityManifest, review_quality_manifest
from .competition_cohort_service_allocation import RawWeight, ServiceRecipientAmount
from .competition_cohort_service_certification import (
    CertifiedServiceAllocation,
    ServiceAllocationReview,
    verify_service_allocation_certificate,
)
from .competition_round_journal import RecordReservation, RoundJournal
from .competition_settlement import PromotionHeadBinding
from .competition_store import CompetitionStore
from .open_competition import CompetitionPolicy, Hotkey, RegistrationSnapshot, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex


class CohortRewardAllocation(StrictProtocolModel):
    schema_: Literal["umi-cohort-reward-allocation/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    service_certificate_sha256: Hex32
    quality_manifest_sha256: Hex32
    promotion_head: PromotionHeadBinding
    recipients: Annotated[tuple[ServiceRecipientAmount, ...], Field(max_length=65535)]
    burn_weight: RawWeight
    recipient_rule: Literal["fixed_hotkey_absence_to_burn"] = "fixed_hotkey_absence_to_burn"
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def conserved(self):
        keys = [identity(r.hotkey) for r in self.recipients]
        if keys != sorted(set(keys)) or any(r.raw_weight == 0 for r in self.recipients):
            raise ValueError("reward recipients must be positive, unique and canonically ordered")
        if sum(r.raw_weight for r in self.recipients) + self.burn_weight != 65535:
            raise ValueError("reward allocation must conserve the complete raw budget")
        return self


def build_reward_allocation(
    service: CertifiedServiceAllocation,
    service_review: ServiceAllocationReview,
    benchmark: CohortQualityManifest,
    benchmark_review: ClosedQualityReview,
    promotion: PromotionHeadBinding,
) -> CohortRewardAllocation:
    """Assemble replayed evidence; promotion must come from the owner's store.

    This pure builder does not authenticate the caller's promotion selection.
    Use retain_reward_allocation at the service boundary.
    """
    service_amounts = verify_service_allocation_certificate(service, service_review)
    review_quality_manifest(benchmark, benchmark_review)
    promotion = PromotionHeadBinding.model_validate_json(canonical_json_bytes(promotion))
    statement = service_review.statement
    if (
        statement.policy_sha256 != digest(benchmark_review.policy)
        or statement.round_sha256 != digest(benchmark_review.roster.round)
        or service_amounts.request_closure_sha256 != benchmark.request_closure_sha256
    ):
        raise ValueError("service and benchmark evidence must belong to the same closed round")
    amounts, hotkeys = defaultdict(int), {}
    for item in service_amounts.recipients:
        who = identity(item.hotkey)
        amounts[who] += item.raw_weight
        hotkeys[who] = item.hotkey
    burn = service_amounts.burn_weight
    if promotion.contributor_hotkey is None:
        burn += service_amounts.model_budget
    elif service_amounts.model_budget:
        key = identity(promotion.contributor_hotkey)
        amounts[key] += service_amounts.model_budget
        hotkeys[key] = min(
            hotkeys.get(key, promotion.contributor_hotkey), promotion.contributor_hotkey
        )
    return CohortRewardAllocation(
        schema="umi-cohort-reward-allocation/1",
        policy_sha256=statement.policy_sha256,
        round_sha256=statement.round_sha256,
        service_certificate_sha256=digest(service),
        quality_manifest_sha256=digest(benchmark),
        promotion_head=promotion,
        recipients=tuple(
            ServiceRecipientAmount(hotkey=hotkeys[key], raw_weight=amount)
            for key, amount in sorted(amounts.items())
            if amount
        ),
        burn_weight=burn,
    )


def retain_reward_allocation(
    journal: RoundJournal,
    promotion_store: CompetitionStore,
    service: CertifiedServiceAllocation,
    service_review: ServiceAllocationReview,
    benchmark: CohortQualityManifest,
    benchmark_review: ClosedQualityReview,
    *,
    maximum_promotion_bytes: int,
) -> CohortRewardAllocation:
    """Retain the first complete allocation, replay it unchanged on restart.

    New selection uses the independently accepted local promotion head. Recovery
    checks that same historical receipt, so a later promotion cannot rewrite
    already sealed rewards. The host must authenticate the selected stores and
    recheck current cohort authority before calling this port.
    """
    if digest(promotion_store.policy) != digest(service_review.policy):
        raise ValueError("promotion store belongs to another policy")
    slot = service_review.slot
    with journal.locked():
        old = journal.get("cohort_reward_allocation", slot)
        previous = (
            None
            if old is None
            else CohortRewardAllocation.model_validate_json(canonical_json_bytes(old))
        )
        round_id = service_review.statement.round_sha256
        promotion = (
            promotion_store.reviewed_promotion_head(round_id, maximum_bytes=maximum_promotion_bytes)
            if previous is None
            else promotion_store.reviewed_promotion_at(
                round_id,
                previous.promotion_head.promotion_sha256,
                maximum_bytes=maximum_promotion_bytes,
            )
        )
        result = build_reward_allocation(
            service, service_review, benchmark, benchmark_review, promotion
        )
        raw = canonical_json_bytes(result)
        journal.reserve_records(
            "cohort-reward-allocation:" + slot,
            (RecordReservation("cohort_reward_allocation", slot, len(raw), sha256_hex(raw)),),
        )
        journal.put("cohort_reward_allocation", slot, result)
        return result


class RecipientProjection(StrictProtocolModel):
    hotkey: Hotkey
    raw_weight: RawWeight
    uid: Annotated[int, Field(ge=0, le=255)] | None
    reason: Literal["registered", "absent_to_burn", "burn_destination"]


class CohortRewardProjection(StrictProtocolModel):
    schema_: Literal["umi-cohort-reward-projection/1"] = Field(alias="schema")
    allocation_sha256: Hex32
    snapshot_sha256: Hex32
    recipients: tuple[RecipientProjection, ...]
    uids: tuple[int, ...]
    weights: tuple[RawWeight, ...]
    chain_submission_authorized: Literal[False] = False


def project_owned_reward_allocation(
    allocation: CohortRewardAllocation,
    observation: OwnedCompetitionChainObservation,
    policy: CompetitionPolicy,
    *,
    chain_config: CompetitionChainConfig,
) -> CohortRewardProjection:
    """Project against a fresh, complete registry from the selected proof owner.

    The execution consumer must independently replay the allocation's certificate,
    current standing control and transaction authority. This only verifies the
    registration input to the fixed-amount projection.
    """
    validate_owned_weight_observation(observation)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    chain_config = CompetitionChainConfig.model_validate_json(canonical_json_bytes(chain_config))
    if (
        chain_config.policy_sha256 != digest(policy)
        or observation.chain_config_sha256 != digest(chain_config)
        or observation.registrations_complete is not True
        or tuple(r.uid for r in observation.registrations)
        != tuple(range(observation.registered_uid_count))
    ):
        raise ValueError("reward projection requires the selected complete registration proof")
    snapshot = RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=observation.block,
        block_hash=observation.block_hash,
        registrations=observation.registrations,
        burn_destination=observation.burn_destination,
    )
    result = project_reward_allocation(
        allocation, snapshot, policy, current_block=observation.block
    )
    validate_owned_weight_observation(observation)
    return result


def project_reward_allocation(
    allocation: CohortRewardAllocation,
    snapshot: RegistrationSnapshot,
    policy: CompetitionPolicy,
    *,
    current_block: int,
) -> CohortRewardProjection:
    """Map fixed amounts without rerounding; the host supplies proved membership.

    This checks the snapshot's shape/freshness, not its finality proof. No UID
    inherits a departed hotkey's share. A returning hotkey recovers its share in
    future projections. Standing control and transaction reconciliation remain
    required independently of these bytes.
    """
    allocation = CohortRewardAllocation.model_validate_json(canonical_json_bytes(allocation))
    snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(snapshot))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if allocation.policy_sha256 != digest(policy):
        raise ValueError("reward allocation belongs to another policy")
    if (
        type(current_block) is not int
        or not 0 <= current_block <= 2**53 - 1
        or not 0 <= current_block - snapshot.block <= policy.maximum_snapshot_age_blocks
    ):
        raise ValueError("reward snapshot is stale or from the future")
    burn = snapshot.burn_destination
    if burn is None or burn.uid >= policy.maximum_uids:
        raise ValueError("reward projection requires a currently proved burn destination")
    by_key = {
        identity(r.hotkey): r.uid for r in snapshot.registrations if r.uid < policy.maximum_uids
    }
    amounts = defaultdict(int)
    amounts[burn.uid] = allocation.burn_weight
    projected = []
    for recipient in allocation.recipients:
        who = identity(recipient.hotkey)
        uid = by_key.get(who)
        amounts[burn.uid if uid is None else uid] += recipient.raw_weight
        projected.append(
            RecipientProjection(
                hotkey=recipient.hotkey,
                raw_weight=recipient.raw_weight,
                uid=uid,
                reason=(
                    "burn_destination"
                    if who == identity(burn.hotkey)
                    else "absent_to_burn"
                    if uid is None
                    else "registered"
                ),
            )
        )
    row = sorted((uid, amount) for uid, amount in amounts.items() if amount)
    return CohortRewardProjection(
        schema="umi-cohort-reward-projection/1",
        allocation_sha256=digest(allocation),
        snapshot_sha256=digest(snapshot),
        recipients=tuple(projected),
        uids=tuple(uid for uid, _ in row),
        weights=tuple(w for _, w in row),
    )
