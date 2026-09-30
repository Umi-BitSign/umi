"""Portable original evaluation inputs, available before reward certification.

The receiver selects policy, history and service terms independently and replays
the original execution evidence. This package carries no signer, readiness flag
or authorization to submit weights. Model artifacts remain in the separately
verified promotion store; evaluator signing still requires its own journal.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_endpoint_archive import (
    MAX_ARCHIVE_OBJECT_BYTES,
    EndpointObjectSource,
    read_endpoint_object,
)
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_quality import ClosedQualityReview
from .competition_cohort_reward_package import (
    DEFAULT_PACKAGE_BYTES,
    MAX_PACKAGE_OBJECTS,
    DecisionSource,
    PulseSource,
    ReplayObjectCollector,
    RewardIntakeRef,
    RewardPackageObject,
    RewardPulseRef,
    RewardReplayInputs,
    _check_bound,
)
from .competition_cohort_service_certification import ServiceAllocationReview
from .competition_cohort_service_quality import build_service_reference_reveal
from .competition_endpoint_execution import RetainedRevealPulse
from .competition_reward_manifest import RewardReplayRequirement
from .open_competition import CompetitionPolicy, digest
from .policy import scoring_policy_hash
from .private_files import publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class SettlementInputPackage(StrictProtocolModel):
    # Version 2 carries complete committed originals for reference certification.
    # Version 1 keeps its existing post-reveal semantics and canonical bytes.
    schema_: Literal["umi-settlement-input-package/1", "umi-settlement-input-package/2"] = Field(
        alias="schema"
    )
    policy_sha256: Hex32
    inputs: RewardReplayInputs
    intake: Annotated[tuple[RewardIntakeRef, ...], Field(max_length=MAX_PACKAGE_OBJECTS)]
    pulses: Annotated[tuple[RewardPulseRef, ...], Field(max_length=MAX_PACKAGE_OBJECTS)]
    objects: Annotated[tuple[RewardPackageObject, ...], Field(max_length=MAX_PACKAGE_OBJECTS)]

    @model_validator(mode="after")
    def inventory(self):
        for keys in (
            [item.consent_sha256 for item in self.intake],
            [item.round for item in self.pulses],
            [item.sha256 for item in self.objects],
        ):
            if keys != sorted(set(keys)):
                raise ValueError("settlement input inventory must be unique and ordered")
        return self


@dataclass(frozen=True)
class ReplayedSettlementInputs:
    inputs: RewardReplayInputs
    intake: tuple[tuple[str, bytes], ...]
    objects: EndpointObjectSource
    decisions: DecisionSource
    pulses: PulseSource
    quality: ClosedQualityReview | None
    service: ServiceAllocationReview | None


def _reviews(
    inputs: RewardReplayInputs,
    policy: CompetitionPolicy,
    requirement: RewardReplayRequirement,
    objects: EndpointObjectSource,
    decisions: DecisionSource,
    intake: tuple[tuple[str, bytes], ...],
    pulses: PulseSource,
    tip: str,
    block: int,
) -> tuple[ClosedQualityReview | None, ServiceAllocationReview | None]:
    if (
        digest(inputs.history.plan) != requirement.cohort_sha256
        or digest(inputs.terms) != requirement.terms_sha256
        or tuple(digest(c.catalog) for c in inputs.catalogs) != requirement.catalog_sha256s
    ):
        raise ValueError("settlement inputs differ from the approved cohort or service terms")
    state, _, _ = replay_cohort_decisions(inputs.history, policy, decisions)
    if state.phase == "reference_reveal":
        if (
            inputs.terms.policy_sha256 != digest(policy)
            or inputs.terms.transport_policy_sha256 != scoring_policy_hash(inputs.transport)
            or any(c.catalog.service_terms_sha256 != digest(inputs.terms) for c in inputs.catalogs)
        ):
            raise ValueError("reference inputs differ from selected service terms")
        reveal = build_service_reference_reveal(
            inputs.closure,
            inputs.roster,
            inputs.suite,
            objects,
            policy,
            inputs.history,
            inputs.transport,
            expected_catalogs=inputs.catalogs,
            expected_seals=inputs.seals,
            decision_source=decisions,
            intake_records=iter(intake),
            expected_tip_sha256=tip,
            current_block=block,
        )
        if inputs.reveal != reveal:
            raise ValueError("reference inputs changed the committed inventory")
        return None, None
    common = dict(
        expected_catalogs=inputs.catalogs,
        expected_seals=inputs.seals,
        decision_source=decisions,
        pulses=pulses,
        expected_tip_sha256=tip,
        current_block=block,
    )
    quality = ClosedQualityReview(
        inputs.closure,
        inputs.roster,
        objects,
        inputs.suite,
        policy,
        inputs.history,
        transport=inputs.transport,
        intake_records=iter(intake),
        **common,
    )
    # Constructor verification alone does not read every participant's outputs.
    for participant in quality.closure.participants:
        quality.outcome(participant.submission_sha256)
    service = ServiceAllocationReview(
        inputs.closure,
        inputs.roster,
        objects,
        policy,
        inputs.history,
        inputs.transport,
        inputs.terms,
        inputs.reveal,
        expected_terms_sha256=requirement.terms_sha256,
        intake_records=iter(intake),
        **common,
    )
    return quality, service


def prepare_settlement_inputs(
    inputs: RewardReplayInputs,
    policy: CompetitionPolicy,
    requirement: RewardReplayRequirement,
    objects: EndpointObjectSource,
    decisions: DecisionSource,
    intake_records: Iterable[tuple[str, bytes]],
    pulses: PulseSource,
    *,
    expected_tip_sha256: str,
    current_block: int,
    maximum_bytes: int = DEFAULT_PACKAGE_BYTES,
) -> SettlementInputPackage:
    """Capture originals for reference certification or subsequent quality votes."""
    inputs = RewardReplayInputs.model_validate_json(canonical_json_bytes(inputs))
    view = verify_cohort_history(
        inputs.history,
        policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    if view.state.phase not in {"reference_reveal", "evidence"}:
        raise ValueError("original settlement inputs require reference reveal or evidence")
    captured = ReplayObjectCollector(objects, maximum_bytes)
    records, intake, pulse_refs = [], [], {}
    for key, raw in intake_records:
        if len(records) >= MAX_PACKAGE_OBJECTS:
            raise ValueError("settlement intake exceeds its record bound")
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_ARCHIVE_OBJECT_BYTES:
            raise ValueError("settlement intake exceeds its byte bound")
        record_id = captured.retain(json.loads(raw))
        if captured(record_id) != raw:
            raise ValueError("settlement intake must preserve canonical bytes")
        records.append((key, raw))
        intake.append(RewardIntakeRef(consent_sha256=key, record_sha256=record_id))

    def decision(key):
        value = CohortDecisionInput.model_validate_json(canonical_json_bytes(decisions(key)))
        if captured.retain(value) != key:
            raise ValueError("settlement input decision identity changed")
        return value

    def pulse(round_):
        value = RetainedRevealPulse.model_validate_json(canonical_json_bytes(pulses(round_)))
        if value.round != round_:
            raise ValueError("settlement input pulse belongs to another round")
        key = captured.retain(value)
        if pulse_refs.setdefault(round_, key) != key:
            raise ValueError("settlement input pulse changed during capture")
        return value

    _reviews(
        inputs,
        policy,
        requirement,
        captured,
        decision,
        tuple(records),
        pulse,
        expected_tip_sha256,
        current_block,
    )
    package = SettlementInputPackage(
        schema="umi-settlement-input-package/2"
        if view.state.phase == "reference_reveal"
        else "umi-settlement-input-package/1",
        policy_sha256=digest(policy),
        inputs=inputs,
        intake=tuple(sorted(intake, key=lambda r: r.consent_sha256)),
        pulses=tuple(
            RewardPulseRef(round=n, pulse_sha256=k) for n, k in sorted(pulse_refs.items())
        ),
        objects=tuple(
            RewardPackageObject(sha256=k, value=json.loads(v))
            for k, v in sorted(captured.values.items())
        ),
    )
    if len(canonical_json_bytes(package)) > maximum_bytes:
        raise ValueError("settlement inputs including metadata exceed their byte bound")
    return package


def replay_settlement_inputs(
    package: SettlementInputPackage,
    policy: CompetitionPolicy,
    requirement: RewardReplayRequirement,
    current_history: CohortRecoveryHistory,
    *,
    expected_package_sha256: str,
    expected_tip_sha256: str,
    current_block: int,
    current_decisions: DecisionSource | None = None,
    maximum_bytes: int = DEFAULT_PACKAGE_BYTES,
) -> ReplayedSettlementInputs:
    """Replay a replica against owned selections after arbitrary processing delay."""
    _check_bound(maximum_bytes)
    raw = canonical_json_bytes(package)
    if len(raw) > maximum_bytes:
        raise ValueError("settlement input package exceeds its byte bound")
    package = SettlementInputPackage.model_validate_json(raw)
    original = package.inputs.history
    if (
        digest(package) != expected_package_sha256
        or package.policy_sha256 != digest(policy)
        or original.plan != current_history.plan
        or original.authority != current_history.authority
        or original.genesis != current_history.genesis
        or original.genesis_signatures != current_history.genesis_signatures
        or current_history.transitions[: len(original.transitions)] != original.transitions
    ):
        raise ValueError("settlement input identity or history differs from owned selection")
    original_tip = (
        digest(original.transitions[-1].transition)
        if original.transitions
        else digest(original.genesis)
    )
    original_view = verify_cohort_history(
        original,
        policy,
        expected_tip_sha256=original_tip,
        current_block=current_block,
    )
    reference = package.schema_ == "umi-settlement-input-package/2"
    if original_view.state.phase != ("reference_reveal" if reference else "evidence"):
        raise ValueError("original settlement inputs differ from their schema's phase")
    view = verify_cohort_history(
        current_history,
        policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    allowed = (
        {"reference_reveal"}
        if reference
        else {
            "evidence",
            "review",
            "certification",
            "first_admission",
            "complete",
        }
    )
    if view.state.phase not in allowed:
        raise ValueError("settlement input history is not active after reference reveal")
    inventory = {o.sha256: canonical_json_bytes(o.value) for o in package.objects}
    captured = ReplayObjectCollector(inventory.__getitem__, maximum_bytes)
    for key in inventory:
        read_endpoint_object(inventory.__getitem__, key)
    original_decisions = {
        item.transition.evidence_sha256
        for item in original.transitions
        if item.transition.operation != "revoke"
    }
    if not original_decisions <= inventory.keys():
        raise ValueError("settlement inputs lack original decision evidence")
    pulse_refs = {p.round: p.pulse_sha256 for p in package.pulses}
    used_pulses = set()

    def decision(key):
        if key in inventory:
            return CohortDecisionInput.model_validate_json(captured(key))
        if key in original_decisions or current_decisions is None:
            raise FileNotFoundError("settlement decision evidence is unavailable")
        value = CohortDecisionInput.model_validate_json(
            canonical_json_bytes(current_decisions(key))
        )
        if digest(value) != key:
            raise ValueError("settlement current decision identity changed")
        return value

    def pulse(round_):
        value = RetainedRevealPulse.model_validate_json(captured(pulse_refs[round_]))
        if value.round != round_:
            raise ValueError("settlement input pulse belongs to another round")
        used_pulses.add(round_)
        return value

    inputs = package.inputs.model_copy(update={"history": current_history})
    records = tuple((r.consent_sha256, captured(r.record_sha256)) for r in package.intake)
    quality, service = _reviews(
        inputs,
        policy,
        requirement,
        captured,
        decision,
        records,
        pulse,
        expected_tip_sha256,
        current_block,
    )
    if set(captured.values) != inventory.keys() or used_pulses != pulse_refs.keys():
        raise ValueError("settlement input package contains unreferenced evidence")
    return ReplayedSettlementInputs(inputs, records, captured, decision, pulse, quality, service)


def publish_settlement_inputs(
    path: Path, package: SettlementInputPackage, *, maximum_bytes: int = DEFAULT_PACKAGE_BYTES
) -> None:
    _check_bound(maximum_bytes)
    publish_private_model(path, package, maximum_bytes=maximum_bytes)


def load_settlement_inputs(
    path: Path,
    policy: CompetitionPolicy,
    requirement: RewardReplayRequirement,
    current_history: CohortRecoveryHistory,
    *,
    maximum_bytes: int = DEFAULT_PACKAGE_BYTES,
    **selection,
) -> ReplayedSettlementInputs:
    _check_bound(maximum_bytes)
    package = read_private_model(path, SettlementInputPackage, maximum_bytes=maximum_bytes)
    return replay_settlement_inputs(
        package,
        policy,
        requirement,
        current_history,
        maximum_bytes=maximum_bytes,
        **selection,
    )
