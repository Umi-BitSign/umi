"""Private, portable reward evidence for delayed native validator replay.

The host selects policy, cohort inputs and current history independently. Model
promotion receipts/assets and model award assets stay in its verified store. A package never
authorizes a transaction or asserts that its embedded history is still current.
Legacy competition packages and their admission deadlines are unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, JsonValue, model_validator

from .aggregate_json import DetachedInventoryItem
from .canonical_stream import canonical_json_size
from .competition_cohort_aggregate_files import publish_aggregate_model, read_aggregate_model
from .competition_cohort_aggregate_model import AggregateProtocolModel
from .competition_cohort_capacity import (
    LEGACY_AGGREGATE_REPLAY_BYTES,
    check_aggregate_evidence_bytes,
)
from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_endpoint_archive import (
    MAX_ARCHIVE_OBJECT_BYTES,
    EndpointObjectSource,
    read_endpoint_object,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_model_award import ModelArtifactVerifier
from .competition_cohort_quality import ClosedQualityReview
from .competition_cohort_quality_signing import CohortQualityManifest
from .competition_cohort_reward_allocation import CohortRewardAllocation
from .competition_cohort_reward_certification import verify_certified_reward_allocation
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_certification import (
    CertifiedServiceAllocation,
    ServiceAllocationReview,
)
from .competition_cohort_service_closure import CohortServiceRequestClosure
from .competition_cohort_service_quality import ServiceReferenceReveal, ServiceTerms
from .competition_cohort_service_seal import ServiceWorkSeal
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .competition_endpoint_execution import RetainedRevealPulse
from .competition_store import CompetitionStore
from .competition_work_progress import progress_items
from .host_memory_request_bounds import (
    check_stage_json,
    stage_bounds,
    stage_count,
    stage_limit,
    stage_object_budget,
)
from .open_competition import CompetitionPolicy, EvaluationSuite, digest
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_PACKAGE_OBJECTS = 65536
DEFAULT_PACKAGE_BYTES = LEGACY_AGGREGATE_REPLAY_BYTES
DecisionSource = Callable[[str], CohortDecisionInput]
PulseSource = Callable[[int], RetainedRevealPulse]


def _check_bound(maximum_bytes: int) -> None:
    check_aggregate_evidence_bytes(maximum_bytes)


class RewardIntakeRef(StrictProtocolModel):
    consent_sha256: Hex32
    record_sha256: Hex32


class RewardPulseRef(StrictProtocolModel):
    round: Annotated[int, Field(ge=1, le=2**64 - 1)]
    pulse_sha256: Hex32


class RewardReplayInputs(StrictProtocolModel):
    """Complete selected inputs; references and responses are private evidence."""

    closure: CohortServiceRequestClosure
    roster: RecoverableRosterEvidence
    suite: EvaluationSuite
    transport: ScoringPolicy
    terms: ServiceTerms
    reveal: ServiceReferenceReveal
    catalogs: Annotated[tuple[SignedServiceWorkCatalog, ...], Field(min_length=1, max_length=64)]
    seals: Annotated[tuple[ServiceWorkSeal, ...], Field(min_length=1, max_length=64)]
    history: CohortRecoveryHistory


class RewardPackageObject(StrictProtocolModel, DetachedInventoryItem):
    sha256: Hex32
    value: JsonValue


class CohortRewardPackage(AggregateProtocolModel):
    schema_: Literal["umi-cohort-reward-package/1"] = Field(alias="schema")
    policy_sha256: Hex32
    inputs: RewardReplayInputs
    allocation: CohortRewardAllocation
    service: CertifiedServiceAllocation
    benchmark: CohortQualityManifest
    intake: Annotated[tuple[RewardIntakeRef, ...], Field(max_length=MAX_PACKAGE_OBJECTS)]
    pulses: Annotated[tuple[RewardPulseRef, ...], Field(max_length=MAX_PACKAGE_OBJECTS)]
    objects: Annotated[tuple[RewardPackageObject, ...], Field(max_length=MAX_PACKAGE_OBJECTS)]
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def unique_order(self):
        for keys in (
            [o.sha256 for o in self.objects],
            [r.consent_sha256 for r in self.intake],
            [p.round for p in self.pulses],
        ):
            if keys != sorted(set(keys)):
                raise ValueError("reward package inventory must be unique and ordered")
        return self


class ReplayObjectCollector:
    """Bound and authenticate each source before retaining or replaying it."""

    def __init__(self, source: EndpointObjectSource, maximum_bytes: int):
        _check_bound(maximum_bytes)
        self.source, self.maximum_bytes = source, maximum_bytes
        self.values: dict[str, bytes] = {}
        self.used = 0

    def __call__(self, key: str) -> bytes:
        if key not in self.values:
            stage_count("maximum_objects", len(self.values) + 1)
            remaining = stage_limit("maximum_input_bytes", self.maximum_bytes) - self.used
            with stage_object_budget(remaining):
                self._remember(key, read_endpoint_object(self.source, key))
        return self.values[key]

    def _remember(self, key: str, raw: bytes) -> None:
        if key in self.values:
            if self.values[key] != raw:
                raise ValueError("reward package source changed")
            return
        if len(self.values) >= MAX_PACKAGE_OBJECTS or self.used + len(raw) > self.maximum_bytes:
            raise ValueError("reward package evidence exceeds its bound")
        stage_count("maximum_objects", len(self.values) + 1)
        stage_count("maximum_input_bytes", self.used + len(raw))
        check_stage_json(raw, kind="object")
        self.values[key] = raw
        self.used += len(raw)

    def retain(self, value: StrictProtocolModel | JsonValue) -> str:
        if stage_bounds() is not None:
            size = canonical_json_size(value)
            stage_count("maximum_object_bytes", size)
            stage_count("maximum_input_bytes", self.used + size)
        raw = canonical_json_bytes(value)
        key = digest(value)
        self._remember(key, read_endpoint_object({key: raw}.__getitem__, key))
        return key


def _replay(
    inputs: RewardReplayInputs,
    allocation: CohortRewardAllocation,
    service: CertifiedServiceAllocation,
    benchmark: CohortQualityManifest,
    policy: CompetitionPolicy,
    promotion_store: CompetitionStore,
    objects: EndpointObjectSource,
    decisions: DecisionSource,
    intake: tuple[tuple[str, bytes], ...],
    pulses: PulseSource,
    history: CohortRecoveryHistory,
    expected_tip: str,
    current_block: int,
    expected_terms: str,
    expected_catalogs: tuple[str, ...],
    maximum_promotion_bytes: int,
    verify_model_artifact: ModelArtifactVerifier | None = None,
) -> CohortRewardAllocation:
    if (
        history.plan != inputs.history.plan
        or history.authority != inputs.history.authority
        or history.genesis != inputs.history.genesis
        or history.genesis_signatures != inputs.history.genesis_signatures
        or history.transitions[: len(inputs.history.transitions)] != inputs.history.transitions
        or digest(inputs.terms) != expected_terms
        or tuple(digest(c.catalog) for c in inputs.catalogs) != expected_catalogs
    ):
        raise ValueError("reward package differs from selected inputs or current history")
    common = dict(
        expected_catalogs=inputs.catalogs,
        expected_seals=inputs.seals,
        decision_source=decisions,
        pulses=pulses,
        expected_tip_sha256=expected_tip,
        current_block=current_block,
    )
    sr = ServiceAllocationReview(
        inputs.closure,
        inputs.roster,
        objects,
        policy,
        history,
        inputs.transport,
        inputs.terms,
        inputs.reveal,
        expected_terms_sha256=expected_terms,
        intake_records=iter(intake),
        **common,
    )
    br = ClosedQualityReview(
        inputs.closure,
        inputs.roster,
        objects,
        inputs.suite,
        policy,
        history,
        transport=inputs.transport,
        intake_records=iter(intake),
        **common,
    )
    return verify_certified_reward_allocation(
        allocation,
        promotion_store,
        service,
        sr,
        benchmark,
        br,
        history,
        decisions,
        expected_tip_sha256=expected_tip,
        current_block=current_block,
        maximum_promotion_bytes=maximum_promotion_bytes,
        verify_model_artifact=verify_model_artifact,
    )


def prepare_reward_package(
    inputs: RewardReplayInputs,
    allocation: CohortRewardAllocation,
    service: CertifiedServiceAllocation,
    benchmark: CohortQualityManifest,
    policy: CompetitionPolicy,
    promotion_store: CompetitionStore,
    objects: EndpointObjectSource,
    decision_source: DecisionSource,
    intake_records: Iterable[tuple[str, bytes]],
    pulses: PulseSource,
    *,
    expected_tip_sha256: str,
    current_block: int,
    expected_terms_sha256: str,
    expected_catalog_sha256s: tuple[str, ...],
    maximum_promotion_bytes: int,
    maximum_bytes: int = DEFAULT_PACKAGE_BYTES,
    verify_model_artifact: ModelArtifactVerifier | None = None,
) -> CohortRewardPackage:
    """Replay native evidence and retain exactly the objects it actually reads.

    No source path, network address, signer or command enters the package.
    The host must publish the returned object privately and replicate both it
    and the selected promotion history before advertising durable admission.
    """
    inputs = RewardReplayInputs.model_validate_json(canonical_json_bytes(inputs))
    captured = ReplayObjectCollector(objects, maximum_bytes)
    refs, records, pulse_refs = [], [], {}
    for key, raw in intake_records:
        if len(refs) >= MAX_PACKAGE_OBJECTS:
            raise ValueError("reward package intake exceeds its bound")
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_ARCHIVE_OBJECT_BYTES:
            raise ValueError("reward package intake record exceeds its byte bound")
        # Authenticate the original canonical bytes without changing them.
        record_id = captured.retain(json.loads(raw))
        if captured(record_id) != raw:
            raise ValueError("reward package intake is not canonical")
        refs.append(RewardIntakeRef(consent_sha256=key, record_sha256=record_id))
        records.append((key, raw))

    def decision(key):
        value = CohortDecisionInput.model_validate_json(canonical_json_bytes(decision_source(key)))
        if captured.retain(value) != key:
            raise ValueError("reward package decision identity changed")
        return value

    def pulse(round_):
        value = RetainedRevealPulse.model_validate_json(canonical_json_bytes(pulses(round_)))
        if value.round != round_:
            raise ValueError("reward package pulse belongs to another round")
        key = captured.retain(value)
        if round_ in pulse_refs and pulse_refs[round_] != key:
            raise ValueError("reward package pulse changed")
        pulse_refs[round_] = key
        return value

    result = _replay(
        inputs,
        allocation,
        service,
        benchmark,
        policy,
        promotion_store,
        captured,
        decision,
        tuple(records),
        pulse,
        inputs.history,
        expected_tip_sha256,
        current_block,
        expected_terms_sha256,
        expected_catalog_sha256s,
        maximum_promotion_bytes,
        verify_model_artifact,
    )
    package = CohortRewardPackage(
        schema="umi-cohort-reward-package/1",
        policy_sha256=digest(policy),
        inputs=inputs,
        allocation=result,
        service=service,
        benchmark=benchmark,
        intake=tuple(sorted(refs, key=lambda x: x.consent_sha256)),
        pulses=tuple(
            RewardPulseRef(round=k, pulse_sha256=v) for k, v in sorted(pulse_refs.items())
        ),
        objects=tuple(
            RewardPackageObject(sha256=k, value=json.loads(v))
            for k, v in progress_items(
                sorted(captured.values.items()),
                stage="reward_package_serialization",
                unit="objects",
                cohort=digest(inputs.history.plan),
            )
        ),
    )
    if canonical_json_size(package) > maximum_bytes:
        raise ValueError("reward package including metadata exceeds its bound")
    return package


def replay_reward_package(
    package: CohortRewardPackage,
    policy: CompetitionPolicy,
    promotion_store: CompetitionStore,
    current_history: CohortRecoveryHistory,
    *,
    expected_package_sha256: str,
    expected_cohort_sha256: str,
    expected_tip_sha256: str,
    current_block: int,
    expected_terms_sha256: str,
    expected_catalog_sha256s: tuple[str, ...],
    maximum_promotion_bytes: int,
    maximum_bytes: int = DEFAULT_PACKAGE_BYTES,
    current_decision_source: DecisionSource | None = None,
    verify_model_artifact: ModelArtifactVerifier | None = None,
) -> CohortRewardAllocation:
    """Detach caller content before replaying any mutable nested protocol values."""
    snapshot = _validated_reward_snapshot(package, maximum_bytes)
    return _replay_detached_reward_package(
        snapshot,
        policy,
        promotion_store,
        current_history,
        expected_package_sha256=expected_package_sha256,
        expected_cohort_sha256=expected_cohort_sha256,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
        expected_terms_sha256=expected_terms_sha256,
        expected_catalog_sha256s=expected_catalog_sha256s,
        maximum_promotion_bytes=maximum_promotion_bytes,
        maximum_bytes=maximum_bytes,
        current_decision_source=current_decision_source,
        verify_model_artifact=verify_model_artifact,
    )


def _validated_reward_snapshot(
    package: CohortRewardPackage, maximum_bytes: int
) -> CohortRewardPackage:
    """Own one validated snapshot; do not retain its temporary canonical bytes."""
    _check_bound(maximum_bytes)
    raw = canonical_json_bytes(package)
    if len(raw) > maximum_bytes:
        raise ValueError("reward package exceeds its byte bound")
    return CohortRewardPackage.model_validate_json(raw)


def _replay_detached_reward_package(
    package: CohortRewardPackage,
    policy: CompetitionPolicy,
    promotion_store: CompetitionStore,
    current_history: CohortRecoveryHistory,
    *,
    expected_package_sha256: str,
    expected_cohort_sha256: str,
    expected_tip_sha256: str,
    current_block: int,
    expected_terms_sha256: str,
    expected_catalog_sha256s: tuple[str, ...],
    maximum_promotion_bytes: int,
    maximum_bytes: int = DEFAULT_PACKAGE_BYTES,
    current_decision_source: DecisionSource | None = None,
    verify_model_artifact: ModelArtifactVerifier | None = None,
) -> CohortRewardAllocation:
    """Reconstruct native reviews even when original settlement targets passed.

    Expected identities/current history come from the host's selected authority,
    never from an untrusted package's self-description. The host independently
    verifies finality and promotion history. Missing evidence remains pending.
    """
    _check_bound(maximum_bytes)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if (
        digest(package) != expected_package_sha256
        or package.policy_sha256 != digest(policy)
        or digest(package.inputs.history.plan) != expected_cohort_sha256
    ):
        raise ValueError("reward package differs from selected identity or policy")
    inventory = {
        o.sha256: canonical_json_bytes(o.value)
        for o in progress_items(
            package.objects,
            stage="reward_package_inventory",
            unit="objects",
            cohort=expected_cohort_sha256,
        )
    }
    source = ReplayObjectCollector(inventory.__getitem__, maximum_bytes)
    # Check every declared object, including those missing from a replay traversal.
    for item in progress_items(
        package.objects,
        stage="reward_package_object_integrity",
        unit="objects",
        cohort=expected_cohort_sha256,
    ):
        read_endpoint_object(inventory.__getitem__, item.sha256)
    pulse_refs = {p.round: p.pulse_sha256 for p in package.pulses}
    used_pulses: set[int] = set()
    original_decisions = {
        signed.transition.evidence_sha256
        for signed in package.inputs.history.transitions
        if signed.transition.requires_progress_evidence
    }
    if not original_decisions <= inventory.keys():
        raise ValueError("reward package lacks original cohort decisions")

    def pulse(round_):
        value = RetainedRevealPulse.model_validate_json(source(pulse_refs[round_]))
        if value.round != round_:
            raise ValueError("reward package pulse belongs to another round")
        used_pulses.add(round_)
        return value

    def decision(key):
        if key in inventory:
            return CohortDecisionInput.model_validate_json(source(key))
        if current_decision_source is None:
            raise FileNotFoundError("current cohort decision evidence is unavailable")
        value = CohortDecisionInput.model_validate_json(
            canonical_json_bytes(current_decision_source(key))
        )
        if digest(value) != key:
            raise ValueError("current cohort decision evidence changed its identity")
        return value

    result = _replay(
        package.inputs,
        package.allocation,
        package.service,
        package.benchmark,
        policy,
        promotion_store,
        source,
        decision,
        tuple((r.consent_sha256, source(r.record_sha256)) for r in package.intake),
        pulse,
        current_history,
        expected_tip_sha256,
        current_block,
        expected_terms_sha256,
        expected_catalog_sha256s,
        maximum_promotion_bytes,
        verify_model_artifact,
    )
    if set(source.values) != set(inventory) or used_pulses != pulse_refs.keys():
        raise ValueError("reward package contains unreferenced evidence")
    return result


def publish_reward_package(
    path: Path, package: CohortRewardPackage, *, maximum_bytes: int = DEFAULT_PACKAGE_BYTES
) -> None:
    """Atomically retain exact private bytes; this is not proof of qualification."""
    _check_bound(maximum_bytes)
    publish_aggregate_model(path, package, maximum_bytes=maximum_bytes)


def load_reward_package(
    path: Path,
    policy: CompetitionPolicy,
    promotion_store: CompetitionStore,
    current_history: CohortRecoveryHistory,
    *,
    maximum_bytes: int = DEFAULT_PACKAGE_BYTES,
    **selection,
) -> CohortRewardAllocation:
    """Load a retained replica and fully replay it, without a coordinator call."""
    _check_bound(maximum_bytes)
    package = read_aggregate_model(path, CohortRewardPackage, maximum_bytes=maximum_bytes)
    return replay_reward_package(
        package,
        policy,
        promotion_store,
        current_history,
        maximum_bytes=maximum_bytes,
        **selection,
    )
