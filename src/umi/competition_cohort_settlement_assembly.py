"""Assemble original settlement inputs from certified phase results and owner exports."""

from pathlib import Path

from .competition_cohort_coordinator import replay_cohort_decisions
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_preparation import PreparedCohortRound
from .competition_cohort_reward_package import (
    MAX_PACKAGE_OBJECTS,
    DecisionSource,
    ReplayObjectCollector,
    RewardReplayInputs,
    _check_bound,
)
from .competition_cohort_service_closure import CohortServiceRequestClosure
from .competition_cohort_service_quality import ServiceReferenceReveal, ServiceTerms
from .competition_cohort_service_seal import ServiceWorkSeal
from .competition_cohort_service_work import MAX_CATALOG_BYTES, SignedServiceWorkCatalog
from .competition_cohort_settlement_config import SettlementOriginalSources
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_cohort_settlement_inputs import SettlementInputPackage, prepare_settlement_inputs
from .competition_endpoint_execution import RetainedRevealPulse
from .competition_reward_manifest import RewardReplayRequirement
from .open_competition import CompetitionPolicy, EvaluationSuite, digest
from .policy import ScoringPolicy
from .private_files import read_private_model
from .protocol import canonical_json_bytes


def assemble_settlement_inputs(
    sources: SettlementOriginalSources,
    policy: CompetitionPolicy,
    requirement: RewardReplayRequirement,
    history: CohortRecoveryHistory,
    decisions: DecisionSource,
    *,
    current_block: int,
    maximum_bytes: int,
) -> SettlementInputPackage:
    """No signer or inference port; incomplete original evidence stays pending.

    The caller selects current certified history independently of the source files.
    A late first build uses the original evidence-phase prefix, so advancing the
    current history does not change the package identity.
    """
    _check_bound(maximum_bytes)
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=history_tip(history), current_block=current_block
    )
    if view.state.phase not in {
        "evidence",
        "review",
        "certification",
        "first_admission",
        "complete",
    }:
        raise ValueError("settlement assembly requires active certified reference reveal")
    replay_cohort_decisions(history, policy, decisions)
    revealed = view.closure("reference_reveal")
    count = next(i + 1 for i, s in enumerate(history.transitions) if s.transition == revealed)
    original = history.model_copy(update={"transitions": history.transitions[:count]})
    cohort = digest(history.plan)
    if requirement.cohort_sha256 != cohort:
        raise ValueError("settlement assembly changes the selected cohort")
    declared_bytes = 0

    def source_file(path, model, limit):
        nonlocal declared_bytes
        value = read_private_model(path, model, maximum_bytes=min(limit, maximum_bytes))
        declared_bytes += len(canonical_json_bytes(value))
        if declared_bytes > maximum_bytes:
            raise ValueError("settlement source declarations exceed their aggregate byte bound")
        return value

    prepared = source_file(
        Path(sources.round_directory) / (cohort + ".json"),
        PreparedCohortRound,
        maximum_bytes,
    )
    objects = ReplayObjectCollector(
        SettlementEvidenceFiles(Path(sources.objects_directory)), maximum_bytes
    )

    def phase_result(phase, model):
        decision = decisions(view.closure(phase).evidence_sha256)
        if decision.progress is None or decision.progress.progress.phase_result_sha256 is None:
            raise ValueError("certified phase has no retained result identity")
        return model.model_validate_json(objects(decision.progress.progress.phase_result_sha256))

    closure = phase_result("requests", CohortServiceRequestClosure)
    reveal = phase_result("reference_reveal", ServiceReferenceReveal)
    terms = ServiceTerms.model_validate_json(objects(requirement.terms_sha256))
    catalogs = tuple(
        source_file(
            Path(sources.catalogs_directory) / (key + ".json"),
            SignedServiceWorkCatalog,
            MAX_CATALOG_BYTES,
        )
        for key in requirement.catalog_sha256s
    )
    if tuple(digest(c.catalog) for c in catalogs) != requirement.catalog_sha256s:
        raise ValueError("settlement catalog delivery changes the approved inventory")
    inputs = RewardReplayInputs(
        closure=closure,
        roster=prepared.roster,
        suite=EvaluationSuite.model_validate_json(objects(history.plan.suite_sha256)),
        transport=source_file(
            Path(sources.transport_directory) / (terms.transport_policy_sha256 + ".json"),
            ScoringPolicy,
            8 * 1024**2,
        ),
        terms=terms,
        reveal=reveal,
        catalogs=catalogs,
        seals=tuple(
            ServiceWorkSeal.model_validate_json(objects(c.seal_sha256)) for c in closure.catalogs
        ),
        history=original,
    )
    intake = CohortIntake(sources.intake, policy, eligible_tracks=sources.eligible_tracks)
    records = intake.export_records(
        cohort, maximum_bytes=maximum_bytes, maximum_records=MAX_PACKAGE_OBJECTS
    )

    def pulse(number):
        return read_private_model(
            Path(sources.pulses_directory) / (str(number) + ".json"),
            RetainedRevealPulse,
            maximum_bytes=4096,
        )

    return prepare_settlement_inputs(
        inputs,
        policy,
        requirement,
        objects,
        decisions,
        records,
        pulse,
        expected_tip_sha256=history_tip(original),
        current_block=current_block,
        maximum_bytes=maximum_bytes,
    )
