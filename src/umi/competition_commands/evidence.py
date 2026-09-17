"""Competition evidence command handlers."""

from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import TypeAdapter

from ..competition_endpoint_execution import EndpointPairedEvidence
from ..competition_evidence import IndependentEvaluationEvidence, replay_independent_evaluation
from ..competition_execution import ModelExecutionEvidence
from ..open_competition import (
    AttestedResult,
    CompetitionPolicy,
    EvaluationRound,
    EvaluationSuite,
    SignedSubmission,
    aggregate_quality,
    digest,
    qualifies_for_promotion,
    replay_evaluation,
)
from .common import (
    ExecutionInputs,
    ExecutionRevealPulses,
    PublicationEvidenceInputs,
    PublicationRoster,
    load_json,
)


def prepare_settlement_package(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_package import (
        CompetitionPackageLimits,
        CompetitionReleaseIdentity,
        prepare_competition_package,
    )
    from ..competition_publication import (
        PublicationReplayLimits,
        SignedCutoffPublication,
        SignedSettlementPublication,
    )
    from ..competition_settlement import CompetitionSettlement

    roster = load_json(args.roster, PublicationRoster)
    evidence = load_json(args.evidence, PublicationEvidenceInputs)
    prepared = prepare_competition_package(
        policy=policy,
        cutoff_certificate=load_json(args.cutoff_certificate, SignedCutoffPublication),
        settlement_certificate=load_json(args.certificate, SignedSettlementPublication),
        retained_settlement=load_json(args.retained_settlement, CompetitionSettlement),
        roster=roster.submissions,
        evidence=tuple((entry.submission, entry.evidence) for entry in evidence.entries),
        replay_limits=load_json(args.replay_limits, PublicationReplayLimits),
        release_identity=load_json(args.release_identity, CompetitionReleaseIdentity),
        destination_root=Path(args.destination).absolute(),
        limits=load_json(args.package_limits, CompetitionPackageLimits),
    )
    return prepared.model_dump(mode="json", by_alias=True)


def replay_settlement_package(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_package import CompetitionPackageLimits, CompetitionReleaseIdentity
    from ..competition_worker import CompetitionReplayWorker, CompetitionWorkerCapacity

    worker = CompetitionReplayWorker(
        Path(args.state).absolute(),
        package_limits=load_json(args.package_limits, CompetitionPackageLimits),
        capacity=load_json(args.worker_capacity, CompetitionWorkerCapacity),
    )
    result = worker.run(
        Path(args.package).absolute(),
        expected_package_sha256=args.expected_package_sha256,
        expected_policy_sha256=digest(policy),
        observed_release=load_json(args.release_identity, CompetitionReleaseIdentity),
    )
    return result.model_dump(mode="json", by_alias=True)


def verify_cutoff_publication(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_publication import (
        PublicationReplayLimits,
        SignedCutoffPublication,
        SignedSettlementPublication,
        cutoff_publication_digest,
        settlement_publication_digest,
        verify_cutoff_publication,
        verify_settlement_publication,
    )
    from ..competition_settlement import CompetitionSettlement

    roster = load_json(args.roster, PublicationRoster)
    limits = load_json(args.replay_limits, PublicationReplayLimits)
    if args.command == "verify-cutoff-publication":
        result = verify_cutoff_publication(
            load_json(args.certificate, SignedCutoffPublication),
            policy=policy,
            submissions=roster.submissions,
            limits=limits,
        )
        result_digest = cutoff_publication_digest(result)
    else:
        evidence = load_json(args.evidence, PublicationEvidenceInputs)
        result = verify_settlement_publication(
            load_json(args.certificate, SignedSettlementPublication),
            cutoff_certificate=load_json(args.cutoff_certificate, SignedCutoffPublication),
            policy=policy,
            submissions=roster.submissions,
            evidence=tuple((item.submission, item.evidence) for item in evidence.entries),
            retained_settlement=load_json(args.retained_settlement, CompetitionSettlement),
            limits=limits,
        )
        result_digest = settlement_publication_digest(result)
    return {
        "status": "publication_replayed",
        "publication_sha256": result_digest,
        "chain_submission_authorized": False,
        "publication_timing_proven": False,
    }


def assemble_endpoint_execution(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_endpoint_execution import assemble_endpoint_evidence
    from ..competition_execution import EndpointIncumbentEvidence
    from ..competition_scheduling import AssignmentPublicationJournal
    from ..policy import ScoringPolicy

    pulses = load_json(args.reveal_pulses, ExecutionRevealPulses).pulses
    if len({p.round for p in pulses}) != len(pulses):
        raise ValueError("duplicate retained reveal pulse")
    journal = AssignmentPublicationJournal(
        Path(args.dispatch_state).absolute(), policy, load_json(args.legacy_policy, ScoringPolicy)
    )
    return assemble_endpoint_evidence(
        incumbent=load_json(args.incumbent_execution, EndpointIncumbentEvidence),
        journal=journal,
        publication_sha256=args.publication_sha256,
        suite=load_json(args.suite, EvaluationSuite),
        pulses={p.round: p for p in pulses},
        current_block=args.current_block,
    ).model_dump(mode="json", by_alias=True)


def execution_status(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_execution import ExecutionJournal

    return ExecutionJournal(Path(args.state).absolute(), policy).status(args.execution_key) or {
        "status": "unknown_execution",
        "chain_submission_authorized": False,
    }


def propose_execution_result(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_execution import common_execution_result, run_record_from_execution
    from ..open_competition import EvaluationResult

    suite = load_json(args.suite, EvaluationSuite)
    if args.command == "propose-execution-result":
        value = common_execution_result(
            load_json(args.inputs, ExecutionInputs).executions,
            suite,
            policy,
            current_block=args.current_block,
        )
    else:
        value = run_record_from_execution(
            load_json(args.execution, TypeAdapter(ModelExecutionEvidence | EndpointPairedEvidence)),
            load_json(args.result, EvaluationResult),
            suite,
            policy,
            current_block=args.current_block,
        )
    return {
        "object": value.model_dump(mode="json", by_alias=True),
        "signed": False,
        "chain_submission_authorized": False,
    }


def inspect_policy(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    return {
        "policy_sha256": digest(policy),
        "mode": "rehearsal_no_weight",
        "endpoint_reward_bps": policy.endpoint_reward_bps,
        "model_reward_bps": policy.model_reward_bps,
        "chain_submission_authorized": False,
    }


def replay_evaluations(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    independent = args.command == "replay-independent-evaluation"
    replay = replay_independent_evaluation if independent else replay_evaluation
    candidate, incumbent = replay(
        load_json(
            args.evaluation, IndependentEvaluationEvidence if independent else AttestedResult
        ),
        load_json(args.submission, SignedSubmission),
        load_json(args.round, EvaluationRound),
        load_json(args.suite, EvaluationSuite),
        policy,
        current_block=args.current_block,
    )
    return {
        "candidate_quality": str(aggregate_quality(candidate, policy)),
        "incumbent_quality": str(aggregate_quality(incumbent, policy)),
        "quality_gate_passed": qualifies_for_promotion(candidate, incumbent, policy),
        "chain_submission_authorized": False,
    }
