"""Competition store command handlers."""

from __future__ import annotations

import argparse
from pathlib import Path

from ..competition_evidence import IndependentEvaluationEvidence
from ..competition_launch import PublicIntakeDeployment, PublicLaunchIdentity
from ..competition_settlement import EvidenceCutoffSchedule
from ..competition_store import AttestedPromotionReview, CompetitionStore
from ..open_competition import (
    AttestedResult,
    CompetitionPolicy,
    EvaluationRound,
    EvaluationSuite,
    ModelBundle,
    RegistrationSnapshot,
    SignedSubmission,
    digest,
)
from .common import (
    ProjectionInput,
    SettlementInput,
    load_json,
)


def open_store(args: argparse.Namespace, policy: CompetitionPolicy) -> CompetitionStore:
    if getattr(args, "evaluator_review_limits", None) is not None:
        from ..competition_publication import PublicationReplayLimits
        from ..competition_review_history import EvaluatorReviewStore

        store = EvaluatorReviewStore(
            Path(args.state).absolute(),
            policy,
            limits=load_json(args.evaluator_review_limits, PublicationReplayLimits),
        )
    else:
        public_launch = (
            load_json(args.public_launch, PublicLaunchIdentity)
            if getattr(args, "public_launch", None)
            else None
        )
        checkpoint = getattr(args, "submission_head_checkpoint_directory", None)
        store = CompetitionStore(
            Path(args.state).absolute(),
            policy,
            public_launch=public_launch,
            submission_head_checkpoint_directory=(
                Path(checkpoint).absolute() if checkpoint is not None else None
            ),
        )
    return store


def status(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return {
        "policy_sha256": digest(policy),
        "baseline": store.baseline_summary(),
        "mode": "rehearsal_no_weight",
        "chain_submission_authorized": False,
    }


def export_intake_archive(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_intake_archive import export_intake_archive as export

    deployment = load_json(args.deployment, PublicIntakeDeployment)
    store = CompetitionStore(
        Path(args.state).absolute(),
        policy,
        public_launch=deployment.launch_identity(),
        submission_head_checkpoint_directory=Path(
            args.submission_head_checkpoint_directory
        ).absolute(),
    )
    return export(
        store,
        Path(args.destination),
        confirmed_quiesced=args.confirm_quiesced_backup,
    )


def admit(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return store.admit(
        load_json(args.submission, SignedSubmission),
        load_json(args.snapshot, RegistrationSnapshot),
        args.current_block,
    )


def record_evaluation(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return store.record_evaluation(
        signed=load_json(args.submission, SignedSubmission),
        attested=load_json(args.evaluation, AttestedResult),
        round_=load_json(args.round, EvaluationRound),
        suite=load_json(args.suite, EvaluationSuite),
        observed_block=args.observed_block,
    )


def record_independent_evaluation(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return store.record_independent_evaluation(
        signed=load_json(args.submission, SignedSubmission),
        evidence=load_json(args.evaluation, IndependentEvaluationEvidence),
        round_=load_json(args.round, EvaluationRound),
        suite=load_json(args.suite, EvaluationSuite),
        observed_block=args.observed_block,
    )


def fix_evidence_cutoff(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return store.fix_evidence_cutoff(
        load_json(args.round, EvaluationRound),
        load_json(args.schedule, EvidenceCutoffSchedule),
        observed_block=args.observed_block,
    )


def settle_round(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    inputs = load_json(args.inputs, SettlementInput)
    return store.settle(
        round_=inputs.round,
        suite=inputs.suite,
        evidence=tuple((entry.submission, entry.evidence) for entry in inputs.entries),
        snapshot=load_json(args.snapshot, RegistrationSnapshot),
        current_block=args.current_block,
    )


def settlement_status(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return {
        "status": store.settlement_status(args.round_sha256),
        "chain_submission_authorized": False,
    }


def round_status(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return store.round_status(args.round_sha256)


def initialize_baseline(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return store.initialize_baseline(
        load_json(args.manifest, ModelBundle), Path(args.archive).absolute()
    )


def close_round(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return {
        "round_sha256": store.close_round(
            load_json(args.round, EvaluationRound), current_block=args.current_block
        )
    }


def promote(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    return store.promote(
        signed=load_json(args.submission, SignedSubmission),
        attested=load_json(args.evaluation, AttestedResult),
        round_=load_json(args.round, EvaluationRound),
        suite=load_json(args.suite, EvaluationSuite),
        review=load_json(args.review, AttestedPromotionReview),
        archive=Path(args.archive).absolute(),
        snapshot=load_json(args.snapshot, RegistrationSnapshot),
        current_block=args.current_block,
    )


def project_weights(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    inputs = load_json(args.inputs, ProjectionInput)
    projection = store.project(
        round_=inputs.round,
        suite=inputs.suite,
        evaluations=tuple((e.submission, e.evaluation) for e in inputs.entries),
        snapshot=load_json(args.snapshot, RegistrationSnapshot),
        current_block=args.current_block,
    )
    return projection.model_dump(mode="json", by_alias=True)


def serve_rehearsal(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    store = open_store(args, policy)
    import uvicorn

    from ..competition_api import create_app

    async def fixture_snapshot() -> RegistrationSnapshot:
        return load_json(args.snapshot, RegistrationSnapshot)

    # Fixture snapshots are intentionally restricted to a loopback rehearsal.
    # There is no flag that upgrades them to public, finality-verified intake.
    uvicorn.run(create_app(store, fixture_snapshot), host="127.0.0.1", port=args.port)
    return {"status": "stopped", "chain_submission_authorized": False}
