"""Explicit initialization and miner consent for recoverable cohort intake."""

from __future__ import annotations

import argparse
import asyncio

from ..competition_cohort_client import fetch_cohort_admission, submit_cohort_participation
from ..competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from ..competition_cohort_intake import CohortIntake
from ..competition_cohort_participation import (
    CohortParticipationConsent,
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from ..open_competition import CompetitionPolicy, SignedSubmission, digest, identity, sign_object
from ..protocol import canonical_json_bytes
from .common import load_json


def initialize_intake(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_service import CompetitionServiceConfig

    config = load_json(args.config, CompetitionServiceConfig)
    if config.policy_sha256 != digest(policy) or config.recoverable_intake is None:
        raise ValueError("configuration does not select recoverable intake for this policy")
    CohortIntake(
        config.recoverable_intake,
        policy,
        eligible_tracks=config.public_deployment.eligible_tracks,
        capacity=config.admission_capacity,
        initialize=True,
    )
    return {"status": "cohort_intake_initialized", "chain_submission_authorized": False}


def sign_consent(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    body = load_json(args.consent, CohortParticipationConsent)
    signed = load_json(args.submission, SignedSubmission)
    history = load_json(args.history, CohortRecoveryHistory)
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=args.expected_tip_sha256,
        current_block=args.current_block,
    )
    sub = signed.submission
    if (
        view.state.phase != "intake"
        or not view.state.not_before_block <= args.current_block
        or body.cohort_sha256 != view.state.cohort_sha256
        or body.authority_sha256 != view.state.authority_sha256
        or body.submission_sha256 != digest(sub)
        or identity(body.hotkey) != identity(sub.hotkey)
        or sub.policy_sha256 != digest(policy)
        or sub.accepted_terms_sha256 != policy.contribution_terms_sha256
        or not history.authority.authority.issued_at_block
        <= body.signed_at_block
        <= args.current_block
        or args.current_block < sub.valid_from_block
        or not policy.valid_from_block
        <= sub.valid_from_block
        < sub.valid_through_block
        <= policy.valid_through_block
        or sub.valid_through_block - sub.valid_from_block
        > policy.maximum_submission_lifetime_blocks
    ):
        raise ValueError("consent does not cover the selected open cohort and contribution")
    import bittensor as bt

    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey_name, path=args.wallet_path)
    request = CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(consent=body, signature=sign_object(body, wallet)),
    )
    return request.model_dump(mode="json", by_alias=True)


def submit_consent(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    receipt = asyncio.run(
        submit_cohort_participation(
            origin=args.origin,
            policy=policy,
            request=load_json(args.request, CohortParticipationRequest),
        )
    )
    return receipt.model_dump(mode="json", by_alias=True)


def query_admission(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    status = asyncio.run(
        fetch_cohort_admission(
            origin=args.origin,
            policy=policy,
            request=load_json(args.request, CohortParticipationRequest),
        )
    )
    return status.model_dump(mode="json", by_alias=True)


def run_admission_worker(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_cohort_admission_worker import (
        CohortAdmissionWorkerConfig,
        run_admission_worker,
    )

    return asyncio.run(
        run_admission_worker(
            load_json(args.config, CohortAdmissionWorkerConfig),
            policy,
            once=args.once,
            report=lambda value: print(canonical_json_bytes(value).decode(), flush=True),
        )
    )
