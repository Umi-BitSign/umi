"""Competition models command handlers."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from ..competition_artifacts import preserve_bundle, verify_bundle_directory
from ..open_competition import CompetitionPolicy, ModelBundle, SignedSubmission, digest
from .common import (
    load_json,
)


def prepare_endpoint_incumbent(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_authorization import SignedEndpointAuthorization
    from ..competition_endpoint_execution import prepare_incumbent_job
    from ..competition_runner import OFFLINE_RUNTIME
    from ..policy import ScoringPolicy

    return prepare_incumbent_job(
        publication=load_json(args.publication, SignedEndpointAuthorization),
        submission_sha256=args.submission_sha256,
        incumbent=load_json(args.incumbent, ModelBundle),
        runtime=load_json(args.runtime, OFFLINE_RUNTIME),
        evaluator_hotkey=args.evaluator_hotkey,
        policy=policy,
        legacy_policy=load_json(args.legacy_policy, ScoringPolicy),
    ).model_dump(mode="json", by_alias=True)


def run_model_evaluation(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
    from ..competition_execution import (
        EndpointIncumbentJob,
        ExecutionJournal,
        ModelEvaluationJob,
        execution_boundary,
        run_endpoint_incumbent,
        run_model_evaluation,
        validate_incumbent_job,
        validate_job,
    )

    endpoint = args.command == "run-endpoint-incumbent"
    job = (
        validate_incumbent_job(load_json(args.job, EndpointIncumbentJob), policy)
        if endpoint
        else validate_job(load_json(args.job, ModelEvaluationJob), policy)
    )
    chain = load_json(args.chain_config, CompetitionChainConfig)
    if chain.policy_sha256 != digest(policy) or chain.collection_timeout_seconds > 15:
        raise ValueError("execution requires a matching bounded finalized provider")
    state = Path(args.state).absolute()
    chain_state = Path(chain.state_directory).resolve()
    resolved = state.resolve()
    if (
        resolved == chain_state
        or resolved in chain_state.parents
        or chain_state in resolved.parents
    ):
        raise ValueError("execution and finalized-provider directories must not overlap")
    journal = ExecutionJournal(
        state,
        policy,
        maximum_jobs=args.maximum_jobs,
        maximum_bytes=args.maximum_evidence_bytes,
    )

    async def run():
        provider = None

        async def prepare_boundaries():
            nonlocal provider
            # Construction/startup happens only after the journal wins the
            # atomic reservation, never during any completed/failed retry.
            provider = FinalizedRegistrationProvider(chain, policy)
            await provider.start()
            await provider.wait_ready()

        async def boundary():
            assert provider is not None
            return execution_boundary(await provider.collect())

        try:
            execute_job = run_endpoint_incumbent if endpoint else run_model_evaluation
            return await execute_job(
                job=job,
                policy=policy,
                archive=Path(args.archive).absolute(),
                videos=Path(args.videos).absolute(),
                journal=journal,
                boundary_provider=boundary,
                prepare_boundaries=prepare_boundaries,
            )
        finally:
            if provider is not None:
                await provider.aclose()

    return asyncio.run(run()).model_dump(mode="json", by_alias=True)


def run_offline_case(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_runner import OFFLINE_RUNTIME, evaluate_offline_case

    runtime = load_json(args.runtime, OFFLINE_RUNTIME)
    bundle = load_json(args.manifest, ModelBundle)
    with Path(args.video).open("rb") as stream:
        video = stream.read(runtime.maximum_video_bytes + 1)
    result = asyncio.run(
        evaluate_offline_case(
            bundle=bundle,
            archive=Path(args.archive).absolute(),
            runtime=runtime,
            policy=policy,
            case_id=args.case_id,
            video_sha256=args.video_sha256,
            video=video,
        )
    )
    return {
        "schema": "umi-offline-case-observation/1",
        "policy_sha256": digest(policy),
        "model_sha256": digest(bundle),
        "runtime_sha256": digest(runtime),
        "output": result.model_dump(mode="json"),
        "chain_submission_authorized": False,
    }


def verify_bundle(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    bundle = load_json(args.manifest, ModelBundle)
    verified = verify_bundle_directory(bundle, Path(args.source).absolute(), policy)
    if args.command == "preserve-bundle":
        preserve_bundle(bundle, Path(args.source).absolute(), Path(args.archive).absolute(), policy)
    return {"model_sha256": verified, "status": args.command, "model_executed": False}


def retrieve_bundle(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_retrieval import ArtifactRetrievalLimits, retrieve_signed_model_bundle

    signed = load_json(args.submission, SignedSubmission)
    limits = ArtifactRetrievalLimits(
        maximum_files=args.maximum_files,
        maximum_file_bytes=args.maximum_file_bytes,
        maximum_total_bytes=args.maximum_total_bytes,
        request_timeout_seconds=args.request_timeout_seconds,
        total_download_timeout_seconds=args.total_download_timeout_seconds,
    )
    asyncio.run(
        retrieve_signed_model_bundle(
            signed,
            source_base_url=args.source_base_url,
            archive=Path(args.archive).absolute(),
            policy=policy,
            limits=limits,
        )
    )
    return {
        "status": "bundle_preserved",
        "model_sha256": signed.submission.model_revision,
        "model_executed": False,
        "chain_submission_authorized": False,
    }
