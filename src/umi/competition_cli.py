"""Local successor rehearsal commands. No command can submit chain weights."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Annotated

from pydantic import Field

from .competition_artifacts import preserve_bundle, verify_bundle_directory
from .competition_evidence import IndependentEvaluationEvidence, replay_independent_evaluation
from .competition_execution import ModelExecutionEvidence
from .competition_settlement import EvidenceCutoffSchedule
from .competition_store import AttestedPromotionReview, CompetitionStore
from .open_competition import (
    AttestedResult,
    CompetitionPolicy,
    EvaluationRound,
    EvaluationSuite,
    ModelBundle,
    RegistrationSnapshot,
    SignedSubmission,
    StrictProtocolModel,
    Submission,
    aggregate_quality,
    digest,
    qualifies_for_promotion,
    replay_evaluation,
    sign_object,
)
from .protocol import canonical_json_bytes

MAX_JSON_BYTES = 64 * 1024 * 1024


class ReplayEntry(StrictProtocolModel):
    submission: SignedSubmission
    evaluation: AttestedResult


class ProjectionInput(StrictProtocolModel):
    round: EvaluationRound
    suite: EvaluationSuite
    entries: Annotated[tuple[ReplayEntry, ...], Field(min_length=1, max_length=512)]


class IndependentReplayEntry(StrictProtocolModel):
    submission: SignedSubmission
    evidence: IndependentEvaluationEvidence


class SettlementInput(StrictProtocolModel):
    round: EvaluationRound
    suite: EvaluationSuite
    entries: Annotated[tuple[IndependentReplayEntry, ...], Field(min_length=1, max_length=512)]


class ExecutionInputs(StrictProtocolModel):
    executions: Annotated[tuple[ModelExecutionEvidence, ...], Field(min_length=1, max_length=64)]


class PublicationRoster(StrictProtocolModel):
    submissions: Annotated[tuple[SignedSubmission, ...], Field(min_length=1, max_length=512)]


class PublicationEvidenceInputs(StrictProtocolModel):
    entries: Annotated[tuple[IndependentReplayEntry, ...], Field(min_length=1, max_length=512)]


def _load(path: str, model):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("rehearsal JSON exceeds the byte limit")
    return model.model_validate_json(data)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, help="reviewed successor policy JSON")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inspect-policy")
    intake = commands.add_parser("serve-intake")
    intake.add_argument("--config", required=True)
    submit = commands.add_parser("submit")
    submit.add_argument("--submission", required=True)
    submit.add_argument("--origin", required=True)
    origin = commands.add_parser("check-endpoint-origin")
    origin.add_argument("--submission", required=True)
    origin.add_argument("--chain-config", required=True)
    dispatch = commands.add_parser("run-endpoint-dispatch")
    dispatch.add_argument("--config", required=True)
    dispatch.add_argument("--legacy-policy", required=True)
    dispatch.add_argument("--once", action="store_true")
    feed = commands.add_parser("serve-assignment-feed")
    for name in ("legacy-policy", "state", "nonce-path"):
        feed.add_argument("--" + name, required=True)
    feed.add_argument("--port", type=int, default=8099)
    feed_sign = commands.add_parser("sign-assignment-query")
    for name in ("query", "wallet-name", "hotkey-name", "wallet-path"):
        feed_sign.add_argument("--" + name, required=True)
    discover = commands.add_parser("discover-assignments")
    for name in ("origin", "legacy-policy", "wallet-name", "hotkey-name", "wallet-path"):
        discover.add_argument("--" + name, required=True)
    discover.add_argument("--publication")
    discover.add_argument("--after")
    discover.add_argument("--limit", type=int, default=20)
    inspection = commands.add_parser("inspect-host-upgrade")
    for name in ("config", "accepted-directive", "expected-hotkey"):
        inspection.add_argument("--" + name, required=True)
    inspection.add_argument(
        "--expected-platform", choices=("linux/amd64", "linux/arm64"), required=True
    )
    inspection.add_argument("--service-uid", type=int, required=True)
    inspection.add_argument("--staged-directory")
    for name in ("verify-cutoff-publication", "verify-settlement-publication"):
        certificate = commands.add_parser(name)
        for param in ("certificate", "roster", "replay-limits"):
            certificate.add_argument("--" + param, required=True)
        if name == "verify-settlement-publication":
            for param in ("cutoff-certificate", "evidence", "retained-settlement"):
                certificate.add_argument("--" + param, required=True)
    prepare_package = commands.add_parser("prepare-settlement-package")
    for name in (
        "cutoff-certificate",
        "certificate",
        "retained-settlement",
        "roster",
        "evidence",
        "replay-limits",
        "release-identity",
        "package-limits",
        "destination",
    ):
        prepare_package.add_argument("--" + name, required=True)
    replay_package = commands.add_parser("replay-settlement-package")
    for name in (
        "package",
        "expected-package-sha256",
        "release-identity",
        "package-limits",
        "worker-capacity",
        "state",
    ):
        replay_package.add_argument("--" + name, required=True)
    offline = commands.add_parser("run-offline-case")
    for name in ("runtime", "manifest", "archive", "video", "case-id", "video-sha256"):
        offline.add_argument("--" + name, required=True)
    model_run = commands.add_parser("run-model-evaluation")
    for name in ("job", "chain-config", "archive", "videos", "state"):
        model_run.add_argument("--" + name, required=True)
    model_run.add_argument("--maximum-jobs", type=int, default=1024)
    model_run.add_argument("--maximum-evidence-bytes", type=int, default=1024**3)
    execution_status = commands.add_parser("execution-status")
    execution_status.add_argument("--state", required=True)
    execution_status.add_argument("--execution-key", required=True)
    for name in ("propose-execution-result", "prepare-execution-record"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--suite", required=True)
        cmd.add_argument("--current-block", type=int, required=True)
        if name == "propose-execution-result":
            cmd.add_argument("--inputs", required=True)
        else:
            cmd.add_argument("--execution", required=True)
            cmd.add_argument("--result", required=True)
    for name in ("verify-bundle", "preserve-bundle"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--manifest", required=True)
        cmd.add_argument("--source", required=True)
        if name == "preserve-bundle":
            cmd.add_argument("--archive", required=True)
    retrieval = commands.add_parser("retrieve-bundle")
    for name in ("submission", "source-base-url", "archive"):
        retrieval.add_argument("--" + name, required=True)
    for name in ("maximum-files", "maximum-file-bytes", "maximum-total-bytes"):
        retrieval.add_argument("--" + name, required=True, type=int)
    for name in ("request-timeout-seconds", "total-download-timeout-seconds"):
        retrieval.add_argument("--" + name, required=True, type=float)
    sign = commands.add_parser("sign-submission")
    sign.add_argument("--submission", required=True)
    sign.add_argument("--wallet-name", required=True)
    sign.add_argument("--hotkey-name", required=True)
    sign.add_argument("--wallet-path", required=True)
    for name in (
        "status",
        "admit",
        "initialize-baseline",
        "close-round",
        "promote",
        "project-weights",
        "record-evaluation",
        "record-independent-evaluation",
        "fix-evidence-cutoff",
        "settle-round",
        "settlement-status",
        "round-status",
        "serve-rehearsal",
    ):
        cmd = commands.add_parser(name)
        cmd.add_argument("--state", required=True)
        if name in {"admit", "promote", "project-weights", "serve-rehearsal", "settle-round"}:
            cmd.add_argument("--snapshot", required=True)
        if name in {"admit", "promote", "record-evaluation", "record-independent-evaluation"}:
            cmd.add_argument("--submission", required=True)
        if name in {
            "promote",
            "close-round",
            "record-evaluation",
            "record-independent-evaluation",
            "fix-evidence-cutoff",
        }:
            cmd.add_argument("--round", required=True)
        if name in {"close-round", "promote", "project-weights", "admit", "settle-round"}:
            cmd.add_argument("--current-block", required=True, type=int)
        if name in {"initialize-baseline", "promote"}:
            cmd.add_argument("--archive", required=True)
        if name == "initialize-baseline":
            cmd.add_argument("--manifest", required=True)
        if name in {"promote", "record-evaluation", "record-independent-evaluation"}:
            cmd.add_argument("--evaluation", required=True)
            cmd.add_argument("--suite", required=True)
        if name in {"record-evaluation", "record-independent-evaluation", "fix-evidence-cutoff"}:
            cmd.add_argument("--observed-block", required=True, type=int)
        if name in {"round-status", "settlement-status"}:
            cmd.add_argument("--round-sha256", required=True)
        if name == "promote":
            cmd.add_argument("--review", required=True)
        if name in {"project-weights", "settle-round"}:
            cmd.add_argument("--inputs", required=True)
        if name == "fix-evidence-cutoff":
            cmd.add_argument("--schedule", required=True)
        if name == "serve-rehearsal":
            cmd.add_argument("--port", type=int, default=8098)
    for name in ("replay-evaluation", "replay-independent-evaluation"):
        replay = commands.add_parser(name)
        for argument in ("submission", "evaluation", "round", "suite"):
            replay.add_argument("--" + argument, required=True)
        replay.add_argument("--current-block", type=int, required=True)
    return parser


def execute(args: argparse.Namespace) -> dict:
    policy = _load(args.policy, CompetitionPolicy)
    if args.command == "run-endpoint-dispatch":
        from .competition_dispatch import EndpointDispatchConfig, run_dispatch
        from .policy import ScoringPolicy

        return asyncio.run(
            run_dispatch(
                _load(args.config, EndpointDispatchConfig),
                policy,
                _load(args.legacy_policy, ScoringPolicy),
                once=args.once,
                report=lambda status: print(canonical_json_bytes(status).decode(), flush=True),
            )
        )
    if args.command == "prepare-settlement-package":
        from .competition_package import (
            CompetitionPackageLimits,
            CompetitionReleaseIdentity,
            prepare_competition_package,
        )
        from .competition_publication import (
            PublicationReplayLimits,
            SignedCutoffPublication,
            SignedSettlementPublication,
        )
        from .competition_settlement import CompetitionSettlement

        roster = _load(args.roster, PublicationRoster)
        evidence = _load(args.evidence, PublicationEvidenceInputs)
        prepared = prepare_competition_package(
            policy=policy,
            cutoff_certificate=_load(args.cutoff_certificate, SignedCutoffPublication),
            settlement_certificate=_load(args.certificate, SignedSettlementPublication),
            retained_settlement=_load(args.retained_settlement, CompetitionSettlement),
            roster=roster.submissions,
            evidence=tuple((entry.submission, entry.evidence) for entry in evidence.entries),
            replay_limits=_load(args.replay_limits, PublicationReplayLimits),
            release_identity=_load(args.release_identity, CompetitionReleaseIdentity),
            destination_root=Path(args.destination).absolute(),
            limits=_load(args.package_limits, CompetitionPackageLimits),
        )
        return prepared.model_dump(mode="json", by_alias=True)
    if args.command == "replay-settlement-package":
        from .competition_package import CompetitionPackageLimits, CompetitionReleaseIdentity
        from .competition_worker import CompetitionReplayWorker, CompetitionWorkerCapacity

        worker = CompetitionReplayWorker(
            Path(args.state).absolute(),
            package_limits=_load(args.package_limits, CompetitionPackageLimits),
            capacity=_load(args.worker_capacity, CompetitionWorkerCapacity),
        )
        result = worker.run(
            Path(args.package).absolute(),
            expected_package_sha256=args.expected_package_sha256,
            expected_policy_sha256=digest(policy),
            observed_release=_load(args.release_identity, CompetitionReleaseIdentity),
        )
        return result.model_dump(mode="json", by_alias=True)
    if args.command == "serve-assignment-feed":
        import uvicorn

        from .competition_feed import create_assignment_feed
        from .competition_scheduling import AssignmentPublicationJournal
        from .policy import ScoringPolicy

        if not 1024 <= args.port <= 65535:
            raise ValueError("assignment feed port is invalid")
        journal = AssignmentPublicationJournal(
            Path(args.state).absolute(),
            policy,
            _load(args.legacy_policy, ScoringPolicy),
        )
        app = create_assignment_feed(journal, nonce_path=Path(args.nonce_path).absolute())
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=args.port,
            limit_concurrency=32,
            backlog=64,
            timeout_keep_alive=5,
        )
        return {"status": "stopped", "chain_submission_authorized": False}
    if args.command == "sign-assignment-query":
        import bittensor as bt

        from .competition_feed import AssignmentFeedQuery, SignedAssignmentFeedQuery

        query = _load(args.query, AssignmentFeedQuery)
        if query.policy_sha256 != digest(policy):
            raise ValueError("assignment query belongs to another policy")
        wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey_name, path=args.wallet_path)
        return SignedAssignmentFeedQuery(
            query=query, signature=sign_object(query, wallet)
        ).model_dump(mode="json", by_alias=True)
    if args.command == "discover-assignments":
        import time

        import bittensor as bt

        from .competition_feed import (
            AssignmentFeedQuery,
            SignedAssignmentFeedQuery,
            query_assignment_feed,
        )
        from .policy import ScoringPolicy

        legacy = _load(args.legacy_policy, ScoringPolicy)
        wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey_name, path=args.wallet_path)
        signer = bt.resolve_signer(wallet, role="hotkey")
        query = AssignmentFeedQuery(
            schema="umi-assignment-feed-query/1",
            policy_sha256=digest(policy),
            miner_hotkey=signer.ss58_address,
            nonce_unix_ns=str(time.time_ns()),
            operation="publication" if args.publication else "list",
            publication_sha256=args.publication,
            after=args.after,
            limit=args.limit,
        )
        signed = SignedAssignmentFeedQuery(query=query, signature=sign_object(query, wallet))
        return asyncio.run(
            query_assignment_feed(
                origin=args.origin, signed=signed, policy=policy, legacy_policy=legacy
            )
        )
    if args.command == "inspect-host-upgrade":
        from dataclasses import asdict

        from .competition_upgrade import inspect_successor_upgrade
        from .validator_supervisor import MAX_SUPERVISOR_DOCUMENT_BYTES

        with Path(args.accepted_directive).open("rb") as stream:
            raw = stream.read(MAX_SUPERVISOR_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_SUPERVISOR_DOCUMENT_BYTES:
            raise ValueError("accepted directive exceeds its byte limit")
        result = inspect_successor_upgrade(
            config_path=Path(args.config).absolute(),
            accepted_directive_bytes=raw,
            expected_hotkey=args.expected_hotkey,
            expected_platform=args.expected_platform,
            service_uid=args.service_uid,
            staged_directory=None
            if args.staged_directory is None
            else Path(args.staged_directory).absolute(),
        )
        # The inspected installation still binds its original signed policy.
        # Supplying --policy here does not replace that historical binding.
        return asdict(result)
    if args.command in {"verify-cutoff-publication", "verify-settlement-publication"}:
        from .competition_publication import (
            PublicationReplayLimits,
            SignedCutoffPublication,
            SignedSettlementPublication,
            cutoff_publication_digest,
            settlement_publication_digest,
            verify_cutoff_publication,
            verify_settlement_publication,
        )
        from .competition_settlement import CompetitionSettlement

        roster = _load(args.roster, PublicationRoster)
        limits = _load(args.replay_limits, PublicationReplayLimits)
        if args.command == "verify-cutoff-publication":
            result = verify_cutoff_publication(
                _load(args.certificate, SignedCutoffPublication),
                policy=policy,
                submissions=roster.submissions,
                limits=limits,
            )
            result_digest = cutoff_publication_digest(result)
        else:
            evidence = _load(args.evidence, PublicationEvidenceInputs)
            result = verify_settlement_publication(
                _load(args.certificate, SignedSettlementPublication),
                cutoff_certificate=_load(args.cutoff_certificate, SignedCutoffPublication),
                policy=policy,
                submissions=roster.submissions,
                evidence=tuple((item.submission, item.evidence) for item in evidence.entries),
                retained_settlement=_load(args.retained_settlement, CompetitionSettlement),
                limits=limits,
            )
            result_digest = settlement_publication_digest(result)
        return {
            "status": "publication_replayed",
            "publication_sha256": result_digest,
            "chain_submission_authorized": False,
            "publication_timing_proven": False,
        }
    if args.command == "check-endpoint-origin":
        from .competition_chain import CompetitionChainConfig
        from .competition_origin import FinalizedEndpointProvider

        chain = _load(args.chain_config, CompetitionChainConfig)
        signed = _load(args.submission, SignedSubmission)

        async def check():
            provider = FinalizedEndpointProvider(chain, policy)
            try:
                await provider.start()
                return (await provider.wait_origin_ready(signed)).status()
            finally:
                await provider.aclose()

        return asyncio.run(check())
    if args.command == "run-model-evaluation":
        from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
        from .competition_execution import (
            ExecutionJournal,
            ModelEvaluationJob,
            execution_boundary,
            run_model_evaluation,
            validate_job,
        )

        job = validate_job(_load(args.job, ModelEvaluationJob), policy)
        chain = _load(args.chain_config, CompetitionChainConfig)
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
                return await run_model_evaluation(
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
    if args.command == "execution-status":
        from .competition_execution import ExecutionJournal

        return ExecutionJournal(Path(args.state).absolute(), policy).status(args.execution_key) or {
            "status": "unknown_execution",
            "chain_submission_authorized": False,
        }
    if args.command in {"propose-execution-result", "prepare-execution-record"}:
        from .competition_execution import common_execution_result, run_record_from_execution
        from .open_competition import EvaluationResult

        suite = _load(args.suite, EvaluationSuite)
        if args.command == "propose-execution-result":
            value = common_execution_result(
                _load(args.inputs, ExecutionInputs).executions,
                suite,
                policy,
                current_block=args.current_block,
            )
        else:
            value = run_record_from_execution(
                _load(args.execution, ModelExecutionEvidence),
                _load(args.result, EvaluationResult),
                suite,
                policy,
                current_block=args.current_block,
            )
        return {
            "object": value.model_dump(mode="json", by_alias=True),
            "signed": False,
            "chain_submission_authorized": False,
        }
    if args.command == "serve-intake":
        from .competition_service import CompetitionServiceConfig, serve_intake

        serve_intake(_load(args.config, CompetitionServiceConfig), policy)
        return {"status": "stopped", "chain_submission_authorized": False}
    if args.command == "submit":
        from .competition_client import submit_signed_submission

        receipt = asyncio.run(
            submit_signed_submission(
                origin=args.origin,
                policy=policy,
                signed=_load(args.submission, SignedSubmission),
            )
        )
        return receipt.model_dump(mode="json", by_alias=True)
    if args.command == "run-offline-case":
        from .competition_runner import OfflineCpuRuntime, evaluate_offline_case

        runtime = _load(args.runtime, OfflineCpuRuntime)
        bundle = _load(args.manifest, ModelBundle)
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
    if args.command == "inspect-policy":
        return {
            "policy_sha256": digest(policy),
            "mode": "rehearsal_no_weight",
            "endpoint_reward_bps": policy.endpoint_reward_bps,
            "model_reward_bps": policy.model_reward_bps,
            "chain_submission_authorized": False,
        }
    if args.command in {"verify-bundle", "preserve-bundle"}:
        bundle = _load(args.manifest, ModelBundle)
        verified = verify_bundle_directory(bundle, Path(args.source).absolute(), policy)
        if args.command == "preserve-bundle":
            preserve_bundle(
                bundle, Path(args.source).absolute(), Path(args.archive).absolute(), policy
            )
        return {"model_sha256": verified, "status": args.command, "model_executed": False}
    if args.command == "retrieve-bundle":
        from .competition_retrieval import ArtifactRetrievalLimits, retrieve_signed_model_bundle

        signed = _load(args.submission, SignedSubmission)
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
    if args.command == "sign-submission":
        import bittensor as bt

        sub = _load(args.submission, Submission)
        if sub.policy_sha256 != digest(policy):
            raise ValueError("submission belongs to another policy")
        # Resolving the hotkey signer does not access coldkey material.
        wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey_name, path=args.wallet_path)
        signed = SignedSubmission(submission=sub, signature=sign_object(sub, wallet))
        return signed.model_dump(mode="json", by_alias=True)
    if args.command in {"replay-evaluation", "replay-independent-evaluation"}:
        independent = args.command == "replay-independent-evaluation"
        replay = replay_independent_evaluation if independent else replay_evaluation
        candidate, incumbent = replay(
            _load(
                args.evaluation, IndependentEvaluationEvidence if independent else AttestedResult
            ),
            _load(args.submission, SignedSubmission),
            _load(args.round, EvaluationRound),
            _load(args.suite, EvaluationSuite),
            policy,
            current_block=args.current_block,
        )
        return {
            "candidate_quality": str(aggregate_quality(candidate)),
            "incumbent_quality": str(aggregate_quality(incumbent)),
            "quality_gate_passed": qualifies_for_promotion(candidate, incumbent, policy),
            "chain_submission_authorized": False,
        }
    store = CompetitionStore(Path(args.state).absolute(), policy)
    if args.command == "status":
        return {
            "policy_sha256": digest(policy),
            "baseline": store.baseline_summary(),
            "mode": "rehearsal_no_weight",
            "chain_submission_authorized": False,
        }
    if args.command == "admit":
        return store.admit(
            _load(args.submission, SignedSubmission),
            _load(args.snapshot, RegistrationSnapshot),
            args.current_block,
        )
    if args.command == "record-evaluation":
        return store.record_evaluation(
            signed=_load(args.submission, SignedSubmission),
            attested=_load(args.evaluation, AttestedResult),
            round_=_load(args.round, EvaluationRound),
            suite=_load(args.suite, EvaluationSuite),
            observed_block=args.observed_block,
        )
    if args.command == "record-independent-evaluation":
        return store.record_independent_evaluation(
            signed=_load(args.submission, SignedSubmission),
            evidence=_load(args.evaluation, IndependentEvaluationEvidence),
            round_=_load(args.round, EvaluationRound),
            suite=_load(args.suite, EvaluationSuite),
            observed_block=args.observed_block,
        )
    if args.command == "fix-evidence-cutoff":
        return store.fix_evidence_cutoff(
            _load(args.round, EvaluationRound),
            _load(args.schedule, EvidenceCutoffSchedule),
            observed_block=args.observed_block,
        )
    if args.command == "settle-round":
        inputs = _load(args.inputs, SettlementInput)
        return store.settle(
            round_=inputs.round,
            suite=inputs.suite,
            evidence=tuple((entry.submission, entry.evidence) for entry in inputs.entries),
            snapshot=_load(args.snapshot, RegistrationSnapshot),
            current_block=args.current_block,
        )
    if args.command == "settlement-status":
        return {
            "status": store.settlement_status(args.round_sha256),
            "chain_submission_authorized": False,
        }
    if args.command == "round-status":
        return store.round_status(args.round_sha256)
    if args.command == "initialize-baseline":
        return store.initialize_baseline(
            _load(args.manifest, ModelBundle), Path(args.archive).absolute()
        )
    if args.command == "close-round":
        return {
            "round_sha256": store.close_round(
                _load(args.round, EvaluationRound), current_block=args.current_block
            )
        }
    if args.command == "promote":
        return store.promote(
            signed=_load(args.submission, SignedSubmission),
            attested=_load(args.evaluation, AttestedResult),
            round_=_load(args.round, EvaluationRound),
            suite=_load(args.suite, EvaluationSuite),
            review=_load(args.review, AttestedPromotionReview),
            archive=Path(args.archive).absolute(),
            snapshot=_load(args.snapshot, RegistrationSnapshot),
            current_block=args.current_block,
        )
    if args.command == "project-weights":
        inputs = _load(args.inputs, ProjectionInput)
        projection = store.project(
            round_=inputs.round,
            suite=inputs.suite,
            evaluations=tuple((e.submission, e.evaluation) for e in inputs.entries),
            snapshot=_load(args.snapshot, RegistrationSnapshot),
            current_block=args.current_block,
        )
        return projection.model_dump(mode="json", by_alias=True)
    if args.command == "serve-rehearsal":
        import uvicorn

        from .competition_api import create_app

        async def fixture_snapshot() -> RegistrationSnapshot:
            return _load(args.snapshot, RegistrationSnapshot)

        # Fixture snapshots are intentionally restricted to a loopback rehearsal.
        # There is no flag that upgrades them to public, finality-verified intake.
        uvicorn.run(create_app(store, fixture_snapshot), host="127.0.0.1", port=args.port)
        return {"status": "stopped", "chain_submission_authorized": False}
    raise ValueError("unsupported competition command")


def main(argv: list[str] | None = None) -> None:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = execute(args)
    except (OSError, ValueError, RuntimeError) as error:
        # Pydantic exceptions can contain complete input payloads. Do not print
        # them into public terminal logs or mistake malformed data for success.
        parser.exit(2, f"competition command rejected ({type(error).__name__}); check inputs\n")
    print(canonical_json_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
