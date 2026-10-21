"""Publish a certified native cohort winner through existing owned histories."""

from __future__ import annotations

import argparse
import asyncio
from functools import partial
from pathlib import Path

from ..competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from ..competition_cohort_baseline_review import (
    CertifiedCohortBaselineReview,
    cohort_baseline_record,
    verify_baseline_review,
)
from ..competition_cohort_review_config import PhaseReviewServiceConfig
from ..competition_evaluator import EvaluatorConfig
from ..competition_execution import execution_boundary
from ..competition_intake_archive import load_intake_archive
from ..competition_review_history import EvaluatorReviewStore
from ..competition_runtime_port import baseline_record_digest
from ..competition_service import CompetitionServiceConfig
from ..competition_store import CompetitionStore, HistoricalIntakeArchiveBinding
from ..competition_transport_verification import TransferProgress
from ..concurrency import run_owned_thread
from ..open_competition import CompetitionPolicy, digest
from .common import load_json

StoreConfig = CompetitionServiceConfig | PhaseReviewServiceConfig | EvaluatorConfig


def _directory(config: StoreConfig) -> Path:
    if isinstance(config, CompetitionServiceConfig):
        return Path(config.state_directory)
    if isinstance(config, PhaseReviewServiceConfig):
        return Path(config.promotion_directory)
    if config.settlement_review_directory is None or config.settlement_replay_limits is None:
        raise ValueError("cohort baseline requires existing evaluator review history")
    return Path(config.settlement_review_directory)


def _open_store(config: StoreConfig, policy: CompetitionPolicy, *, read_only: bool):
    directory = _directory(config)
    if isinstance(config, CompetitionServiceConfig):
        archives = tuple(load_intake_archive(item) for item in config.historical_archives)
        return CompetitionStore(
            directory,
            policy,
            admission_capacity=config.admission_capacity,
            public_launch=config.public_deployment.launch_identity(),
            submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
            historical_intake_archive_bindings=tuple(
                HistoricalIntakeArchiveBinding(
                    schema="umi-historical-intake-archive-binding/1",
                    policy_sha256=digest(item.manifest.policy),
                    manifest_sha256=item.manifest_sha256,
                )
                for item in archives
            ),
            read_only_existing=read_only,
        )
    if isinstance(config, PhaseReviewServiceConfig):
        # Matches the current phase review boot's promotion store role/bindings.
        return CompetitionStore(directory, policy, read_only_existing=read_only)
    return EvaluatorReviewStore(
        directory, policy, limits=config.settlement_replay_limits, read_only_existing=read_only
    )


def _protected_paths(config: StoreConfig):
    yield _directory(config)
    yield Path(config.chain.state_directory)
    if isinstance(config, CompetitionServiceConfig):
        yield Path(config.submission_head_checkpoint_directory)
        if config.recoverable_intake is not None:
            yield Path(config.recoverable_intake.directory)
        if config.recoverable_service is not None:
            yield from config.recoverable_service.stores()
        yield from (Path(item.directory) for item in config.historical_archives)
    elif isinstance(config, PhaseReviewServiceConfig):
        yield from config.stores()
        yield from (
            Path(config.signer_key_file),
            Path(config.owner_token_file),
            Path(config.vote_token_file),
        )
        if config.direct_model_review is not None:
            yield Path(config.direct_model_review.r2_credentials_file)
    else:
        for name in (
            "state_directory",
            "wallet_path",
            "order_directory",
            "reveal_directory",
            "peer_directory",
            "outbox_directory",
            "archive_directory",
            "video_directory",
        ):
            yield Path(getattr(config, name))


def activate(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    if not args.check_only and not args.confirm_quiesced_backup:
        raise ValueError(
            "cohort baseline publication requires quiesced owners and a verified backup"
        )
    with TransferProgress(
        "cohort_baseline_publication_preflight",
        1,
        unit="histories",
        planning_unit_seconds=(0.01, 60),
    ) as progress:
        certificate = verify_baseline_review(
            load_json(args.certificate, CertifiedCohortBaselineReview), policy
        )
        record = cohort_baseline_record(certificate.review)
        target = baseline_record_digest(record)
        if args.intake_config:
            config = load_json(args.intake_config, CompetitionServiceConfig)
        elif args.reviewer_config:
            config = load_json(args.reviewer_config, PhaseReviewServiceConfig)
        else:
            config = load_json(args.evaluator_config, EvaluatorConfig)
        chain = load_json(args.chain_config, CompetitionChainConfig)
        config_policy = (
            digest(config.policy)
            if isinstance(config, PhaseReviewServiceConfig)
            else config.policy_sha256
        )
        if config_policy != digest(policy) or chain.policy_sha256 != digest(policy):
            raise ValueError("cohort baseline configurations must bind the certificate policy")
        if (
            chain.chain_pin != config.chain.chain_pin
            or chain.finality_pin != config.chain.finality_pin
        ):
            raise ValueError("cohort baseline observer differs from the configured chain authority")
        if isinstance(config, PhaseReviewServiceConfig):
            series = config.series
        elif (
            isinstance(config, CompetitionServiceConfig) and config.recoverable_service is not None
        ):
            series = config.recoverable_service.series
        else:
            series = None
        if series is not None and digest(series) != certificate.review.series_sha256:
            raise ValueError("cohort baseline belongs to another configured standing series")
        if series is not None:
            selected = {plan.sequence: digest(plan) for plan in series.cohorts}
            review = certificate.review
            if (
                selected.get(review.source_sequence) != review.source_cohort_sha256
                or selected.get(review.target_sequence) != review.target_cohort_sha256
            ):
                raise ValueError(
                    "cohort baseline differs from its configured source or target plan"
                )
        if (
            isinstance(config, CompetitionServiceConfig)
            and config.retained_state.baseline_promotion_sha256 != target
        ):
            raise ValueError(
                "replacement intake config must pin the certified cohort baseline head"
            )
        directory = _directory(config)
        if (
            not directory.is_absolute()
            or directory.resolve(strict=True) != directory
            or not (directory / "competition.sqlite3").is_file()
        ):
            raise ValueError("cohort baseline requires a canonical existing durable history")
        chain_directory = Path(chain.state_directory).resolve()
        for path in _protected_paths(config):
            original = path.resolve()
            if (
                chain_directory == original
                or chain_directory in original.parents
                or original in chain_directory.parents
            ):
                raise ValueError(
                    "cohort baseline observer needs separate history and finality state"
                )
        required = (
            config.retained_state.required_submission_sha256s
            if isinstance(config, CompetitionServiceConfig)
            else None
        )
        reader = _open_store(config, policy, read_only=True)
        status = reader.cohort_baseline_application_status(
            certificate, required_submission_sha256s=required
        )
        progress.advance(1, restored=status == "completed")
    result = {
        "status": "cohort_baseline_already_applied"
        if status == "completed"
        else "cohort_baseline_applied",
        "promotion_sha256": target,
        "model_sha256": record["model_sha256"],
        "contributor_hotkey": record["contributor_hotkey"],
        "chain_submission_authorized": False,
        "cohort_holds_changed": False,
    }
    if args.check_only:
        return {
            **result,
            "status": "cohort_baseline_preflight_passed",
            "application_pending": status == "pending",
            "current_finalized_window_checked": False,
        }
    if status == "completed":
        return result

    async def run():
        provider = FinalizedRegistrationProvider(chain, policy)
        try:
            with TransferProgress(
                "cohort_baseline_publication_finality",
                1,
                unit="observations",
                planning_unit_seconds=(
                    12,
                    chain.startup_timeout_seconds + chain.collection_timeout_seconds,
                ),
            ) as progress:
                await provider.start()
                await provider.wait_ready()
                capture = await provider.collect()
                block = execution_boundary(capture).block
                review = certificate.review
                if not review.not_before_block <= block <= review.valid_through_block:
                    raise ValueError("cohort baseline is outside its application window")
                progress.advance(1)
            # The existing-only native preflight must pass before opening a writer.
            writer = await run_owned_thread(partial(_open_store, config, policy, read_only=False))
            loop = asyncio.get_running_loop()

            def fresh_block():
                future = asyncio.run_coroutine_threadsafe(provider.collect(), loop)
                try:
                    return execution_boundary(
                        future.result(timeout=chain.collection_timeout_seconds + 5)
                    ).block
                except BaseException:
                    future.cancel()
                    raise

            await run_owned_thread(
                partial(writer.apply_cohort_baseline, certificate, observed_block=fresh_block)
            )
            return result
        finally:
            await provider.aclose()

    return asyncio.run(run())
