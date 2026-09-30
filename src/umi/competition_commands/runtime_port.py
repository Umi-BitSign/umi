"""One-shot runtime-port activation after quiescing and backing up service state."""

from __future__ import annotations

import argparse
import asyncio
from functools import partial
from pathlib import Path

from ..competition_artifacts import verify_preserved_bundle
from ..competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from ..competition_execution import execution_boundary
from ..competition_intake_archive import load_intake_archive
from ..competition_policy_lineage import registered_lineage
from ..competition_review_history import EvaluatorReviewStore
from ..competition_runtime_port import (
    SignedRuntimePortReview,
    baseline_record_digest,
    runtime_port_record,
    verify_runtime_port,
)
from ..competition_store import CompetitionStore, HistoricalIntakeArchiveBinding
from ..concurrency import run_owned_thread
from ..open_competition import CompetitionPolicy, digest
from .common import load_json


def _open_store(config, policy, record):
    from ..competition_service import CompetitionServiceConfig

    if isinstance(config, CompetitionServiceConfig):
        if config.retained_state.baseline_promotion_sha256 != baseline_record_digest(record):
            raise ValueError("replacement intake config must pin the reviewed runtime-port head")
        archives = tuple(load_intake_archive(item) for item in config.historical_archives)
        store = CompetitionStore(
            Path(config.state_directory),
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
        )
        return store
    if config.settlement_review_directory is None or config.settlement_replay_limits is None:
        raise ValueError("runtime port requires an existing evaluator review history")
    return EvaluatorReviewStore(
        Path(config.settlement_review_directory),
        policy,
        limits=config.settlement_replay_limits,
    )


def activate(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_evaluator import EvaluatorConfig
    from ..competition_service import CompetitionServiceConfig

    if not args.confirm_quiesced_backup:
        raise ValueError("runtime port requires quiesced services and a verified backup")
    certificate = verify_runtime_port(
        load_json(args.certificate, SignedRuntimePortReview), registered_lineage(policy)
    )
    review = certificate.review
    if review.policy_sha256 != digest(policy):
        raise ValueError("runtime port must activate under its target policy")
    config = (
        load_json(args.intake_config, CompetitionServiceConfig)
        if args.intake_config
        else load_json(args.evaluator_config, EvaluatorConfig)
    )
    chain = load_json(args.chain_config, CompetitionChainConfig)
    if (
        config.policy_sha256 != digest(policy)
        or chain.policy_sha256 != digest(policy)
        or chain.collection_timeout_seconds > 15
    ):
        raise ValueError(
            "runtime port configuration must bind the target policy and bounded provider"
        )
    directory = Path(
        config.state_directory
        if isinstance(config, CompetitionServiceConfig)
        else config.settlement_review_directory or ""
    )
    if not directory.is_absolute() or not (directory / "competition.sqlite3").is_file():
        raise ValueError("runtime port requires an existing durable ledger")
    chain_directory = Path(chain.state_directory).resolve()
    if (
        directory.resolve() == chain_directory
        or directory.resolve() in chain_directory.parents
        or chain_directory in directory.resolve().parents
    ):
        raise ValueError("runtime port chain and ledger directories must not overlap")

    async def run():
        provider = FinalizedRegistrationProvider(chain, policy)
        try:
            await provider.start()
            await provider.wait_ready()
            await run_owned_thread(
                verify_preserved_bundle,
                review.original,
                Path(args.archive).absolute(),
                registered_lineage(policy).policy(review.source_policy_sha256),
            )
            await run_owned_thread(
                verify_preserved_bundle, review.replacement, Path(args.archive).absolute(), policy
            )
            capture = await provider.collect()
            # Refuse early/late activation before opening a successor-bound store.
            if (
                not review.not_before_block
                <= execution_boundary(capture).block
                <= review.valid_through_block
            ):
                raise ValueError("runtime port is outside its application window")
            store = await run_owned_thread(_open_store, config, policy, runtime_port_record(review))
            loop = asyncio.get_running_loop()

            def fresh_block():
                future = asyncio.run_coroutine_threadsafe(provider.collect(), loop)
                try:
                    capture = future.result(timeout=chain.collection_timeout_seconds + 5)
                except BaseException:
                    future.cancel()
                    raise
                return execution_boundary(capture).block

            # Keep finality collection alive while all preserved bytes are hashed.
            result = await run_owned_thread(
                partial(
                    store.apply_runtime_port,
                    certificate,
                    archive=Path(args.archive).absolute(),
                    observed_block=fresh_block,
                ),
            )
            return {
                "status": "unrewarded_runtime_port_applied",
                "promotion_sha256": baseline_record_digest(result),
                "model_sha256": result["model_sha256"],
                "contributor_hotkey": None,
                "chain_submission_authorized": False,
            }
        finally:
            await provider.aclose()

    return asyncio.run(run())
