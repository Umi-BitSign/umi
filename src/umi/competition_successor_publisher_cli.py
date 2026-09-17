"""Sign completed rounds using explicit local release-authority controls.

An optional wallet-free feed receives the signed round after verification.
This command does not start a validator or submit a transaction.
Its stdout contains the signed publication, never wallet material or input paths.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from .competition_evaluator import Directory, _read
from .competition_launch import PublicLaunchIdentity
from .competition_package import PreparedCompetitionPackage
from .competition_store import CompetitionStore
from .competition_successor_feed import SuccessorFeedConfig, SuccessorPublicationFeed
from .competition_successor_follow import AutomaticSuccessorPublisher, SuccessorFollowConfig
from .competition_successor_publication import (
    SuccessorRoundPublicationBuilder,
    SuccessorRoundPublicationPlan,
)
from .competition_successor_publisher import CurrentSuccessorRoundPublisher
from .competition_worker import CompetitionReplayWorker, CompetitionWorkerCapacity
from .open_competition import CompetitionPolicy, digest
from .protocol import StrictProtocolModel, canonical_json_bytes


class AuthorityWallet(StrictProtocolModel):
    wallet_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    hotkey_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    wallet_path: Directory

    def load(self):
        import bittensor as bt

        return bt.Wallet(name=self.wallet_name, hotkey=self.hotkey_name, path=self.wallet_path)


class SuccessorPublisherConfig(StrictProtocolModel):
    schema_: Literal["umi-successor-publisher-config/2"] = Field(alias="schema")
    plan: SuccessorRoundPublicationPlan
    public_launch: PublicLaunchIdentity
    chain: CompetitionChainConfig
    intake_directory: Directory
    submission_head_checkpoint_directory: Directory
    publication_directory: Directory
    replay_directory: Directory
    replay_capacity: CompetitionWorkerCapacity
    authorization_wallet: AuthorityWallet
    directive_wallets: Annotated[tuple[AuthorityWallet, ...], Field(min_length=1, max_length=16)]
    maximum_rounds: Annotated[int, Field(ge=1, le=65536)] = 1024
    maximum_journal_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3

    @model_validator(mode="after")
    def separate_state(self):
        if self.chain.policy_sha256 != self.plan.policy_sha256:
            raise ValueError("publisher chain and plan policies differ")
        roots = tuple(
            Path(value)
            for value in (
                self.intake_directory,
                self.submission_head_checkpoint_directory,
                self.publication_directory,
                self.replay_directory,
                self.chain.state_directory,
            )
        )
        for i, left in enumerate(roots):
            for right in roots[i + 1 :]:
                if left == right or left in right.parents or right in left.parents:
                    raise ValueError("publisher state directories must be separate")
        return self


@asynccontextmanager
async def _managed_publisher(config, policy, *, feed_config=None):
    config = SuccessorPublisherConfig.model_validate_json(canonical_json_bytes(config))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if config.plan.policy_sha256 != digest(policy):
        raise ValueError("publisher policy differs from approved plan")
    feed = None
    if feed_config is not None:
        feed_config = SuccessorFeedConfig.model_validate_json(canonical_json_bytes(feed_config))
        if feed_config.plan != config.plan:
            raise ValueError("delivery and signing plans differ")
        destination = Path(feed_config.directory)
        for source in (
            config.intake_directory,
            config.submission_head_checkpoint_directory,
            config.publication_directory,
            config.replay_directory,
            config.chain.state_directory,
            config.authorization_wallet.wallet_path,
            *(wallet.wallet_path for wallet in config.directive_wallets),
        ):
            source = Path(source)
            if (
                destination == source
                or destination in source.parents
                or source in destination.parents
            ):
                raise ValueError("delivery must be separate from authority and source state")
        feed = SuccessorPublicationFeed(feed_config)
    # These are operator-selected local stores. A missing intake store is a
    # setup error; never manufacture a new empty source to replace its history.
    intake = Path(config.intake_directory)
    if not (intake / "competition.sqlite3").is_file():
        raise ValueError("publisher requires the retained intake store")
    store = CompetitionStore(
        intake,
        policy,
        public_launch=config.public_launch,
        submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
    )
    builder = SuccessorRoundPublicationBuilder(
        Path(config.publication_directory),
        config.plan,
        maximum_rounds=config.maximum_rounds,
        maximum_bytes=config.maximum_journal_bytes,
    )
    replay = CompetitionReplayWorker(
        Path(config.replay_directory),
        package_limits=config.plan.package_limits,
        capacity=config.replay_capacity,
    )
    provider = FinalizedRegistrationProvider(config.chain, policy)
    try:
        publisher = CurrentSuccessorRoundPublisher(builder, store, replay, provider)
        await provider.start()
        await provider.wait_ready()
        # Only the explicitly named authority hotkeys are resolved by the
        # signing core. No coldkey or validator wallet is selected implicitly.
        signers = {
            "authorization_wallet": config.authorization_wallet.load(),
            "directive_wallets": tuple(w.load() for w in config.directive_wallets),
        }
        yield publisher, feed, signers
    finally:
        await provider.aclose()


async def sign_round(config, policy, prepared, *, feed_config=None):
    async with _managed_publisher(config, policy, feed_config=feed_config) as (
        publisher,
        feed,
        signers,
    ):
        result = await publisher.build(prepared, **signers)
        if feed is not None:
            await feed.retain_async(result, prepared)
        return result


async def follow_rounds(config, policy, follow_config, *, feed_config, once=False, report=None):
    config = SuccessorPublisherConfig.model_validate_json(canonical_json_bytes(config))
    follow_config = SuccessorFollowConfig.model_validate_json(canonical_json_bytes(follow_config))
    if feed_config is None:
        raise ValueError("automatic publication requires its delivery feed")
    feed_config = SuccessorFeedConfig.model_validate_json(canonical_json_bytes(feed_config))
    for source in (follow_config.certificate_directory, follow_config.package_directory):
        source = Path(source)
        for other in (
            config.intake_directory,
            config.submission_head_checkpoint_directory,
            config.publication_directory,
            config.replay_directory,
            config.chain.state_directory,
            feed_config.directory,
            config.authorization_wallet.wallet_path,
            *(wallet.wallet_path for wallet in config.directive_wallets),
        ):
            other = Path(other)
            if source == other or source in other.parents or other in source.parents:
                raise ValueError("completed-round sources overlap authority or execution state")
    async with _managed_publisher(config, policy, feed_config=feed_config) as (
        publisher,
        feed,
        signers,
    ):
        automatic = AutomaticSuccessorPublisher(publisher, feed, follow_config, **signers)
        while True:
            # Invalid inputs and journal conflicts fail closed. A service
            # manager may restart this command; durable holds are not cleared.
            result = await automatic.tick()
            if report is not None:
                report(result)
            if once:
                return result
            await asyncio.sleep(follow_config.poll_interval_seconds)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "policy"):
        parser.add_argument("--" + name, required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepared-package", type=Path)
    mode.add_argument("--follow-config", type=Path)
    parser.add_argument("--feed-config", type=Path)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if args.follow_config is not None and args.feed_config is None:
        parser.error("--follow-config requires --feed-config")
    if args.once and args.follow_config is None:
        parser.error("--once requires --follow-config")
    try:
        config = _read(args.config, SuccessorPublisherConfig)
        policy = _read(args.policy, CompetitionPolicy)
        feed_config = (
            None if args.feed_config is None else _read(args.feed_config, SuccessorFeedConfig)
        )
        if args.follow_config is not None:
            follow_config = _read(args.follow_config, SuccessorFollowConfig)
            asyncio.run(
                follow_rounds(
                    config,
                    policy,
                    follow_config,
                    feed_config=feed_config,
                    once=args.once,
                    report=lambda result: print(
                        canonical_json_bytes(result).decode("utf-8"), flush=True
                    ),
                )
            )
            return
        prepared = _read(args.prepared_package, PreparedCompetitionPackage)
        result = asyncio.run(sign_round(config, policy, prepared, feed_config=feed_config))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"successor publication rejected ({type(error).__name__}); check inputs\n")
    print(canonical_json_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
