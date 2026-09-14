"""Sign one settled round using explicit local release-authority controls.

This command does not publish a feed, start a validator or submit a transaction.
Its stdout contains the signed publication, never wallet material or input paths.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from .competition_evaluator import Directory, _read
from .competition_package import PreparedCompetitionPackage
from .competition_store import CompetitionStore
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
    schema_: Literal["umi-successor-publisher-config/1"] = Field(alias="schema")
    plan: SuccessorRoundPublicationPlan
    chain: CompetitionChainConfig
    intake_directory: Directory
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


async def sign_round(config, policy, prepared):
    config = SuccessorPublisherConfig.model_validate_json(canonical_json_bytes(config))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if config.plan.policy_sha256 != digest(policy):
        raise ValueError("publisher policy differs from approved plan")
    # These are operator-selected local stores. A missing intake store is a
    # setup error; never manufacture a new empty source to replace its history.
    intake = Path(config.intake_directory)
    if not (intake / "competition.sqlite3").is_file():
        raise ValueError("publisher requires the retained intake store")
    store = CompetitionStore(intake, policy)
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
        return await publisher.build(
            prepared,
            authorization_wallet=config.authorization_wallet.load(),
            directive_wallets=tuple(w.load() for w in config.directive_wallets),
        )
    finally:
        await provider.aclose()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "policy", "prepared-package"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        config = _read(args.config, SuccessorPublisherConfig)
        policy = _read(args.policy, CompetitionPolicy)
        prepared = _read(args.prepared_package, PreparedCompetitionPackage)
        result = asyncio.run(sign_round(config, policy, prepared))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"successor publication rejected ({type(error).__name__}); check inputs\n")
    print(canonical_json_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
