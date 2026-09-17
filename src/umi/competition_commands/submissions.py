"""Competition submissions command handlers."""

from __future__ import annotations

import argparse
import asyncio

from ..open_competition import CompetitionPolicy, SignedSubmission, Submission, digest, sign_object
from .common import (
    load_json,
)


def sign_assignment_query(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    import bittensor as bt

    from ..competition_feed import AssignmentFeedQuery, SignedAssignmentFeedQuery

    query = load_json(args.query, AssignmentFeedQuery)
    if query.policy_sha256 != digest(policy):
        raise ValueError("assignment query belongs to another policy")
    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey_name, path=args.wallet_path)
    return SignedAssignmentFeedQuery(query=query, signature=sign_object(query, wallet)).model_dump(
        mode="json", by_alias=True
    )


def discover_assignments(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    import time

    import bittensor as bt

    from ..competition_feed import (
        AssignmentFeedQuery,
        SignedAssignmentFeedQuery,
        query_assignment_feed,
    )
    from ..policy import ScoringPolicy

    legacy = load_json(args.legacy_policy, ScoringPolicy)
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


def check_endpoint_origin(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_chain import CompetitionChainConfig
    from ..competition_origin import FinalizedEndpointProvider

    chain = load_json(args.chain_config, CompetitionChainConfig)
    signed = load_json(args.submission, SignedSubmission)

    async def check():
        provider = FinalizedEndpointProvider(chain, policy)
        try:
            await provider.start()
            return (await provider.wait_origin_ready(signed)).status()
        finally:
            await provider.aclose()

    return asyncio.run(check())


def submit(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_client import submit_signed_submission

    receipt = asyncio.run(
        submit_signed_submission(
            origin=args.origin,
            policy=policy,
            signed=load_json(args.submission, SignedSubmission),
        )
    )
    return receipt.model_dump(mode="json", by_alias=True)


def sign_submission(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    import bittensor as bt

    sub = load_json(args.submission, Submission)
    if sub.policy_sha256 != digest(policy):
        raise ValueError("submission belongs to another policy")
    # Resolving the hotkey signer does not access coldkey material.
    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey_name, path=args.wallet_path)
    signed = SignedSubmission(submission=sub, signature=sign_object(sub, wallet))
    return signed.model_dump(mode="json", by_alias=True)
