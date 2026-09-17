"""Competition services command handlers."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from ..open_competition import CompetitionPolicy
from ..protocol import canonical_json_bytes
from .common import (
    load_json,
)


def serve_round_coordinator(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_rounds import RoundCoordinatorConfig, serve_rounds
    from ..policy import ScoringPolicy

    serve_rounds(
        load_json(args.config, RoundCoordinatorConfig),
        policy,
        legacy=load_json(args.legacy_policy, ScoringPolicy) if args.legacy_policy else None,
    )
    return {"status": "stopped", "chain_submission_authorized": False}


def serve_evaluator_exchange(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_exchange import ExchangeConfig, serve_exchange
    from ..policy import ScoringPolicy

    serve_exchange(
        load_json(args.config, ExchangeConfig),
        policy,
        legacy=load_json(args.legacy_policy, ScoringPolicy) if args.legacy_policy else None,
    )
    return {"status": "stopped", "chain_submission_authorized": False}


def run_evaluator(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_evaluator import EvaluatorConfig, run_evaluator
    from ..policy import ScoringPolicy

    return asyncio.run(
        run_evaluator(
            load_json(args.config, EvaluatorConfig),
            policy,
            legacy=load_json(args.legacy_policy, ScoringPolicy) if args.legacy_policy else None,
            once=args.once,
            report=lambda value: print(canonical_json_bytes(value).decode(), flush=True),
        )
    )


def run_endpoint_dispatch(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_dispatch import EndpointDispatchConfig, run_dispatch
    from ..policy import ScoringPolicy

    return asyncio.run(
        run_dispatch(
            load_json(args.config, EndpointDispatchConfig),
            policy,
            load_json(args.legacy_policy, ScoringPolicy),
            once=args.once,
            report=lambda status: print(canonical_json_bytes(status).decode(), flush=True),
        )
    )


def serve_assignment_feed(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    import uvicorn

    from ..competition_feed import create_assignment_feed
    from ..competition_scheduling import AssignmentPublicationJournal
    from ..policy import ScoringPolicy

    if not 1024 <= args.port <= 65535:
        raise ValueError("assignment feed port is invalid")
    journal = AssignmentPublicationJournal(
        Path(args.state).absolute(),
        policy,
        load_json(args.legacy_policy, ScoringPolicy),
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


def serve_intake(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from ..competition_service import CompetitionServiceConfig, serve_intake

    serve_intake(load_json(args.config, CompetitionServiceConfig), policy)
    return {"status": "stopped", "chain_submission_authorized": False}
