"""Prepare and publish a prospectively authorized cohort certificate format."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

import httpx

from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_model_batch_adoption_operator import (
    ActorPublication,
    ModelBatchAdoptionOperatorConfig,
    publish_for_actor,
    run_model_batch_adoption,
)
from .competition_cohort_model_batch_adoption_series import (
    ModelBatchAdoptionSeriesConfig,
    run_model_batch_adoption_series,
)
from .competition_host_activation import _read_root_control_path
from .open_competition import CompetitionPolicy
from .protocol import canonical_json_bytes


def _root_model(path, kind, maximum_bytes):
    raw = _read_root_control_path(Path(path), maximum_bytes, modes={0o400, 0o444})
    value = kind.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("batch adoption inputs require immutable canonical control files")
    return value


async def _run(path, *, series=False):
    kind = ModelBatchAdoptionSeriesConfig if series else ModelBatchAdoptionOperatorConfig
    config = _root_model(path, kind, 256 * 1024)
    policy = _root_model(config.policy_file, CompetitionPolicy, 8 * 1024**2)
    async with httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
    ) as client:
        if series:
            return await run_model_batch_adoption_series(config, policy, client=client)
        history = _root_model(config.history_file, CohortRecoveryHistory, 32 * 1024**2)
        return await run_model_batch_adoption(config, policy, history, client=client)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "run-series", "publish"))
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    handler = logging.StreamHandler()
    logger = logging.getLogger("umi.competition.progress")
    old_level, old_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        if args.action == "publish":
            if args.config is not None:
                raise ValueError("actor publication takes only its bounded canonical stdin request")
            raw = sys.stdin.buffer.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise ValueError("actor publication exceeds its request bound")
            body = ActorPublication.model_validate_json(raw)
            if canonical_json_bytes(body) != raw:
                raise ValueError("actor publication requires canonical bytes")
            result = publish_for_actor(
                body.target, body.request, body.signed, check_only=body.check_only
            )
        else:
            if args.config is None:
                raise ValueError("batch adoption run requires its operator configuration")
            result = asyncio.run(_run(args.config, series=args.action == "run-series"))
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(error).__name__,
                    "reason_code": getattr(error, "reason_code", None),
                    "retained_work_reused_on_exact_retry": True,
                }
            )
        )
        return 1
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
        logger.propagate = old_propagate
        handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
