"""Private evaluator observations for the compensated request clock.

These observations establish availability only. Original execution evidence and
independent certification remain necessary for every result and reward.
"""

from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter
from pydantic import Field

from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .competition_execution import ExecutionBoundary
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

PATH = "/internal/cohorts/requests/readiness"
MAX_PROBE_BYTES = 64 * 1024


class RequestProbe(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-probe/1"] = Field(alias="schema")
    nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    policy_sha256: Hex32
    cohort_sha256: Hex32
    recovery_tip_sha256: Hex32
    round_sha256: Hex32
    catalog_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=64)]
    order_sha256s: Annotated[tuple[Hex32, ...], Field(max_length=512)]


class EvaluatorRequestReadiness(StrictProtocolModel):
    schema_: Literal["umi-evaluator-request-readiness/1"] = Field(alias="schema")
    probe_sha256: Hex32
    observation: ExecutionBoundary
    ready: bool
    chain_submission_authorized: Literal[False] = False


def nearby(left, right, gap):
    return abs(left.block - right.block) <= gap and (
        left.block != right.block
        or (left.block_hash, left.state_root) == (right.block_hash, right.state_root)
    )


def tasks_running(tasks):
    tasks = tuple(tasks)

    def cancelling(task):
        # Task.cancelling() was added after Python 3.10. A 3.10 task whose
        # cancellation has been delivered is already done/cancelled; before
        # delivery it remains conservatively available for this liveness probe.
        value = getattr(task, "cancelling", None)
        return value() if value is not None else task.cancelled()

    return bool(tasks) and all(not task.done() and not cancelling(task) for task in tasks)


def journal_stamp(journal):
    """Invalidate availability caches when their durable inputs change or disappear."""
    journal._check_files()
    result = []
    for suffix in ("", "-journal", "-wal"):
        path = Path(str(journal.path) + suffix)
        try:
            s = path.lstat()
        except FileNotFoundError:
            if not suffix:
                raise
            result.append(None)
        else:
            result.append((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns))
    return tuple(result)


class _Exporter:
    maximum_bytes = 16384

    def __init__(self, endpoint, timeout_seconds):
        self.endpoint, self.timeout_seconds = endpoint, timeout_seconds

    async def respond(self, probe):
        return canonical_json_bytes(await self.endpoint.request_readiness(probe))


def evaluator_request_readiness_routes(endpoint, *, token: str, timeout_seconds: int) -> APIRouter:
    return phase_review_routes(
        _Exporter(endpoint, timeout_seconds),
        token=token,
        path=PATH,
        request_model=RequestProbe,
        maximum_request_bytes=MAX_PROBE_BYTES,
    )


class RequestReadinessPeer:
    def __init__(self, client, origin, token, *, timeout_seconds: int):
        self.client = PhaseReviewHTTPClient(
            client,
            origin,
            token=token,
            path=PATH,
            maximum_bytes=16384,
            maximum_request_bytes=MAX_PROBE_BYTES,
            timeout_seconds=timeout_seconds,
        )

    async def ready(self, probe, observation, gap):
        raw = await self.client(probe)
        value = EvaluatorRequestReadiness.model_validate_json(raw)
        return (
            canonical_json_bytes(value) == raw
            and value.probe_sha256 == digest(probe)
            and value.ready
            and nearby(value.observation, observation, gap)
        )
