"""Bounded cached evaluator stages, independent of confirmed execution exports.

The private endpoint only copies already emitted diagnostics. Background intake
sampling binds them to the separately observed producer epoch; unavailable older
peers never suppress exports or become evidence of completed work.
"""

import asyncio
import hmac
import json
import math
import re
import time
from collections import OrderedDict
from copy import deepcopy

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from .competition_cohort_observation import observe_http
from .competition_cohort_review_http import _credential
from .protocol import canonical_json_bytes

WORK_PATH = "/internal/cohorts/execution-producer/work/"
MAX_STAGES = 32
MAX_BYTES = 64 * 1024
_TEXT = {"stage", "state", "status", "unit", "eta_basis", "eta_scope", "scope"}
_COUNTS = {"work_id", "completed", "total", "observed_unix_ms", "estimated_finish_unix_ms"}
_NUMBERS = {"percent", "elapsed_seconds", "eta_seconds", "age_seconds"}
_FLAGS = {"stale", "stalled", "stalled_or_retrying"}
_FIELDS = _TEXT | _COUNTS | _NUMBERS | _FLAGS | {"planning_eta_seconds"}


def public_stage(body):
    """Copy explicit counters only; never job ids, paths, inputs or exceptions."""
    if type(body) is not dict:
        raise ValueError("invalid evaluator work stage")
    result = {key: body[key] for key in _FIELDS if key in body}
    for key, value in result.items():
        if value is None:
            if key not in {"eta_seconds", "estimated_finish_unix_ms", "planning_eta_seconds"}:
                raise ValueError("invalid evaluator work null")
        elif key in _TEXT:
            if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,191}", value) is None:
                raise ValueError("invalid evaluator work label")
        elif key in _COUNTS:
            if type(value) is not int or (key != "work_id" and value < 0):
                raise ValueError("invalid evaluator work count")
        elif key in _FLAGS:
            if type(value) is not bool:
                raise ValueError("invalid evaluator work flag")
        elif key in _NUMBERS:
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError("invalid evaluator work measurement")
        elif key == "planning_eta_seconds" and (
            type(value) is not list
            or len(value) != 2
            or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in value)
            or value[0] > value[1]
        ):
            raise ValueError("invalid evaluator planning range")
    if not {"stage", "state", "work_id", "completed", "total"} <= result.keys():
        raise ValueError("incomplete evaluator work stage")
    if result["completed"] > result["total"] or result.get("percent", 0) > 100:
        raise ValueError("evaluator work exceeds its declared scope")
    return result


def aged_stage(body, seconds):
    result = public_stage(body)
    age = result.get("age_seconds", 0) + seconds
    result["age_seconds"] = round(age, 3)
    result["elapsed_seconds"] = round(result.get("elapsed_seconds", 0) + seconds, 3)
    stale = result["stale"] = result.get("stale", False) or age > 120
    eta = result.get("eta_seconds")
    if (
        stale
        or result.get("stalled")
        or result.get("stalled_or_retrying")
        or (eta is not None and eta > 0 and seconds >= eta)
    ):
        result.update(
            eta_seconds=None,
            planning_eta_seconds=None,
            estimated_finish_unix_ms=None,
            eta_basis="stale_evaluator_work" if stale else "evaluator_work_estimate_withdrawn",
        )
    elif eta is not None and eta > 0:
        result["eta_seconds"] = round(eta - seconds, 3)
    return result


def execution_work_routes(*, evaluator, epoch, token, enabled, cohorts, snapshots):
    expected = ("Bearer " + _credential(token)).encode()
    known = frozenset(cohorts)
    router = APIRouter()

    @router.get(WORK_PATH + "{cohort}")
    async def current(cohort: str, request: Request):
        if not hmac.compare_digest(request.headers.get("authorization", "").encode(), expected):
            raise HTTPException(401, "reviewer authentication required")
        if cohort not in known:
            raise HTTPException(404, "cohort diagnostics unavailable")
        try:
            stages = snapshots.active_work_snapshot(cohort)
        except (ValueError, TypeError, KeyError):
            raise HTTPException(503, "evaluator diagnostics require repair") from None
        body = dict(
            schema="umi-execution-work/1",
            evaluator=evaluator,
            epoch_sha256=epoch,
            cohort_sha256=cohort,
            execution_enabled=bool(enabled),
            stages=stages,
        )
        raw = canonical_json_bytes(body)
        if len(raw) > MAX_BYTES:
            raise HTTPException(503, "evaluator diagnostics exceed their byte bound")
        return Response(raw, media_type="application/json")

    return router


class ExecutionWorkObservations:
    def __init__(self, client, peers, capacity):
        self.client, self.peers, self.capacity = client, peers, capacity
        self.cache = OrderedDict()

    async def _fetch(self, evaluator, cohort, epoch):
        origin, token = self.peers[evaluator]
        async with (
            self.capacity,
            self.client.stream(
                "GET",
                origin.rstrip("/") + WORK_PATH + cohort,
                headers={"authorization": "Bearer " + token, "accept-encoding": "identity"},
                timeout=2,
            ) as response,
        ):
            if response.status_code != 200:
                return dict(evaluator=evaluator, status="unavailable", stages=[])
            raw = bytearray()
            async for part in response.aiter_bytes(chunk_size=MAX_BYTES + 1):
                if len(raw) + len(part) > MAX_BYTES:
                    raise ValueError("evaluator diagnostics exceed their byte bound")
                raw.extend(part)
        body = json.loads(raw)
        if (
            type(body) is not dict
            or set(body)
            != {
                "schema",
                "evaluator",
                "epoch_sha256",
                "cohort_sha256",
                "execution_enabled",
                "stages",
            }
            or body["schema"] != "umi-execution-work/1"
            or body["evaluator"] != evaluator
            or body["epoch_sha256"] != epoch
            or body["cohort_sha256"] != cohort
            or body["execution_enabled"] is not True
            or type(body["stages"]) is not list
            or len(body["stages"]) > MAX_STAGES
        ):
            raise ValueError("evaluator work binding differs")
        stages = [public_stage(value) for value in body["stages"]]
        if len({s["work_id"] for s in stages}) != len(stages):
            raise ValueError("evaluator work repeats a stage")
        return dict(evaluator=evaluator, status="current", stages=stages)

    async def sample(self, cohort, evaluators, epochs):
        selected = sorted(set(evaluators))
        if re.fullmatch(r"[0-9a-f]{64}", cohort) is None or len(selected) > 64:
            raise ValueError("evaluator work scope exceeds its bound")

        async def read(evaluator):
            epoch = epochs.get(evaluator)
            if evaluator not in self.peers or epoch is None:
                return dict(evaluator=evaluator, status="epoch_unavailable", stages=[])
            key = (cohort, evaluator)
            old = self.cache.get(key)
            now = time.monotonic()
            if old is not None and old[1] == epoch and now - old[0] < 30:
                result = deepcopy(old[2])
                result["stages"] = [aged_stage(s, now - old[0]) for s in result["stages"]]
                return result
            try:
                result = await observe_http(self._fetch(evaluator, cohort, epoch), timeout=3)
            except (
                httpx.HTTPError,
                OSError,
                ValueError,
                TypeError,
                KeyError,
                asyncio.TimeoutError,
            ):
                result = dict(evaluator=evaluator, status="invalid_or_unavailable", stages=[])
            self.cache[key] = (time.monotonic(), epoch, result)
            self.cache.move_to_end(key)
            while len(self.cache) > 256:
                self.cache.popitem(last=False)
            return deepcopy(result)

        return await asyncio.gather(*(read(e) for e in selected))
