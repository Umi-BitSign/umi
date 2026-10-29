"""Native settlement diagnostics via its existing execution owner and reviewer.

The native producer writes bounded advisory metadata in its execution namespace.
Reviewer background work reads it; private/public GETs copy memory only. Neither
these files nor their transport confer verification, phase or reward authority.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import math
import re
import time
from contextlib import suppress
from copy import deepcopy
from pathlib import Path
from secrets import token_hex
from threading import RLock

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from .competition_cohort_observation import observe_http
from .competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS
from .competition_cohort_review_http import _credential
from .competition_public_results_directory import atomic_write
from .concurrency import run_owned_thread
from .private_files import _read_private_bytes, ensure_private_directory
from .protocol import canonical_json_bytes

SCHEMA = "umi-native-settlement-progress/1"
PATH = "/internal/cohorts/execution-producer/settlement/"
MAX_BYTES = 64 * 1024
PHASES = frozenset(
    (
        "reference_reveal",
        "evidence",
        "review",
        "certification",
        "first_admission",
        "complete",
        "revoked",
    )
)
_KEYS = {
    "phase",
    "stage",
    "state",
    "status",
    "completed",
    "total",
    "percent",
    "elapsed_seconds",
    "eta_seconds",
    "planning_eta_seconds",
    "eta_basis",
    "eta_scope",
    "stalled_or_retrying",
    "unit",
    "reason_code",
    "publication",
    "refresh",
}


def _hex(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("invalid settlement diagnostic identity")
    return value


def checked(body, *, series, cohort, evaluator, role=None):
    """Bound and redact one owner-produced observation, including unknown counts."""
    if type(body) is not dict or body.get("schema") != SCHEMA:
        raise ValueError("invalid settlement diagnostics")
    for key, expected in (
        ("series_sha256", series),
        ("cohort_sha256", cohort),
        ("evaluator", evaluator),
    ):
        if body.get(key) != _hex(expected):
            raise ValueError("settlement diagnostic scope changed")
    if (
        not {
            "phase",
            "stage",
            "state",
            "completed",
            "total",
            "percent",
            "elapsed_seconds",
            "eta_seconds",
            "eta_basis",
        }
        <= body.keys()
    ):
        raise ValueError("incomplete settlement diagnostic scope")
    producer = _hex(body.get("producer_epoch_sha256"))
    if body.get("role") not in {"coordinator", "reviewer"} or (
        role is not None and body["role"] != role
    ):
        raise ValueError("settlement diagnostic role changed")
    observed = body.get("observed_unix_ms")
    if type(observed) is not int or observed < 0 or observed > time.time_ns() // 1_000_000 + 30_000:
        raise ValueError("invalid settlement observation clock")
    result = {key: body[key] for key in _KEYS if key in body}
    if result.get("phase") not in PHASES | {None}:
        raise ValueError("invalid settlement phase")
    for key in ("stage", "state", "status", "unit", "eta_basis", "eta_scope", "reason_code"):
        value = result.get(key)
        if (value is None and key in {"stage", "state", "eta_basis"}) or (
            value is not None
            and (type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,191}", value) is None)
        ):
            raise ValueError("invalid settlement diagnostic label")
    for key in ("completed", "total"):
        value = result.get(key)
        if value is not None and (type(value) is not int or not 0 <= value <= 2**53 - 1):
            raise ValueError("invalid settlement work count")
    if (result.get("completed") is None) != (result.get("total") is None):
        raise ValueError("incomplete settlement count scope")
    if result.get("total") is not None and result["completed"] > result["total"]:
        raise ValueError("settlement work exceeds its scope")
    for key in ("percent", "elapsed_seconds", "eta_seconds"):
        value = result.get(key)
        if value is not None and (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or value < 0
            or (key == "percent" and value > 100)
        ):
            raise ValueError("invalid settlement work measurement")
    if result.get("total") is None and result.get("percent") is not None:
        raise ValueError("settlement percentage has no counted scope")
    planning = result.get("planning_eta_seconds")
    if planning is not None and (
        type(planning) is not list
        or len(planning) != 2
        or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in planning)
        or planning[0] > planning[1]
    ):
        raise ValueError("invalid settlement planning range")
    if type(result.get("stalled_or_retrying", False)) is not bool:
        raise ValueError("invalid settlement retry flag")
    result.update(
        schema=SCHEMA,
        series_sha256=series,
        cohort_sha256=cohort,
        evaluator=evaluator,
        role=body["role"],
        producer_epoch_sha256=producer,
        observed_unix_ms=observed,
        certification_authority=False,
    )
    publication = body.get("publication")
    if publication is not None:
        if (
            type(publication) is not dict
            or set(publication)
            - {
                "state",
                "observed_unix_ms",
                "certification_prefix_sha256",
                "basis",
                "output_current",
                "reason_code",
            }
            or publication.get("state") not in {"completed", "repair_required"}
            or type(publication.get("output_current")) is not bool
        ):
            raise ValueError("invalid native publication diagnostics")
        for key in ("basis", "reason_code"):
            value = publication.get(key)
            if value is not None and (
                type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,191}", value) is None
            ):
                raise ValueError("invalid native publication diagnostic label")
        if "observed_unix_ms" in publication and (
            type(publication["observed_unix_ms"]) is not int
            or not 0 <= publication["observed_unix_ms"] <= observed + 30_000
        ):
            raise ValueError("invalid native publication observation clock")
        if "certification_prefix_sha256" in publication:
            _hex(publication["certification_prefix_sha256"])
        result["publication"] = deepcopy(publication)
    refresh = body.get("refresh")
    if refresh is not None:
        if type(refresh) is not dict or {"publication", "refresh"} & refresh.keys():
            raise ValueError("invalid recursive settlement refresh diagnostics")
        result["refresh"] = checked(
            refresh, series=series, cohort=cohort, evaluator=evaluator, role=role
        )
        if result["refresh"]["producer_epoch_sha256"] != producer:
            raise ValueError("settlement refresh changed its producer epoch")
    return result


def age(body):
    result = deepcopy(body)
    elapsed = max(0, time.time_ns() // 1_000_000 - result["observed_unix_ms"]) / 1000
    result["age_seconds"] = round(elapsed, 3)
    result["stale"] = elapsed > 120
    eta = result.get("eta_seconds")
    if (
        result["stale"]
        or result.get("stalled_or_retrying")
        or (eta is not None and eta > 0 and elapsed >= eta)
    ):
        result.update(
            eta_seconds=None,
            planning_eta_seconds=None,
            eta_basis="stale_settlement_observation"
            if result["stale"]
            else "settlement_estimate_withdrawn",
            stalled_or_retrying=True,
        )
    elif eta is not None and eta > 0:
        result["eta_seconds"] = round(eta - elapsed, 3)
    return result


def _path(root, series, cohort, role):
    return (
        Path(root) / ".settlement-progress" / _hex(series) / (_hex(cohort) + "-" + role + ".json")
    )


class SettlementProgressProducer:
    def __init__(self, roots, *, series, cohort, evaluator, role, publication=None):
        self.roots = tuple(dict.fromkeys(Path(p) for p in roots))
        self.series, self.cohort, self.evaluator, self.role = series, cohort, evaluator, role
        self.epoch = token_hex(32)
        self.lock = RLock()
        self.started = self.stage_started = time.monotonic()
        self.phase = None
        self.stage = "settlement_recovery"
        self.state = "starting"
        self.reason = None
        self.last = None
        self.observation = None
        self.publication = publication
        self.publication_prefix = None
        self.publication_observation = None

    def bind_publication(self, certification_prefix):
        with self.lock:
            self.publication_prefix = _hex(certification_prefix)

    def update(self, stage, *, phase=None, state="running", reason=None):
        with self.lock:
            if stage != self.stage or (phase is not None and phase != self.phase):
                self.stage_started = time.monotonic()
            self.stage, self.state, self.reason = stage, state, reason
            if phase is not None:
                self.phase = phase
            self.last = time.time_ns() // 1_000_000

    def snapshot(self):
        with self.lock:
            body = dict(
                schema=SCHEMA,
                series_sha256=self.series,
                cohort_sha256=self.cohort,
                evaluator=self.evaluator,
                role=self.role,
                producer_epoch_sha256=self.epoch,
                phase=self.phase,
                stage=self.stage,
                state=self.state,
                completed=None,
                total=None,
                percent=None,
                unit="actions",
                elapsed_seconds=round(time.monotonic() - self.stage_started, 3),
                eta_seconds=None,
                eta_basis="awaiting_native_counted_scope",
                eta_scope="current_settlement_stage_only_excludes_chain_reward_activation",
                stalled_or_retrying=self.state == "retrying",
                observed_unix_ms=time.time_ns() // 1_000_000,
            )
            if self.reason is not None:
                body["reason_code"] = self.reason
            stages = PUBLIC_COHORT_PROGRESS.active_work_snapshot(self.cohort)
            eligible = [s for s in stages if s.get("observed_unix_ms", 0) >= (self.last or 0)]
            if eligible and self.state not in {"retrying", "held", "completed"}:
                work = eligible[-1]
                body.update({k: work[k] for k in _KEYS if k in work and k != "phase"})
                body["stalled_or_retrying"] = bool(
                    work.get("stalled") or work.get("stalled_or_retrying")
                )
            if self.state == "completed" and self.stage == "settlement_package_published":
                body.update(
                    completed=1,
                    total=1,
                    percent=100,
                    eta_seconds=0,
                    eta_basis="native_package_publication_completed",
                )
            if self.state == "retrying":
                body.update(
                    eta_seconds=None,
                    planning_eta_seconds=None,
                    eta_basis="retry_requires_new_native_progress_sample",
                )
            publication = self.publication_observation
            if publication is not None:
                body["publication"] = deepcopy(publication)
                if self.phase in {"first_admission", "complete"}:
                    body["refresh"] = {k: v for k, v in body.items() if k != "publication"}
                    body.update(stage="settlement_package_published", unit="publications")
                    if publication["state"] == "completed":
                        body.pop("reason_code", None)
                        body.pop("status", None)
                        body.update(
                            state="completed",
                            elapsed_seconds=None,
                            stalled_or_retrying=False,
                            planning_eta_seconds=None,
                            completed=1,
                            total=1,
                            percent=100,
                            eta_seconds=0,
                            eta_basis="native_package_publication_completed",
                        )
                    else:
                        body.update(
                            state="repair_required",
                            completed=None,
                            total=None,
                            percent=None,
                            eta_seconds=None,
                            eta_basis="native_publication_repair_required",
                            stalled_or_retrying=True,
                            reason_code=publication["reason_code"],
                        )
        return checked(
            body, series=self.series, cohort=self.cohort, evaluator=self.evaluator, role=self.role
        )

    def publish(self):
        # This runs in the existing owned background publisher, never on GET.
        if self.publication is not None and self.publication_prefix is not None:
            observed = self.publication.observe(self.publication_prefix)
            with self.lock:
                self.publication_observation = observed
        body = self.snapshot()
        raw = canonical_json_bytes(body)
        if len(raw) > MAX_BYTES:
            raise ValueError("settlement diagnostic exceeds byte bound")
        for root in self.roots:
            path = _path(root, self.series, self.cohort, self.role)
            ensure_private_directory(path.parent)
            atomic_write(path, raw, immutable=False)
        self.observation = body


class SettlementProgressRelay:
    def __init__(self, root, *, series, evaluator, cohorts):
        self.root, self.series, self.evaluator = root, series, evaluator
        self.cohorts = tuple(cohorts)
        self.lock = RLock()
        self.cache = {}

    def sample(self):
        current = {}
        for cohort in self.cohorts:
            snapshots = []
            for role in ("coordinator", "reviewer"):
                try:
                    raw = _read_private_bytes(
                        _path(self.root, self.series, cohort, role), maximum_bytes=MAX_BYTES
                    )
                    body = checked(
                        json.loads(raw),
                        series=self.series,
                        cohort=cohort,
                        evaluator=self.evaluator,
                        role=role,
                    )
                except (OSError, ValueError, TypeError):
                    continue
                snapshots.append(body)
            current[cohort] = snapshots
        with self.lock:
            self.cache = current

    def snapshot(self, cohort):
        with self.lock:
            return deepcopy(self.cache.get(cohort, []))

    async def run(self, stop, **unused):
        while not stop.is_set():
            with suppress(Exception):
                await run_owned_thread(self.sample)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=5)


def settlement_progress_routes(*, evaluator, epoch, token, cohorts, relay):
    expected = ("Bearer " + _credential(token)).encode()
    router = APIRouter()
    known = frozenset(cohorts)

    @router.get(PATH + "{cohort}")
    async def current(cohort: str, request: Request):
        if not hmac.compare_digest(request.headers.get("authorization", "").encode(), expected):
            raise HTTPException(401, "reviewer authentication required")
        if cohort not in known or relay is None:
            raise HTTPException(404, "settlement diagnostics unavailable")
        body = dict(
            schema="umi-settlement-work/1",
            evaluator=evaluator,
            reviewer_epoch_sha256=epoch,
            series_sha256=relay.series,
            cohort_sha256=cohort,
            snapshots=relay.snapshot(cohort),
        )
        return Response(canonical_json_bytes(body), media_type="application/json")

    return router


class SettlementProgressObservations:
    def __init__(self, client, peers, capacity):
        self.client, self.peers, self.capacity = client, peers, capacity

    async def sample(self, cohort, epochs, *, series):
        async def fetch(evaluator, epoch):
            origin, token = self.peers[evaluator]
            async with (
                self.capacity,
                self.client.stream(
                    "GET",
                    origin.rstrip("/") + PATH + cohort,
                    headers={"authorization": "Bearer " + token, "accept-encoding": "identity"},
                    timeout=2,
                ) as response,
            ):
                if response.status_code != 200:
                    return []
                raw = bytearray()
                async for part in response.aiter_bytes(chunk_size=MAX_BYTES + 1):
                    raw.extend(part)
                    if len(raw) > MAX_BYTES:
                        raise ValueError("settlement diagnostics exceed byte bound")
            body = json.loads(raw)
            if (
                type(body) is not dict
                or body.get("schema") != "umi-settlement-work/1"
                or body.get("evaluator") != evaluator
                or body.get("reviewer_epoch_sha256") != epoch
                or body.get("series_sha256") != series
                or body.get("cohort_sha256") != cohort
                or type(body.get("snapshots")) is not list
                or len(body["snapshots"]) > 2
            ):
                raise ValueError("settlement transport binding changed")
            result = [
                checked(value, series=series, cohort=cohort, evaluator=evaluator)
                for value in body["snapshots"]
            ]
            if len({s["role"] for s in result}) != len(result):
                raise ValueError("settlement diagnostics repeat a role")
            return result

        async def read(evaluator, epoch):
            try:
                return await observe_http(fetch(evaluator, epoch), timeout=3)
            except (
                httpx.HTTPError,
                OSError,
                ValueError,
                TypeError,
                KeyError,
                asyncio.TimeoutError,
            ):
                return []

        if len(epochs) > 64:
            raise ValueError("settlement producer inventory exceeds bound")
        groups = await asyncio.gather(
            *(read(e, epoch) for e, epoch in epochs.items() if e in self.peers)
        )
        snapshots = [s for group in groups for s in group]
        # A coordinator's current phase takes precedence. Never sum role-local
        # counts or reinterpret reviewer completion as certified settlement.
        fresh = [s for s in snapshots if not age(s)["stale"] and s.get("phase") in PHASES]
        selected = next((s for s in fresh if s["role"] == "coordinator"), None)
        selected = selected or next(iter(fresh), None)
        if selected is not None:
            return selected
        previous = next(iter(snapshots), None)
        return dict(
            cohort_sha256=cohort,
            phase=None if previous is None else previous.get("phase"),
            stage="settlement_diagnostics_unavailable",
            state="waiting",
            completed=None,
            total=None,
            percent=None,
            eta_seconds=None,
            eta_basis="awaiting_current_settlement_producer",
            stalled_or_retrying=True,
            observed_unix_ms=time.time_ns() // 1_000_000
            if previous is None
            else previous["observed_unix_ms"],
        )
