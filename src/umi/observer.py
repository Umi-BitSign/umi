"""Read-only public observer API for finalized SN78 state.

HTTP handlers only read an atomically published cache. Chain collection happens
in the application lifespan and never in response to a public request.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import math
import os
import re
import time
from collections.abc import Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .encoding import account_id32
from .observer_bootstrap_service_feed import (
    BOOTSTRAP_SERVICE_MECHANISM,
    ObserverBootstrapServiceFeed,
    VerifiedBootstrapServicePublication,
    VerifiedSimpleBootstrapConfiguration,
    build_observer_bootstrap_service_feed,
)
from .observer_bundle_feed import (
    BundleFeedSnapshot,
    ObserverBundleFeed,
    VerifiedEvidenceObject,
    VerifiedFeedWindow,
    VerifiedMinerSolution,
    build_production_observer_bundle_feed,
)
from .observer_chain import BittensorChainCollector, ChainCollectionError, ChainCollector
from .observer_directive_feed import (
    ObserverDirectiveFeed,
    ObserverDirectiveFeedError,
    VerifiedDirectivePage,
    build_observer_directive_feed,
)
from .observer_models import (
    OBSERVER_API_VERSION,
    PROTOCOL_VERSION,
    SN78_NETUID,
    SPECIFICATION_VERSION,
    UMI_MECHANISM_ID,
    ActivationGate,
    ActivationGatesResponse,
    BenchmarksResponse,
    BootstrapServiceChainReceiptRecord,
    BootstrapServiceChainValidator,
    BootstrapServiceEconomicEffect,
    BootstrapServiceEvidenceLocator,
    BootstrapServiceMiner,
    BootstrapServiceRecord,
    BootstrapServiceResponse,
    BundleFeedHealthRecord,
    ChainEconomicLeaderboard,
    ChainEconomicLeaderboardEntry,
    ComponentPilotRecord,
    CursorPage,
    ErrorDetail,
    ErrorResponse,
    EvidenceCursorPage,
    EvidenceObjectLink,
    FinalizedBlock,
    IncidentRecord,
    IncidentsResponse,
    LeaderboardResponse,
    MinerSolutionRecord,
    NetworkResponse,
    ObserverModel,
    ObserverSnapshot,
    ParticipantsResponse,
    PilotBundleLocator,
    PilotResponse,
    PilotSolutionEvidenceLinks,
    PilotSolutionRecord,
    PilotSolutionsResponse,
    PilotsResponse,
    ProtocolState,
    PublicEndpointPilotChainEvidence,
    PublicEndpointPilotEvidence,
    PublicEndpointPilotTransportEvidence,
    ReleasedBundleLocator,
    ReleasedWindow,
    SolutionEvidenceLinks,
    SourceProvenance,
    StatusResponse,
    UmiTranslationLeaderboard,
    ValidatorLocalScoreRecord,
    WindowResponse,
    WindowSolutionsResponse,
    WindowsResponse,
)
from .observer_pilot_feed import (
    ObserverPilotFeed,
    VerifiedComponentPilot,
    VerifiedPilotSolution,
    build_observer_pilot_feed,
)
from .protocol import canonical_json_bytes

_WINDOW_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
_LOGGER = logging.getLogger(__name__)
_STATIC_PROTOCOL_FACTS = {
    "activation_evidence_available": False,
    "api_version": OBSERVER_API_VERSION,
    "chain_result_classification": "unverified",
    "conformance_evidence_available": False,
    "economic_era": "unverified",
    "expected_chain_name": "UMI",
    "mechanism_id": UMI_MECHANISM_ID,
    "netuid": SN78_NETUID,
    "phase": "pre_public_calibration",
    "protocol": PROTOCOL_VERSION,
    "scoring_policy_hash": None,
    "specification_version": SPECIFICATION_VERSION,
    "service_weight_evidence_sha256": None,
    "service_weight_kind": None,
    "service_weights_active": False,
    "service_weights_economically_effective": False,
    "section_14_gate_credit": False,
    "translation_weights_active": False,
    "validator_input_eligible": False,
}
_STATIC_CONTRACT_REVISION = hashlib.sha256(
    json.dumps(
        _STATIC_PROTOCOL_FACTS,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()
_STATIC_SOURCE = SourceProvenance(
    source_id=f"umi-observer-contract-{_STATIC_CONTRACT_REVISION[:16]}",
    source_kind="dashboard_static",
    verification_status="repository_static",
    block=None,
    artifact_sha256=_STATIC_CONTRACT_REVISION,
)

_COMMON_ERROR_RESPONSES = {
    422: {"model": ErrorResponse, "description": "Invalid bounded request"},
    503: {"model": ErrorResponse, "description": "No acceptably recent snapshot"},
}
_CURSOR_ERROR_RESPONSES = {
    **_COMMON_ERROR_RESPONSES,
    409: {"model": ErrorResponse, "description": "Cursor belongs to another snapshot"},
}
_WINDOW_ERROR_RESPONSES = {
    **_COMMON_ERROR_RESPONSES,
    404: {"model": ErrorResponse, "description": "Released window or solution evidence not found"},
    409: {"model": ErrorResponse, "description": "Validator selection required"},
}
_PILOT_ERROR_RESPONSES = {
    **_COMMON_ERROR_RESPONSES,
    404: {"model": ErrorResponse, "description": "Verified component pilot not found"},
}
_BOOTSTRAP_ERROR_RESPONSES = {
    **_COMMON_ERROR_RESPONSES,
    404: {"model": ErrorResponse, "description": "Verified bootstrap publication not found"},
}

_ACTIVATION_GATE_IDS = (
    "chain_interface_and_runtime",
    "copy_proof_response_envelopes",
    "legacy_weight_cutover",
    "independent_validators",
    "independent_miners",
    "independent_publishers",
    "metric_validity",
    "canary_validation",
    "positive_miner_utility",
    "challenge_supply",
    "validator_economics",
    "thirty_day_shadow_soak",
    "adversarial_drills",
)
_OUTSTANDING_GAP_CODES = tuple(
    sorted(
        (
            "activation_gates_not_passed",
            "active_scoring_policy_unavailable",
            "public_calibration_not_started",
            "released_audit_bundle_feed_unavailable",
            "umi_weight_cutover_unverified",
        )
    )
)


class ObserverUnavailable(RuntimeError):
    """Raised when there is no acceptably recent complete snapshot."""


class PublicAPIError(RuntimeError):
    """A bounded error safe to return from a public endpoint."""

    def __init__(self, status_code: int, reason_code: str) -> None:
        super().__init__(reason_code)
        self.status_code = status_code
        self.reason_code = reason_code


@dataclass(frozen=True)
class SnapshotView:
    snapshot: ObserverSnapshot
    freshness: Literal["fresh", "stale"]
    age_seconds: int
    finalized_head_age_seconds: int
    remaining_stale_seconds: int


class SnapshotCache:
    """Single-flight, atomic last-good cache for one finalized observation."""

    def __init__(
        self,
        collector: ChainCollector,
        *,
        fresh_for_seconds: float = 24.0,
        maximum_stale_seconds: float = 120.0,
        refresh_interval_seconds: float = 12.0,
        refresh_timeout_seconds: float = 45.0,
        maximum_finalized_head_age_seconds: float = 120.0,
        maximum_future_block_skew_seconds: float = 30.0,
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        for name, value in (
            ("fresh_for_seconds", fresh_for_seconds),
            ("maximum_stale_seconds", maximum_stale_seconds),
            ("refresh_interval_seconds", refresh_interval_seconds),
            ("refresh_timeout_seconds", refresh_timeout_seconds),
            ("maximum_finalized_head_age_seconds", maximum_finalized_head_age_seconds),
        ):
            if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number")
        if maximum_stale_seconds < fresh_for_seconds:
            raise ValueError("maximum_stale_seconds must be at least fresh_for_seconds")
        if refresh_interval_seconds > 60:
            raise ValueError("refresh_interval_seconds must not exceed 60 seconds")
        if (
            isinstance(maximum_future_block_skew_seconds, bool)
            or not math.isfinite(maximum_future_block_skew_seconds)
            or maximum_future_block_skew_seconds < 0
        ):
            raise ValueError("maximum_future_block_skew_seconds must be finite and non-negative")
        self._collector = collector
        self._fresh_for_seconds = float(fresh_for_seconds)
        self._maximum_stale_seconds = float(maximum_stale_seconds)
        self._refresh_interval_seconds = float(refresh_interval_seconds)
        self._refresh_timeout_seconds = float(refresh_timeout_seconds)
        self._maximum_finalized_head_age_seconds = float(maximum_finalized_head_age_seconds)
        self._maximum_future_block_skew_seconds = float(maximum_future_block_skew_seconds)
        self._monotonic = monotonic
        self._clock = clock
        self._snapshot: ObserverSnapshot | None = None
        self._published_at_monotonic: float | None = None
        self._last_refresh_failed = False
        self._refresh_lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def refresh(self) -> bool:
        """Collect and atomically publish a complete snapshot."""

        if self._refresh_lock.locked():
            async with self._refresh_lock:
                return not self._last_refresh_failed
        async with self._refresh_lock:
            try:
                candidate = await asyncio.wait_for(
                    self._collector.collect(),
                    timeout=self._refresh_timeout_seconds,
                )
                if not isinstance(candidate, ObserverSnapshot):
                    raise ChainCollectionError("invalid_collector_snapshot")
                self._validate_head_age(candidate)
                self._validate_progression(candidate)
                if (
                    self._snapshot is not None
                    and _finalized_block(candidate).hash == _finalized_block(self._snapshot).hash
                ):
                    # A successful RPC response is not proof that finality advanced.
                    # Keep the original publication time so a stalled finalized head
                    # eventually fails closed.
                    self._last_refresh_failed = False
                    return True
            except Exception as error:
                self._last_refresh_failed = True
                reason_code = (
                    error.reason_code
                    if isinstance(error, ChainCollectionError)
                    else "snapshot_refresh_failed"
                )
                last_block = (
                    _finalized_block(self._snapshot).number
                    if self._snapshot is not None
                    else "none"
                )
                _LOGGER.warning(
                    "observer_refresh_failed reason_code=%s last_finalized_block=%s",
                    reason_code,
                    last_block,
                )
                return False
            self._snapshot = candidate
            self._published_at_monotonic = self._monotonic()
            self._last_refresh_failed = False
            _LOGGER.info(
                "observer_snapshot_published finalized_block=%s",
                _finalized_block(candidate).number,
            )
            return True

    def _head_age_seconds(self, snapshot: ObserverSnapshot) -> float:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ChainCollectionError("invalid_observer_clock")
        now_utc = now.astimezone(timezone.utc)
        age = (now_utc - _finalized_block(snapshot).timestamp).total_seconds()
        if age < -self._maximum_future_block_skew_seconds:
            raise ChainCollectionError("finalized_head_timestamp_in_future")
        return max(0.0, age)

    def _validate_head_age(self, snapshot: ObserverSnapshot) -> None:
        if self._head_age_seconds(snapshot) > self._maximum_finalized_head_age_seconds:
            raise ChainCollectionError("finalized_head_too_old")

    def _validate_progression(self, candidate: ObserverSnapshot) -> None:
        if self._snapshot is None:
            return
        previous = _finalized_block(self._snapshot)
        current = _finalized_block(candidate)
        previous_number = int(previous.number)
        current_number = int(current.number)
        if current_number < previous_number:
            raise ChainCollectionError("finalized_height_regressed")
        if current_number == previous_number and current.hash != previous.hash:
            raise ChainCollectionError("finalized_block_conflict")
        if current_number == previous_number + 1 and current.parent_hash != previous.hash:
            raise ChainCollectionError("finalized_parent_conflict")

    def current(self) -> SnapshotView:
        snapshot = self._snapshot
        published = self._published_at_monotonic
        if snapshot is None or published is None:
            raise ObserverUnavailable("snapshot_unavailable")
        elapsed = max(0.0, self._monotonic() - published)
        try:
            finalized_head_age = self._head_age_seconds(snapshot)
        except ChainCollectionError as error:
            raise ObserverUnavailable("snapshot_head_time_invalid") from error
        if (
            elapsed > self._maximum_stale_seconds
            or finalized_head_age > self._maximum_finalized_head_age_seconds
        ):
            raise ObserverUnavailable("snapshot_too_stale")
        stale = self._last_refresh_failed or elapsed > self._fresh_for_seconds
        return SnapshotView(
            snapshot=snapshot,
            freshness="stale" if stale else "fresh",
            age_seconds=int(elapsed),
            finalized_head_age_seconds=int(finalized_head_age),
            remaining_stale_seconds=max(
                0,
                min(
                    math.floor(self._maximum_stale_seconds - elapsed),
                    math.floor(self._maximum_finalized_head_age_seconds - finalized_head_age),
                ),
            ),
        )

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        await self.refresh()
        self._task = asyncio.create_task(self._run(), name="umi-observer-refresh")

    async def close(self) -> None:
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(
                    self._stop.wait(),
                    timeout=self._refresh_interval_seconds,
                )
            except asyncio.TimeoutError:
                await self.refresh()


class ParticipantsQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["all", "miner", "validator"] = "all"
    limit: int = Field(default=100, ge=1, le=512)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)


class EvidenceQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: int = Field(default=100, ge=1, le=256)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)


class SolutionQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validator: str | None = Field(default=None, pattern=_WINDOW_ID_RE.pattern)
    limit: int = Field(default=25, ge=1, le=50)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)


class PilotSolutionQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: int = Field(default=14, ge=1, le=14)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)


def _finalized_block(snapshot: ObserverSnapshot) -> FinalizedBlock:
    blocks = [
        source.block
        for source in snapshot.sources
        if source.source_kind == "chain_finalized" and source.block is not None
    ]
    if len(blocks) != 1:
        raise ValueError("snapshot does not have one finalized block")
    return blocks[0]


def _sources(snapshot: ObserverSnapshot) -> tuple[SourceProvenance, ...]:
    if any(source.source_id == _STATIC_SOURCE.source_id for source in snapshot.sources):
        return snapshot.sources
    return (*snapshot.sources, _STATIC_SOURCE)


@dataclass(frozen=True)
class BootstrapServiceSelection:
    publication: VerifiedBootstrapServicePublication | VerifiedSimpleBootstrapConfiguration | None
    reason_code: str
    validator_uids: tuple[int, ...] = ()
    warning_codes: tuple[str, ...] = ()


def _select_simple_bootstrap_service(
    snapshot: ObserverSnapshot,
    configuration: VerifiedSimpleBootstrapConfiguration,
) -> BootstrapServiceSelection:
    """Recognize the common lease's exact row from one finalized snapshot."""

    network = snapshot.network
    body = configuration.signed_lease.body
    block = int(_finalized_block(snapshot).number)
    if not body.valid_from_block <= block < body.hard_sunset_block:
        return BootstrapServiceSelection(None, "bootstrap_service_lease_inactive")
    if network.runtime_spec_version != str(body.required_runtime_spec_version):
        return BootstrapServiceSelection(None, "bootstrap_service_runtime_spec_mismatch")
    if network.mechanism_count != body.required_mechanism_count:
        return BootstrapServiceSelection(None, "bootstrap_service_mechanism_count_mismatch")
    if (
        network.counts.registered != body.required_max_allowed_uids
        or network.counts.maximum_uids != body.required_max_allowed_uids
    ):
        return BootstrapServiceSelection(None, "bootstrap_service_uid_domain_mismatch")
    if network.hyperparameters.weights_version_key != str(body.weights_version_key):
        return BootstrapServiceSelection(None, "bootstrap_service_weights_version_mismatch")
    if network.hyperparameters.min_allowed_weights != body.required_min_allowed_weights:
        return BootstrapServiceSelection(None, "bootstrap_service_minimum_weights_mismatch")
    if network.commit_reveal_enabled is not body.required_commit_reveal_enabled:
        return BootstrapServiceSelection(None, "bootstrap_service_commit_reveal_mismatch")
    if network.commit_reveal_version != str(body.required_commit_reveal_version):
        return BootstrapServiceSelection(None, "bootstrap_service_commit_reveal_version_mismatch")
    if network.reveal_period_epochs != str(body.required_reveal_period_epochs):
        return BootstrapServiceSelection(None, "bootstrap_service_reveal_period_mismatch")
    if network.epoch.tempo_blocks != str(body.required_tempo):
        return BootstrapServiceSelection(None, "bootstrap_service_tempo_mismatch")
    if network.hyperparameters.activity_cutoff_blocks != str(body.required_activity_cutoff_blocks):
        return BootstrapServiceSelection(None, "bootstrap_service_activity_cutoff_changed")
    if network.hyperparameters.weights_rate_limit_blocks != str(
        body.required_weights_set_rate_limit
    ):
        return BootstrapServiceSelection(None, "bootstrap_service_weights_rate_limit_changed")
    if network.pending_weight_commit_count != 0:
        return BootstrapServiceSelection(None, "bootstrap_service_pending_commit_queue_not_empty")
    if network.subnet_exists is not True or network.subnet_started is not True:
        return BootstrapServiceSelection(None, "bootstrap_service_subnet_not_started")

    participants_by_uid = {item.uid: item for item in snapshot.participants}
    owner = participants_by_uid.get(0)
    if owner is None or account_id32(owner.hotkey) != bytes.fromhex(
        network.subnet_owner_hotkey_account_id32[2:]
    ):
        return BootstrapServiceSelection(None, "bootstrap_service_subnet_owner_mapping_changed")
    for entry in configuration.signed_manifest.manifest.entries:
        participant = participants_by_uid.get(entry.uid)
        if (
            participant is None
            or account_id32(participant.hotkey) != account_id32(entry.miner_hotkey)
            or participant.validator_permit
            or not participant.serving_announced
        ):
            return BootstrapServiceSelection(
                None,
                "bootstrap_service_eligible_miner_mapping_changed",
            )
        if participant.serving_origin != entry.origin:
            return BootstrapServiceSelection(
                None,
                "bootstrap_service_eligible_miner_origin_changed",
            )

    expected_row = configuration.expected_row
    rows_by_validator = {
        item.validator_uid: item.weights for item in network.validator_mechid0_rows
    }
    exact: list[int] = []
    mismatched: list[int] = []
    cutoff = body.required_activity_cutoff_blocks
    for participant in snapshot.participants:
        if not participant.validator_permit:
            continue
        row = rows_by_validator.get(participant.uid, ())
        fresh = int(participant.last_update_block) + cutoff >= block
        if participant.chain_active and fresh and row == expected_row:
            exact.append(participant.uid)
        elif row and (participant.chain_active or fresh):
            mismatched.append(participant.uid)
    if not exact:
        return BootstrapServiceSelection(None, "bootstrap_service_exact_active_row_unavailable")
    warnings = tuple(
        f"bootstrap_service_mismatched_active_row_uid_{uid}" for uid in sorted(mismatched)
    )
    return BootstrapServiceSelection(
        configuration,
        "bootstrap_service_active",
        validator_uids=tuple(sorted(exact)),
        warning_codes=warnings,
    )


def _select_bootstrap_service(
    snapshot: ObserverSnapshot,
    feed: ObserverBootstrapServiceFeed | None,
) -> BootstrapServiceSelection:
    """Match one verified publication against current finalized chain state."""

    if (feed is None or not feed.publications) and (feed is None or feed.simple_bootstrap is None):
        return BootstrapServiceSelection(None, "bootstrap_service_evidence_unavailable")
    if feed.simple_bootstrap is not None:
        return _select_simple_bootstrap_service(snapshot, feed.simple_bootstrap)
    network = snapshot.network
    block = int(_finalized_block(snapshot).number)
    if network.runtime_spec_version != "455":
        return BootstrapServiceSelection(None, "bootstrap_service_runtime_spec_mismatch")
    if network.mechanism_count != 1:
        return BootstrapServiceSelection(None, "bootstrap_service_mechanism_count_mismatch")
    if network.counts.registered != 256 or network.counts.maximum_uids != 256:
        return BootstrapServiceSelection(None, "bootstrap_service_uid_domain_mismatch")
    if network.hyperparameters.weights_version_key != str(1 << 32):
        return BootstrapServiceSelection(None, "bootstrap_service_weights_version_mismatch")
    if network.hyperparameters.min_allowed_weights != 256:
        return BootstrapServiceSelection(None, "bootstrap_service_minimum_weights_mismatch")
    if network.commit_reveal_enabled is not False:
        return BootstrapServiceSelection(None, "bootstrap_service_commit_reveal_not_disabled")
    if network.pending_weight_commit_count != 0:
        return BootstrapServiceSelection(None, "bootstrap_service_pending_commit_queue_not_empty")
    if network.subnet_exists is not True or network.subnet_started is not True:
        return BootstrapServiceSelection(None, "bootstrap_service_subnet_not_started")
    participants_by_uid = {item.uid: item for item in snapshot.participants}
    call_matches = [
        item
        for item in feed.publications
        if (
            (validator := participants_by_uid.get(item.receipt.validator_uid)) is not None
            and validator.validator_permit
            and validator.chain_active
            and item.receipt.weight_call.block_number == int(validator.last_update_block)
            and account_id32(item.receipt.validator_hotkey) == account_id32(validator.hotkey)
            and item.receipt.validator_uid == item.authorization.validator_uid
            and account_id32(item.receipt.validator_hotkey)
            == account_id32(item.authorization.validator_hotkey)
        )
    ]
    if len(call_matches) != 1:
        return BootstrapServiceSelection(None, "bootstrap_service_validator_row_unmatched")
    publication = call_matches[0]
    validator = participants_by_uid[publication.receipt.validator_uid]
    expected_owner = (
        publication.call_material.operational_preflight.chain.subnet_owner_hotkey_account_id32
    )
    if network.subnet_owner_hotkey_account_id32 != expected_owner:
        return BootstrapServiceSelection(None, "bootstrap_service_subnet_owner_mapping_changed")
    if block < publication.receipt.observation_block:
        return BootstrapServiceSelection(None, "bootstrap_service_receipt_not_finalized_at_head")
    if block > publication.manifest.active_through_block:
        return BootstrapServiceSelection(None, "bootstrap_service_row_inactive")
    expected_cutoff = (
        publication.call_material.operational_preflight.chain.snapshot.activity_cutoff_blocks
    )
    if network.hyperparameters.activity_cutoff_blocks != str(expected_cutoff):
        return BootstrapServiceSelection(None, "bootstrap_service_activity_cutoff_changed")
    competing_validators = [
        item
        for item in snapshot.participants
        if item.uid != validator.uid
        and item.validator_permit
        and (item.chain_active or int(item.last_update_block) + expected_cutoff >= block)
    ]
    for entry in publication.signed_manifest.manifest.entries:
        participant = participants_by_uid.get(entry.uid)
        if (
            participant is None
            or account_id32(participant.hotkey) != account_id32(entry.miner_hotkey)
            or participant.validator_permit
            or not participant.serving_announced
            or int(participant.registration_block) > publication.receipt.weight_call.block_number
        ):
            return BootstrapServiceSelection(
                None,
                "bootstrap_service_eligible_miner_mapping_changed",
            )
        if participant.serving_origin != entry.origin:
            return BootstrapServiceSelection(
                None,
                "bootstrap_service_eligible_miner_origin_changed",
            )
    expected_row = tuple(tuple(item) for item in publication.receipt.expected_applied_row)
    rows_by_validator = {
        item.validator_uid: item.weights for item in network.validator_mechid0_rows
    }
    if rows_by_validator.get(validator.uid) != expected_row:
        return BootstrapServiceSelection(None, "bootstrap_service_applied_row_mismatch")
    warning_codes = tuple(
        f"bootstrap_service_other_active_validator_uid_{item.uid}"
        for item in sorted(competing_validators, key=lambda candidate: candidate.uid)
    )
    return BootstrapServiceSelection(
        publication,
        "bootstrap_service_active",
        validator_uids=(validator.uid,),
        warning_codes=warning_codes,
    )


def _bootstrap_service_economic_effect(
    snapshot: ObserverSnapshot,
    selection: BootstrapServiceSelection,
) -> BootstrapServiceEconomicEffect:
    """Conservatively classify the authorized row's observed economic effect."""

    publication = selection.publication
    if publication is None:
        return BootstrapServiceEconomicEffect(
            economically_effective=False,
            reason_codes=("bootstrap_service_inactive",),
            mismatched_active_validator_uids=(),
            zero_consensus_eligible_miner_uids=(),
            unavailable_consensus_eligible_miner_uids=(),
            zero_incentive_eligible_miner_uids=(),
            unavailable_incentive_eligible_miner_uids=(),
        )

    if isinstance(publication, VerifiedSimpleBootstrapConfiguration):
        expected_row = publication.expected_row
        activity_cutoff = publication.signed_lease.body.required_activity_cutoff_blocks
    else:
        expected_row = tuple(tuple(item) for item in publication.receipt.expected_applied_row)
        activity_cutoff = (
            publication.call_material.operational_preflight.chain.snapshot.activity_cutoff_blocks
        )

    block = int(_finalized_block(snapshot).number)
    rows_by_validator = {
        item.validator_uid: item.weights for item in snapshot.network.validator_mechid0_rows
    }
    mismatched = tuple(
        sorted(
            participant.uid
            for participant in snapshot.participants
            if participant.validator_permit
            and (
                participant.chain_active
                or int(participant.last_update_block) + activity_cutoff >= block
            )
            and (row := rows_by_validator.get(participant.uid, ()))
            and row != expected_row
        )
    )

    participants_by_uid = {item.uid: item for item in snapshot.participants}
    zero_consensus: list[int] = []
    unavailable_consensus: list[int] = []
    zero_incentive: list[int] = []
    unavailable_incentive: list[int] = []
    for entry in publication.signed_manifest.manifest.entries:
        participant = participants_by_uid.get(entry.uid)
        consensus = None if participant is None else participant.chain_metrics.consensus
        incentive = None if participant is None else participant.chain_metrics.incentive
        if consensus is None:
            unavailable_consensus.append(entry.uid)
        elif int(consensus.raw_numerator) == 0:
            zero_consensus.append(entry.uid)
        if incentive is None:
            unavailable_incentive.append(entry.uid)
        elif int(incentive.raw_numerator) == 0:
            zero_incentive.append(entry.uid)

    reasons: set[str] = set()
    if mismatched:
        reasons.add("bootstrap_service_mismatched_active_row_present")
    if zero_consensus:
        reasons.add("bootstrap_service_eligible_miner_consensus_zero")
    if unavailable_consensus:
        reasons.add("bootstrap_service_eligible_miner_consensus_unavailable")
    if zero_incentive:
        reasons.add("bootstrap_service_eligible_miner_incentive_zero")
    if unavailable_incentive:
        reasons.add("bootstrap_service_eligible_miner_incentive_unavailable")
    return BootstrapServiceEconomicEffect(
        economically_effective=not reasons,
        reason_codes=tuple(sorted(reasons)),
        mismatched_active_validator_uids=mismatched,
        zero_consensus_eligible_miner_uids=tuple(sorted(zero_consensus)),
        unavailable_consensus_eligible_miner_uids=tuple(sorted(unavailable_consensus)),
        zero_incentive_eligible_miner_uids=tuple(sorted(zero_incentive)),
        unavailable_incentive_eligible_miner_uids=tuple(sorted(unavailable_incentive)),
    )


def _protocol_state(
    snapshot: ObserverSnapshot,
    released_windows: Sequence[VerifiedFeedWindow] = (),
    bootstrap_publication: (
        VerifiedBootstrapServicePublication | VerifiedSimpleBootstrapConfiguration | None
    ) = None,
    *,
    service_weights_economically_effective: bool = False,
) -> ProtocolState:
    network = snapshot.network
    observed_names = tuple(
        value.casefold() for value in (network.name, network.identity) if value is not None
    )
    identity_matches = "umi" in observed_names if observed_names else None
    public_solution_windows = _public_solution_windows(released_windows)
    policy_hashes = {item.scoring_policy_hash for item in public_solution_windows}
    has_released = bool(public_solution_windows)
    return ProtocolState(
        protocol=_STATIC_PROTOCOL_FACTS["protocol"],
        specification_version=_STATIC_PROTOCOL_FACTS["specification_version"],
        phase="shadow_calibration" if has_released else _STATIC_PROTOCOL_FACTS["phase"],
        netuid=_STATIC_PROTOCOL_FACTS["netuid"],
        mechanism_id=_STATIC_PROTOCOL_FACTS["mechanism_id"],
        translation_weights_active=_STATIC_PROTOCOL_FACTS["translation_weights_active"],
        service_weights_active=bootstrap_publication is not None,
        service_weights_economically_effective=service_weights_economically_effective,
        service_weight_kind=(
            BOOTSTRAP_SERVICE_MECHANISM if bootstrap_publication is not None else None
        ),
        service_weight_evidence_sha256=(
            None if bootstrap_publication is None else bootstrap_publication.publication_id
        ),
        section_14_gate_credit=False,
        scoring_policy_hash=next(iter(policy_hashes)) if len(policy_hashes) == 1 else None,
        conformance_evidence_available=has_released,
        activation_evidence_available=_STATIC_PROTOCOL_FACTS["activation_evidence_available"],
        economic_era=(
            "legacy_bootstrap"
            if bootstrap_publication is not None
            else _STATIC_PROTOCOL_FACTS["economic_era"]
        ),
        chain_result_classification=(
            "legacy_or_bootstrap"
            if bootstrap_publication is not None
            else _STATIC_PROTOCOL_FACTS["chain_result_classification"]
        ),
        expected_chain_name=_STATIC_PROTOCOL_FACTS["expected_chain_name"],
        chain_identity_matches_expected=identity_matches,
        validator_input_eligible=_STATIC_PROTOCOL_FACTS["validator_input_eligible"],
    )


def _public_solution_windows(
    released_windows: Sequence[VerifiedFeedWindow],
) -> tuple[VerifiedFeedWindow, ...]:
    """Return replayed releases that actually carry complete reveal solutions."""

    return tuple(item for item in released_windows if _has_public_solution_evidence(item))


def _has_public_solution_evidence(item: VerifiedFeedWindow) -> bool:
    return (
        item.reveal_stage_manifest is not None
        and item.reveal_result is not None
        and (item.solution_count if item.solution_count is not None else len(item.solutions)) > 0
    )


def _envelope(view: SnapshotView) -> dict[str, Any]:
    return {
        "generated_at": view.snapshot.collected_at,
        "freshness": view.freshness,
        "snapshot_age_seconds": view.age_seconds,
        "finalized_head_age_seconds": view.finalized_head_age_seconds,
        "sources": _sources(view.snapshot),
    }


def _encode_cursor(*, block_hash: str, role: str, offset: int) -> str:
    raw = json.dumps(
        {"block_hash": block_hash, "offset": offset, "role": role},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str, *, block_hash: str, role: str) -> int:
    if _CURSOR_RE.fullmatch(cursor) is None:
        raise PublicAPIError(422, "invalid_cursor")
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
        value = json.loads(raw)
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise PublicAPIError(422, "invalid_cursor") from error
    if not isinstance(value, dict) or set(value) != {"block_hash", "offset", "role"}:
        raise PublicAPIError(422, "invalid_cursor")
    if value["block_hash"] != block_hash:
        raise PublicAPIError(409, "cursor_snapshot_changed")
    if value["role"] != role:
        raise PublicAPIError(422, "cursor_role_mismatch")
    offset = value["offset"]
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise PublicAPIError(422, "invalid_cursor")
    return offset


def _feed_revision(windows: Sequence[VerifiedFeedWindow], kind: str) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "kind": kind,
                "manifests": [item.manifest_sha256 for item in windows],
                "validators": [item.validator_account_id32 for item in windows],
            }
        )
    ).hexdigest()


def _encode_evidence_cursor(*, revision: str, kind: str, offset: int) -> str:
    raw = canonical_json_bytes({"kind": kind, "offset": offset, "revision": revision})
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_evidence_cursor(cursor: str, *, revision: str, kind: str) -> int:
    if _CURSOR_RE.fullmatch(cursor) is None:
        raise PublicAPIError(422, "invalid_cursor")
    try:
        padding = "=" * (-len(cursor) % 4)
        value = json.loads(base64.b64decode(cursor + padding, altchars=b"-_", validate=True))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise PublicAPIError(422, "invalid_cursor") from error
    if not isinstance(value, dict) or set(value) != {"kind", "offset", "revision"}:
        raise PublicAPIError(422, "invalid_cursor")
    if value["kind"] != kind:
        raise PublicAPIError(422, "cursor_feed_mismatch")
    if value["revision"] != revision:
        raise PublicAPIError(409, "cursor_snapshot_changed")
    offset = value["offset"]
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise PublicAPIError(422, "invalid_cursor")
    return offset


def _validate_cors_origins(origins: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            origin == "*"
            or parsed.scheme != "https"
            or not parsed.hostname
            or not parsed.hostname.isascii()
            or not origin.isascii()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or "*" in origin
        ):
            raise ValueError("CORS origins must be exact HTTPS origins")
        canonical = f"https://{parsed.netloc}"
        if origin.rstrip("/") != canonical:
            raise ValueError("CORS origins must use their canonical HTTPS form")
        if canonical not in result:
            result.append(canonical)
    return tuple(result)


def _validate_trusted_hosts(hosts: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    for host in hosts:
        if (
            not host
            or host == "*"
            or "*" in host
            or "://" in host
            or "/" in host
            or "@" in host
            or any(character.isspace() for character in host)
        ):
            raise ValueError("trusted hosts must be exact host names")
        if host not in result:
            result.append(host)
    if not result:
        raise ValueError("at least one trusted host is required")
    return tuple(result)


def _if_none_match_matches(value: str | None, etag: str) -> bool:
    if value is None:
        return False
    for candidate in value.split(","):
        candidate = candidate.strip()
        if candidate == "*":
            return True
        if candidate.startswith("W/"):
            candidate = candidate[2:].strip()
        if candidate == etag:
            return True
    return False


def _cache_control(view: SnapshotView) -> str:
    if view.freshness == "stale":
        return "public, max-age=0, must-revalidate"
    max_age = min(5, view.remaining_stale_seconds)
    stale_if_error = max(0, view.remaining_stale_seconds - max_age)
    directives = [f"public, max-age={max_age}"]
    if stale_if_error:
        directives.append(f"stale-if-error={stale_if_error}")
    directives.append("must-revalidate")
    return ", ".join(directives)


def _render(request: Request, model: ObserverModel, view: SnapshotView) -> Response:
    body = model.model_dump_json(by_alias=True).encode("utf-8")
    etag = '"' + hashlib.sha256(body).hexdigest() + '"'
    block = _finalized_block(view.snapshot)
    released_artifacts = sorted(
        source.artifact_sha256
        for source in model.sources
        if source.source_kind
        in {
            "released_audit_bundle",
            "component_pilot_bundle",
            "bootstrap_service_bundle",
        }
        and source.artifact_sha256 is not None
    )
    dataset_revision = (
        block.hash
        if not released_artifacts
        else hashlib.sha256(
            canonical_json_bytes(
                {"finalized_block_hash": block.hash, "released_artifacts": released_artifacts}
            )
        ).hexdigest()
    )
    headers = {
        "Cache-Control": _cache_control(view),
        "ETag": etag,
        "X-UMI-Dataset-Revision": dataset_revision,
        "X-UMI-Contract-Revision": _STATIC_CONTRACT_REVISION,
        "X-UMI-Finalized-Block": block.number,
    }
    if _if_none_match_matches(request.headers.get("if-none-match"), etag):
        return Response(status_code=304, headers=headers)
    if request.method == "HEAD":
        headers["Content-Length"] = str(len(body))
        return Response(status_code=200, headers=headers, media_type="application/json")
    return Response(content=body, status_code=200, headers=headers, media_type="application/json")


def _render_immutable_bytes(
    request: Request,
    data: bytes,
    *,
    media_type: str,
    sha256: str,
    bundle_sha256: str,
    bundle_header: str = "X-UMI-Pilot-Bundle",
) -> Response:
    """Serve one startup-verified content-addressed evidence object."""

    if hashlib.sha256(data).hexdigest() != sha256:
        raise RuntimeError("immutable evidence object no longer matches its digest")
    etag = f'"{sha256}"'
    headers = {
        "Cache-Control": "public, max-age=31536000, immutable",
        "Content-Length": str(len(data)),
        "ETag": etag,
        bundle_header: bundle_sha256,
    }
    if _if_none_match_matches(request.headers.get("if-none-match"), etag):
        return Response(status_code=304, headers=headers)
    if request.method == "HEAD":
        return Response(status_code=200, headers=headers, media_type=media_type)
    return Response(content=data, status_code=200, headers=headers, media_type=media_type)


def _error(status_code: int, reason_code: str) -> JSONResponse:
    body = ErrorResponse(error=ErrorDetail(reason_code=reason_code))
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json", by_alias=True),
        headers={"Cache-Control": "no-store"},
    )


def create_observer_app(
    cache: SnapshotCache,
    *,
    bundle_feed: ObserverBundleFeed | None = None,
    pilot_feed: ObserverPilotFeed | None = None,
    bootstrap_service_feed: ObserverBootstrapServiceFeed | None = None,
    directive_feed: ObserverDirectiveFeed | None = None,
    directive_feed_read_concurrency: int = 4,
    directive_feed_read_timeout_seconds: float = 5.0,
    directive_feed_readiness_timeout_seconds: float = 30.0,
    bundle_feed_poll_seconds: float = 15,
    cors_origins: Sequence[str] = (),
    trusted_hosts: Sequence[str] = ("127.0.0.1", "localhost", "testserver"),
) -> FastAPI:
    """Build an API whose request handlers have no outbound network path."""

    if bootstrap_service_feed is not None and pilot_feed is None:
        raise ValueError("bootstrap service feed requires the verified pilot feed")
    if (
        isinstance(directive_feed_read_concurrency, bool)
        or not isinstance(directive_feed_read_concurrency, int)
        or not 1 <= directive_feed_read_concurrency <= 16
    ):
        raise ValueError("directive feed read concurrency must be from 1 through 16")
    for value, label in (
        (directive_feed_read_timeout_seconds, "directive feed read timeout"),
        (directive_feed_readiness_timeout_seconds, "directive feed readiness timeout"),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 < value <= 300
        ):
            raise ValueError(f"{label} must be finite and in (0, 300]")
    allowed_origins = _validate_cors_origins(cors_origins)
    allowed_hosts = _validate_trusted_hosts(trusted_hosts)

    def build_directive_read_slots(count: int) -> asyncio.Queue[None]:
        slots: asyncio.Queue[None] = asyncio.Queue(maxsize=count)
        for _ in range(count):
            slots.put_nowait(None)
        return slots

    directive_public_read_slots = build_directive_read_slots(directive_feed_read_concurrency)
    directive_readiness_slots = build_directive_read_slots(1)

    async def run_directive_read(
        operation: Callable[[], Any],
        *,
        slots: asyncio.Queue[None],
        timeout_seconds: float,
    ) -> Any:
        try:
            slots.get_nowait()
        except asyncio.QueueEmpty as error:
            raise ObserverDirectiveFeedError("directive_feed_read_saturated") from error
        try:
            task = asyncio.create_task(asyncio.to_thread(operation))
        except Exception:
            slots.put_nowait(None)
            raise

        def release_slot(completed: asyncio.Task[Any]) -> None:
            if completed.cancelled():
                pass
            else:
                completed.exception()
            try:
                slots.put_nowait(None)
            except asyncio.QueueFull:
                _LOGGER.error("observer_directive_read_gate_overrelease")

        task.add_done_callback(release_slot)
        try:
            return await asyncio.wait_for(
                asyncio.shield(task),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            # The worker thread cannot be cancelled safely. Its slot remains held
            # until the task actually exits and the callback above returns it.
            raise ObserverDirectiveFeedError("directive_feed_read_timeout") from error

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await cache.start()
        if bundle_feed is not None:
            await bundle_feed.start(
                lambda: int(_finalized_block(cache.current().snapshot).number),
                bundle_feed_poll_seconds,
            )
        try:
            yield
        finally:
            if bundle_feed is not None:
                await bundle_feed.close()
            await cache.close()

    app = FastAPI(
        title="UMI SN78 observer API",
        version=OBSERVER_API_VERSION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts))
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(allowed_origins),
            allow_credentials=False,
            allow_methods=["GET", "HEAD", "OPTIONS"],
            allow_headers=["Accept", "If-None-Match"],
            expose_headers=[
                "ETag",
                "X-UMI-Contract-Revision",
                "X-UMI-Dataset-Revision",
                "X-UMI-Finalized-Block",
                "X-UMI-Pilot-Bundle",
                "X-UMI-Bootstrap-Bundle",
            ],
            max_age=600,
        )

    @app.middleware("http")
    async def response_security_headers(request: Request, call_next: Callable[..., Any]):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=2592000"
        return response

    @app.exception_handler(ObserverUnavailable)
    async def unavailable_handler(_: Request, __: ObserverUnavailable) -> JSONResponse:
        return _error(503, "snapshot_unavailable")

    @app.exception_handler(PublicAPIError)
    async def public_error_handler(_: Request, error: PublicAPIError) -> JSONResponse:
        return _error(error.status_code, error.reason_code)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, error: RequestValidationError) -> JSONResponse:
        locations = {tuple(item.get("loc", ())) for item in error.errors()}
        if ("path", "window_id") in locations:
            reason_code = "invalid_window_id"
        elif ("path", "pilot_id") in locations:
            reason_code = "invalid_pilot_id"
        elif ("path", "publication_id") in locations:
            reason_code = "invalid_bootstrap_publication_id"
        elif ("path", "object_sha256") in locations:
            reason_code = "invalid_object_sha256"
        else:
            reason_code = "invalid_request"
        return _error(422, reason_code)

    def directive_page_response(request: Request, page: VerifiedDirectivePage) -> Response:
        headers = {
            "Cache-Control": "no-cache, no-store, must-revalidate, no-transform",
            "Content-Encoding": "identity",
            "Content-Length": str(len(page.data)),
            "ETag": f'"{page.sha256}"',
            "X-UMI-Directive-Head": page.head_directive_sha256,
            "X-UMI-Directive-Page-SHA256": page.sha256,
            "X-UMI-Directive-Sequence": str(page.head_sequence),
        }
        if request.method == "HEAD":
            return Response(status_code=200, headers=headers, media_type="application/json")
        return Response(
            content=page.data,
            status_code=200,
            headers=headers,
            media_type="application/json",
        )

    def current() -> SnapshotView:
        return cache.current()

    def bootstrap_selection(view: SnapshotView) -> BootstrapServiceSelection:
        return _select_bootstrap_service(view.snapshot, bootstrap_service_feed)

    def current_protocol_state(
        view: SnapshotView,
        feed: BundleFeedSnapshot,
    ) -> ProtocolState:
        selection = bootstrap_selection(view)
        return _protocol_state(
            view.snapshot,
            feed.windows,
            selection.publication,
            service_weights_economically_effective=_bootstrap_service_economic_effect(
                view.snapshot,
                selection,
            ).economically_effective,
        )

    def released(view: SnapshotView) -> BundleFeedSnapshot:
        if bundle_feed is None:
            return BundleFeedSnapshot((), ())
        finalized_height = int(_finalized_block(view.snapshot).number)
        snapshot = bundle_feed.snapshot()
        return BundleFeedSnapshot(
            tuple(
                item for item in snapshot.windows if item.audit_release_block <= finalized_height
            ),
            snapshot.health,
        )

    def released_sources(
        view: SnapshotView, feed: BundleFeedSnapshot
    ) -> tuple[SourceProvenance, ...]:
        values = list(_sources(view.snapshot))
        active_bootstrap = bootstrap_selection(view).publication
        if active_bootstrap is not None:
            values.append(
                SourceProvenance(
                    source_id=f"bootstrap-service-{active_bootstrap.publication_id}",
                    source_kind="bootstrap_service_bundle",
                    verification_status="bootstrap_current_state_verified",
                    block=None,
                    policy_hash=active_bootstrap.manifest.policy_sha256,
                    artifact_sha256=active_bootstrap.publication_id,
                )
            )
        for item in feed.windows:
            values.append(
                SourceProvenance(
                    source_id=f"released-{item.validator_account_id32}-{item.manifest_sha256}",
                    source_kind="released_audit_bundle",
                    verification_status="bundle_verified",
                    block=None,
                    policy_hash=item.scoring_policy_hash,
                    artifact_sha256=item.manifest_sha256,
                )
            )
        return tuple(values)

    def released_envelope(
        view: SnapshotView,
        feed: BundleFeedSnapshot,
        selected: Sequence[VerifiedFeedWindow] = (),
    ) -> dict[str, Any]:
        representatives: dict[str, VerifiedFeedWindow] = {}
        for item in feed.windows:
            prior = representatives.get(item.scoring_policy_hash)
            item_key = (
                _has_public_solution_evidence(item),
                item.window_index,
                item.validator_account_id32,
            )
            prior_key = (
                (
                    False,
                    -1,
                    "",
                )
                if prior is None
                else (
                    _has_public_solution_evidence(prior),
                    prior.window_index,
                    prior.validator_account_id32,
                )
            )
            if prior is None or item_key > prior_key:
                representatives[item.scoring_policy_hash] = item
        merged = {item.manifest_sha256: item for item in (*selected, *representatives.values())}
        source_feed = BundleFeedSnapshot(
            tuple(sorted(merged.values(), key=lambda item: item.manifest_sha256)),
            feed.health,
        )
        return _envelope(view) | {"sources": released_sources(view, source_feed)}

    def evidence_link(
        item: VerifiedFeedWindow,
        reference: VerifiedEvidenceObject | None,
    ) -> EvidenceObjectLink | None:
        if reference is None:
            return None
        return EvidenceObjectLink(
            sha256=reference.sha256,
            media_type=reference.media_type,
            size_bytes=reference.size_bytes,
            url=(f"{item.public_origin}/{item.bundle_relative_path}/objects/{reference.sha256}"),
        )

    def bundle_locator(item: VerifiedFeedWindow) -> ReleasedBundleLocator:
        return ReleasedBundleLocator(
            public_origin=item.public_origin,
            index_url=(f"{item.public_origin}/validators/{item.validator_account_id32}/index.json"),
            relative_path=item.bundle_relative_path,
            manifest_url=f"{item.public_origin}/{item.bundle_relative_path}/manifest.json",
            manifest_sha256=item.manifest_sha256,
            tree_sha256=item.tree_sha256,
            reveal_stage_manifest=evidence_link(item, item.reveal_stage_manifest),
            reveal_result=evidence_link(item, item.reveal_result),
        )

    def released_window(item: VerifiedFeedWindow) -> ReleasedWindow:
        return ReleasedWindow(
            window_id=item.window_id,
            window_index=str(item.window_index),
            terminal_classification=item.terminal_classification,
            audit_release_block=str(item.audit_release_block),
            audit_release_block_hash=item.audit_release_block_hash,
            audit_bundle_sha256=item.manifest_sha256,
            evidence=bundle_locator(item),
            validator_account_id32=item.validator_account_id32,
            scoring_policy_hash=item.scoring_policy_hash,
            reason_codes=item.reason_codes,
            score_scope="validator_local",
            validator_local_scores=tuple(
                ValidatorLocalScoreRecord(
                    miner_root_account_id32=score.miner_root_account_id32,
                    assigned_clips=score.assigned_clips,
                    accuracy={
                        "numerator": str(score.accuracy_numerator),
                        "denominator": str(score.accuracy_denominator),
                    },
                    eligible=score.eligible,
                    utility={
                        "numerator": str(score.utility_numerator),
                        "denominator": str(score.utility_denominator),
                    },
                )
                for score in item.scores
            ),
        )

    def released_solution(
        item: VerifiedFeedWindow,
        solution: VerifiedMinerSolution,
    ) -> MinerSolutionRecord:
        evidence = solution.evidence

        def required(reference: VerifiedEvidenceObject) -> EvidenceObjectLink:
            link = evidence_link(item, reference)
            if link is None:
                raise ValueError("required solution evidence locator is absent")
            return link

        return MinerSolutionRecord(
            assignment_id=solution.assignment_id,
            request_leaf=solution.request_leaf,
            batch_id=solution.batch_id,
            challenge_id=solution.challenge_id,
            miner_hotkey=solution.miner_hotkey,
            miner_root_account_id32=solution.miner_root_account_id32,
            stratum=solution.stratum,
            metric=solution.metric,
            canary=solution.canary,
            outer_disposition=solution.outer_disposition,
            zero_score_reason=solution.zero_score_reason,
            response_plaintext_valid=solution.response_plaintext_valid,
            response_status=solution.response_status,
            hypothesis=solution.hypothesis,
            response_error_code=solution.response_error_code,
            model_revision=solution.model_revision,
            references=solution.references,
            canary_actual_references=solution.canary_actual_references,
            score=(
                None
                if solution.score_numerator is None
                else {
                    "numerator": str(solution.score_numerator),
                    "denominator": str(solution.score_denominator),
                }
            ),
            score_trace=solution.score_trace,
            canary_result=solution.canary_result,
            evidence=SolutionEvidenceLinks(
                prepared_attempt=required(evidence.prepared_attempt),
                request=required(evidence.request),
                attempt_outcome=required(evidence.attempt_outcome),
                retained_response=evidence_link(item, evidence.retained_response),
                response_plaintext=evidence_link(item, evidence.response_plaintext),
                response_decryption=required(evidence.response_decryption),
                ground_truth_plaintext=evidence_link(item, evidence.ground_truth_plaintext),
                ground_truth_decryption=evidence_link(item, evidence.ground_truth_decryption),
            ),
        )

    def released_health(feed: BundleFeedSnapshot) -> tuple[BundleFeedHealthRecord, ...]:
        return tuple(
            BundleFeedHealthRecord(
                validator_account_id32=item.validator_account_id32,
                status=item.status,
                last_error_code=item.last_error_code,
                last_checked_unix=(
                    None if item.last_checked_unix is None else str(item.last_checked_unix)
                ),
                accepted_entries=item.accepted_entries,
            )
            for item in feed.health
        )

    def configured_pilots() -> tuple[VerifiedComponentPilot, ...]:
        return () if pilot_feed is None else pilot_feed.pilots

    def pilot_envelope(
        view: SnapshotView,
        selected: Sequence[VerifiedComponentPilot],
    ) -> dict[str, Any]:
        sources = list(_sources(view.snapshot))
        active_bootstrap = bootstrap_selection(view).publication
        if active_bootstrap is not None:
            sources.append(
                SourceProvenance(
                    source_id=f"bootstrap-service-{active_bootstrap.publication_id}",
                    source_kind="bootstrap_service_bundle",
                    verification_status="bootstrap_current_state_verified",
                    block=None,
                    policy_hash=active_bootstrap.manifest.policy_sha256,
                    artifact_sha256=active_bootstrap.publication_id,
                )
            )
        sources.extend(
            SourceProvenance(
                source_id=f"component-pilot-{pilot.pilot_id}",
                source_kind="component_pilot_bundle",
                verification_status="component_replay_verified",
                block=None,
                policy_hash=None,
                artifact_sha256=pilot.manifest_sha256,
            )
            for pilot in selected
        )
        return _envelope(view) | {"sources": tuple(sources)}

    def pilot_object_link(
        pilot: VerifiedComponentPilot,
        digest: str,
    ) -> EvidenceObjectLink:
        evidence_object = pilot.objects.get(digest)
        if evidence_object is None:
            raise ValueError("verified pilot projection names an absent object")
        return EvidenceObjectLink(
            sha256=evidence_object.sha256,
            media_type=evidence_object.media_type,
            size_bytes=evidence_object.size_bytes,
            url=(
                f"{pilot.public_origin}/api/v1/pilots/{pilot.pilot_id}"
                f"/bundle/objects/{evidence_object.sha256}"
            ),
        )

    def pilot_record(pilot: VerifiedComponentPilot) -> ComponentPilotRecord:
        public_endpoint_evidence = None
        if pilot.public_endpoint is not None:
            verified = pilot.public_endpoint
            attestation = verified.attestation
            chain = attestation.chain_observation
            public_endpoint_evidence = PublicEndpointPilotEvidence(
                campaign_id=attestation.campaign_id,
                coordinator_hotkey=attestation.coordinator_hotkey,
                coordinator_signature_verified=True,
                chain=PublicEndpointPilotChainEvidence(
                    observation_class=chain.observation_class,
                    network=chain.network,
                    genesis_block_hash=chain.genesis_block_hash,
                    block_number=str(chain.block_number),
                    block_hash=chain.block_hash,
                    block_timestamp_unix_ms=str(chain.block_timestamp_unix_ms),
                    storage_proofs_verified=False,
                    expected_miner_uid=attestation.expected_miner_uid,
                    miner_hotkey=attestation.miner_hotkey,
                    validator_permit=False,
                ),
                transport=PublicEndpointPilotTransportEvidence(
                    announced_origin=attestation.announced_origin,
                    contacted_origin=attestation.contacted_origin,
                    coordinator_attested_origin_match=True,
                    request_digest=attestation.request_digest,
                    known_public_challenge=True,
                    public_miner_transport_used=True,
                    attempt_count=1,
                    outcome_classification=attestation.outcome_classification,
                    failure_code=attestation.failure_code,
                    miner_signed_envelope_verified=(attestation.miner_signed_envelope_verified),
                    miner_signed_plaintext_verified=(attestation.miner_signed_plaintext_verified),
                    response_receipt_time_is_coordinator_assertion=True,
                    attempt_completeness_is_coordinator_assertion=True,
                ),
                attestation=pilot_object_link(pilot, verified.attestation_ref.sha256),
                signature=pilot_object_link(pilot, verified.signature_ref.sha256),
            )
        return ComponentPilotRecord(
            pilot_id=pilot.pilot_id,
            pilot_profile=(
                "local_in_process" if pilot.public_endpoint is None else "public_endpoint"
            ),
            evidence_class="component_test_no_weight",
            terminal_code="component_test_no_weight",
            translation_weights_active=False,
            protocol_conformance=False,
            activation_evidence=False,
            deterministic_replay_verified=True,
            bundle_manifest_sha256=pilot.manifest_sha256,
            bundle_bytes=pilot.bundle_bytes,
            object_count=len(pilot.objects),
            solution_count=len(pilot.solutions),
            validator_hotkey=pilot.validator_hotkey,
            miner_hotkey=pilot.miner_hotkey,
            missing_canonical_stages=pilot.missing_stages,
            public_endpoint_evidence=public_endpoint_evidence,
            evidence=PilotBundleLocator(
                public_origin=pilot.public_origin,
                manifest_sha256=pilot.manifest_sha256,
                manifest_url=(
                    f"{pilot.public_origin}/api/v1/pilots/{pilot.pilot_id}/bundle/manifest.json"
                ),
                replay_command=(
                    "umi-validator replay --bundle ./bundle"
                    if pilot.public_endpoint is None
                    else "umi-public-pilot replay --bundle ./bundle"
                ),
            ),
        )

    def pilot_solution(
        pilot: VerifiedComponentPilot,
        solution: VerifiedPilotSolution,
    ) -> PilotSolutionRecord:
        return PilotSolutionRecord(
            batch_id=solution.batch_id,
            challenge_id=solution.challenge_id,
            validator_hotkey=solution.validator_hotkey,
            miner_hotkey=solution.miner_hotkey,
            video_sha256=solution.video_sha256,
            stratum=solution.stratum,
            metric=solution.metric,
            response_plaintext_valid=solution.response_plaintext_valid,
            response_status=solution.response_status,
            hypothesis=solution.hypothesis,
            response_error_code=solution.response_error_code,
            model_revision=solution.model_revision,
            references=solution.references,
            failure_code=solution.failure_code,
            score={
                "numerator": str(solution.score_numerator),
                "denominator": str(solution.score_denominator),
            },
            score_trace=solution.score_trace,
            evidence=PilotSolutionEvidenceLinks(
                request=pilot_object_link(pilot, solution.request_sha256),
                authentication_record=pilot_object_link(
                    pilot, solution.authentication_record_sha256
                ),
                response_envelope=(
                    None
                    if solution.response_envelope_sha256 is None
                    else pilot_object_link(pilot, solution.response_envelope_sha256)
                ),
                response_signature=(
                    None
                    if solution.response_signature_sha256 is None
                    else pilot_object_link(pilot, solution.response_signature_sha256)
                ),
                response_plaintext=(
                    None
                    if solution.response_plaintext_sha256 is None
                    else pilot_object_link(pilot, solution.response_plaintext_sha256)
                ),
                ground_truth_envelope=pilot_object_link(
                    pilot, solution.ground_truth_envelope_sha256
                ),
                ground_truth_plaintext=pilot_object_link(
                    pilot, solution.ground_truth_plaintext_sha256
                ),
                scoring=pilot_object_link(pilot, solution.scoring_sha256),
            ),
        )

    def configured_bootstrap_publications() -> tuple[
        VerifiedBootstrapServicePublication | VerifiedSimpleBootstrapConfiguration,
        ...,
    ]:
        return () if bootstrap_service_feed is None else bootstrap_service_feed.evidence_items()

    def bootstrap_locator(
        publication: VerifiedBootstrapServicePublication | VerifiedSimpleBootstrapConfiguration,
    ) -> BootstrapServiceEvidenceLocator:
        return BootstrapServiceEvidenceLocator(
            publication_id=publication.publication_id,
            public_origin=publication.public_origin,
            manifest_sha256=publication.publication_id,
            manifest_url=(
                f"{publication.public_origin}/api/v1/bootstrap-service/"
                f"{publication.publication_id}/bundle/manifest.json"
            ),
            expected_row_sha256=publication.manifest.expected_row_sha256,
        )

    def bootstrap_miners(
        publication: VerifiedBootstrapServicePublication | VerifiedSimpleBootstrapConfiguration,
    ) -> tuple[BootstrapServiceMiner, ...]:
        entries = sorted(
            publication.signed_manifest.manifest.entries,
            key=lambda item: item.uid,
        )
        return tuple(
            BootstrapServiceMiner(
                uid=entry.uid,
                miner_hotkey=entry.miner_hotkey,
                origin=entry.origin,
                pilot_id=entry.pilot_id,
                pilot_url=f"{publication.public_origin}/api/v1/pilots/{entry.pilot_id}",
                solutions_url=(
                    f"{publication.public_origin}/api/v1/pilots/{entry.pilot_id}/solutions"
                ),
            )
            for entry in entries
        )

    def bootstrap_record(
        view: SnapshotView,
        selection: BootstrapServiceSelection,
    ) -> BootstrapServiceRecord | BootstrapServiceChainReceiptRecord:
        publication = selection.publication
        if publication is None:  # pragma: no cover - caller invariant
            raise ValueError("inactive bootstrap selection has no record")
        if isinstance(publication, VerifiedSimpleBootstrapConfiguration):
            block = _finalized_block(view.snapshot)
            by_uid = {item.uid: item for item in view.snapshot.participants}
            cutoff = publication.signed_lease.body.required_activity_cutoff_blocks
            validators = tuple(
                BootstrapServiceChainValidator(
                    uid=uid,
                    hotkey=by_uid[uid].hotkey,
                    last_update_block=by_uid[uid].last_update_block,
                    active_through_block=str(
                        min(
                            int(by_uid[uid].last_update_block) + cutoff,
                            publication.signed_lease.body.hard_sunset_block - 1,
                        )
                    ),
                )
                for uid in selection.validator_uids
            )
            return BootstrapServiceChainReceiptRecord(
                evidence_class="finalized_chain_state",
                mechanism=BOOTSTRAP_SERVICE_MECHANISM,
                translation_weights_active=False,
                section_14_gate_credit=False,
                storage_proofs_verified=False,
                subnet_emission_enabled=view.snapshot.network.subnet_emission_enabled,
                policy_sha256=publication.manifest.policy_sha256,
                eligibility_manifest_sha256=(publication.manifest.eligibility_manifest_sha256),
                umi_git_revision=publication.manifest.umi_git_revision,
                observation_block=block.number,
                observation_block_hash=block.hash,
                hard_sunset_block=str(publication.manifest.hard_sunset_block),
                exact_validator_rows=validators,
                eligible_miners=bootstrap_miners(publication),
                evidence=bootstrap_locator(publication),
            )
        return BootstrapServiceRecord(
            mechanism=BOOTSTRAP_SERVICE_MECHANISM,
            translation_weights_active=False,
            section_14_gate_credit=False,
            storage_proofs_verified=False,
            policy_sha256=publication.manifest.policy_sha256,
            eligibility_manifest_sha256=publication.manifest.eligibility_manifest_sha256,
            submission_id=publication.manifest.submission_id,
            umi_git_revision=publication.manifest.umi_git_revision,
            validator_uid=publication.receipt.validator_uid,
            validator_hotkey=publication.receipt.validator_hotkey,
            weight_call_block=str(publication.receipt.weight_call.block_number),
            weight_call_block_hash=publication.receipt.weight_call.block_hash,
            observation_block=str(publication.receipt.observation_block),
            observation_block_hash=publication.receipt.observation_block_hash,
            active_through_block=str(publication.manifest.active_through_block),
            hard_sunset_block=str(publication.manifest.hard_sunset_block),
            eligible_miners=bootstrap_miners(publication),
            evidence=bootstrap_locator(publication),
        )

    def bootstrap_envelope(
        view: SnapshotView,
        publication: (
            VerifiedBootstrapServicePublication | VerifiedSimpleBootstrapConfiguration | None
        ),
    ) -> dict[str, Any]:
        sources = list(_sources(view.snapshot))
        if publication is not None:
            sources.append(
                SourceProvenance(
                    source_id=f"bootstrap-service-{publication.publication_id}",
                    source_kind="bootstrap_service_bundle",
                    verification_status="bootstrap_current_state_verified",
                    block=None,
                    policy_hash=publication.manifest.policy_sha256,
                    artifact_sha256=publication.publication_id,
                )
            )
        return _envelope(view) | {"sources": tuple(sources)}

    @app.get("/healthz", include_in_schema=False)
    async def health() -> JSONResponse:
        return JSONResponse(
            status_code=200,
            content={"status": "ok"},
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/readyz", include_in_schema=False)
    async def ready() -> JSONResponse:
        try:
            view = current()
        except ObserverUnavailable:
            return _error(503, "snapshot_unavailable")
        if directive_feed is not None:
            try:
                await run_directive_read(
                    directive_feed.verify_readiness,
                    slots=directive_readiness_slots,
                    timeout_seconds=directive_feed_readiness_timeout_seconds,
                )
            except ObserverDirectiveFeedError:
                _LOGGER.warning("observer_directive_readiness_rejected")
                return _error(503, "validator_directive_feed_unavailable")
        return JSONResponse(
            status_code=200,
            content={"status": view.freshness},
            headers={"Cache-Control": "no-store"},
        )

    @app.head(
        "/api/v1/validator-directives/{validator_account_id32}/after/"
        "{after_sequence}/{cursor}.json",
        include_in_schema=False,
    )
    @app.get(
        "/api/v1/validator-directives/{validator_account_id32}/after/"
        "{after_sequence}/{cursor}.json",
        responses={
            **_COMMON_ERROR_RESPONSES,
            404: {"model": ErrorResponse, "description": "Validator directive page not found"},
        },
    )
    async def validator_directive_page(
        request: Request,
        validator_account_id32: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")],
        after_sequence: Annotated[int, Path(ge=0, le=(1 << 53) - 1)],
        cursor: Annotated[str, Path(pattern=r"^(?:initial|[0-9a-f]{64})$")],
    ) -> Response:
        if request.url.query:
            raise PublicAPIError(422, "validator_directive_query_not_allowed")
        if (after_sequence == 0) != (cursor == "initial"):
            raise PublicAPIError(422, "validator_directive_cursor_invalid")
        if directive_feed is None:
            raise PublicAPIError(404, "validator_directive_not_found")
        try:
            page = await run_directive_read(
                lambda: directive_feed.read_page(
                    validator_account_id32,
                    after_sequence=after_sequence,
                    cursor=cursor,
                ),
                slots=directive_public_read_slots,
                timeout_seconds=directive_feed_read_timeout_seconds,
            )
        except ObserverDirectiveFeedError:
            _LOGGER.warning(
                "observer_directive_page_rejected validator_account_id32=%s after_sequence=%s",
                validator_account_id32,
                after_sequence,
            )
            raise PublicAPIError(503, "validator_directive_page_unavailable") from None
        if page is None:
            raise PublicAPIError(404, "validator_directive_not_found")
        return directive_page_response(request, page)

    @app.head("/api/v1/status", include_in_schema=False)
    @app.get(
        "/api/v1/status",
        response_model=StatusResponse,
        responses={503: _COMMON_ERROR_RESPONSES[503]},
    )
    async def status(request: Request) -> Response:
        view = current()
        feed = released(view)
        protocol_state = current_protocol_state(view, feed)
        feed_unhealthy = any(item.status in {"degraded", "stale"} for item in feed.health)
        public_solution_windows = _public_solution_windows(feed.windows)
        gaps = set(_OUTSTANDING_GAP_CODES)
        if feed.windows:
            gaps.discard("released_audit_bundle_feed_unavailable")
        if public_solution_windows:
            gaps.discard("public_calibration_not_started")
        if len({item.scoring_policy_hash for item in public_solution_windows}) == 1:
            gaps.discard("active_scoring_policy_unavailable")
        if protocol_state.service_weights_economically_effective:
            gaps.discard("umi_weight_cutover_unverified")
        response = StatusResponse(
            **released_envelope(view, feed),
            service_status=(
                "ready" if view.freshness == "fresh" and not feed_unhealthy else "degraded"
            ),
            protocol_state=protocol_state,
            finalized_block=_finalized_block(view.snapshot),
            outstanding_gap_codes=tuple(sorted(gaps)),
        )
        return _render(request, response, view)

    @app.head("/api/v1/network", include_in_schema=False)
    @app.get(
        "/api/v1/network",
        response_model=NetworkResponse,
        responses={503: _COMMON_ERROR_RESPONSES[503]},
    )
    async def network(request: Request) -> Response:
        view = current()
        feed = released(view)
        response = NetworkResponse(
            **released_envelope(view, feed),
            protocol_state=current_protocol_state(view, feed),
            network=view.snapshot.network,
        )
        return _render(request, response, view)

    @app.head("/api/v1/participants", include_in_schema=False)
    @app.get(
        "/api/v1/participants",
        response_model=ParticipantsResponse,
        responses=_CURSOR_ERROR_RESPONSES,
    )
    async def participants(
        request: Request,
        query: Annotated[ParticipantsQuery, Query()],
    ) -> Response:
        view = current()
        feed = released(view)
        block = _finalized_block(view.snapshot)
        offset = (
            _decode_cursor(query.cursor, block_hash=block.hash, role=query.role)
            if query.cursor is not None
            else 0
        )
        eligible = tuple(
            participant
            for participant in view.snapshot.participants
            if query.role == "all" or participant.role == query.role
        )
        if offset > len(eligible):
            raise PublicAPIError(422, "invalid_cursor")
        selected = eligible[offset : offset + query.limit]
        next_offset = offset + len(selected)
        next_cursor = (
            _encode_cursor(block_hash=block.hash, role=query.role, offset=next_offset)
            if next_offset < len(eligible)
            else None
        )
        response = ParticipantsResponse(
            **released_envelope(view, feed),
            protocol_state=current_protocol_state(view, feed),
            page=CursorPage(
                role=query.role,
                limit=query.limit,
                total=len(eligible),
                returned=len(selected),
                next_cursor=next_cursor,
            ),
            participants=selected,
        )
        return _render(request, response, view)

    @app.head("/api/v1/leaderboard", include_in_schema=False)
    @app.get(
        "/api/v1/leaderboard",
        response_model=LeaderboardResponse,
        responses={503: _COMMON_ERROR_RESPONSES[503]},
    )
    async def leaderboard(request: Request) -> Response:
        view = current()
        feed = released(view)
        public_solution_windows = _public_solution_windows(feed.windows)
        miners = tuple(
            participant for participant in view.snapshot.participants if participant.role == "miner"
        )
        rankable = sorted(
            (
                participant
                for participant in miners
                if participant.chain_metrics.incentive is not None
            ),
            key=lambda participant: (
                -int(participant.chain_metrics.incentive.raw_numerator),
                participant.uid,
            ),
        )
        chain_source_ids = tuple(
            sorted(
                source.source_id
                for source in view.snapshot.sources
                if source.source_kind == "chain_finalized"
            )
        )
        raw_counts: dict[str, int] = {}
        first_positions: dict[str, int] = {}
        for position, participant in enumerate(rankable, start=1):
            incentive = participant.chain_metrics.incentive
            if incentive is None:
                raise ValueError("rankable participant has no native incentive")
            raw = incentive.raw_numerator
            raw_counts[raw] = raw_counts.get(raw, 0) + 1
            first_positions.setdefault(raw, position)
        if not rankable:
            ranking_status = "unavailable"
            ranking_reason = "native_incentive_unavailable"
        elif len(raw_counts) == 1:
            ranking_status = "no_economic_separation"
            ranking_reason = "all_observed_incentives_equal"
        else:
            ranking_status = "ranked"
            ranking_reason = None
        response = LeaderboardResponse(
            **released_envelope(view, feed),
            protocol_state=current_protocol_state(view, feed),
            chain_economics=ChainEconomicLeaderboard(
                ranking_status=ranking_status,
                reason_code=ranking_reason,
                source_ids=chain_source_ids,
                excluded_missing_incentive=len(miners) - len(rankable),
                entries=tuple(
                    ChainEconomicLeaderboardEntry(
                        chain_rank=(
                            None
                            if ranking_status != "ranked"
                            else first_positions[participant.chain_metrics.incentive.raw_numerator]
                        ),
                        incentive_tie_size=raw_counts[
                            participant.chain_metrics.incentive.raw_numerator
                        ],
                        uid=participant.uid,
                        hotkey=participant.hotkey,
                        chain_active=participant.chain_active,
                        serving_announced=participant.serving_announced,
                        incentive=participant.chain_metrics.incentive,
                        dividends=participant.chain_metrics.dividends,
                        emission=participant.chain_metrics.emission,
                    )
                    for participant in rankable
                ),
            ),
            umi_translation=UmiTranslationLeaderboard(
                availability="unavailable" if public_solution_windows else "not_started",
                reason_code=(
                    "validator_local_scores_not_consensus"
                    if public_solution_windows
                    else "public_calibration_not_started"
                ),
                entries=(),
            ),
        )
        return _render(request, response, view)

    @app.head("/api/v1/windows", include_in_schema=False)
    @app.get(
        "/api/v1/windows",
        response_model=WindowsResponse,
        responses=_CURSOR_ERROR_RESPONSES,
    )
    async def windows(request: Request, query: Annotated[EvidenceQuery, Query()]) -> Response:
        view = current()
        feed = released(view)
        revision = _feed_revision(feed.windows, "windows")
        offset = (
            0
            if query.cursor is None
            else _decode_evidence_cursor(query.cursor, revision=revision, kind="windows")
        )
        if offset > len(feed.windows):
            raise PublicAPIError(422, "cursor_offset_out_of_range")
        selected = feed.windows[offset : offset + query.limit]
        next_offset = offset + len(selected)
        records = tuple(released_window(item) for item in selected)
        response = WindowsResponse(
            **released_envelope(view, feed, selected),
            protocol_state=current_protocol_state(view, feed),
            availability="available" if feed.windows else "not_started",
            reason_code=None if feed.windows else "public_calibration_not_started",
            windows=records,
            bundle_feed_health=released_health(feed),
            page=EvidenceCursorPage(
                limit=query.limit,
                total=len(feed.windows),
                returned=len(records),
                next_cursor=(
                    None
                    if next_offset >= len(feed.windows)
                    else _encode_evidence_cursor(
                        revision=revision,
                        kind="windows",
                        offset=next_offset,
                    )
                ),
            ),
        )
        return _render(request, response, view)

    @app.head("/api/v1/windows/{window_id}", include_in_schema=False)
    @app.get(
        "/api/v1/windows/{window_id}",
        response_model=WindowResponse,
        responses=_WINDOW_ERROR_RESPONSES,
    )
    async def window_detail(
        request: Request,
        window_id: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
        validator: Annotated[str | None, Query(pattern=_WINDOW_ID_RE.pattern)] = None,
    ) -> Response:
        view = current()
        feed = released(view)
        matches = [
            item
            for item in feed.windows
            if item.window_id == window_id
            and (validator is None or item.validator_account_id32 == validator)
        ]
        if not matches:
            raise PublicAPIError(404, "released_window_not_found")
        if len(matches) != 1:
            raise PublicAPIError(409, "released_window_validator_required")
        response = WindowResponse(
            **released_envelope(view, feed, matches),
            protocol_state=current_protocol_state(view, feed),
            window=released_window(matches[0]),
        )
        return _render(request, response, view)

    @app.head("/api/v1/windows/{window_id}/solutions", include_in_schema=False)
    @app.get(
        "/api/v1/windows/{window_id}/solutions",
        response_model=WindowSolutionsResponse,
        responses=_WINDOW_ERROR_RESPONSES,
    )
    async def window_solutions(
        request: Request,
        window_id: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
        query: Annotated[SolutionQuery, Query()],
    ) -> Response:
        view = current()
        feed = released(view)
        matches = [
            item
            for item in feed.windows
            if item.window_id == window_id
            and (query.validator is None or item.validator_account_id32 == query.validator)
        ]
        if not matches:
            raise PublicAPIError(404, "released_window_not_found")
        if len(matches) != 1:
            raise PublicAPIError(409, "released_window_validator_required")
        item = matches[0]
        if not _has_public_solution_evidence(item):
            raise PublicAPIError(404, "released_solution_evidence_not_found")
        kind = f"solutions:{item.validator_account_id32}:{item.window_id}"
        revision = _feed_revision((item,), kind)
        offset = (
            0
            if query.cursor is None
            else _decode_evidence_cursor(query.cursor, revision=revision, kind=kind)
        )
        total = item.solution_count if item.solution_count is not None else len(item.solutions)
        if offset > total:
            raise PublicAPIError(422, "cursor_offset_out_of_range")
        if isinstance(bundle_feed, ObserverBundleFeed):
            stored_total, selected = bundle_feed.solution_page(
                item.validator_account_id32,
                item.window_id,
                offset=offset,
                limit=query.limit,
            )
            if stored_total != total:
                raise PublicAPIError(503, "released_bundle_feed_inconsistent")
        else:
            selected = item.solutions[offset : offset + query.limit]
        next_offset = offset + len(selected)
        response = WindowSolutionsResponse(
            **released_envelope(view, feed, (item,)),
            protocol_state=current_protocol_state(view, feed),
            window=released_window(item),
            page=EvidenceCursorPage(
                limit=query.limit,
                total=total,
                returned=len(selected),
                next_cursor=(
                    None
                    if next_offset >= total
                    else _encode_evidence_cursor(
                        revision=revision,
                        kind=kind,
                        offset=next_offset,
                    )
                ),
            ),
            solutions=tuple(released_solution(item, solution) for solution in selected),
        )
        return _render(request, response, view)

    @app.head("/api/v1/bootstrap-service", include_in_schema=False)
    @app.get(
        "/api/v1/bootstrap-service",
        response_model=BootstrapServiceResponse,
        responses={503: _COMMON_ERROR_RESPONSES[503]},
    )
    async def bootstrap_service(request: Request) -> Response:
        view = current()
        releases = released(view)
        publications = tuple(
            sorted(configured_bootstrap_publications(), key=lambda item: item.publication_id)
        )
        selection = bootstrap_selection(view)
        economic_effect = _bootstrap_service_economic_effect(view.snapshot, selection)
        response = BootstrapServiceResponse(
            **bootstrap_envelope(view, selection.publication),
            protocol_state=current_protocol_state(view, releases),
            availability="active" if selection.publication is not None else "inactive",
            reason_code=None if selection.publication is not None else selection.reason_code,
            warning_codes=selection.warning_codes,
            economic_effect=economic_effect,
            current=(None if selection.publication is None else bootstrap_record(view, selection)),
            verified_publications=tuple(bootstrap_locator(item) for item in publications),
        )
        return _render(request, response, view)

    @app.head(
        "/api/v1/bootstrap-service/{publication_id}/bundle/manifest.json",
        include_in_schema=False,
    )
    @app.get(
        "/api/v1/bootstrap-service/{publication_id}/bundle/manifest.json",
        responses=_BOOTSTRAP_ERROR_RESPONSES,
    )
    async def bootstrap_service_manifest(
        request: Request,
        publication_id: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
    ) -> Response:
        publication = (
            None if bootstrap_service_feed is None else bootstrap_service_feed.get(publication_id)
        )
        if publication is None:
            raise PublicAPIError(404, "bootstrap_service_publication_not_found")
        return _render_immutable_bytes(
            request,
            publication.manifest_bytes,
            media_type="application/json",
            sha256=publication.publication_id,
            bundle_sha256=publication.publication_id,
            bundle_header="X-UMI-Bootstrap-Bundle",
        )

    @app.head(
        "/api/v1/bootstrap-service/{publication_id}/bundle/objects/{object_sha256}",
        include_in_schema=False,
    )
    @app.get(
        "/api/v1/bootstrap-service/{publication_id}/bundle/objects/{object_sha256}",
        responses=_BOOTSTRAP_ERROR_RESPONSES,
    )
    async def bootstrap_service_object(
        request: Request,
        publication_id: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
        object_sha256: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
    ) -> Response:
        publication = (
            None if bootstrap_service_feed is None else bootstrap_service_feed.get(publication_id)
        )
        if publication is None:
            raise PublicAPIError(404, "bootstrap_service_publication_not_found")
        evidence_object = publication.objects.get(object_sha256)
        if evidence_object is None:
            raise PublicAPIError(404, "bootstrap_service_object_not_found")
        return _render_immutable_bytes(
            request,
            evidence_object.data,
            media_type=evidence_object.media_type,
            sha256=evidence_object.sha256,
            bundle_sha256=publication.publication_id,
            bundle_header="X-UMI-Bootstrap-Bundle",
        )

    @app.head("/api/v1/pilots", include_in_schema=False)
    @app.get(
        "/api/v1/pilots",
        response_model=PilotsResponse,
        responses=_CURSOR_ERROR_RESPONSES,
    )
    async def pilots(request: Request, query: Annotated[EvidenceQuery, Query()]) -> Response:
        view = current()
        all_pilots = configured_pilots()
        revision = hashlib.sha256(
            canonical_json_bytes(
                {"kind": "pilots", "manifests": [pilot.pilot_id for pilot in all_pilots]}
            )
        ).hexdigest()
        offset = (
            0
            if query.cursor is None
            else _decode_evidence_cursor(query.cursor, revision=revision, kind="pilots")
        )
        if offset > len(all_pilots):
            raise PublicAPIError(422, "cursor_offset_out_of_range")
        selected = all_pilots[offset : offset + query.limit]
        next_offset = offset + len(selected)
        response = PilotsResponse(
            **pilot_envelope(view, selected),
            protocol_state=current_protocol_state(view, released(view)),
            availability="available" if all_pilots else "not_started",
            reason_code=None if all_pilots else "public_component_pilot_not_started",
            page=EvidenceCursorPage(
                limit=query.limit,
                total=len(all_pilots),
                returned=len(selected),
                next_cursor=(
                    None
                    if next_offset >= len(all_pilots)
                    else _encode_evidence_cursor(
                        revision=revision,
                        kind="pilots",
                        offset=next_offset,
                    )
                ),
            ),
            pilots=tuple(pilot_record(pilot) for pilot in selected),
        )
        return _render(request, response, view)

    @app.head("/api/v1/pilots/{pilot_id}", include_in_schema=False)
    @app.get(
        "/api/v1/pilots/{pilot_id}",
        response_model=PilotResponse,
        responses=_PILOT_ERROR_RESPONSES,
    )
    async def pilot_detail(
        request: Request,
        pilot_id: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
    ) -> Response:
        view = current()
        pilot = None if pilot_feed is None else pilot_feed.get(pilot_id)
        if pilot is None:
            raise PublicAPIError(404, "component_pilot_not_found")
        response = PilotResponse(
            **pilot_envelope(view, (pilot,)),
            protocol_state=current_protocol_state(view, released(view)),
            pilot=pilot_record(pilot),
        )
        return _render(request, response, view)

    @app.head("/api/v1/pilots/{pilot_id}/solutions", include_in_schema=False)
    @app.get(
        "/api/v1/pilots/{pilot_id}/solutions",
        response_model=PilotSolutionsResponse,
        responses={**_PILOT_ERROR_RESPONSES, 409: _CURSOR_ERROR_RESPONSES[409]},
    )
    async def pilot_solutions(
        request: Request,
        pilot_id: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
        query: Annotated[PilotSolutionQuery, Query()],
    ) -> Response:
        view = current()
        pilot = None if pilot_feed is None else pilot_feed.get(pilot_id)
        if pilot is None:
            raise PublicAPIError(404, "component_pilot_not_found")
        kind = f"pilot-solutions:{pilot.pilot_id}"
        offset = (
            0
            if query.cursor is None
            else _decode_evidence_cursor(
                query.cursor,
                revision=pilot.manifest_sha256,
                kind=kind,
            )
        )
        if offset > len(pilot.solutions):
            raise PublicAPIError(422, "cursor_offset_out_of_range")
        selected = pilot.solutions[offset : offset + query.limit]
        next_offset = offset + len(selected)
        response = PilotSolutionsResponse(
            **pilot_envelope(view, (pilot,)),
            protocol_state=current_protocol_state(view, released(view)),
            pilot=pilot_record(pilot),
            page=EvidenceCursorPage(
                limit=query.limit,
                total=len(pilot.solutions),
                returned=len(selected),
                next_cursor=(
                    None
                    if next_offset >= len(pilot.solutions)
                    else _encode_evidence_cursor(
                        revision=pilot.manifest_sha256,
                        kind=kind,
                        offset=next_offset,
                    )
                ),
            ),
            solutions=tuple(pilot_solution(pilot, solution) for solution in selected),
        )
        return _render(request, response, view)

    @app.head(
        "/api/v1/pilots/{pilot_id}/bundle/manifest.json",
        include_in_schema=False,
    )
    @app.get(
        "/api/v1/pilots/{pilot_id}/bundle/manifest.json",
        responses=_PILOT_ERROR_RESPONSES,
    )
    async def pilot_manifest(
        request: Request,
        pilot_id: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
    ) -> Response:
        pilot = None if pilot_feed is None else pilot_feed.get(pilot_id)
        if pilot is None:
            raise PublicAPIError(404, "component_pilot_not_found")
        return _render_immutable_bytes(
            request,
            pilot.manifest_bytes,
            media_type="application/json",
            sha256=pilot.manifest_sha256,
            bundle_sha256=pilot.manifest_sha256,
        )

    @app.head(
        "/api/v1/pilots/{pilot_id}/bundle/objects/{object_sha256}",
        include_in_schema=False,
    )
    @app.get(
        "/api/v1/pilots/{pilot_id}/bundle/objects/{object_sha256}",
        responses=_PILOT_ERROR_RESPONSES,
    )
    async def pilot_object(
        request: Request,
        pilot_id: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
        object_sha256: Annotated[str, Path(pattern=_WINDOW_ID_RE.pattern)],
    ) -> Response:
        pilot = None if pilot_feed is None else pilot_feed.get(pilot_id)
        if pilot is None:
            raise PublicAPIError(404, "component_pilot_not_found")
        evidence_object = pilot.objects.get(object_sha256)
        if evidence_object is None:
            raise PublicAPIError(404, "component_pilot_object_not_found")
        return _render_immutable_bytes(
            request,
            evidence_object.data,
            media_type=evidence_object.media_type,
            sha256=evidence_object.sha256,
            bundle_sha256=pilot.manifest_sha256,
        )

    @app.head("/api/v1/activation-gates", include_in_schema=False)
    @app.get(
        "/api/v1/activation-gates",
        response_model=ActivationGatesResponse,
        responses={503: _COMMON_ERROR_RESPONSES[503]},
    )
    async def activation_gates(request: Request) -> Response:
        view = current()
        feed = released(view)
        response = ActivationGatesResponse(
            **released_envelope(view, feed),
            protocol_state=current_protocol_state(view, feed),
            readiness="not_ready",
            gates=tuple(
                ActivationGate(
                    gate_id=gate_id,
                    status="pending",
                    evidence_available=False,
                    evidence_sha256=None,
                )
                for gate_id in _ACTIVATION_GATE_IDS
            ),
        )
        return _render(request, response, view)

    @app.head("/api/v1/benchmarks", include_in_schema=False)
    @app.get(
        "/api/v1/benchmarks",
        response_model=BenchmarksResponse,
        responses={503: _COMMON_ERROR_RESPONSES[503]},
    )
    async def benchmarks(request: Request) -> Response:
        view = current()
        feed = released(view)
        response = BenchmarksResponse(
            **released_envelope(view, feed),
            protocol_state=current_protocol_state(view, feed),
            availability="not_started",
            reason_code="public_benchmark_feed_not_started",
            benchmarks=(),
        )
        return _render(request, response, view)

    @app.head("/api/v1/incidents", include_in_schema=False)
    @app.get(
        "/api/v1/incidents",
        response_model=IncidentsResponse,
        responses=_CURSOR_ERROR_RESPONSES,
    )
    async def incidents(request: Request, query: Annotated[EvidenceQuery, Query()]) -> Response:
        view = current()
        feed = released(view)
        incident_windows = tuple(
            item for item in feed.windows if item.terminal_classification != "calibration_no_weight"
        )
        all_records = tuple(
            IncidentRecord(
                incident_id=hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "manifest_sha256": item.manifest_sha256,
                            "reason_code": reason,
                            "validator_account_id32": item.validator_account_id32,
                        }
                    )
                ).hexdigest(),
                reason_code=reason,
                window_id=item.window_id,
                published_at=None,
                observer_verified_at=(
                    None
                    if item.observer_verified_unix is None
                    else datetime.fromtimestamp(item.observer_verified_unix, tz=timezone.utc)
                ),
                artifact_sha256=item.manifest_sha256,
                validator_account_id32=item.validator_account_id32,
                audit_release_block=str(item.audit_release_block),
                terminal_classification=item.terminal_classification,
            )
            for item in incident_windows
            for reason in item.reason_codes
        )
        revision = hashlib.sha256(
            canonical_json_bytes(
                {
                    "incidents": [item.incident_id for item in all_records],
                    "kind": "incidents",
                }
            )
        ).hexdigest()
        offset = (
            0
            if query.cursor is None
            else _decode_evidence_cursor(query.cursor, revision=revision, kind="incidents")
        )
        if offset > len(all_records):
            raise PublicAPIError(422, "cursor_offset_out_of_range")
        records = all_records[offset : offset + query.limit]
        next_offset = offset + len(records)
        selected_hashes = {item.artifact_sha256 for item in records}
        selected_windows = tuple(
            item for item in incident_windows if item.manifest_sha256 in selected_hashes
        )
        response = IncidentsResponse(
            **released_envelope(view, feed, selected_windows),
            protocol_state=current_protocol_state(view, feed),
            availability="available" if all_records else "not_started",
            reason_code=None if all_records else "public_incident_feed_not_started",
            incidents=records,
            bundle_feed_health=released_health(feed),
            page=EvidenceCursorPage(
                limit=query.limit,
                total=len(all_records),
                returned=len(records),
                next_cursor=(
                    None
                    if next_offset >= len(all_records)
                    else _encode_evidence_cursor(
                        revision=revision,
                        kind="incidents",
                        offset=next_offset,
                    )
                ),
            ),
        )
        return _render(request, response, view)

    return app


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve the read-only SN78 observer API")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8092)
    parser.add_argument("--network", choices=("finney",), default="finney")
    parser.add_argument("--bundle-feed-config")
    parser.add_argument("--pilot-feed-config")
    parser.add_argument("--bootstrap-service-feed-config")
    parser.add_argument(
        "--directive-feed-config",
        default=os.environ.get("UMI_OBSERVER_DIRECTIVE_FEED_CONFIG") or None,
    )
    parser.add_argument("--cors-origin", action="append", default=[])
    parser.add_argument("--trusted-host", action="append", default=[])
    parser.add_argument("--fresh-for-seconds", type=float, default=24.0)
    parser.add_argument("--maximum-stale-seconds", type=float, default=120.0)
    parser.add_argument("--refresh-interval-seconds", type=float, default=12.0)
    parser.add_argument("--refresh-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--finalized-head-timeout-seconds", type=float, default=20.0)
    parser.add_argument("--maximum-finalized-head-age-seconds", type=float, default=120.0)
    parser.add_argument("--maximum-future-block-skew-seconds", type=float, default=30.0)
    parser.add_argument(
        "--log-level",
        choices=("critical", "error", "warning", "info", "debug"),
        default="info",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    if isinstance(args.port, bool) or not 1 <= args.port <= 65_535:
        raise SystemExit("--port must be from 1 through 65535")
    logging.basicConfig(level=getattr(logging, args.log_level.upper()))
    trusted_hosts = args.trusted_host or [args.listen_host, "localhost", "127.0.0.1"]
    collector = BittensorChainCollector(
        network=args.network,
        finalized_head_timeout_seconds=args.finalized_head_timeout_seconds,
    )
    cache = SnapshotCache(
        collector,
        fresh_for_seconds=args.fresh_for_seconds,
        maximum_stale_seconds=args.maximum_stale_seconds,
        refresh_interval_seconds=args.refresh_interval_seconds,
        refresh_timeout_seconds=args.refresh_timeout_seconds,
        maximum_finalized_head_age_seconds=args.maximum_finalized_head_age_seconds,
        maximum_future_block_skew_seconds=args.maximum_future_block_skew_seconds,
    )
    bundle_feed = None
    bundle_feed_poll_seconds = 15.0
    if args.bundle_feed_config:
        bundle_feed, bundle_feed_poll_seconds = build_production_observer_bundle_feed(
            args.bundle_feed_config
        )
    pilot_feed = (
        None
        if args.pilot_feed_config is None
        else build_observer_pilot_feed(args.pilot_feed_config)
    )
    if args.bootstrap_service_feed_config and pilot_feed is None:
        raise SystemExit("--bootstrap-service-feed-config requires --pilot-feed-config")
    bootstrap_service_feed = (
        None
        if args.bootstrap_service_feed_config is None
        else build_observer_bootstrap_service_feed(
            args.bootstrap_service_feed_config,
            pilot_feed=pilot_feed,
        )
    )
    directive_feed = (
        None
        if args.directive_feed_config is None
        else build_observer_directive_feed(args.directive_feed_config)
    )
    app = create_observer_app(
        cache,
        bundle_feed=bundle_feed,
        pilot_feed=pilot_feed,
        bootstrap_service_feed=bootstrap_service_feed,
        directive_feed=directive_feed,
        bundle_feed_poll_seconds=bundle_feed_poll_seconds,
        cors_origins=args.cors_origin,
        trusted_hosts=trusted_hosts,
    )
    uvicorn.run(app, host=args.listen_host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
