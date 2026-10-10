"""Authenticated original request evidence for independent completion review.

Service observations and complete queue seals come from the explicitly selected
owner. Its signature authenticates that source, not network availability. The
reviewer selects the roster/catalogs/transport locally and replays the original
terminals; an owner-supplied completion flag cannot close unresolved work.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_availability import (
    CohortAvailabilityObservation,
    unavailable_service_blocks,
)
from .competition_cohort_coordinator import CohortDecisionInput, CohortPhaseProgress
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_intake_records import RetainedCohortParticipation, read_participation
from .competition_cohort_request_phase import (
    NativeRequestProgressSource,
    NativeRequestReview,
    RequestProgressReviewRecord,
    replay_request_completion,
)
from .competition_cohort_review_export import MAX_EXPORT_BYTES, review_export_limits
from .competition_cohort_reward_package import ReplayObjectCollector, RewardPackageObject
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_closure import CohortServiceRequestClosure
from .competition_cohort_service_seal import ServiceWorkSeal
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RequestReviewRequest(StrictProtocolModel):
    schema_: Literal["umi-request-review-request/1"] = Field(alias="schema")
    challenge: Hex32
    progress: CohortPhaseProgress


class RequestReviewExport(StrictProtocolModel):
    schema_: Literal["umi-request-review-export/1"] = Field(alias="schema")
    record: RequestProgressReviewRecord
    history: CohortRecoveryHistory
    decisions: Annotated[tuple[CohortDecisionInput, ...], Field(max_length=128)]
    roster_sha256: Hex32
    catalogs: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=64)]
    transport_sha256: Hex32
    services: Annotated[
        tuple[CohortAvailabilityObservation, ...], Field(min_length=1, max_length=262144)
    ]
    seals: Annotated[tuple[ServiceWorkSeal, ...], Field(max_length=64)]
    records: Annotated[tuple[RetainedCohortParticipation, ...], Field(max_length=65536)]
    objects: Annotated[tuple[RewardPackageObject, ...], Field(max_length=65536)]


class RequestReviewResponse(StrictProtocolModel):
    schema_: Literal["umi-request-review-response/1"] = Field(alias="schema")
    challenge: Hex32
    evidence: RequestReviewExport


class SignedRequestReviewResponse(StrictProtocolModel):
    response: RequestReviewResponse
    signature: Signature


class RequestReviewExporter:
    def __init__(
        self,
        source: NativeRequestProgressSource,
        owner: str,
        sign: Callable[[RequestReviewResponse], Awaitable[Signature]],
        *,
        maximum_bytes: int = MAX_EXPORT_BYTES,
        timeout_seconds: int = 2400,
    ):
        review_export_limits(maximum_bytes, timeout_seconds)
        self.source, self.owner, self.sign = source, identity(owner), sign
        if self.owner not in {identity(e.hotkey) for e in source.intake.policy.evaluators}:
            raise ValueError("request export owner is outside the configured evaluator set")
        self.maximum_bytes, self.timeout_seconds = maximum_bytes, timeout_seconds

    def export(self, progress: CohortPhaseProgress) -> RequestReviewExport:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        captured = ReplayObjectCollector(self.source.objects, self.maximum_bytes)
        original = self.source._read(progress, captured)
        with self.source.intake._connection() as (db, store):
            if store.published_history(progress.cohort_sha256) != original.history:
                raise OSError("request history changed during owner export")
            services, records, size = [], [], captured.used
            for (raw,) in db.execute(
                "SELECT substr(body,1,16385) FROM cohort_service_observations "
                "WHERE cohort=? AND phase='requests' AND sequence<=? ORDER BY sequence",
                (progress.cohort_sha256, original.record.service.sequence),
            ):
                size += len(raw)
                if size > self.maximum_bytes:
                    raise OSError("request export exceeds capacity; preserve and retry")
                services.append(CohortAvailabilityObservation.model_validate_json(raw))
            for _, raw in self.source.intake._records(db, original.history):
                size += len(raw)
                if size > self.maximum_bytes:
                    raise OSError("request export exceeds capacity; preserve and retry")
                records.append(read_participation(raw))
            if tuple(digest(r.request.consent.consent) for r in records) != original.consents:
                raise OSError("request inventory changed during owner export")
        seals = ()
        if progress.completion == "complete":
            closure = CohortServiceRequestClosure.model_validate_json(
                captured(progress.phase_result_sha256)
            )
            seals = tuple(
                ServiceWorkSeal.model_validate_json(captured(c.seal_sha256))
                for c in closure.catalogs
            )
        result = RequestReviewExport(
            schema="umi-request-review-export/1",
            record=original.record,
            history=original.history,
            decisions=original.decisions,
            roster_sha256=digest(self.source.roster),
            catalogs=tuple(digest(c.catalog) for c in self.source.catalogs),
            transport_sha256=scoring_policy_hash(self.source.transport),
            services=tuple(services),
            seals=seals,
            records=tuple(records),
            objects=tuple(
                RewardPackageObject(sha256=k, value=json.loads(raw))
                for k, raw in sorted(captured.values.items())
            ),
        )
        if len(canonical_json_bytes(result)) > self.maximum_bytes:
            raise OSError("request export exceeds capacity; preserve and retry")
        return result

    async def respond(self, request: RequestReviewRequest) -> bytes:
        request = RequestReviewRequest.model_validate_json(canonical_json_bytes(request))
        evidence = await run_owned_thread(self.export, request.progress)
        response = RequestReviewResponse(
            schema="umi-request-review-response/1", challenge=request.challenge, evidence=evidence
        )
        signature = await wait_for_owned(self.sign(response), timeout=self.timeout_seconds)
        if identity(signature.hotkey) != self.owner:
            raise ValueError("request export was signed by another owner")
        verify_signature(response, signature)
        raw = canonical_json_bytes(
            SignedRequestReviewResponse(response=response, signature=signature)
        )
        if len(raw) > self.maximum_bytes:
            raise OSError("signed request export exceeds capacity; preserve and retry")
        return raw


def replay_request_export(
    exported: RequestReviewExport,
    policy: CompetitionPolicy,
    *,
    roster: RecoverableRosterEvidence,
    catalogs: tuple[SignedServiceWorkCatalog, ...],
    transport: ScoringPolicy,
    maximum_sample_gap_blocks: int,
    maximum_bytes: int,
) -> NativeRequestReview:
    record, history = exported.record, exported.history
    progress = record.progress
    if (
        exported.roster_sha256 != digest(roster)
        or exported.catalogs != tuple(digest(c.catalog) for c in catalogs)
        or exported.transport_sha256 != scoring_policy_hash(transport)
        or progress.phase != "requests"
        or progress.cohort_sha256 != roster.round.cohort_sha256
    ):
        raise ValueError(
            "request export differs from locally selected round, catalogs or transport"
        )
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=history_tip(history),
        current_block=progress.observed_at_block,
    )
    opened = view.closure("preparation")
    selected = next((d for d in exported.decisions if digest(d) == opened.evidence_sha256), None)
    if (
        selected is None
        or selected.progress is None
        or selected.progress.progress.phase_result_sha256 != digest(roster.round)
    ):
        raise ValueError("request roster differs from certified preparation")
    started = opened.observed_at_block
    first = next(i for i, t in enumerate(history.transitions) if t.transition == opened)
    tips = {digest(t.transition) for t in history.transitions[first:]}
    previous = None
    for service in exported.services:
        if (
            service.cohort_sha256 != progress.cohort_sha256
            or service.phase != "requests"
            or service.phase_started_block != started
            or service.observation.block < started
            or service.recovery_tip_sha256 not in tips
            or service.sequence != (1 if previous is None else previous.sequence + 1)
            or service.predecessor_sha256 != (None if previous is None else digest(previous))
            or service.unavailable_blocks
            != unavailable_service_blocks(previous, service, maximum_sample_gap_blocks)
        ):
            raise ValueError("request export service history is incomplete or inconsistent")
        previous = service
    if (
        previous != record.service
        or (record.fence is not None and record.fence not in exported.services)
        or (
            record.tail_fence is not None
            and not any(s.observation == record.tail_fence.observation for s in exported.services)
        )
    ):
        raise ValueError("request export changed its original service observation or fence")
    records = tuple(
        (digest(r.request.consent.consent), canonical_json_bytes(r)) for r in exported.records
    )
    if tuple(k for k, _ in records) != tuple(sorted({k for k, _ in records})):
        raise ValueError("request export inventory must be unique and ordered")
    keys = tuple(o.sha256 for o in exported.objects)
    if keys != tuple(sorted(set(keys))):
        raise ValueError("request export objects must be unique and ordered")
    values = {o.sha256: canonical_json_bytes(o.value) for o in exported.objects}

    def read(key: str) -> bytes:
        if key not in values:
            raise FileNotFoundError("request export original object is unavailable")
        return values[key]

    objects = ReplayObjectCollector(read, maximum_bytes)
    result = replay_request_completion(
        record,
        history,
        exported.decisions,
        policy=policy,
        roster=roster,
        catalogs=catalogs,
        seals=exported.seals,
        transport=transport,
        intake_records=records,
        objects=objects,
    )
    if set(objects.values) != set(values):
        raise ValueError("request export must contain exactly its native replay objects")
    return result
