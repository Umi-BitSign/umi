"""Owner-side request completion from compensated service and native queue records.

The host supplies actual readiness and owned finality. Accepted work remains
pending until every original terminal can be replayed. This observer neither
signs progress nor reveals references. Remote reviewers need authenticated owner
exports; sharing a peer's live database is not a supported transport.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from pydantic import Field

from .competition_chain import RegistrationCapture
from .competition_cohort_availability import (
    CohortAvailabilityObservation,
    CohortServiceAvailability,
    CohortServiceEpoch,
    pending_availability_progress,
)
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortPhaseProgress,
    _choice,
    replay_cohort_decisions,
)
from .competition_cohort_endpoint_archive import EndpointObjectSource, JournalEndpointObjects
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake import CohortIntake
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_orders import SignedRecoverableEvaluationOrder
from .competition_cohort_recovery import StandingCohortRecoveryAuthority
from .competition_cohort_request_closure import PendingRequestClosure, build_request_closure
from .competition_cohort_request_completion import (
    PendingServiceRequestClosure,
    build_service_request_closure,
)
from .competition_cohort_request_progress import (
    RequestClosureProgressEvidence,
    request_closure_progress,
)
from .competition_cohort_request_terminal import SignedRequestTerminal
from .competition_cohort_reward_package import DEFAULT_PACKAGE_BYTES, ReplayObjectCollector
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_closure import (
    CohortServiceRequestClosure,
    review_service_request_closure,
)
from .competition_cohort_service_queue import ServiceWorkQueue
from .competition_cohort_service_requests import ServiceWorkRequests
from .competition_cohort_service_terminal import ServiceWorkTerminals
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .competition_round_journal import RoundJournal
from .open_competition import digest
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


class RequestProgressReviewRecord(StrictProtocolModel):
    schema_: Literal["umi-request-progress-review/1"] = Field(alias="schema")
    progress: CohortPhaseProgress
    history_sha256: Hex32
    service: CohortAvailabilityObservation
    fence: CohortAvailabilityObservation | None


@dataclass(frozen=True)
class NativeRequestReview:
    record: RequestProgressReviewRecord
    history: CohortRecoveryHistory
    decisions: tuple[CohortDecisionInput, ...]
    consents: tuple[str, ...]


class NativeRequestProgressSource:
    def __init__(
        self,
        intake: CohortIntake,
        journal: RoundJournal,
        *,
        roster: RecoverableRosterEvidence,
        catalogs: tuple[SignedServiceWorkCatalog, ...],
        queues: tuple[ServiceWorkQueue, ...],
        transport: ScoringPolicy,
        orders: Callable[[], Iterable[SignedRecoverableEvaluationOrder]],
        terminals: Callable[[SignedRecoverableEvaluationOrder, str], SignedRequestTerminal | None],
        objects: EndpointObjectSource,
        maximum_sample_gap_blocks: int = 10,
        maximum_observation_bytes: int = 256 * 1024**2,
        maximum_replay_bytes: int = DEFAULT_PACKAGE_BYTES,
    ):
        self.intake, self.journal = intake, journal
        self.roster = RecoverableRosterEvidence.model_validate_json(canonical_json_bytes(roster))
        self.catalogs = tuple(
            SignedServiceWorkCatalog.model_validate_json(canonical_json_bytes(c)) for c in catalogs
        )
        self.transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
        self.cohort = self.roster.round.cohort_sha256
        intake._allowed(self.cohort)
        if not isinstance(
            intake.history(self.cohort).authority.authority, StandingCohortRecoveryAuthority
        ):
            raise ValueError("automatic request closure requires standing cohort authority")
        keys = tuple(digest(c.catalog) for c in self.catalogs)
        if (
            not 1 <= len(keys) <= 64
            or keys != tuple(sorted(set(keys)))
            or tuple(q.config.catalog_sha256 for q in queues) != keys
            or any(q.policy != intake.policy for q in queues)
        ):
            raise ValueError("request observer requires every configured catalog owner")
        self.queues = tuple(queues)
        self.services = tuple(
            ServiceWorkTerminals(ServiceWorkRequests(q, self.transport)) for q in queues
        )
        self.orders, self.terminals, self.external = orders, terminals, objects
        self.objects = JournalEndpointObjects(journal)
        self.epoch = CohortServiceEpoch()
        self.gap, self.observation_bytes = maximum_sample_gap_blocks, maximum_observation_bytes
        self.replay_bytes = maximum_replay_bytes
        # Bind the read-set limit before any source I/O.
        ReplayObjectCollector(objects, maximum_replay_bytes)
        self.journal.put(
            "request_phase_binding",
            self.cohort,
            {
                "schema": "umi-request-phase-owner/1",
                "intake": intake.config.model_dump(mode="json", by_alias=True),
                "roster": digest(self.roster),
                "catalogs": keys,
                "transport": scoring_policy_hash(self.transport),
            },
        )

    def _availability(self, store):
        return CohortServiceAvailability(
            store,
            self.intake.policy,
            maximum_sample_gap_blocks=self.gap,
            maximum_bytes=self.observation_bytes,
            epoch=self.epoch,
        )

    def _source(self, key):
        # Partial immutable exports survive retry. New evidence comes only from
        # configured source ports and the native accepted-work owners.
        for source in (self.objects, self.external, *(s.objects for s in self.services)):
            try:
                return source(key)
            except FileNotFoundError:
                continue
        raise FileNotFoundError("request completion original object is unavailable")

    def _state(self, store, state):
        history = store.published_history(self.cohort)
        decisions = tuple(
            store.source(self.cohort, s.transition.evidence_sha256, CohortDecisionInput)
            for s in history.transitions
            if s.transition.operation != "revoke"
        )
        source = {digest(d): d for d in decisions}
        current, restored, prior = replay_cohort_decisions(
            history, self.intake.policy, source.__getitem__
        )
        if current != state or state.phase != "requests":
            raise ValueError("request completion requires its active owned history")
        return history, decisions, source, restored, prior

    def _service(self, db, availability, service, state, restored, prior):
        availability._last(self.cohort, "requests")
        raw = canonical_json_bytes(service)
        row = db.execute(
            "SELECT substr(body,1,16385) FROM cohort_service_observations "
            "WHERE cohort=? AND phase='requests' AND sequence=?",
            (self.cohort, service.sequence),
        ).fetchone()
        pending_availability_progress(state, service)
        if row != (raw,) or service.unavailable_blocks < max(restored, prior):
            raise ValueError("request progress differs from retained service history")

    def _fence(self, db, availability, state, restored, prior):
        raw = self.journal.get("request_window_fence", state.tip_sha256)
        if raw is None:
            return None
        value = CohortAvailabilityObservation.model_validate_json(canonical_json_bytes(raw))
        self._service(db, availability, value, state, restored, prior)
        target = next(t.target_block for t in state.targets if t.phase == "requests")
        if (
            not value.serving
            or value.observation.block < target + value.unavailable_blocks - restored
        ):
            raise ValueError("request queue was fenced before restoring unavailable service")
        return value

    def sample_service(
        self, state, capture: RegistrationCapture, *, serving: bool
    ) -> CohortAvailabilityObservation | None:
        """Record dispatch readiness without replaying requests or sealing queues."""
        self.epoch.identity()
        if type(serving) is not bool:
            raise ValueError("request readiness must be an actual boolean")
        with self.intake._connection() as (db, store):
            history, _, _, restored, prior = self._state(store, state)
            availability = self._availability(store)
            if self._fence(db, availability, state, restored, prior) is not None:
                return
            return availability.observe(
                self.cohort, capture, serving=serving, genesis_signatures=history.genesis_signatures
            )

    def observe(self, state, capture: RegistrationCapture, *, serving: bool) -> CohortPhaseProgress:
        """Called by the owned runtime after probing admission/dispatch readiness."""
        self.epoch.identity()
        with self.intake._connection() as (db, store):
            history, decisions, sources, restored, prior = self._state(store, state)
            availability = self._availability(store)
            service = availability.observe(
                self.cohort, capture, serving=serving, genesis_signatures=history.genesis_signatures
            )
            self._service(db, availability, service, state, restored, prior)
            progress = pending_availability_progress(state, service)
            target = next(t.target_block for t in state.targets if t.phase == "requests")
            fence = self._fence(db, availability, state, restored, prior)
            if (
                service.serving
                and service.observation.block >= target + service.unavailable_blocks - restored
            ):
                if fence is None:
                    if any(q.retained_seal() is not None for q in self.queues):
                        raise ValueError("request queue lacks its original service-window fence")
                    # Preserve the compensated fence before touching any queue.
                    # A crash between different queues resumes the same fence.
                    self.journal.put("request_window_fence", state.tip_sha256, service)
                    fence = service
                owner_history = CohortOrderHistory(history=history, decisions=decisions)
                seals = tuple(
                    q.seal(owner_history, capture, expected_tip_sha256=state.tip_sha256)
                    for q in self.queues
                )
                if any(s.observation.block < fence.observation.block for s in seals):
                    raise ValueError("request queue was sealed before its service-window fence")
                captured = ReplayObjectCollector(self._source, self.replay_bytes)
                records = tuple(self.intake._records(db, history))
                common = dict(
                    decision_source=sources.__getitem__,
                    intake_records=records,
                    expected_tip_sha256=state.tip_sha256,
                    current_block=service.observation.block,
                )
                try:
                    benchmark = build_request_closure(
                        self.roster,
                        self.orders(),
                        self.terminals,
                        captured,
                        self.intake.policy,
                        history,
                        service.observation,
                        **common,
                    )
                    captured.retain(benchmark)
                    for seal in seals:
                        captured.retain(seal)
                    by_catalog = {
                        q.config.catalog_sha256: s
                        for q, s in zip(self.queues, self.services, strict=True)
                    }
                    closure = build_service_request_closure(
                        benchmark,
                        self.roster,
                        self.catalogs,
                        seals,
                        lambda a: by_catalog[a.admission.catalog_sha256].read(a),
                        captured,
                        self.intake.policy,
                        history,
                        self.transport,
                        **common,
                    )
                except (PendingRequestClosure, PendingServiceRequestClosure) as pending:
                    count = (
                        len(pending.obligations)
                        if isinstance(pending, PendingRequestClosure)
                        else len(pending.work)
                    )
                    logger.info(
                        "cohort_requests_pending cohort=%s reason=%s count=%s",
                        self.cohort,
                        type(pending).__name__,
                        count,
                    )
                else:
                    progress, evidence = request_closure_progress(closure, service, state)
                    captured.retain(closure)
                    captured.retain(evidence)
                    # A complete progress record is written only after its entire
                    # native replay read-set is durable. Retry needs no inference.
                    for key, raw in captured.values.items():
                        self.journal.put("endpoint_replay_object", key, json.loads(raw))
            record = RequestProgressReviewRecord(
                schema="umi-request-progress-review/1",
                progress=progress,
                history_sha256=digest(history),
                service=service,
                fence=fence,
            )
            self.journal.put("request_progress", digest(progress), record)
            return progress

    def read(self, progress: CohortPhaseProgress) -> NativeRequestReview:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        raw = self.journal.get("request_progress", digest(progress))
        if raw is None:
            raise FileNotFoundError("request progress has not been retained")
        record = RequestProgressReviewRecord.model_validate_json(canonical_json_bytes(raw))
        with self.intake._connection() as (db, store):
            state, _ = store.status(self.cohort)
            history, decisions, sources, restored, prior = self._state(store, state)
            if record.progress != progress or record.history_sha256 != digest(history):
                raise ValueError("request review changed its original progress or history")
            availability = self._availability(store)
            self._service(db, availability, record.service, state, restored, prior)
            records = tuple(self.intake._records(db, history))
            if progress.completion == "complete":
                fence = self._fence(db, availability, state, restored, prior)
                if fence is None or record.fence != fence:
                    raise ValueError("request completion lacks its original window fence")
                closure = CohortServiceRequestClosure.model_validate_json(
                    self.objects(progress.phase_result_sha256)
                )
                seals = tuple(q.retained_seal() for q in self.queues)
                if any(s is None or s.observation.block < fence.observation.block for s in seals):
                    raise ValueError("request completion changed an owner queue fence")
                review_service_request_closure(
                    closure,
                    self.roster,
                    ReplayObjectCollector(self.objects, self.replay_bytes),
                    self.intake.policy,
                    history,
                    self.transport,
                    expected_catalogs=self.catalogs,
                    expected_seals=seals,
                    decision_source=sources.__getitem__,
                    intake_records=records,
                    expected_tip_sha256=state.tip_sha256,
                    current_block=progress.observed_at_block,
                )
                expected, evidence = request_closure_progress(closure, record.service, state)
                retained = RequestClosureProgressEvidence.model_validate_json(
                    self.objects(progress.evidence_sha256)
                )
                if retained != evidence:
                    raise ValueError("request completion changed its original closure evidence")
            else:
                expected = pending_availability_progress(state, record.service)
            if expected != progress:
                raise ValueError("request progress differs from native completion")
            return NativeRequestReview(record, history, decisions, tuple(k for k, _ in records))

    def decision(self, transition, evidence: CohortDecisionInput):
        reviewed = self.read(evidence.progress.progress)
        if evidence.observation != reviewed.record.service.observation:
            raise ValueError("request decision changed its original finalized observation")
        sources = {digest(d): d for d in reviewed.decisions}
        state, restored, prior = replay_cohort_decisions(
            reviewed.history, self.intake.policy, sources.__getitem__
        )
        expected, _ = _choice(
            state,
            reviewed.history.authority.authority,
            self.intake.policy,
            evidence,
            restored,
            prior,
        )
        if transition != expected:
            raise ValueError("request decision differs from native completion")
        return digest(reviewed.history)
