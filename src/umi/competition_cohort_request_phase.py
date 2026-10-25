"""Owner-side request completion from compensated service and native queue records.

The host supplies actual readiness and owned finality. Closure replays every
original terminal or its explicit qualified tail disposition. This observer neither
signs progress nor reveals references. Remote reviewers need authenticated owner
exports; sharing a peer's live database is not a supported transport.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field, model_serializer, model_validator

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
from .competition_cohort_request_closure import (
    CohortRequestClosure,
    PendingRequestClosure,
    build_request_closure,
)
from .competition_cohort_request_completion import (
    PendingServiceRequestClosure,
    build_service_request_closure,
)
from .competition_cohort_request_inventory import request_inventory_observations
from .competition_cohort_request_progress import (
    RequestClosureProgressEvidence,
    request_closure_progress,
)
from .competition_cohort_request_tail import (
    MINIMUM_REQUEST_OPEN_MS,
    RequestTailObservation,
    review_request_tail,
)
from .competition_cohort_request_tail_owner import select_request_tail
from .competition_cohort_request_terminal import SignedRequestTerminal
from .competition_cohort_reward_package import DEFAULT_PACKAGE_BYTES, ReplayObjectCollector
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_closure import (
    CohortServiceRequestClosure,
    review_service_request_closure,
)
from .competition_cohort_service_fence import ServiceTailAdmissionFence, ServiceTailFenceBinding
from .competition_cohort_service_partial import (
    PendingPaidPartialInventory,
    ServicePaidPartials,
    paid_partial_observations,
)
from .competition_cohort_service_queue import ServiceWorkQueue
from .competition_cohort_service_requests import ServiceWorkRequests
from .competition_cohort_service_seal import ServiceWorkSeal
from .competition_cohort_service_terminal import ServiceWorkTerminals
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistration
from .competition_round_journal import RoundJournal
from .competition_verification_reuse import VerificationReuse, verification_owner_operation
from .open_competition import CompetitionPolicy, digest, identity
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


def _observation_terminal_reader(read):
    """Share exact owned reads within one observation, without hashing a round.

    The source still authenticates each terminal. These keys grant no authority
    and never survive the observation: another observation must see new arrivals.
    Retain the order itself so Python cannot reuse its object ID for another read.
    """
    reads = {}

    def terminal(order, evaluator):
        key = id(order), identity(evaluator)
        if key not in reads:
            reads[key] = (order, read(order, evaluator))
        return reads[key][1]

    return terminal


class RequestProgressReviewRecord(StrictProtocolModel):
    schema_: Literal["umi-request-progress-review/1", "umi-request-progress-review/2"] = Field(
        alias="schema"
    )
    progress: CohortPhaseProgress
    history_sha256: Hex32
    service: CohortAvailabilityObservation
    fence: CohortAvailabilityObservation | None
    tail_fence: RequestTailObservation | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.tail_fence is None:
            value.pop("tail_fence", None)
        return value

    @model_validator(mode="after")
    def selected_version(self):
        if (self.schema_ == "umi-request-progress-review/2") != (self.tail_fence is not None):
            raise ValueError("request review version differs from its explicit tail fence")
        return self


@dataclass(frozen=True)
class NativeRequestReview:
    record: RequestProgressReviewRecord
    history: CohortRecoveryHistory
    decisions: tuple[CohortDecisionInput, ...]
    consents: tuple[str, ...]
    tail: RequestTailObservation | None = None
    inventory_observations: tuple[ExecutionBoundary, ...] = ()


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
        partial_source: Callable[[str], Iterable[str]] | None = None,
        inventory_source: Callable[..., Iterable[str]] | None = None,
        publish_inventory_cutoff: Callable[[RequestTailObservation], None] | None = None,
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
        self.partial_source = partial_source
        self.inventory_source = inventory_source
        self.publish_inventory_cutoff = publish_inventory_cutoff
        self.objects = JournalEndpointObjects(journal)
        self.epoch = CohortServiceEpoch()
        self.gap, self.observation_bytes = maximum_sample_gap_blocks, maximum_observation_bytes
        self.replay_bytes = maximum_replay_bytes
        # Bind the read-set limit before any source I/O.
        ReplayObjectCollector(objects, maximum_replay_bytes)
        binding = {
            "schema": "umi-request-phase-owner/1",
            "intake": intake.config.model_dump(mode="json", by_alias=True),
            "roster": digest(self.roster),
            "catalogs": keys,
            "transport": scoring_policy_hash(self.transport),
        }
        self.journal.put("request_phase_binding", self.cohort, binding)
        # Builders and the enclosing service closure share this native owner's
        # successful replay. Each participant is checkpointed on the first pass;
        # independent reviewers still select their own verification authority.
        self.verification_reuse = VerificationReuse(
            journal.root / "request-observation-verification",
            owner={
                "kind": "request_observation",
                "journal": str(journal.root),
                "binding": binding,
                "policy": digest(intake.policy),
            },
        )
        self.tail_admission_binding = ServiceTailFenceBinding(
            schema="umi-private-service-tail-fence-binding/1",
            directory=str(self.queues[0].journal.root / "cohort-tail-admission"),
            cohort_sha256=self.cohort,
            policy_sha256=digest(intake.policy),
        )
        # Existing queues gain an additive private admission dependency before
        # any cutoff publication. A restarted queue reads it without reopening
        # the lifecycle owner's live SQLite journal.
        for queue in self.queues:
            queue.bind_tail_admission_fence(self.tail_admission_binding)

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
            if s.transition.requires_progress_evidence
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

    def _tail_fence(self, state, history, sources):
        raw = self.journal.get("request_tail_fence", state.tip_sha256)
        try:
            durable = read_private_model(
                Path(self.tail_admission_binding.directory) / "tail.json",
                ServiceTailAdmissionFence,
                maximum_bytes=128 * 1024,
            )
        except FileNotFoundError:
            if raw is not None:
                raise FileNotFoundError(
                    "request tail lost its shared durable admission fence"
                ) from None
            return None
        if (
            durable.cohort_sha256 != self.cohort
            or durable.policy_sha256 != digest(self.intake.policy)
            or durable.recovery_tip_sha256 != state.tip_sha256
            or durable.catalog_sha256s != tuple(digest(c.catalog) for c in self.catalogs)
        ):
            raise ValueError("shared request tail fence changed its original owner bindings")
        value = review_request_tail(
            durable.tail,
            roster=self.roster,
            history=history,
            policy=self.intake.policy,
            decision_source=sources.__getitem__,
            observation=durable.tail.observation,
        )
        if raw is None:
            # Publication can commit before its owner-journal acknowledgement.
            # Admissions already see the exact fence; roll forward that record.
            self.journal.put("request_tail_fence", state.tip_sha256, value)
        elif RequestTailObservation.model_validate_json(canonical_json_bytes(raw)) != value:
            raise ValueError("request tail changed its shared durable admission fence")
        return value

    def _retain_tail_fence(self, state, tail):
        publish_private_model(
            Path(self.tail_admission_binding.directory) / "tail.json",
            ServiceTailAdmissionFence(
                schema="umi-private-service-tail-admission-fence/1",
                cohort_sha256=self.cohort,
                policy_sha256=digest(self.intake.policy),
                recovery_tip_sha256=state.tip_sha256,
                catalog_sha256s=tuple(digest(c.catalog) for c in self.catalogs),
                tail=tail,
            ),
            maximum_bytes=128 * 1024,
        )
        self.journal.put("request_tail_fence", state.tip_sha256, tail)

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

    def request_opening(self, state):
        """Return the original certified request opening without changing it."""
        with self.intake._connection() as (_, store):
            history, _, sources, _, _ = self._state(store, state)
            opened = next(
                item.transition
                for item in history.transitions
                if item.transition.phase == "preparation"
                and item.transition.operation == "close_phase"
            )
            return sources[opened.evidence_sha256].observation

    def _seal_queues_locked(self, state, capture, history, decisions, fence, tail_fence):
        """Finish a validated fence while every catalog's admission lease is held."""
        first_fence = fence.observation if fence is not None else tail_fence.observation
        if execution_boundary(capture).block < first_fence.block:
            raise ValueError("request queue capture precedes its admission fence")
        owner_history = CohortOrderHistory(history=history, decisions=decisions)
        values = tuple(
            q.seal_locked(owner_history, capture, expected_tip_sha256=state.tip_sha256)
            for q in self.queues
        )
        if any(s.observation.block < first_fence.block for s in values):
            raise ValueError("request queue was sealed before its admission fence")
        return values

    def has_fence_hint(self, state) -> bool:
        """Schedule retained-fence replay before probes, without authorizing a seal.

        Only presence is needed here. seal_fenced must still authenticate the
        current native history and exact fence at the coordinator's capture.
        Include a published tail whose owner acknowledgement was interrupted.
        """
        with self.journal.read_transaction() as db:
            if any(
                self.journal.get_raw(kind, state.tip_sha256, db=db) is not None
                for kind in ("request_window_fence", "request_tail_fence")
            ):
                return True
        try:
            (Path(self.tail_admission_binding.directory) / "tail.json").lstat()
        except FileNotFoundError:
            return False
        return True

    def seal_fenced(self, state, capture: RegistrationCapture) -> None:
        """Finish an existing native fence before readiness can age this capture.

        This uses the coordinator's unchanged observation and never selects a
        new cutoff. Full terminal replay and independent closure review remain
        necessary before complete progress or a phase transition is possible.
        """
        self.epoch.identity()
        with self.intake._connection() as (db, store):
            history, decisions, sources, restored, prior = self._state(store, state)
            fence = self._fence(db, self._availability(store), state, restored, prior)
            tail_fence = self._tail_fence(state, history, sources)
            if fence is None and tail_fence is None:
                return
            with ExitStack() as leases:
                for queue in self.queues:
                    leases.enter_context(queue.journal.locked())
                self._seal_queues_locked(state, capture, history, decisions, fence, tail_fence)

    @contextmanager
    def prepare(self, state):
        """Own admissions before finality, then authenticate and sample native state.

        Intake must remain available during collection: fresh registration
        persistence calls its retention reader on another owned thread. Native
        replay runs after capture under all admission leases, so competing
        admission writers cannot advance the queue highwater while it replays.
        Preparation, sampling and cleanup must run on the same owned thread.
        """
        self.epoch.identity()
        with ExitStack() as leases:
            for queue in self.queues:
                leases.enter_context(queue.journal.locked())

            def sample(capture, *, serving, opened=None, seal_only=False):
                # Other intake owners use fail-fast admission leases and unwind
                # intake before retrying; they cannot wait on these leases.
                with self.intake._connection() as (db, store):
                    native = self._state(store, state)
                    # Retained fences remain authoritative even if readiness
                    # or opening-proof retrieval prevents new progress.
                    history, decisions, sources, restored, prior = native
                    fence = self._fence(db, self._availability(store), state, restored, prior)
                    tail_fence = self._tail_fence(state, history, sources)
                    if fence is not None or tail_fence is not None:
                        self._seal_queues_locked(
                            state, capture, history, decisions, fence, tail_fence
                        )
                    if seal_only:
                        return
                    return self._observe(
                        state,
                        capture,
                        serving=serving,
                        opened=opened,
                        db=db,
                        store=store,
                        native=native,
                        queues_locked=True,
                    )

            yield sample

    def observe(
        self,
        state,
        capture: RegistrationCapture,
        *,
        serving: bool,
        opened: HistoricalRegistration | None = None,
    ) -> CohortPhaseProgress:
        """Called by the owned runtime after probing admission/dispatch readiness."""
        self.epoch.identity()
        with self.intake._connection() as (db, store):
            return self._observe(
                state,
                capture,
                serving=serving,
                opened=opened,
                db=db,
                store=store,
                native=self._state(store, state),
                queues_locked=False,
            )

    @verification_owner_operation
    def _observe(
        self, state, capture, *, serving, opened=None, db, store, native, queues_locked
    ) -> CohortPhaseProgress:
        history, decisions, sources, restored, prior = native
        availability = self._availability(store)
        service = availability.observe(
            self.cohort, capture, serving=serving, genesis_signatures=history.genesis_signatures
        )
        self._service(db, availability, service, state, restored, prior)
        progress = pending_availability_progress(state, service)
        target = next(t.target_block for t in state.targets if t.phase == "requests")
        fence = self._fence(db, availability, state, restored, prior)
        tail_fence = self._tail_fence(state, history, sources)
        if tail_fence is not None and self.publish_inventory_cutoff is not None:
            self.publish_inventory_cutoff(tail_fence)
        ordinary_ready = (
            service.serving
            and service.observation.block >= target + service.unavailable_blocks - restored
        )
        tail_ready = (
            opened is not None
            and type(opened.timestamp_ms) is int
            and type(capture.provenance.get("timestamp_ms")) is int
            and capture.provenance["timestamp_ms"] - opened.timestamp_ms >= MINIMUM_REQUEST_OPEN_MS
        )
        if ordinary_ready or tail_ready:
            captured = ReplayObjectCollector(self._source, self.replay_bytes)
            common = dict(
                decision_source=sources.__getitem__,
                expected_tip_sha256=state.tip_sha256,
                current_block=service.observation.block,
            )
            by_catalog = {
                q.config.catalog_sha256: owner
                for q, owner in zip(self.queues, self.services, strict=True)
            }
            service_reads, paid_partials = {}, {}
            pending_partials = []
            admissions_locked = False

            benchmark_terminal = _observation_terminal_reader(self.terminals)

            def service_terminal(assignment):
                key = digest(assignment)
                if key not in service_reads:
                    owner = by_catalog[assignment.admission.catalog_sha256]
                    read = owner.read_locked if admissions_locked else owner.read
                    service_reads[key] = read(
                        assignment, preserve_completed=tail_ready, allow_partial=tail_ready
                    )
                return service_reads[key]

            # Hold every native admission lease across the exact accepted
            # inventory, threshold decision and seals. A nonqualifying tail
            # leaves admissions open, including while dispatch is unavailable.
            seals = None

            def seal_queues():
                return self._seal_queues_locked(
                    state, capture, history, decisions, fence, tail_fence
                )

            with ExitStack() as leases:
                inventories = tuple(
                    leases.enter_context(
                        nullcontext(q.closure_inventory_locked(capture=capture))
                        if queues_locked
                        else q.closure_inventory(capture=capture)
                    )
                    for q in self.queues
                )
                admissions_locked = True
                # A validated durable fence has already closed admissions.
                # Finish that original seal before the expensive terminal
                # replay can age its capture. The native monotonic check
                # remains in seal_locked, and every closure input below is
                # still replayed before complete progress can be retained.
                fenced_seals = (
                    seal_queues() if fence is not None or tail_fence is not None else None
                )
                common["intake_records"] = tuple(self.intake._records(db, history))
                orders = tuple(self.orders())
                tail = select_request_tail(
                    plan=history.plan,
                    history=history,
                    roster=self.roster,
                    orders=orders,
                    terminals=benchmark_terminal,
                    catalogs=self.catalogs,
                    seals=(),
                    service_terminals=service_terminal,
                    objects=captured,
                    policy=self.intake.policy,
                    opened=opened,
                    capture=capture,
                    accepted_assignments=(a for values in inventories for a in values),
                )
                if tail is not None and tail_fence is not None:
                    tail = tail.model_copy(
                        update={
                            "selected_observation": tail_fence.observation,
                            "selected_timestamp_ms": tail_fence.observed_timestamp_ms,
                        }
                    )
                if ordinary_ready or tail is not None:
                    if fence is None and tail_fence is None:
                        if any(q._retained_seal() is not None for q in self.queues):
                            raise ValueError("request queue lacks its original admission fence")
                        if ordinary_ready and tail is None:
                            self.journal.put("request_window_fence", state.tip_sha256, service)
                            fence = service
                    if tail is not None and tail_fence is None:
                        # Retain one cutoff even when the ordinary window
                        # was already fenced, so evaluator inventory can
                        # acknowledge a fixed observation across retries.
                        self._retain_tail_fence(state, tail)
                        tail_fence = tail
                        if self.publish_inventory_cutoff is not None:
                            self.publish_inventory_cutoff(tail_fence)
                    seals = fenced_seals if fenced_seals is not None else seal_queues()
                    if tail is not None:
                        durable_fence = ServiceTailAdmissionFence(
                            schema="umi-private-service-tail-admission-fence/1",
                            cohort_sha256=self.cohort,
                            policy_sha256=digest(self.intake.policy),
                            recovery_tip_sha256=state.tip_sha256,
                            catalog_sha256s=tuple(digest(c.catalog) for c in self.catalogs),
                            tail=tail_fence,
                        )
                        # Capture the signed native inventory while every
                        # original admission/journal lease remains held.
                        for inventory in inventories:
                            for assignment in inventory:
                                if service_terminal(assignment) is not None:
                                    continue
                                owner = by_catalog[assignment.admission.catalog_sha256]
                                try:
                                    paid_partials[digest(assignment)] = ServicePaidPartials(
                                        owner
                                    ).read_locked(assignment, durable_fence)
                                except PendingPaidPartialInventory:
                                    pending_partials.append(assignment.admission.work_sha256)
            admissions_locked = queues_locked
            if seals is not None:
                for seal in seals:
                    captured.retain(seal)
                try:
                    if pending_partials:
                        raise PendingServiceRequestClosure(tuple(pending_partials))
                    benchmark = build_request_closure(
                        self.roster,
                        orders,
                        benchmark_terminal,
                        captured,
                        self.intake.policy,
                        history,
                        service.observation,
                        tail=tail,
                        partial_source=self.partial_source,
                        inventory_source=self.inventory_source,
                        **common,
                    )
                    captured.retain(benchmark)
                    closure = build_service_request_closure(
                        benchmark,
                        self.roster,
                        self.catalogs,
                        seals,
                        service_terminal,
                        captured,
                        self.intake.policy,
                        history,
                        self.transport,
                        partial_source=lambda assignment: paid_partials.get(digest(assignment)),
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
                    progress, evidence = request_closure_progress(
                        closure, service, state, tail=tail
                    )
                    captured.retain(closure)
                    captured.retain(evidence)
                    # A complete progress record is written only after its entire
                    # native replay read-set is durable. Retry needs no inference.
                    for key, raw in captured.values.items():
                        self.journal.put("endpoint_replay_object", key, json.loads(raw))
        # Pending progress has no closure authority. Keep its review bytes
        # unchanged if this same finalized observation subsequently selects
        # a tail cutoff while evaluator inventories are still in transit.
        # The durable owner fence remains separate and is included once a
        # complete closure actually binds it into certified evidence.
        review_tail_fence = tail_fence if progress.completion == "complete" else None
        record = RequestProgressReviewRecord(
            schema="umi-request-progress-review/1"
            if review_tail_fence is None
            else "umi-request-progress-review/2",
            progress=progress,
            history_sha256=digest(history),
            service=service,
            fence=fence,
            tail_fence=review_tail_fence,
        )
        self.journal.put("request_progress", digest(progress), record)
        return progress

    def read(self, progress: CohortPhaseProgress) -> NativeRequestReview:
        return self._read(progress, self.objects)

    @verification_owner_operation
    def _read(
        self, progress: CohortPhaseProgress, objects: EndpointObjectSource
    ) -> NativeRequestReview:
        """The exporter wraps owned objects to retain the exact native read set."""
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
                tail_fence = self._tail_fence(state, history, sources)
                if (
                    (fence is None and tail_fence is None)
                    or record.fence != fence
                    or record.tail_fence != tail_fence
                ):
                    raise ValueError("request completion lacks its original admission fence")
                seals = tuple(q.retained_seal() for q in self.queues)
                first_fence = fence.observation if fence is not None else tail_fence.observation
                if any(s is None or s.observation.block < first_fence.block for s in seals):
                    raise ValueError("request completion changed an owner queue fence")
            else:
                seals = ()
            return replay_request_completion(
                record,
                history,
                decisions,
                policy=self.intake.policy,
                roster=self.roster,
                catalogs=self.catalogs,
                seals=seals,
                transport=self.transport,
                intake_records=records,
                objects=ReplayObjectCollector(objects, self.replay_bytes),
            )

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


def replay_request_completion(
    record: RequestProgressReviewRecord,
    history: CohortRecoveryHistory,
    decisions: tuple[CohortDecisionInput, ...],
    *,
    policy: CompetitionPolicy,
    roster: RecoverableRosterEvidence,
    catalogs: tuple[SignedServiceWorkCatalog, ...],
    seals: tuple[ServiceWorkSeal, ...],
    transport: ScoringPolicy,
    intake_records: tuple[tuple[str, bytes], ...],
    objects: EndpointObjectSource,
) -> NativeRequestReview:
    """Replay original terminal evidence after authenticating its owner and service history."""
    progress = record.progress
    sources = {digest(d): d for d in decisions}
    required = {
        t.transition.evidence_sha256
        for t in history.transitions
        if t.transition.requires_progress_evidence
    }
    if len(sources) != len(decisions) or set(sources) != required:
        raise ValueError("request review needs every original decision exactly once")
    state, restored, prior = replay_cohort_decisions(history, policy, sources.__getitem__)
    if (
        not isinstance(history.authority.authority, StandingCohortRecoveryAuthority)
        or state.phase != "requests"
        or record.history_sha256 != digest(history)
        or record.service.unavailable_blocks < max(restored, prior)
    ):
        raise ValueError("request review differs from its original standing history")
    expected = pending_availability_progress(state, record.service)
    tail = None
    inventory_observations = ()
    if progress.completion == "complete":
        fence = record.fence
        tail_fence = record.tail_fence
        target = next(t.target_block for t in state.targets if t.phase == "requests")
        if fence is not None:
            if (
                not fence.serving
                or fence.observation.block > record.service.observation.block
                or fence.observation.block < target + fence.unavailable_blocks - restored
            ):
                raise ValueError("request completion lacks its original compensated fence")
            pending_availability_progress(state, fence)
        if tail_fence is not None:
            review_request_tail(
                tail_fence,
                roster=roster,
                history=history,
                policy=policy,
                decision_source=sources.__getitem__,
                observation=tail_fence.observation,
            )
            if tail_fence.observation.block > record.service.observation.block:
                raise ValueError("request tail fence is ahead of its closure")
        if fence is None and tail_fence is None:
            raise ValueError("request completion lacks its original admission fence")
        first_fence = fence.observation if fence is not None else tail_fence.observation
        if any(s.observation.block < first_fence.block for s in seals):
            raise ValueError("request queue was sealed before its admission fence")
        closure = CohortServiceRequestClosure.model_validate_json(
            objects(progress.phase_result_sha256)
        )
        review_service_request_closure(
            closure,
            roster,
            objects,
            policy,
            history,
            transport,
            expected_catalogs=catalogs,
            expected_seals=seals,
            decision_source=sources.__getitem__,
            intake_records=intake_records,
            expected_tip_sha256=state.tip_sha256,
            current_block=progress.observed_at_block,
        )
        benchmark = CohortRequestClosure.model_validate_json(
            objects(closure.benchmark_closure_sha256)
        )
        tail = benchmark.tail
        inventory_observations = (
            *request_inventory_observations(benchmark, objects),
            *paid_partial_observations(closure, objects),
        )
        if tail_fence is not None and (
            tail is None
            or tail.opened_observation != tail_fence.opened_observation
            or tail.opened_timestamp_ms != tail_fence.opened_timestamp_ms
            or tail.original_hotkeys != tail_fence.original_hotkeys
            or tail.observed_timestamp_ms < tail_fence.observed_timestamp_ms
            or (tail.selected_observation or tail.observation) != tail_fence.observation
            or (tail.selected_timestamp_ms or tail.observed_timestamp_ms)
            != tail_fence.observed_timestamp_ms
        ):
            raise ValueError("request completion changed its original tail fence")
        expected, evidence = request_closure_progress(closure, record.service, state, tail=tail)
        retained = RequestClosureProgressEvidence.model_validate_json(
            objects(progress.evidence_sha256)
        )
        if retained != evidence:
            raise ValueError("request completion changed its original closure evidence")
    elif seals:
        raise ValueError("pending request review cannot claim a complete queue inventory")
    if expected != progress:
        raise ValueError("request progress differs from native completion")
    return NativeRequestReview(
        record,
        history,
        decisions,
        tuple(k for k, _ in intake_records),
        tail,
        inventory_observations,
    )
