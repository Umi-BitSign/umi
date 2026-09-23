"""Native intake progress and completion fencing for recoverable cohorts.

The enclosing service owns readiness probes and finality. This observer retains
their samples under the same lock as consent admission, then freezes membership
only after authenticated outage compensation allows closure. It does not sign
progress: independent certifiers must review the retained service and consent
evidence before authorizing a transition.
"""

from __future__ import annotations

from dataclasses import dataclass

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
    replay_cohort_decisions,
)
from .competition_cohort_intake import CohortIntake, cohort_intake_bytes, history_tip
from .competition_cohort_intake_seal import CohortIntakeSeal, EmptyCohortIntake, build_intake_seal
from .competition_execution import execution_boundary
from .competition_store import AdmissionCapacityError
from .open_competition import digest
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class NativeIntakeProgress:
    progress: CohortPhaseProgress
    service: CohortAvailabilityObservation
    seal: CohortIntakeSeal | None


class CohortIntakePhaseObserver:
    def __init__(
        self,
        intake: CohortIntake,
        *,
        maximum_sample_gap_blocks: int = 10,
        maximum_observation_bytes: int = 256 * 1024**2,
    ):
        self.intake = intake
        self.epoch = CohortServiceEpoch()
        self.gap, self.maximum_bytes = maximum_sample_gap_blocks, maximum_observation_bytes

    def observe(
        self,
        cohort: str,
        capture: RegistrationCapture,
        *,
        serving: bool,
        expected_tip_sha256: str,
    ) -> NativeIntakeProgress:
        if type(serving) is not bool:
            raise ValueError("intake readiness must be an actual boolean")
        self.epoch.identity()  # Forked workers must own a new observer lifetime.
        self.intake._allowed(cohort)
        observation = execution_boundary(capture)
        with self.intake._connection() as (db, store):
            history = store.published_history(cohort)
            if history_tip(history) != expected_tip_sha256:
                raise ValueError(
                    "intake history changed before observing; retry current generation"
                )
            state, restored, prior_unavailable = replay_cohort_decisions(
                history,
                self.intake.policy,
                lambda key: store.source(cohort, key, CohortDecisionInput),
            )
            if state.phase != "intake" or observation.block < state.observed_at_block:
                raise ValueError("intake phase is closed or observation regressed")
            availability = CohortServiceAvailability(
                store,
                self.intake.policy,
                maximum_sample_gap_blocks=self.gap,
                maximum_bytes=self.maximum_bytes,
                epoch=self.epoch,
            )
            db.execute("""CREATE TABLE IF NOT EXISTS cohort_intake_service_seals (
                cohort TEXT NOT NULL, tip TEXT NOT NULL, body BLOB NOT NULL,
                PRIMARY KEY(cohort,tip))""")
            seal = self.intake._seal(db, history, expected_tip_sha256)
            if seal is not None:
                row = db.execute(
                    "SELECT substr(body,1,16385) FROM cohort_intake_service_seals "
                    "WHERE cohort=? AND tip=?",
                    (cohort, expected_tip_sha256),
                ).fetchone()
                if row is None:
                    raise ValueError("intake seal lacks retained service observations")
                service = CohortAvailabilityObservation.model_validate_json(row[0])
                retained = db.execute(
                    "SELECT substr(body,1,16385) FROM cohort_service_observations "
                    "WHERE cohort=? AND phase='intake' AND sequence=?",
                    (cohort, service.sequence),
                ).fetchone()
                # Replay the retained chain; a copied digest alone is insufficient.
                availability._last(cohort, "intake")
                if (
                    len(row[0]) > 16384
                    or canonical_json_bytes(service) != row[0]
                    or retained != row
                    or service.observation != seal.observation
                    or service.cohort_sha256 != cohort
                    or service.recovery_tip_sha256 != expected_tip_sha256
                    or service.phase != "intake"
                    or not service.serving
                ):
                    raise ValueError("intake seal differs from its service observations")
            else:
                previous = availability._last(cohort, "intake")
                if (
                    previous is not None
                    and db.execute(
                        "SELECT 1 FROM cohort_intake_service_seals WHERE cohort=? AND body=?",
                        (cohort, canonical_json_bytes(previous)),
                    ).fetchone()
                ):
                    # A certified extension reopened a fenced generation. Its
                    # closed interval was unavailable even within one process.
                    availability.observe(
                        cohort,
                        capture,
                        serving=False,
                        genesis_signatures=history.genesis_signatures,
                    )
                ready = (
                    serving
                    and db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone()[0]
                    < self.intake.capacity.maximum_records
                    and cohort_intake_bytes(db) < self.intake.capacity.maximum_bytes
                )
                service = availability.observe(
                    cohort,
                    capture,
                    serving=ready,
                    genesis_signatures=history.genesis_signatures,
                )
            if service.unavailable_blocks < max(restored, prior_unavailable):
                raise ValueError("intake availability regressed behind certified progress")
            earliest = state.targets[0].target_block + service.unavailable_blocks - restored
            if seal is None and (not service.serving or observation.block < earliest):
                return NativeIntakeProgress(
                    pending_availability_progress(state, service), service, None
                )
            if seal is None:
                # Hold the admission lock from the observation through the seal.
                # Both records commit together; a crash cannot strand an
                # irreversible fence without its availability evidence.
                try:
                    seal = build_intake_seal(
                        history,
                        self.intake.policy,
                        observation,
                        capture.snapshot,
                        self.intake._records(db, history),
                        expected_tip_sha256=expected_tip_sha256,
                    )
                except EmptyCohortIntake:
                    return NativeIntakeProgress(
                        pending_availability_progress(state, service), service, None
                    )
                raw = canonical_json_bytes(seal)
                if len(raw) > 4 * 1024**2:
                    raise AdmissionCapacityError("intake seal needs additional durable capacity")
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        "INSERT INTO cohort_intake_seals VALUES (?,?,?)",
                        (cohort, expected_tip_sha256, raw),
                    )
                    db.execute(
                        "INSERT INTO cohort_intake_service_seals VALUES (?,?,?)",
                        (cohort, expected_tip_sha256, canonical_json_bytes(service)),
                    )
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
            # Validate the actual fence time, not a later fresh signing time.
            if seal.observation.block < earliest or observation.block < seal.observation.block:
                raise ValueError("intake was sealed before restoring unavailable service")
            progress = CohortPhaseProgress(
                schema="umi-cohort-phase-progress/1",
                cohort_sha256=cohort,
                recovery_tip_sha256=expected_tip_sha256,
                phase="intake",
                observed_at_block=observation.block,
                unavailable_blocks=service.unavailable_blocks,
                completion="complete",
                phase_result_sha256=digest(seal),
                evidence_sha256=digest(seal),
            )
            return NativeIntakeProgress(progress, service, seal)
