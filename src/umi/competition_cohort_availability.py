"""Durable service observations for recoverable cohort windows.

The service owner supplies actual admission/dispatch readiness and captures from
its owned finality provider. A point-in-time health response cannot prove an
entire interval. Only consecutive ready observations in the same process epoch,
within the configured sampling gap, credit service. Unknown intervals restore
time to participants. These are local observations, not portable service proofs
or quorum certificates; independent progress reviewers must check their source.

The enclosing host owns the private SQLite connection and exclusive process
lock. Changing capacity may unblock collection without expiring any evidence.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated, Literal

from pydantic import Field

from .competition_chain import RegistrationCapture
from .competition_cohort_coordinator import CohortPhaseProgress
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_recovery import Block, CohortRecoveryState, Phase
from .competition_cohort_recovery_store import CohortRecoveryStore
from .competition_execution import ExecutionBoundary, execution_boundary
from .open_competition import CompetitionPolicy, Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CohortAvailabilityObservation(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-observation/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    recovery_tip_sha256: Hex32
    phase: Phase
    phase_started_block: Block
    sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    predecessor_sha256: Hex32 | None
    process_epoch: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    observation: ExecutionBoundary
    serving: bool
    unavailable_blocks: Block


def pending_availability_progress(
    state: CohortRecoveryState, receipt: CohortAvailabilityObservation
) -> CohortPhaseProgress:
    """Bind pending progress to retained local observations, before quorum review."""
    receipt = CohortAvailabilityObservation.model_validate_json(canonical_json_bytes(receipt))
    if (
        receipt.cohort_sha256 != state.cohort_sha256
        or receipt.recovery_tip_sha256 != state.tip_sha256
        or receipt.phase != state.phase
        or receipt.observation.block < state.observed_at_block
    ):
        raise ValueError("service observation belongs to another cohort phase or history")
    return CohortPhaseProgress(
        schema="umi-cohort-phase-progress/1",
        cohort_sha256=state.cohort_sha256,
        recovery_tip_sha256=state.tip_sha256,
        phase=receipt.phase,
        observed_at_block=receipt.observation.block,
        unavailable_blocks=receipt.unavailable_blocks,
        completion="pending",
        phase_result_sha256=None,
        evidence_sha256=digest(receipt),
    )


class CohortServiceAvailability:
    def __init__(
        self,
        store: CohortRecoveryStore,
        policy: CompetitionPolicy,
        *,
        maximum_sample_gap_blocks: int = 10,
        maximum_bytes: int = 256 * 1024**2,
    ):
        if type(maximum_sample_gap_blocks) is not int or not 1 <= maximum_sample_gap_blocks <= 300:
            raise ValueError("service sampling gap must be between 1 and 300 blocks")
        if type(maximum_bytes) is not int or not 1024 <= maximum_bytes <= 16 * 1024**3:
            raise ValueError("service observation capacity is outside bounds")
        self.store, self.db = store, store.db
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.gap, self.maximum_bytes = maximum_sample_gap_blocks, maximum_bytes
        # Reopening never credits unobserved time to the previous process.
        self.epoch = uuid.uuid4().hex
        with self._transaction():
            self.db.execute("""CREATE TABLE IF NOT EXISTS cohort_service_binding (
                id INTEGER PRIMARY KEY CHECK(id=1), sample_gap INTEGER NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS cohort_service_observations (
                cohort TEXT NOT NULL, phase TEXT NOT NULL, sequence INTEGER NOT NULL,
                body BLOB NOT NULL, PRIMARY KEY(cohort,phase,sequence))""")
            rows = self.db.execute("SELECT sample_gap FROM cohort_service_binding").fetchall()
            if not rows:
                if self.db.execute("SELECT 1 FROM cohort_service_observations LIMIT 1").fetchone():
                    raise ValueError("service observation binding is missing")
                self.db.execute("INSERT INTO cohort_service_binding VALUES (1,?)", (self.gap,))
            elif rows != [(self.gap,)]:
                raise ValueError("service sampling rule differs from retained observations")
        # Replayed on first access and whenever a different connection commits.
        self._cache: dict[
            tuple[str, str], tuple[tuple[int, int], CohortAvailabilityObservation]
        ] = {}

    def _version(self) -> tuple[int, int]:
        return self.db.execute("PRAGMA data_version").fetchone()[0], self.db.total_changes

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        if self.db.in_transaction:
            raise ValueError("service observations require their own transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            self._cache = {}
            raise

    def _unavailable(self, prior, current) -> int:
        start = current.phase_started_block
        block = current.observation.block
        if prior is None:
            return max(0, block - start)
        if (
            block < prior.observation.block
            or current.phase_started_block != prior.phase_started_block
            or (
                block == prior.observation.block
                and (current.observation.block_hash, current.observation.state_root)
                != (prior.observation.block_hash, prior.observation.state_root)
            )
        ):
            raise ValueError("service observation finality regressed or changed")
        elapsed = max(0, block - max(start, prior.observation.block))
        continuous = (
            current.process_epoch == prior.process_epoch
            and current.serving
            and prior.serving
            and block - prior.observation.block <= self.gap
        )
        return prior.unavailable_blocks + (0 if continuous else elapsed)

    def _last(self, cohort: str, phase: str) -> CohortAvailabilityObservation | None:
        version = self._version()
        cached = self._cache.get((cohort, phase))
        if cached is not None and cached[0] == version:
            return cached[1]
        prior = None
        for sequence, raw in self.db.execute(
            "SELECT sequence,substr(body,1,16385) FROM cohort_service_observations "
            "WHERE cohort=? AND phase=? ORDER BY sequence",
            (cohort, phase),
        ):
            receipt = CohortAvailabilityObservation.model_validate_json(raw)
            if (
                len(raw) > 16384
                or canonical_json_bytes(receipt) != raw
                or receipt.cohort_sha256 != cohort
                or receipt.phase != phase
                or receipt.sequence != sequence
                or sequence != (1 if prior is None else prior.sequence + 1)
                or receipt.predecessor_sha256 != (None if prior is None else digest(prior))
                or receipt.unavailable_blocks != self._unavailable(prior, receipt)
            ):
                raise ValueError("retained service observations are incomplete or inconsistent")
            prior = receipt
        if prior is not None:
            self._cache[(cohort, phase)] = (version, prior)
        return prior

    def observe(
        self,
        cohort: str,
        capture: RegistrationCapture,
        *,
        serving: bool,
        genesis_signatures: tuple[Signature, ...],
    ) -> CohortAvailabilityObservation:
        if type(serving) is not bool:
            raise ValueError("service readiness must be an actual boolean")
        observation = execution_boundary(capture)
        with self._transaction():
            history = self.store.read_history(cohort, genesis_signatures=genesis_signatures)
            if history.plan.policy_sha256 != digest(self.policy):
                raise ValueError("service observation policy differs from the admitted cohort")
            tip = digest(
                history.transitions[-1].transition if history.transitions else history.genesis
            )
            view = verify_cohort_history(
                history, self.policy, expected_tip_sha256=tip, current_block=observation.block
            )
            state = view.state
            if state.phase in {"complete", "revoked"}:
                raise ValueError("terminal cohorts do not accept new service observations")
            start = (
                history.plan.not_before_block
                if not view.closed_phases
                else view.closed_phases[-1].observed_at_block
            )
            prior = self._last(cohort, state.phase)
            receipt = CohortAvailabilityObservation(
                schema="umi-cohort-service-observation/1",
                cohort_sha256=cohort,
                recovery_tip_sha256=tip,
                phase=state.phase,
                phase_started_block=start,
                sequence=1 if prior is None else prior.sequence + 1,
                predecessor_sha256=None if prior is None else digest(prior),
                process_epoch=self.epoch,
                observation=observation,
                serving=serving,
                unavailable_blocks=0,
            )
            receipt = receipt.model_copy(
                update={"unavailable_blocks": self._unavailable(prior, receipt)}
            )
            if prior is not None and all(
                getattr(prior, key) == getattr(receipt, key)
                for key in ("recovery_tip_sha256", "process_epoch", "observation", "serving")
            ):
                return prior
            raw = canonical_json_bytes(receipt)
            used = self.db.execute(
                "SELECT COALESCE(SUM(length(body)),0) FROM cohort_service_observations"
            ).fetchone()[0]
            if used + len(raw) > self.maximum_bytes:
                raise OSError("service observation capacity exhausted; preserve state and retry")
            self.db.execute(
                "INSERT INTO cohort_service_observations VALUES (?,?,?,?)",
                (cohort, state.phase, receipt.sequence, raw),
            )
            version = self._version()
        self._cache[(cohort, receipt.phase)] = (version, receipt)
        return receipt
