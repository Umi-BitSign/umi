"""Durable round preparation under the native intake/admission owner lock."""

from __future__ import annotations

import threading

from .competition_chain import RegistrationCapture
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_preparation import PreparedCohortRound, prepare_cohort_round
from .competition_cohort_recovery import cohort_tracks
from .competition_cohort_roster import RecoverableRosterParticipant
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_store import AdmissionCapacityError, CompetitionStore
from .open_competition import digest
from .protocol import canonical_json_bytes


class CohortPreparation:
    def __init__(
        self,
        queue: CohortAdmissionQueue,
        promotion_store: CompetitionStore,
        *,
        maximum_bytes: int = 64 * 1024**2,
        maximum_promotion_bytes: int = 16 * 1024**2,
    ):
        if digest(queue.policy) != digest(promotion_store.policy):
            raise ValueError("round preparation promotion store uses another policy")
        if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 256 * 1024**2:
            raise ValueError("invalid prepared round byte bound")
        if (
            type(maximum_promotion_bytes) is not int
            or not 1 <= maximum_promotion_bytes <= 16 * 1024**2
        ):
            raise ValueError("invalid prepared promotion byte bound")
        self.queue, self.promotion = queue, promotion_store
        self.maximum_bytes, self.maximum_promotion_bytes = maximum_bytes, maximum_promotion_bytes
        # A retained round is immutable for one certified history generation.
        # Its full replay verifies every submission and can be deliberately
        # expensive, so serialize that replay separately from the intake lock
        # and reuse its canonical result.  Fresh history and retained-row checks
        # below still fence closure, revocation and local state replacement.
        self._retained_lock = threading.Lock()
        self._retained_cache: dict[tuple[str, str], bytes] = {}

    def prepare(
        self, cohort: str, capture: RegistrationCapture, *, expected_tip_sha256: str
    ) -> PreparedCohortRound:
        """Return the original committed round; missing admissions remain pending.

        The host owns the capture provider and these stores. This method does not read
        another running process's database, sign a phase, or reveal evaluation labels.
        """
        observation = execution_boundary(capture)
        return self._prepare(
            cohort,
            observation,
            expected_tip_sha256=expected_tip_sha256,
            current_block=observation.block,
        )

    def retained(
        self, cohort: str, *, expected_tip_sha256: str, current_block: int
    ) -> PreparedCohortRound:
        """Replay a retained round without selecting or creating a new one."""
        key = (cohort, expected_tip_sha256)
        with self._retained_lock:
            raw = self._retained_cache.get(key)
            if raw is not None:
                cached = PreparedCohortRound.model_validate_json(raw)
                queue, intake = self.queue, self.queue.intake
                intake._allowed(cohort)
                with queue._connection() as (db, store):
                    history = store.published_history(cohort)
                    if history_tip(history) != expected_tip_sha256:
                        raise ValueError(
                            "intake history changed before preparation; retry current history"
                        )
                    view = verify_cohort_history(
                        history,
                        queue.policy,
                        expected_tip_sha256=expected_tip_sha256,
                        current_block=current_block,
                    )
                    if view.state.phase in {"intake", "revoked"}:
                        raise ValueError(
                            "round preparation requires certified intake and active authority"
                        )
                    row = db.execute(
                        "SELECT digest,substr(body,1,?),observed "
                        "FROM cohort_prepared_rounds WHERE cohort=?",
                        (self.maximum_bytes + 1, cohort),
                    ).fetchone()
                    if (
                        row is None
                        or row[1] != raw
                        or row[0] != digest(cached)
                        or row[2] != cached.observation.block
                    ):
                        self._retained_cache.pop(key, None)
                        raise ValueError("retained preparation changed after verified replay")
                return cached
            result = self._prepare(
                cohort,
                None,
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
            )
            self._retained_cache[key] = canonical_json_bytes(result)
            return result

    def _prepare(
        self,
        cohort: str,
        observation: ExecutionBoundary | None,
        *,
        expected_tip_sha256: str,
        current_block: int,
    ) -> PreparedCohortRound:
        queue, intake = self.queue, self.queue.intake
        intake._allowed(cohort)
        with queue._connection() as (db, store):
            history = store.published_history(cohort)
            if history_tip(history) != expected_tip_sha256:
                raise ValueError("intake history changed before preparation; retry current history")
            view = verify_cohort_history(
                history,
                queue.policy,
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
            )
            if view.state.phase in {"intake", "revoked"}:
                raise ValueError("round preparation requires certified intake and active authority")
            closing = view.closure("intake")
            seal = intake._seal(db, history, closing.predecessor_sha256)
            if seal is None:
                raise FileNotFoundError("certified intake seal is not retained yet")
            db.execute(
                "CREATE TABLE IF NOT EXISTS cohort_prepared_rounds "
                "(cohort TEXT PRIMARY KEY, digest TEXT NOT NULL, "
                "observed INTEGER NOT NULL, body BLOB NOT NULL)"
            )
            row = db.execute(
                "SELECT digest,substr(body,1,?),observed "
                "FROM cohort_prepared_rounds WHERE cohort=?",
                (self.maximum_bytes + 1, cohort),
            ).fetchone()
            previous = None
            if row is not None:
                if len(row[1]) > self.maximum_bytes:
                    raise ValueError("retained preparation exceeds its byte bound")
                previous = PreparedCohortRound.model_validate_json(row[1])
                if (
                    canonical_json_bytes(previous) != row[1]
                    or digest(previous) != row[0]
                    or previous.observation.block != row[2]
                ):
                    raise ValueError("retained preparation changed its canonical bytes or identity")
            elif view.state.phase != "preparation":
                raise FileNotFoundError("original preparation must be restored after certification")
            elif observation is None:
                raise FileNotFoundError("original prepared round is not retained yet")
            members = []
            for selected in sorted(seal.selected, key=lambda s: s.submission_sha256):
                _, record = queue._record(db, store, cohort, selected.consent_sha256)
                certificate = queue._certificate(db, record)
                if certificate is None:
                    raise FileNotFoundError("sealed participant admission is not certified yet")
                members.append(RecoverableRosterParticipant(record=record, admission=certificate))
            promotion = (
                self.promotion.reviewed_promotion_head(
                    cohort, maximum_bytes=self.maximum_promotion_bytes
                )
                if previous is None
                else self.promotion.reviewed_promotion_at(
                    cohort,
                    previous.promotion_head.promotion_sha256,
                    maximum_bytes=self.maximum_promotion_bytes,
                )
            )
            result = prepare_cohort_round(
                history,
                queue.policy,
                seal,
                tuple(members),
                promotion,
                observation if previous is None else previous.observation,
                eligible_tracks=cohort_tracks(history.plan, tuple(sorted(set(intake.tracks)))),
                decision_source=lambda key: store.source(cohort, key, CohortDecisionInput),
                intake_records=intake._records(db, history),
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
            )
            raw = canonical_json_bytes(result)
            if previous is not None:
                if raw != row[1]:
                    raise ValueError("round preparation changed its original retained inputs")
                return result
            if len(raw) > self.maximum_bytes:
                raise AdmissionCapacityError("round preparation needs additional durable capacity")
            with queue._transaction(db):
                db.execute(
                    "INSERT INTO cohort_prepared_rounds VALUES (?,?,?,?)",
                    (cohort, digest(result), result.observation.block, raw),
                )
            return result
