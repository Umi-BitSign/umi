"""Durable round preparation and authority-checked read-only reuse."""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, replace

from .competition_chain import RegistrationCapture
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_preparation import PreparedCohortRound, prepare_cohort_round
from .competition_cohort_preparation_publication import PreparedRoundPublication
from .competition_cohort_recovery import cohort_tracks
from .competition_cohort_roster import RecoverableRosterParticipant
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_store import AdmissionCapacityError, CompetitionStore
from .host_memory_request_bounds import check_stage_json
from .host_memory_runtime import authorize_memory
from .open_competition import digest, digest_canonical_bytes
from .protocol import canonical_json_bytes


@dataclass(frozen=True, slots=True)
class _VerifiedRound:
    raw: bytes
    sha256: str
    value: PreparedCohortRound
    tip_sha256: str
    round_sha256: str


class CohortPreparation:
    def __init__(
        self,
        queue: CohortAdmissionQueue,
        promotion_store: CompetitionStore,
        *,
        maximum_bytes: int = 64 * 1024**2,
        maximum_promotion_bytes: int = 16 * 1024**2,
        runtime_adoption=None,
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
        self.runtime_adoption = runtime_adoption
        if runtime_adoption is not None:
            from .competition_cohort_recovery import verify_recovery_authority
            from .competition_evaluation_runtime import (
                SignedCohortEvaluationRuntimeAdoption,
                verify_runtime_adoption_selection,
            )

            self.runtime_adoption = SignedCohortEvaluationRuntimeAdoption.model_validate_json(
                canonical_json_bytes(runtime_adoption)
            )
            authority_sha256 = self.runtime_adoption.adoption.authority_sha256
            cohort = next(
                (key for key, value in queue.intake.bindings.items() if value == authority_sha256),
                None,
            )
            if cohort is None:
                raise ValueError("runtime amendment selects no configured intake authority")
            history = queue.intake.history(cohort)
            verify_recovery_authority(history.authority, queue.policy)
            verify_runtime_adoption_selection(
                self.runtime_adoption, policy=queue.policy, authority=history.authority.authority
            )
        # A retained round is immutable after the certified intake selection.
        # Its full replay verifies every submission and can be deliberately
        # expensive, so serialize that replay separately from the intake lock
        # and reuse its canonical result.  Fresh history and retained-row checks
        # below still fence closure, revocation and local state replacement.
        self._retained_lock = threading.Lock()
        self._retained_cache: OrderedDict[str, _VerifiedRound] = OrderedDict()
        self._retained_bytes = 0

    def prepare(
        self, cohort: str, capture: RegistrationCapture, *, expected_tip_sha256: str
    ) -> PreparedCohortRound:
        """Return the original committed round; missing admissions remain pending.

        The host owns the capture provider and these stores. This method does not read
        another running process's database, sign a phase, or reveal evaluation labels.
        """
        authorize_memory(None, cohort, "preparation")
        observation = execution_boundary(capture)
        return self._prepare(
            cohort,
            observation,
            expected_tip_sha256=expected_tip_sha256,
            current_block=observation.block,
        ).value

    def prepare_publication(self, cohort, capture, *, expected_tip_sha256):
        """Prepare and retain one private snapshot without a second preparation pass."""
        authorize_memory(None, cohort, "preparation")
        observation = execution_boundary(capture)
        saved = self._retained(
            cohort,
            expected_tip_sha256=expected_tip_sha256,
            current_block=observation.block,
            observation=observation,
        )
        return self._publication(saved)

    def retained(
        self, cohort: str, *, expected_tip_sha256: str, current_block: int
    ) -> PreparedCohortRound:
        """Replay a retained round without exposing the owner's private object."""
        return self._retained(
            cohort, expected_tip_sha256=expected_tip_sha256, current_block=current_block
        ).value.model_copy(deep=True)

    def retained_publication(self, cohort, *, expected_tip_sha256, current_block):
        """Internal immutable bytes after the same fresh authority/source fences."""
        saved = self._retained(
            cohort, expected_tip_sha256=expected_tip_sha256, current_block=current_block
        )
        return self._publication(saved)

    @staticmethod
    def _publication(saved):
        round_ = saved.value.roster.round
        return PreparedRoundPublication(
            saved.raw,
            saved.sha256,
            saved.round_sha256,
            round_.cohort_sha256,
            round_.sequence,
            round_.incumbent_model_sha256,
        )

    def _retained(self, cohort, *, expected_tip_sha256, current_block, observation=None):
        key = cohort
        with self._retained_lock:
            cached = self._retained_cache.get(key)
            if cached is not None:
                queue, intake = self.queue, self.queue.intake
                intake._allowed(cohort)
                # This path only checks an existing immutable round. Keep its
                # current authority and row in one native read-only snapshot;
                # do not queue behind the admission owner's exclusive gate.
                with intake._connection(prefer_history=True) as (db, store):
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
                    closing = view.closure("intake")
                    if (
                        digest(closing) != cached.value.roster.round.intake_closure_sha256
                        or digest(history.plan) != cached.value.roster.round.cohort_sha256
                        or not closing.observed_at_block
                        <= cached.value.observation.block
                        <= current_block
                    ):
                        raise ValueError("retained preparation differs from current intake history")
                    row = db.execute(
                        "SELECT digest,substr(body,1,?),observed "
                        "FROM cohort_prepared_rounds WHERE cohort=?",
                        (self.maximum_bytes + 1, cohort),
                    ).fetchone()
                    if (
                        row is None
                        or row[1] != cached.raw
                        or row[0] != cached.sha256
                        or row[2] != cached.value.observation.block
                    ):
                        self._retained_bytes -= len(self._retained_cache.pop(key).raw)
                        raise ValueError("retained preparation changed after verified replay")
                    if cached.tip_sha256 != expected_tip_sha256:
                        # A new signed tip must replay its timing/decision
                        # evidence, but cannot alter the already verified
                        # original participants, baseline or observation.
                        decisions: dict[str, CohortDecisionInput] = {}

                        def decision(sha: str) -> CohortDecisionInput:
                            if sha not in decisions:
                                value = store.source(cohort, sha, CohortDecisionInput)
                                if digest(value) != sha:
                                    raise ValueError("preparation decision changed its identity")
                                decisions[sha] = value
                            return decisions[sha]

                        state, _, _ = replay_cohort_decisions(history, queue.policy, decision)
                        if state != view.state:
                            raise ValueError(
                                "preparation history differs from native decision replay"
                            )
                        if view.state.phase != "preparation":
                            prepared = view.closure("preparation")
                            if (
                                cached.value.observation.block > prepared.observed_at_block
                                or decision(
                                    prepared.evidence_sha256
                                ).progress.progress.phase_result_sha256
                                != cached.round_sha256
                            ):
                                raise ValueError(
                                    "prepared round differs from certified preparation"
                                )
                        cached = replace(cached, tip_sha256=expected_tip_sha256)
                        self._retained_cache[key] = cached
                self._retained_cache.move_to_end(key)
                return cached
            saved = self._prepare(
                cohort,
                observation,
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
            )
            self._remember(key, saved)
            return saved

    def _remember(self, key, saved):
        previous = self._retained_cache.pop(key, None)
        if previous is not None:
            self._retained_bytes -= len(previous.raw)
        while self._retained_cache and self._retained_bytes + len(saved.raw) > self.maximum_bytes:
            _, old = self._retained_cache.popitem(last=False)
            self._retained_bytes -= len(old.raw)
        self._retained_cache[key] = saved
        self._retained_bytes += len(saved.raw)

    def _prepare(
        self,
        cohort: str,
        observation: ExecutionBoundary | None,
        *,
        expected_tip_sha256: str,
        current_block: int,
    ) -> _VerifiedRound:
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
                check_stage_json(row[1], kind="declaration")
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
                eligible_tracks=cohort_tracks(
                    history.plan,
                    tuple(sorted(set(intake.tracks))),
                    adoption=view.state.model_delivery_adoption,
                ),
                decision_source=lambda key: store.source(cohort, key, CohortDecisionInput),
                intake_records=intake._records(db, history),
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
                runtime_adoption=(
                    previous.roster.round.runtime_adoption
                    if previous is not None
                    else (
                        self.runtime_adoption
                        if self.runtime_adoption is not None
                        and history.plan.sequence
                        >= self.runtime_adoption.adoption.first_cohort_sequence
                        else None
                    )
                ),
            )
            raw = canonical_json_bytes(result)
            if previous is not None:
                if raw != row[1]:
                    raise ValueError("round preparation changed its original retained inputs")
                return _VerifiedRound(
                    raw, row[0], result, expected_tip_sha256, digest(result.roster.round)
                )
            if len(raw) > self.maximum_bytes:
                raise AdmissionCapacityError("round preparation needs additional durable capacity")
            prepared_sha = digest_canonical_bytes(raw)
            with queue._transaction(db):
                db.execute(
                    "INSERT INTO cohort_prepared_rounds VALUES (?,?,?,?)",
                    (cohort, prepared_sha, result.observation.block, raw),
                )
            return _VerifiedRound(
                raw,
                prepared_sha,
                result,
                expected_tip_sha256,
                digest(result.roster.round),
            )
