"""Publish certified request originals into the recurring settlement service.

The owner commits certification before delivery. Missing files or lost write
acknowledgements retry the same originals; only the final immutable history file
makes the handoff discoverable. This port runs beside the native request owner.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from .competition_chain import RegistrationCapture
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import CohortIntakePublisher, history_tip
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_request_phase import (
    NativeRequestProgressSource,
    RequestProgressReviewRecord,
)
from .competition_cohort_request_progress import request_closure_progress
from .competition_cohort_reward_package import MAX_PACKAGE_OBJECTS, ReplayObjectCollector
from .competition_cohort_service_closure import (
    CohortServiceRequestClosure,
    verify_certified_service_request_closure,
)
from .competition_cohort_settlement_config import SettlementOriginalSources
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_execution import ExecutionBoundary
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import private_path, publish_private_model


@dataclass(frozen=True)
class CertifiedRequestExport:
    history: CohortOrderHistory
    objects: dict[str, bytes]


class CohortRequestSettlementPublisher:
    def __init__(
        self,
        source: NativeRequestProgressSource,
        capture: Callable[[], Awaitable[RegistrationCapture]],
        decisions: Callable[[str, str], Awaitable[CohortDecisionInput]],
        publish_proof: Callable[[ExecutionBoundary], Awaitable[None]],
        *,
        sources: SettlementOriginalSources,
        history_directory: Path,
    ):
        self.source, self.capture, self.publish_proof = source, capture, publish_proof
        if (
            sources.intake != source.intake.config
            or sources.eligible_tracks != source.intake.tracks
        ):
            raise ValueError("request delivery requires the selected settlement intake owner")
        self.history_directory = Path(private_path(str(history_directory)))
        if any(
            self.history_directory.is_relative_to(Path(p))
            or Path(p).is_relative_to(self.history_directory)
            for p in sources.stores()
        ):
            raise ValueError("request handoff and original stores must be disjoint")
        self.files = SettlementEvidenceFiles(Path(sources.objects_directory))
        self.intake = CohortIntakePublisher(source.intake, capture, decisions)
        source.journal.put(
            "request_delivery_binding",
            source.cohort,
            {
                "sources": sources.model_dump(mode="json", by_alias=True),
                "history_directory": str(self.history_directory),
            },
        )

    async def __call__(self, history: CohortRecoveryHistory) -> None:
        if digest(history.plan) != self.source.cohort:
            raise ValueError("request publication belongs to another cohort")
        await self.intake(history)
        observed = await self.capture()
        exported = await run_owned_thread(self._export, observed.snapshot.block)
        if exported is None:
            return
        await run_owned_thread(self._objects, exported)
        for decision in exported.history.decisions:
            await self.publish_proof(decision.observation)
        # Recheck the selected authority after asynchronous proof delivery.
        observed = await self.capture()
        await run_owned_thread(self._commit, exported, observed.snapshot.block)

    def _export(self, current_block: int) -> CertifiedRequestExport | None:
        owner = self.source
        with owner.intake._connection() as (db, store):
            history = store.published_history(owner.cohort)
            view = verify_cohort_history(
                history,
                owner.intake.policy,
                expected_tip_sha256=history_tip(history),
                current_block=current_block,
            )
            if view.state.phase == "revoked":
                raise ValueError("request publication authority is revoked")
            closed = next((t for t in view.closed_phases if t.phase == "requests"), None)
            if closed is None:
                return None
            decisions = {
                t.transition.evidence_sha256: store.source(
                    owner.cohort, t.transition.evidence_sha256, CohortDecisionInput
                )
                for t in history.transitions
            }
            progress = decisions[closed.evidence_sha256].progress.progress
            record = RequestProgressReviewRecord.model_validate(
                owner.journal.get("request_progress", digest(progress))
            )
            index = next(i for i, t in enumerate(history.transitions) if t.transition == closed)
            prefix = history.model_copy(update={"transitions": history.transitions[:index]})
            if record.progress != progress or record.history_sha256 != digest(prefix):
                raise ValueError("request publication changes its original progress")
            state, restored, prior = replay_cohort_decisions(
                prefix, owner.intake.policy, decisions.__getitem__
            )
            availability = owner._availability(store)
            owner._service(db, availability, record.service, state, restored, prior)
            fence = owner._fence(db, availability, state, restored, prior)
            seals = tuple(q.retained_seal() for q in owner.queues)
            if (
                fence is None
                or record.fence != fence
                or any(s is None or s.observation.block < fence.observation.block for s in seals)
            ):
                raise ValueError("request publication changed an owner queue fence")
            objects = ReplayObjectCollector(owner.objects, owner.replay_bytes)
            closure = CohortServiceRequestClosure.model_validate_json(
                objects(progress.phase_result_sha256)
            )
            if request_closure_progress(closure, record.service, state)[0] != progress:
                raise ValueError("request publication changed its retained service evidence")
            records = tuple(owner.intake._records(db, history))
            if (
                len(records) > MAX_PACKAGE_OBJECTS
                or sum(len(raw) for _, raw in records) > owner.replay_bytes
            ):
                raise ValueError("request publication intake export exceeds its bound")
            verify_certified_service_request_closure(
                closure,
                owner.roster,
                objects,
                owner.intake.policy,
                history,
                owner.transport,
                expected_catalogs=owner.catalogs,
                expected_seals=seals,
                decision_source=decisions.__getitem__,
                intake_records=records,
                expected_tip_sha256=history_tip(history),
                current_block=current_block,
            )
            for seal in seals:
                objects.retain(seal)
            initial = history.model_copy(update={"transitions": history.transitions[: index + 1]})
            return CertifiedRequestExport(
                CohortOrderHistory(
                    history=initial,
                    decisions=tuple(
                        decisions[t.transition.evidence_sha256] for t in initial.transitions
                    ),
                ),
                objects.values,
            )

    def _objects(self, exported: CertifiedRequestExport) -> None:
        for key in sorted(exported.objects):
            self.files.publish(key, exported.objects.__getitem__)

    def _commit(self, exported: CertifiedRequestExport, current_block: int) -> None:
        owner, initial = self.source, exported.history.history
        with owner.intake._connection() as (_, store):
            current = store.published_history(owner.cohort)
            view = verify_cohort_history(
                current,
                owner.intake.policy,
                expected_tip_sha256=history_tip(current),
                current_block=current_block,
            )
            if (
                view.state.phase == "revoked"
                or current.model_copy(
                    update={"transitions": current.transitions[: len(initial.transitions)]}
                )
                != initial
            ):
                raise ValueError("request publication authority changed during delivery")
            publish_private_model(
                self.history_directory / (owner.cohort + ".json"),
                exported.history,
                maximum_bytes=8 * 1024**2,
            )
