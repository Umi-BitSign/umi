"""Recurring settlement using owned history, original inputs and evaluator journals."""

from __future__ import annotations

import asyncio
import copy
import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress
from functools import partial
from pathlib import Path

from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortProgressIntent,
    CohortRecoveryCoordinator,
    replay_cohort_decisions,
)
from .competition_cohort_endpoint_archive import JournalEndpointObjects
from .competition_cohort_execution_journal import CohortExecutionJournal
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_recovery import RecoverableCohortPlan
from .competition_cohort_recovery_store import CohortRecoveryStore
from .competition_cohort_settlement import CohortSettlement
from .competition_cohort_settlement_assembly import assemble_settlement_inputs
from .competition_cohort_settlement_config import SettlementServiceConfig
from .competition_cohort_settlement_controller import CohortSettlementPhases, SettlementInputBatch
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles, SettlementResultVotes
from .competition_cohort_settlement_exchange import PHASES, SettlementReviewExchange
from .competition_cohort_settlement_inputs import (
    SettlementInputPackage,
    publish_settlement_inputs,
    replay_settlement_inputs,
)
from .competition_cohort_settlement_proofs import SettlementRegistrationFiles
from .competition_cohort_settlement_signing import SettlementPhaseSigner
from .competition_execution import execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_round_journal import RoundJournal
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .open_competition import Signature, digest, identity
from .private_files import ensure_private_directory, publish_private_model, read_private_model
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)
MAX_HISTORY_BYTES = 8 * 1024**2


class CohortSettlementService:
    """One approved cohort. The host keeps its SQLite connection on this thread."""

    def __init__(
        self,
        config: SettlementServiceConfig,
        plan: RecoverableCohortPlan,
        *,
        store: CohortRecoveryStore,
        provider: HistoricalRegistrationProvider,
        proofs: SettlementRegistrationFiles,
        promotion: CompetitionStore,
        executions: tuple[CohortExecutionJournal, ...],
        sign: Callable[..., Awaitable[Signature]],
    ):
        if plan not in config.series.cohorts or provider.policy != config.policy:
            raise ValueError("settlement service differs from its selected series or provider")
        self.config, self.plan = config, plan
        for directory in (config.exchange_inbox, config.exchange_outbox):
            ensure_private_directory(Path(directory))
        self.cohort, self.store, self.provider = digest(plan), store, provider
        self.proofs, self.promotion, self.executions, self.sign = (
            proofs,
            promotion,
            executions,
            sign,
        )
        root = Path(config.state_directory) / digest(config.series) / self.cohort
        binding = {
            "schema": "umi-cohort-settlement-owner/1",
            "series": digest(config.series),
            "cohort": self.cohort,
            "signer": identity(config.signer_hotkey),
            "role": config.role,
            "proposer": identity(config.proposer_hotkey),
        }
        self.journal = RoundJournal(
            root / "results",
            binding,
            maximum_bytes=config.maximum_state_bytes,
            maximum_rounds=65536,
        )
        self.signing = RoundJournal(
            root / "signing",
            binding,
            maximum_bytes=config.maximum_state_bytes,
            maximum_rounds=65536,
        )
        self.data = self.votes = self.phases = self.exchange = self.controller = None
        self.batch_votes = ((), ())
        self.completed_requests = {}
        self.last_report = None
        self.published_tip = None
        self.package = None
        self.reference = False

    async def _handoff(self):
        # This host-selected publication is mandatory, even after restart.
        # A remote input package cannot choose the current history for itself.
        value = await run_owned_thread(
            partial(
                read_private_model,
                Path(self.config.history_directory) / (self.cohort + ".json"),
                CohortOrderHistory,
                maximum_bytes=MAX_HISTORY_BYTES,
            )
        )
        history = value.history
        if history.plan != self.plan or history.authority != self.config.series.recovery:
            raise ValueError("settlement handoff changes the selected cohort or authority")
        decisions = value.inputs()
        if self.store.has_published_history(self.cohort):
            current = self.store.published_history(self.cohort)
            if (
                current.genesis != history.genesis
                or current.genesis_signatures != history.genesis_signatures
            ):
                raise ValueError("settlement handoff changes its original admission")
            shared = min(len(current.transitions), len(history.transitions))
            if current.transitions[:shared] != history.transitions[:shared]:
                raise ValueError("settlement handoff forks owned history")
            if len(history.transitions) <= len(current.transitions):
                return current
        capture = await self.provider.collect()
        block = execution_boundary(capture).block
        verify_cohort_history(
            history,
            self.config.policy,
            expected_tip_sha256=history_tip(history),
            current_block=block,
        )
        replay_cohort_decisions(history, self.config.policy, decisions.__getitem__)
        # Independently authenticate every original decision's finalized capture.
        # Missing archives remain retryable; age alone never rejects them.
        for decision in decisions.values():
            raw, metadata = await self.proofs.read(decision.observation)
            reviewed = await self.provider.review_archive(decision.observation, raw, metadata)
            if reviewed.original != decision.observation:
                raise ValueError("settlement handoff proof changed its original observation")
        self.store.admit(
            history.plan,
            history.authority,
            self.config.policy,
            admitted_at_block=history.genesis.admitted_at_block,
        )
        for value in decisions.values():
            self.store.retain_source(self.cohort, value)
        self.store.publish_history(history, self.config.policy, current_block=block)
        return history

    def _decisions(self, key):
        return self.store.source(self.cohort, key, CohortDecisionInput)

    def _history_deliveries(self):
        root = Path(self.config.exchange_inbox) / "history" / self.cohort
        values, used = [], 0
        if not root.exists():
            return ()
        for path in root.iterdir():
            if path.suffix != ".json":
                continue
            if len(values) >= 128:
                raise ValueError("settlement history delivery exceeds its slot bound")
            value = read_private_model(path, CohortOrderHistory, maximum_bytes=MAX_HISTORY_BYTES)
            used += len(canonical_json_bytes(value))
            if used > self.config.maximum_package_bytes:
                raise ValueError("settlement history delivery exceeds its byte bound")
            if path.stem != history_tip(value.history):
                raise ValueError("settlement history delivery changed its identity")
            values.append(value)
        return tuple(sorted(values, key=lambda v: len(v.history.transitions)))

    async def _receive_history(self, current):
        """Import certified extensions of the independently selected handoff.

        A reviewer needs reference certification before producing result votes;
        waiting for an evidence-vote request would deadlock that handoff. The
        private file supplies originals, never an unchecked readiness signal.
        """
        if self.config.role != "reviewer":
            return current
        selected = None
        for value in await run_owned_thread(self._history_deliveries):
            incoming = value.history
            anchor = current if selected is None else selected.history
            shared = min(len(anchor.transitions), len(incoming.transitions))
            if (
                incoming.plan != anchor.plan
                or incoming.authority != anchor.authority
                or incoming.genesis != anchor.genesis
                or incoming.genesis_signatures != anchor.genesis_signatures
                or incoming.transitions[:shared] != anchor.transitions[:shared]
            ):
                raise ValueError("settlement history delivery forks its selected handoff")
            if len(incoming.transitions) > len(anchor.transitions):
                selected = value
        if selected is None:
            return current
        history, decisions = selected.history, selected.inputs()
        block = execution_boundary(await self.provider.collect()).block
        verify_cohort_history(
            history,
            self.config.policy,
            expected_tip_sha256=history_tip(history),
            current_block=block,
        )
        replay_cohort_decisions(history, self.config.policy, decisions.__getitem__)
        for decision in decisions.values():
            raw, metadata = await self.proofs.read(decision.observation)
            reviewed = await self.provider.review_archive(decision.observation, raw, metadata)
            if reviewed.original != decision.observation:
                raise ValueError("settlement history proof changed its original observation")
        for decision in decisions.values():
            self.store.retain_source(self.cohort, decision)
        self.store.publish_history(history, self.config.policy, current_block=block)
        return history

    async def _start(self, history):
        decisions = {
            t.transition.evidence_sha256: self._decisions(t.transition.evidence_sha256)
            for t in history.transitions
            if t.transition.operation != "revoke"
        }
        state, _ = self.store.status(self.cohort)
        reference = state.phase == "reference_reveal"
        kind = "settlement_reference_input" if reference else "settlement_input"
        filename = self.cohort + ("-reference.json" if reference else ".json")
        path = Path(self.config.inputs_directory) / filename
        prior = self.journal.get(kind, "original")
        block = state.observed_at_block
        if reference:
            intent = self.store.progress_intent(self.cohort, state.tip_sha256, CohortProgressIntent)
            block = (
                intent.observation.block
                if intent is not None
                else execution_boundary(await self.provider.collect()).block
            )
        try:
            package = await run_owned_thread(
                partial(
                    read_private_model,
                    path,
                    SettlementInputPackage,
                    maximum_bytes=self.config.maximum_package_bytes,
                )
            )
        except FileNotFoundError:
            # Once reviewed, a missing original must be restored, never rebuilt
            # from a possibly different source set or newer selection.
            if prior is not None or self.config.original_sources is None:
                raise
            logger.info(
                "settlement_inputs cohort=%s phase=%s status=assembling", self.cohort, state.phase
            )
            package = await run_owned_thread(
                partial(
                    assemble_settlement_inputs,
                    self.config.original_sources,
                    self.config.policy,
                    self.config.manifest.requirement(self.cohort),
                    history,
                    decisions.__getitem__,
                    current_block=block,
                    maximum_bytes=self.config.maximum_package_bytes,
                    retained_objects=JournalEndpointObjects(self.journal),
                )
            )
            await run_owned_thread(
                partial(
                    publish_settlement_inputs,
                    path,
                    package,
                    maximum_bytes=self.config.maximum_package_bytes,
                )
            )
            logger.info(
                "settlement_inputs cohort=%s phase=%s status=retained", self.cohort, state.phase
            )
        if prior is not None and prior != {"sha256": digest(package)}:
            raise ValueError("settlement inputs changed after their first native review")
        self.data = await run_owned_thread(
            partial(
                replay_settlement_inputs,
                package,
                self.config.policy,
                self.config.manifest.requirement(self.cohort),
                history,
                expected_package_sha256=digest(package),
                expected_tip_sha256=history_tip(history),
                current_block=block,
                current_decisions=decisions.__getitem__,
                maximum_bytes=self.config.maximum_package_bytes,
            )
        )
        self.journal.put(kind, "original", {"sha256": digest(package)})
        self.package = package
        delivered = SettlementEvidenceFiles(Path(self.config.exchange_inbox) / "objects")

        def objects(key):
            try:
                return self.data.objects(key)
            except (FileNotFoundError, KeyError):
                return delivered(key)

        owner = CohortSettlement(
            plan=self.plan,
            authority=self.config.series.recovery,
            requirement=self.config.manifest.requirement(self.cohort),
            policy=self.config.policy,
            journal=self.journal,
            promotion_store=self.promotion,
            objects=objects,
            decisions=self._decisions,
            pulses=self.data.pulses,
            output_directory=Path(self.config.settlement_directory),
            maximum_promotion_bytes=self.config.maximum_promotion_bytes,
            maximum_package_bytes=self.config.maximum_package_bytes,
        )
        self.votes = (
            None
            if reference
            else SettlementResultVotes(
                self.data,
                hotkey=self.config.signer_hotkey,
                executions=self.executions,
                journal=self.signing,
                sign=self.sign,
                inbox=Path(self.config.exchange_inbox),
                outbox=Path(self.config.exchange_outbox),
            )
        )
        signer = SettlementPhaseSigner(
            self.signing,
            self.config.policy,
            self.config.signer_hotkey,
            self.sign,
            timeout_seconds=self.config.signing_timeout_seconds,
        )
        phases = CohortSettlementPhases(
            owner=owner,
            store=self.store,
            signer=signer,
            source=self.source,
            peers=(),
        )
        exchange = SettlementReviewExchange(
            phases,
            proposer=self.config.proposer_hotkey,
            inbox=Path(self.config.exchange_inbox),
            outbox=Path(self.config.exchange_outbox),
            proofs=self.proofs,
        )
        if self.config.role == "coordinator":
            phases.peers = tuple(
                exchange.peer(e.hotkey)
                for e in self.config.policy.evaluators
                if identity(e.hotkey) != identity(self.config.signer_hotkey)
            )
            self.controller = CohortRecoveryCoordinator(
                self.store,
                self.cohort,
                self.config.policy,
                history.genesis_signatures,
                self.provider,
                None,
                phases.certify,
                self._publish_history,
                sample_progress=phases.sample,
                attest_progress=phases.attest,
            )
        self.phases, self.exchange = phases, exchange
        self.reference = reference

    def source(self):
        return SettlementInputBatch(
            self.data.inputs.model_copy(
                update={"history": self.store.published_history(self.cohort)}
            ),
            self.data.intake,
            *self.batch_votes,
        )

    async def _publish_history(self, history):
        sources = tuple(
            self._decisions(t.transition.evidence_sha256)
            for t in history.transitions
            if t.transition.operation != "revoke"
        )
        await run_owned_thread(
            partial(
                publish_private_model,
                Path(self.config.exchange_outbox)
                / "history"
                / self.cohort
                / (history_tip(history) + ".json"),
                CohortOrderHistory(history=history, decisions=sources),
                maximum_bytes=MAX_HISTORY_BYTES,
            )
        )

    async def tick(self) -> str:
        self.provider.ensure_observer_running()
        history = await self._receive_history(await self._handoff())
        state, _ = self.store.status(self.cohort)
        if state.phase == "revoked":
            return "revoked"
        if self.published_tip == state.tip_sha256:
            return "package_published"
        if self.phases is None or self.reference != (state.phase == "reference_reveal"):
            await self._start(history)
        if self.config.role == "coordinator":
            await run_owned_thread(
                partial(
                    publish_settlement_inputs,
                    Path(self.config.exchange_outbox)
                    / "inputs"
                    / (self.cohort + ("-reference.json" if self.reference else ".json")),
                    self.package,
                    maximum_bytes=self.config.maximum_package_bytes,
                )
            )
        if self.votes is not None:
            await self.votes.publish()
            self.batch_votes = await run_owned_thread(self.votes.collect)
        if self.config.role == "reviewer":
            for phase in PHASES:
                for kind in ("progress", "transition"):
                    try:
                        request = await run_owned_thread(self.exchange.request, phase, kind)
                    except FileNotFoundError:
                        continue
                    key, sha = (phase, kind), digest(request)
                    if key in self.completed_requests and self.completed_requests[key] != sha:
                        raise ValueError("completed settlement request changed")
                    closed = any(
                        t.transition.phase == phase and t.transition.operation == "close_phase"
                        for t in self.store.published_history(self.cohort).transitions
                    )
                    if closed:
                        self.exchange._check(request)
                        try:
                            self.phases.signer.retained_vote(self.exchange._body(request))
                        except FileNotFoundError:
                            # A late reviewer can accept a quorum certificate
                            # without having voted itself. It must not roll back
                            # to generate a redundant vote for that closed phase.
                            self.completed_requests[key] = sha
                            continue
                    await self.exchange.review(request)
                    self.completed_requests[key] = sha
            return "reviewing"
        if state.phase in PHASES:
            await self.controller.tick()
            return self.store.status(self.cohort)[0].phase
        if state.phase not in ("first_admission", "complete"):
            raise ValueError("settlement handoff has not completed reference reveal")
        # Package replay may take time; snapshot SQLite inputs before moving it
        # to an owned worker thread, just as the phase reviewer does.
        batch = self.source()
        decisions = {
            t.transition.evidence_sha256: self._decisions(t.transition.evidence_sha256)
            for t in batch.inputs.history.transitions
            if t.transition.operation != "revoke"
        }
        owner = copy.copy(self.phases.owner)
        owner.decisions = decisions.__getitem__
        result = await run_owned_thread(
            partial(
                owner.advance,
                batch.inputs,
                batch.intake,
                expected_tip_sha256=state.tip_sha256,
                current_block=state.observed_at_block,
                quality_votes=batch.quality_votes,
                service_votes=batch.service_votes,
            )
        )
        await self._publish_history(batch.inputs.history)
        if result.status == "package_published":
            self.published_tip = state.tip_sha256
        return result.status

    async def run(self, stop: asyncio.Event):
        while not stop.is_set():
            self.provider.ensure_observer_running()
            try:
                report = await self.tick()
            except Exception as error:
                report = "retry:" + type(error).__name__
            if report != self.last_report:
                logger.info(
                    "settlement_status cohort=%s role=%s status=%s",
                    self.cohort,
                    self.config.role,
                    report,
                )
                self.last_report = report
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.config.poll_seconds)
