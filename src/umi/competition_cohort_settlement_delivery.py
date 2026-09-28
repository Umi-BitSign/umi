"""Fixed private slots for native settlement votes and replay objects.

Delivery never supplies authority. Quality signing uses the original local
execution journal; receivers verify every vote against their own native replay.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from functools import partial
from pathlib import Path

from .competition_cohort_endpoint_archive import MAX_ARCHIVE_OBJECT_BYTES, read_endpoint_object
from .competition_cohort_execution_journal import CohortExecutionJournal
from .competition_cohort_order_signer import order_slot
from .competition_cohort_orders import SignedRecoverableEvaluationOrder
from .competition_cohort_quality_signing import SignedClosedQualityVote, sign_closed_quality
from .competition_cohort_reward_package import RewardPackageObject
from .competition_cohort_service_certification import ServiceAllocationVote, sign_service_allocation
from .competition_cohort_settlement_inputs import ReplayedSettlementInputs
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread
from .open_competition import Signature, digest, identity, verify_signature
from .private_files import ensure_private_directory, private_path, publish_private_model
from .private_files import read_private_model as read
from .protocol import canonical_json_bytes

MAX_DELIVERY_BYTES = MAX_ARCHIVE_OBJECT_BYTES + 1024


class SettlementEvidenceFiles:
    def __init__(self, root: Path):
        self.root = Path(private_path(str(root)))
        ensure_private_directory(self.root)

    def _path(self, key: str) -> Path:
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("invalid settlement object identity")
        return self.root / (key + ".json")

    def __call__(self, key: str) -> bytes:
        item = read(self._path(key), RewardPackageObject, maximum_bytes=MAX_DELIVERY_BYTES)
        if item.sha256 != key or digest(item.value) != key:
            raise ValueError("settlement object delivery changed its identity")
        return read_endpoint_object(lambda _: canonical_json_bytes(item.value), key)

    def publish(self, key: str, source) -> None:
        raw = read_endpoint_object(source, key)
        publish_private_model(
            self._path(key),
            RewardPackageObject(sha256=key, value=json.loads(raw)),
            maximum_bytes=MAX_DELIVERY_BYTES,
        )


class SettlementResultVotes:
    def __init__(
        self,
        inputs: ReplayedSettlementInputs,
        *,
        hotkey: str,
        executions: tuple[CohortExecutionJournal, ...],
        journal: RoundJournal,
        sign: Callable[..., Awaitable[Signature]],
        inbox: Path,
        outbox: Path,
    ):
        self.inputs, self.hotkey, self.account = inputs, hotkey, identity(hotkey)
        if inputs.quality is None or inputs.service is None:
            raise ValueError("result votes require certified reference reveal")
        self.executions, self.journal, self.sign = executions, journal, sign
        self.cohort = digest(inputs.inputs.history.plan)
        self.inbox, self.outbox = (Path(private_path(str(p))) for p in (inbox, outbox))
        if self.inbox.is_relative_to(self.outbox) or self.outbox.is_relative_to(self.inbox):
            raise ValueError("settlement vote stores must be disjoint")
        if self.account not in inputs.service.groups or any(
            identity(e.config.signer) != self.account or e.policy != inputs.quality.policy
            for e in executions
        ):
            raise ValueError("settlement signing requires this evaluator's own execution journals")
        for path in (self.inbox, self.outbox):
            ensure_private_directory(path)

    def _quality_path(self, root, submission, account):
        return root / "quality" / self.cohort / submission / (account + ".json")

    def _service_path(self, root, account):
        return root / "service" / self.cohort / (account + ".json")

    def _execution(self, result):
        order = SignedRecoverableEvaluationOrder.model_validate_json(
            read_endpoint_object(self.inputs.objects, result.order_sha256)
        )
        slot, found = order_slot(order.order), []
        for owner in self.executions:
            if owner.journal.get("assignment", slot) is not None:
                assignment = owner.assignment(slot)
                if assignment.certificate != order:
                    raise ValueError("owned execution differs from the reviewed order")
                found.append(owner)
        if not found:
            raise FileNotFoundError("original local evaluator execution is not available")
        if len(found) != 1:
            raise ValueError("multiple journals claim the same evaluator execution")
        return found[0], slot

    async def publish(self) -> None:
        for participant in self.inputs.quality.closure.participants:
            result = await run_owned_thread(
                self.inputs.quality.outcome, participant.submission_sha256
            )
            if self.account not in {identity(r.evaluator_hotkey) for r in result.runs}:
                continue
            owner, slot = await run_owned_thread(self._execution, result)
            with owner.locked(slot):
                vote = await sign_closed_quality(owner, slot, self.inputs.quality, self.sign)
            await run_owned_thread(
                partial(
                    publish_private_model,
                    self._quality_path(self.outbox, result.submission_sha256, self.account),
                    vote,
                    maximum_bytes=MAX_DELIVERY_BYTES,
                )
            )
        vote = await sign_service_allocation(
            self.journal, self.inputs.service, self.hotkey, self.sign
        )
        await run_owned_thread(
            partial(
                publish_private_model,
                self._service_path(self.outbox, self.account),
                vote,
                maximum_bytes=MAX_DELIVERY_BYTES,
            )
        )

    def collect(
        self,
    ) -> tuple[tuple[SignedClosedQualityVote, ...], tuple[ServiceAllocationVote, ...]]:
        quality, service = [], []
        for participant in self.inputs.quality.closure.participants:
            result = self.inputs.quality.outcome(participant.submission_sha256)
            for run in result.runs:
                account = identity(run.evaluator_hotkey)
                root = self.outbox if account == self.account else self.inbox
                try:
                    vote = read(
                        self._quality_path(root, result.submission_sha256, account),
                        SignedClosedQualityVote,
                        maximum_bytes=MAX_DELIVERY_BYTES,
                    )
                except FileNotFoundError:
                    continue
                if vote.result != result or identity(vote.signature.hotkey) != account:
                    raise ValueError(
                        "quality delivery differs from native result or assigned signer"
                    )
                verify_signature(vote.result, vote.signature)
                quality.append(vote)
        for account in sorted(self.inputs.service.groups):
            root = self.outbox if account == self.account else self.inbox
            try:
                vote = read(
                    self._service_path(root, account),
                    ServiceAllocationVote,
                    maximum_bytes=MAX_DELIVERY_BYTES,
                )
            except FileNotFoundError:
                continue
            if identity(vote.signature.hotkey) != account:
                raise ValueError("service delivery changed its signer")
            self.inputs.service.check_vote(vote)
            service.append(vote)
        return tuple(quality), tuple(service)
