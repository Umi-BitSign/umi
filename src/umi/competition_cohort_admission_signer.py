"""Independent historical admission review with restartable, exact-body signing.

The host owns an unlocked signer, the finality provider's lifecycle and the
authoritative history source. A miner or peer cannot choose that history source.
A single returned vote is not an admission quorum or a reward authorization.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from functools import partial

from .competition_cohort_admission_journal import (
    CohortAdmissionJournal,
    CohortAdmissionVote,
    admission_slot,
)
from .competition_cohort_admission_review import review_cohort_participation
from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_intake_records import read_participation
from .competition_cohort_intake_seal import CohortIntakeSeal, verify_intake_closure
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    CohortParticipantAdmission,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_historical_registration import HistoricalRegistrationProvider
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class AdmissionHistory:
    history: CohortRecoveryHistory
    seal: CohortIntakeSeal | None = None
    closure: CohortDecisionInput | None = None


def check_selected(raw: bytes, source: AdmissionHistory, policy: CompetitionPolicy, block: int):
    """After intake closes, sign only a record selected by its certified seal."""
    history = source.history
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=history_tip(history), current_block=block
    )
    if view.state.phase == "revoked":
        raise ValueError("cohort admission signing was revoked")
    if view.state.phase == "intake":
        return
    if source.seal is None or source.closure is None:
        raise FileNotFoundError("certified intake selection is not yet available")
    seal = CohortIntakeSeal.model_validate_json(canonical_json_bytes(source.seal))
    verify_intake_closure(seal, view.closure("intake"), source.closure, policy)
    record = read_participation(raw)
    sub = record.request.signed_submission.submission
    if not any(
        s.record_sha256 == digest(record)
        and s.consent_sha256 == record.proposed_admission.consent_sha256
        and s.submission_sha256 == digest(sub)
        and (identity(s.hotkey), s.track, s.sequence)
        == (identity(sub.hotkey), sub.track, sub.sequence)
        for s in seal.selected
    ):
        raise ValueError("admission record was not selected by certified intake closure")


class CohortAdmissionSigner:
    def __init__(
        self,
        journal: CohortAdmissionJournal,
        provider: HistoricalRegistrationProvider,
        history: Callable[[str], Awaitable[AdmissionHistory]],
        sign: Callable[[CohortParticipantAdmission], Awaitable[Signature]],
    ):
        if provider.policy != journal.policy:
            raise ValueError("admission signer finality belongs to another policy")
        self.journal, self.provider, self.history, self.sign = journal, provider, history, sign
        self.serial = asyncio.Lock()

    async def recover(self, slot: str) -> CohortAdmissionVote:
        saved = await run_owned_thread(self.journal.load, slot)
        if saved is None:
            raise FileNotFoundError("no retained admission signing intent")
        return await self.attest(saved[1], registration_archive=(saved[2], saved[3]))

    async def attest(
        self,
        raw: bytes,
        *,
        registration_archive: tuple[bytes, bytes] | None = None,
    ) -> CohortAdmissionVote:
        slot = admission_slot(raw)
        record = read_participation(raw)
        cohort = record.proposed_admission.cohort_sha256
        if cohort not in self.journal.cohorts:
            raise ValueError("admission signer is not configured for this cohort")
        async with self.serial:
            # flock is nonblocking. Every disk/signing operation drains before
            # releasing it, including when the service is cancelled.
            with self.journal.journal.locked():
                saved = await run_owned_thread(self.journal.load, slot)
                if saved is not None:
                    if saved[1] != raw:
                        raise ValueError(
                            "admission slot already reserved for different original bytes"
                        )
                    if registration_archive is not None and registration_archive != saved[2:4]:
                        raise ValueError(
                            "admission retry changed its retained registration evidence"
                        )
                    if saved[4] is not None:
                        # Returning a committed historical signature does not
                        # require an online RPC or create a new signing action.
                        return saved[4]
                    registration_archive = saved[2:4]
                if registration_archive is None:
                    registration_archive = await self.provider.retained_archive(record.observation)
                source = await self.history(cohort)
                result = await review_cohort_participation(
                    raw,
                    source.history,
                    self.journal.policy,
                    self.provider,
                    expected_tip_sha256=history_tip(source.history),
                    registration_archive=registration_archive,
                )
                current = await self.history(cohort)
                if current.history != source.history:
                    raise OSError("admission history changed during review; retry unchanged")
                check_selected(
                    raw, current, self.journal.policy, result.registration.replayed_at.block_number
                )
                await run_owned_thread(
                    self.journal.remember_history,
                    current.history,
                    result.registration.replayed_at.block_number,
                )
                await run_owned_thread(
                    partial(self.journal.reserve, result.admission, raw, *registration_archive)
                )
                signature = await wait_for_owned(
                    self.sign(result.admission),
                    timeout=self.journal.config.signing_timeout_seconds,
                )
                vote = CohortAdmissionVote(admission=result.admission, signature=signature)
                return await run_owned_thread(self.journal.commit, slot, vote)


def certify_admission(
    votes: Sequence[CohortAdmissionVote], policy: CompetitionPolicy
) -> AttestedCohortParticipantAdmission:
    """Assemble matching individual votes and enforce independent policy groups."""
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if not 1 <= len(votes) <= 64:
        raise ValueError("admission certificate vote count is outside bounds")
    canonical = tuple(
        CohortAdmissionVote.model_validate_json(canonical_json_bytes(v)) for v in votes
    )
    admission = canonical[0].admission
    if any(v.admission != admission for v in canonical):
        raise ValueError("admission certificate contains different bodies")
    signatures = tuple(sorted((v.signature for v in canonical), key=lambda s: identity(s.hotkey)))
    verify_recovery_quorum(admission, signatures, policy)
    return AttestedCohortParticipantAdmission(admission=admission, signatures=signatures)
