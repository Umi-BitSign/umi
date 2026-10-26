"""Durable phase progress votes and exact-decision certificates.

Each signer owns its journal, native evidence reviewer and unlocked hotkey.
Committed votes can be returned offline. Unfinished votes recheck the original
evidence; a delay never changes a reserved body or creates a final expiry.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import Field, model_validator

from .competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
)
from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_intake_review import IntakeProgressReviewRecord
from .competition_cohort_model_delivery_api import require_adoption as require_model_adoption
from .competition_cohort_preparation_phase import PreparationProgressReviewRecord
from .competition_cohort_recovery import (
    CohortRecoveryTransition,
    SignedCohortRecoveryTransition,
    verify_recovery_quorum,
)
from .competition_cohort_request_phase import RequestProgressReviewRecord
from .competition_cohort_request_rule_api import require_adoption
from .competition_cohort_suite_adoption_api import require_adoption as require_suite_adoption
from .competition_progress import log_phase
from .competition_round_journal import RoundJournal
from .competition_work_progress import review_scope
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import (
    CompetitionPolicy,
    Hotkey,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class PhaseProgressReviewer(Protocol):
    policy: CompetitionPolicy
    cohorts: tuple[CohortIntakeBinding, ...]

    async def review(
        self, progress: CohortPhaseProgress
    ) -> (
        IntakeProgressReviewRecord | PreparationProgressReviewRecord | RequestProgressReviewRecord
    ): ...

    async def decision(self, transition, evidence: CohortDecisionInput) -> str: ...


class CohortProgressSignerConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-progress-signer-config/1"] = Field(alias="schema")
    directory: Directory
    policy_sha256: Hex32
    signer: Hotkey
    cohorts: Annotated[tuple[CohortIntakeBinding, ...], Field(min_length=1, max_length=512)]
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    signing_timeout_seconds: Annotated[int, Field(ge=1, le=1200)] = 300

    @model_validator(mode="after")
    def ordered(self):
        keys = tuple(item.cohort_sha256 for item in self.cohorts)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("progress signer cohorts must be unique and ordered")
        return self


class CohortProgressSigner:
    def __init__(
        self,
        config,
        reviewer: PhaseProgressReviewer,
        sign,
    ):
        self.config = CohortProgressSignerConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = reviewer.policy
        if self.config.policy_sha256 != digest(self.policy) or identity(self.config.signer) not in {
            identity(e.hotkey) for e in self.policy.evaluators
        }:
            raise ValueError("progress signer is not authorized by the selected policy")
        if self.config.cohorts != reviewer.cohorts:
            raise ValueError("progress signer and owned intake have different cohort authorities")
        self.reviewer, self.sign = reviewer, sign
        self.serial = asyncio.Lock()
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(
                mode="json", by_alias=True, exclude={"maximum_bytes", "signing_timeout_seconds"}
            ),
            maximum_rounds=65536,
            maximum_bytes=self.config.maximum_bytes,
        )

    def _saved(self, kind, slot, body):
        with self.journal.transaction() as db:
            intent = self.journal.get(kind + "_intent", slot, db=db)
            signature = self.journal.get(kind + "_vote", slot, db=db)
        if intent is not None and intent["body"] != body.model_dump(mode="json", by_alias=True):
            raise ValueError("cohort signing slot is reserved for another body")
        if signature is None:
            return intent, None
        if intent is None:
            raise ValueError("cohort signature lacks its retained intent")
        signature = Signature.model_validate_json(canonical_json_bytes(signature))
        self._check(body, signature)
        return intent, signature

    def _check(self, body, signature):
        if identity(signature.hotkey) != identity(self.config.signer):
            raise ValueError("cohort signature came from another signer")
        verify_signature(body, signature)

    async def _vote(self, kind, slot, body, review):
        async with self.serial:
            with self.journal.locked():
                _intent, signature = await run_owned_thread(self._saved, kind, slot, body)
                if signature is not None:
                    return signature
                with review_scope(kind, body.cohort_sha256, reads=0):
                    reviewed = await review()
                expected = {"body": body.model_dump(mode="json", by_alias=True), "review": reviewed}
                # Original reviewed observations remain in the owned intake and
                # historical archive. The signing journal pins that exact review.
                await run_owned_thread(self.journal.put, kind + "_intent", slot, expected)
                signature = await wait_for_owned(
                    self.sign(body), timeout=self.config.signing_timeout_seconds
                )
                self._check(body, signature)
                await run_owned_thread(self.journal.put, kind + "_vote", slot, signature)
                return signature

    @log_phase("cohort_progress_vote")
    async def attest(self, progress):
        async def review():
            record = await self.reviewer.review(progress)
            return record.model_dump(mode="json", by_alias=True)

        return await self._vote("phase_progress", digest(progress), progress, review)

    @log_phase("cohort_decision_vote")
    async def certify(self, transition, evidence: CohortDecisionInput):
        transition = CohortRecoveryTransition.model_validate_json(canonical_json_bytes(transition))
        if not transition.requires_progress_evidence:
            raise ValueError("ordinary phase signing requires a progress-backed transition")
        evidence = CohortDecisionInput.model_validate_json(canonical_json_bytes(evidence))

        async def review():
            progress = evidence.progress.progress
            retained, signature = await run_owned_thread(
                self._saved, "phase_progress", digest(progress), progress
            )
            if signature is None:
                record = await self.reviewer.review(progress)
                source = record.model_dump(mode="json", by_alias=True)
            else:
                # This signer's own committed exact-progress review survives
                # restart. The separate decision review below checks the current
                # owner history and proposed transition; repeating the original
                # proof pass adds no new authority.
                source = retained["review"]
                if source.get("progress") != progress.model_dump(mode="json", by_alias=True):
                    raise ValueError("retained phase review differs from its signed progress")
            history = await self.reviewer.decision(transition, evidence)
            if history != source["history_sha256"]:
                raise OSError("cohort history changed before decision signing")
            return {
                "source": source,
                "decision": evidence.model_dump(mode="json", by_alias=True),
            }

        # At most one transition per predecessor, even across a lost reply or
        # concurrent proposal. Progress samples may advance before reservation.
        slot = digest({"cohort": transition.cohort_sha256, "tip": transition.predecessor_sha256})
        return await self._vote("phase_decision", slot, transition, review)

    @log_phase("cohort_request_tail_adoption_vote")
    async def certify_request_tail_adoption(self, transition):
        transition = require_adoption(transition)
        if transition.cohort_sha256 not in {c.cohort_sha256 for c in self.config.cohorts}:
            raise ValueError("request-rule vote is outside configured cohorts")

        async def review():
            return await self.reviewer.adoption(transition)

        # Ordinary closure and policy adoption cannot both consume this tip.
        slot = digest({"cohort": transition.cohort_sha256, "tip": transition.predecessor_sha256})
        return await self._vote("phase_decision", slot, transition, review)

    @log_phase("cohort_model_delivery_adoption_vote")
    async def certify_model_delivery_adoption(self, transition):
        transition = require_model_adoption(transition)
        if transition.cohort_sha256 not in {c.cohort_sha256 for c in self.config.cohorts}:
            raise ValueError("model delivery vote is outside configured cohorts")

        async def review():
            return await self.reviewer.model_delivery_adoption(transition)

        slot = digest({"cohort": transition.cohort_sha256, "tip": transition.predecessor_sha256})
        return await self._vote("phase_decision", slot, transition, review)

    @log_phase("cohort_evaluation_suite_adoption_vote")
    async def certify_evaluation_suite_adoption(self, transition):
        transition = require_suite_adoption(transition)
        if transition.cohort_sha256 not in {c.cohort_sha256 for c in self.config.cohorts}:
            raise ValueError("suite vote is outside configured cohorts")

        async def review():
            return await self.reviewer.evaluation_suite_adoption(transition)

        slot = digest({"cohort": transition.cohort_sha256, "tip": transition.predecessor_sha256})
        return await self._vote("phase_decision", slot, transition, review)


class CertifiedPhaseObserver:
    """Native coordinator ports: observe phase evidence, gather independent votes."""

    def __init__(self, observe, signers, policy: CompetitionPolicy):
        self.observe, self.signers = observe, tuple(signers)
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if not 1 <= len(self.signers) <= 64 or any(s.policy != self.policy for s in self.signers):
            raise ValueError("intake certification needs configured policy reviewers")
        identities = [identity(s.config.signer) for s in self.signers]
        if len(set(identities)) != len(identities):
            raise ValueError("intake certification repeats a signer")

    async def _signatures(self, body, method, *args):
        tasks = [asyncio.create_task(getattr(s, method)(*args)) for s in self.signers]
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            signatures = []
            for result in results:
                if isinstance(result, (OSError, ValueError, RuntimeError, sqlite3.Error)):
                    continue  # A temporarily unavailable reviewer need not block a quorum.
                if isinstance(result, BaseException):
                    raise result
                signatures.append(result)
            signatures = tuple(sorted(signatures, key=lambda s: identity(s.hotkey)))
            verify_recovery_quorum(body, signatures, self.policy)
            return signatures
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def __call__(self, state, capture):
        return await self.attest(await self.sample(state, capture))

    async def sample(self, state, capture):
        observed = await self.observe(state, capture)
        return observed if isinstance(observed, CohortPhaseProgress) else observed.progress

    async def attest(self, progress):
        signatures = await self._signatures(progress, "attest", progress)
        return AttestedCohortPhaseProgress(progress=progress, signatures=signatures)

    async def certify(self, transition, evidence):
        signatures = await self._signatures(transition, "certify", transition, evidence)
        return SignedCohortRecoveryTransition(transition=transition, signatures=signatures)


class CertifiedIntakeObserver(CertifiedPhaseObserver):
    """Retained public name for existing intake controller consumers."""
