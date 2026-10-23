"""Private admission evidence and vote intents, retained before signing.

RoundJournal supplies process locking, atomic FULL commits, immutable records,
capacity bounds and conflict holds. Capacity exhaustion leaves the same vote
retryable; there is no time-based expiry of an intent or its original evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_intake_records import read_participation, replay_participation
from .competition_cohort_participation import CohortParticipantAdmission
from .competition_registration_archive import RegistrationArchive
from .competition_round_journal import RoundJournal
from .competition_verification_rules import runtime_identity
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


class CohortAdmissionSignerConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-admission-signer-config/1"] = Field(alias="schema")
    directory: Directory
    policy_sha256: Hex32
    signer: Hotkey
    cohorts: Annotated[tuple[CohortIntakeBinding, ...], Field(min_length=1, max_length=512)]
    maximum_votes: Annotated[int, Field(ge=1, le=65536)] = 4096
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    signing_timeout_seconds: Annotated[int, Field(ge=1, le=1200)] = 300

    @model_validator(mode="after")
    def ordered(self):
        keys = tuple(item.cohort_sha256 for item in self.cohorts)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("admission signer cohorts must be unique and ordered")
        return self


class CohortAdmissionVote(StrictProtocolModel):
    admission: CohortParticipantAdmission
    signature: Signature


class CohortAdmissionIntent(StrictProtocolModel):
    schema_: Literal["umi-cohort-admission-vote-intent/1"] = Field(alias="schema")
    admission: CohortParticipantAdmission
    record_sha256: Hex32
    registration_sha256: Hex32
    metadata_sha256: Hex32


def admission_slot(raw: bytes) -> str:
    record = read_participation(raw)
    sub = record.request.signed_submission.submission
    return digest(
        {
            "schema": "umi-cohort-admission-slot/1",
            "cohort_sha256": record.proposed_admission.cohort_sha256,
            "hotkey": identity(sub.hotkey),
            "track": sub.track,
            "sequence": sub.sequence,
        }
    )


class CohortAdmissionJournal:
    def __init__(self, config: CohortAdmissionSignerConfig, policy: CompetitionPolicy):
        self.config = CohortAdmissionSignerConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if self.config.policy_sha256 != digest(self.policy) or identity(self.config.signer) not in {
            identity(e.hotkey) for e in self.policy.evaluators
        }:
            raise ValueError("admission signer is not authorized by this policy")
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in self.config.cohorts}
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(
                mode="json",
                by_alias=True,
                exclude={
                    "maximum_votes",
                    "maximum_bytes",
                    "signing_timeout_seconds",
                },
            ),
            maximum_rounds=self.config.maximum_votes,
            maximum_bytes=self.config.maximum_bytes,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS cohort_admission_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )

    def remember_history(self, history: CohortRecoveryHistory, block: int) -> None:
        history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
        cohort = digest(history.plan)
        if self.cohorts.get(cohort) != digest(history.authority.authority):
            raise ValueError("admission signer has no configured authority for this cohort")
        tip = digest(history.transitions[-1].transition if history.transitions else history.genesis)
        verify_cohort_history(history, self.policy, expected_tip_sha256=tip, current_block=block)

        def index(db):
            prior = db.execute(
                "SELECT history FROM cohort_admission_heads WHERE cohort=?", (cohort,)
            ).fetchone()
            if prior:
                old = self._history(prior[0], db)
                if (
                    len(history.transitions) < len(old.transitions)
                    or history.genesis != old.genesis
                    or history.transitions[: len(old.transitions)] != old.transitions
                ):
                    raise ValueError("admission signing history rolled back or forked")
            db.execute(
                "INSERT INTO cohort_admission_heads VALUES (?,?) "
                "ON CONFLICT(cohort) DO UPDATE SET history=excluded.history",
                (cohort, digest(history)),
            )

        self.journal.put_many((("admission_history", digest(history), history),), index=index)

    def _history(self, key, db):
        value = self.journal.get("admission_history", key, db=db)
        if value is None or digest(value) != key:
            raise ValueError("retained admission history is missing or changed")
        return CohortRecoveryHistory.model_validate_json(canonical_json_bytes(value))

    def _artifact(self, kind, key, db):
        value = self.journal.get(kind, key, db=db)
        if value is None:
            raise ValueError("retained admission evidence is missing")
        if kind == "admission_metadata":
            if not isinstance(value, dict) or set(value) != {"hex"}:
                raise ValueError("retained admission metadata is invalid")
            raw = bytes.fromhex(value["hex"])
        else:
            raw = canonical_json_bytes(value)
        if hashlib.sha256(raw).hexdigest() != key:
            raise ValueError("retained admission artifact digest differs")
        return raw

    def load(self, slot: str):
        with self.journal.transaction() as db:
            value = self.journal.get("admission_intent", slot, db=db)
            if value is None:
                return None
            intent = CohortAdmissionIntent.model_validate_json(canonical_json_bytes(value))
            raw = self._artifact("admission_record", intent.record_sha256, db)
            evidence = self._artifact("admission_registration", intent.registration_sha256, db)
            metadata = self._artifact("admission_metadata", intent.metadata_sha256, db)
            record = read_participation(raw)
            archive = RegistrationArchive(evidence, metadata)
            if (
                admission_slot(raw) != slot
                or record.proposed_admission != intent.admission
                or intent.registration_sha256 != record.observation.evidence_sha256
                or archive.snapshot != record.snapshot
            ):
                raise ValueError("retained admission intent differs from its evidence")
            row = db.execute(
                "SELECT history FROM cohort_admission_heads WHERE cohort=?",
                (intent.admission.cohort_sha256,),
            ).fetchone()
            if row is None:
                raise ValueError("retained admission lacks its owned history")
            replay_participation(record, self._history(row[0], db), self.policy)
            value = self.journal.get("admission_vote", slot, db=db)
            vote = (
                None
                if value is None
                else CohortAdmissionVote.model_validate_json(canonical_json_bytes(value))
            )
            if vote is not None:
                self.check_vote(intent, vote)
            return intent, raw, evidence, metadata, vote

    def check_vote(self, intent: CohortAdmissionIntent, vote: CohortAdmissionVote):
        if vote.admission != intent.admission or identity(vote.signature.hotkey) != identity(
            self.config.signer
        ):
            raise ValueError("admission vote differs from this signer's reserved body")
        verify_signature(vote.admission, vote.signature)

    def reviewed_participation(self, raw: bytes) -> bool:
        """Reuse this owner's committed review without loading its proof payload.

        The immutable intent binds the exact original record and registration
        evidence. Only a valid vote by this journal's own signer establishes a
        completed review. Current history, finality and seal membership remain
        the phase reviewer's responsibility.
        """
        record = read_participation(raw)
        cohort = record.proposed_admission.cohort_sha256
        if cohort not in self.cohorts:
            raise ValueError("retained participation is outside this admission journal")
        key, expected = self._participation_review_identity(raw)
        slot = admission_slot(raw)
        with self.journal.read_transaction() as db:
            receipt = self.journal.get("participation_review", key, db=db)
            completed = self.journal.get("participation_review_complete", key, db=db)
            value = self.journal.get("admission_intent", slot, db=db)
            committed = self.journal.get("admission_vote", slot, db=db)
        if receipt is not None or completed is not None:
            if receipt != expected or completed != {"review_sha256": key}:
                raise ValueError("completed participation review needs metadata repair")
            return True
        if value is None:
            if committed is not None:
                raise ValueError("committed admission review lacks its retained intent")
            return False
        intent = CohortAdmissionIntent.model_validate_json(canonical_json_bytes(value))
        if (
            intent.record_sha256 != hashlib.sha256(raw).hexdigest()
            or intent.admission != record.proposed_admission
            or intent.registration_sha256 != record.observation.evidence_sha256
        ):
            raise ValueError("retained admission review differs from its exact original record")
        if committed is None:
            return False
        self.check_vote(
            intent, CohortAdmissionVote.model_validate_json(canonical_json_bytes(committed))
        )
        # Historical /1 intents predate explicit native-review checkpoints.
        # Their committed votes are qualified only for the unchanged /1
        # semantics; a future semantic change needs its own native result.
        return (
            expected["verifier_semantics"]
            == hashlib.sha256(b"umi-native-request-verification/1").hexdigest()
        )

    def _participation_review_identity(self, raw: bytes):
        record = read_participation(raw)
        cohort = record.proposed_admission.cohort_sha256
        if self.cohorts.get(cohort) != record.request.consent.consent.authority_sha256:
            raise ValueError("participation review differs from the journal's cohort authority")
        body = {
            "schema": "umi-owned-participation-review/1",
            "record_sha256": hashlib.sha256(raw).hexdigest(),
            "policy_sha256": digest(self.policy),
            "authority_sha256": self.cohorts[cohort],
            "verifier_semantics": runtime_identity(),
        }
        return digest(body), body

    def remember_participation_review(self, raw: bytes) -> None:
        """Checkpoint a successful native phase review before advancing its count."""
        key, body = self._participation_review_identity(raw)
        self.journal.put_many(
            (
                ("participation_review", key, body),
                ("participation_review_complete", key, {"review_sha256": key}),
            )
        )

    def reserve(self, admission, raw, evidence, metadata) -> CohortAdmissionIntent:
        record = read_participation(raw)
        archive = RegistrationArchive(evidence, metadata)
        if (
            record.proposed_admission != admission
            or archive.snapshot != record.snapshot
            or archive.evidence_sha256 != record.observation.evidence_sha256
        ):
            raise ValueError("admission reservation differs from reviewed evidence")
        intent = CohortAdmissionIntent(
            schema="umi-cohort-admission-vote-intent/1",
            admission=admission,
            record_sha256=hashlib.sha256(raw).hexdigest(),
            registration_sha256=hashlib.sha256(evidence).hexdigest(),
            metadata_sha256=hashlib.sha256(metadata).hexdigest(),
        )

        def limit(db):
            count = db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='admission_intent'"
            ).fetchone()[0]
            if count > self.config.maximum_votes:
                raise ValueError("admission vote capacity exhausted")

        self.journal.put_many(
            (
                ("admission_record", intent.record_sha256, json.loads(raw)),
                ("admission_registration", intent.registration_sha256, json.loads(evidence)),
                ("admission_metadata", intent.metadata_sha256, {"hex": metadata.hex()}),
                ("admission_intent", admission_slot(raw), intent),
            ),
            index=limit,
        )
        return intent

    def commit(self, slot: str, vote: CohortAdmissionVote) -> CohortAdmissionVote:
        retained = self.load(slot)
        if retained is None:
            raise ValueError("admission vote has no retained signing intent")
        self.check_vote(retained[0], vote)
        if retained[4] is not None:
            return retained[4]
        self.journal.put("admission_vote", slot, vote)
        return vote
