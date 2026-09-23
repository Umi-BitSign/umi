"""Private coordinator queue for original admission evidence and reviewer votes.

The intake's process lock serializes publication, new consent and certificate
assembly. Reviewers use separate signing/finality state. Only signed votes cross
back into this wallet-free ledger; a certificate admits participation, not rewards.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager

from .competition_chain import RegistrationCapture
from .competition_cohort_admission_journal import CohortAdmissionVote
from .competition_cohort_admission_signer import AdmissionHistory, certify_admission, check_selected
from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_intake import CohortIntake, cohort_intake_bytes
from .competition_cohort_intake_records import read_participation, replay_participation
from .competition_cohort_participation import AttestedCohortParticipantAdmission
from .competition_execution import execution_boundary
from .competition_registration_archive import (
    MAX_ARCHIVE_BYTES,
    MAX_METADATA_BYTES,
    RegistrationArchive,
)
from .competition_store import AdmissionCapacityError
from .open_competition import identity, verify_signature
from .protocol import canonical_json_bytes


class CohortAdmissionQueue:
    def __init__(self, intake: CohortIntake):
        self.intake, self.policy = intake, intake.policy
        self.groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        with self._connection():
            pass

    @contextmanager
    def _connection(self):
        with self.intake._connection() as (db, store):
            db.execute(
                "CREATE TABLE IF NOT EXISTS cohort_admission_artifacts "
                "(digest TEXT PRIMARY KEY, body BLOB NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS cohort_admission_votes "
                "(consent TEXT NOT NULL, signer TEXT NOT NULL, body BLOB NOT NULL, "
                "PRIMARY KEY(consent,signer))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS cohort_admission_certificates "
                "(consent TEXT PRIMARY KEY, body BLOB NOT NULL)"
            )
            yield db, store

    @contextmanager
    def _transaction(self, db):
        db.execute("BEGIN IMMEDIATE")
        try:
            yield
            # Shared capacity includes the new evidence, votes and certificates.
            used = cohort_intake_bytes(db)
            if used > self.intake.capacity.maximum_bytes:
                raise AdmissionCapacityError("cohort admission needs additional durable capacity")
            db.commit()
        except BaseException:
            db.rollback()
            raise

    def _record(self, db, store, cohort, consent):
        self.intake._allowed(cohort)
        row = db.execute(
            "SELECT substr(body,1,4194305) FROM cohort_consents WHERE cohort=? AND consent=?",
            (cohort, consent),
        ).fetchone()
        if row is None:
            raise FileNotFoundError("cohort participation is not retained")
        record = read_participation(row[0])
        if record.proposed_admission.cohort_sha256 != cohort or (
            record.proposed_admission.consent_sha256 != consent
        ):
            raise ValueError("admission queue record differs from its index")
        replay_participation(record, store.published_history(cohort), self.policy)
        return row[0], record

    def record(self, cohort: str, consent: str) -> bytes:
        with self._connection() as (db, store):
            return self._record(db, store, cohort, consent)[0]

    def history(self, cohort: str) -> AdmissionHistory:
        self.intake._allowed(cohort)
        with self._connection() as (db, store):
            return self._history(db, store, cohort)

    def _history(self, db, store, cohort):
        history = store.published_history(cohort)
        closing = next(
            (
                s.transition
                for s in history.transitions
                if s.transition.phase == "intake" and s.transition.operation == "close_phase"
            ),
            None,
        )
        if closing is None:
            return AdmissionHistory(history)
        seal = self.intake._seal(db, history, closing.predecessor_sha256)
        decision = store.source(cohort, closing.evidence_sha256, CohortDecisionInput)
        return AdmissionHistory(history, seal, decision)

    def attach_evidence(self, cohort: str, consent: str, evidence: bytes, metadata: bytes) -> None:
        archive = RegistrationArchive(evidence, metadata)
        with self._connection() as (db, store):
            _, record = self._record(db, store, cohort, consent)
            if (
                archive.snapshot != record.snapshot
                or archive.evidence_sha256 != record.observation.evidence_sha256
            ):
                raise ValueError("admission archive differs from retained registration")
            with self._transaction(db):
                for raw in (evidence, metadata):
                    key = hashlib.sha256(raw).hexdigest()
                    old = db.execute(
                        "SELECT substr(body,1,?) FROM cohort_admission_artifacts WHERE digest=?",
                        (len(raw) + 1, key),
                    ).fetchone()
                    if old is not None and old[0] != raw:
                        raise ValueError("retained admission archive changed")
                    db.execute(
                        "INSERT OR IGNORE INTO cohort_admission_artifacts VALUES (?,?)", (key, raw)
                    )

    def evidence(self, cohort: str, consent: str) -> tuple[bytes, bytes, bytes]:
        import json

        def artifact(db, key, maximum):
            row = db.execute(
                "SELECT substr(body,1,?) FROM cohort_admission_artifacts WHERE digest=?",
                (maximum + 1, key),
            ).fetchone()
            if row is None:
                raise FileNotFoundError("admission archive is not retained yet")
            raw = row[0]
            if (
                type(raw) is not bytes
                or not 0 < len(raw) <= maximum
                or hashlib.sha256(raw).hexdigest() != key
            ):
                raise ValueError("retained admission artifact changed or exceeds its bound")
            return raw

        with self._connection() as (db, store):
            raw, record = self._record(db, store, cohort, consent)
            evidence = artifact(db, record.observation.evidence_sha256, MAX_ARCHIVE_BYTES)
            metadata = artifact(
                db, json.loads(evidence)["runtime_metadata_sha256"], MAX_METADATA_BYTES
            )
            if RegistrationArchive(evidence, metadata).snapshot != record.snapshot:
                raise ValueError("retained admission archive snapshot changed")
            return raw, evidence, metadata

    def pending(self, cohort: str, signer: str, *, after: str = "", limit: int = 16) -> list[str]:
        self.intake._allowed(cohort)
        author = identity(signer)
        if author not in self.groups or type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("admission queue requires an approved bounded reviewer")
        with self._connection() as (db, _):
            return [
                r[0]
                for r in db.execute(
                    "SELECT c.consent FROM cohort_consents c "
                    "LEFT JOIN cohort_admission_certificates a ON a.consent=c.consent "
                    "LEFT JOIN cohort_admission_votes v ON v.consent=c.consent AND v.signer=? "
                    "WHERE c.cohort=? AND c.consent>? AND a.consent IS NULL AND v.consent IS NULL "
                    "ORDER BY c.consent LIMIT ?",
                    (author, cohort, after, limit),
                )
            ]

    def _vote(self, raw, record, author):
        if len(raw) > 16 * 1024:
            raise ValueError("admission vote exceeds its byte bound")
        vote = CohortAdmissionVote.model_validate_json(raw)
        if (
            canonical_json_bytes(vote) != raw
            or identity(vote.signature.hotkey) != author
            or (author not in self.groups or vote.admission != record.proposed_admission)
        ):
            raise ValueError("admission vote differs from its retained record or signer")
        verify_signature(vote.admission, vote.signature)
        return vote

    def _certificate(self, db, record):
        row = db.execute(
            "SELECT substr(body,1,65537) FROM cohort_admission_certificates WHERE consent=?",
            (record.proposed_admission.consent_sha256,),
        ).fetchone()
        if row is None:
            return None
        if len(row[0]) > 65536:
            raise ValueError("admission certificate exceeds its byte bound")
        value = AttestedCohortParticipantAdmission.model_validate_json(row[0])
        if canonical_json_bytes(value) != row[0] or value.admission != record.proposed_admission:
            raise ValueError("retained admission certificate changed")
        expected = certify_admission(
            [CohortAdmissionVote(admission=value.admission, signature=s) for s in value.signatures],
            self.policy,
        )
        if value != expected:
            raise ValueError("admission certificate signatures are not canonical")
        return value

    def certificate(self, cohort: str, consent: str) -> AttestedCohortParticipantAdmission | None:
        with self._connection() as (db, store):
            _, record = self._record(db, store, cohort, consent)
            return self._certificate(db, record)

    def publish_vote(self, vote: CohortAdmissionVote, capture: RegistrationCapture):
        vote = CohortAdmissionVote.model_validate_json(canonical_json_bytes(vote))
        admission = vote.admission
        author, consent, cohort = (
            identity(vote.signature.hotkey),
            admission.consent_sha256,
            admission.cohort_sha256,
        )
        block = execution_boundary(capture).block
        if block < admission.admitted_at_block:
            raise ValueError("admission vote publication predates its registration")
        with self._connection() as (db, store):
            raw, record = self._record(db, store, cohort, consent)
            self._vote(canonical_json_bytes(vote), record, author)
            certified = self._certificate(db, record)
            if certified is not None:
                return certified
            check_selected(raw, self._history(db, store, cohort), self.policy, block)
            prior = db.execute(
                "SELECT substr(body,1,16385) FROM cohort_admission_votes "
                "WHERE consent=? AND signer=?",
                (consent, author),
            ).fetchone()
            if prior is not None:
                vote = self._vote(prior[0], record, author)
            votes = {author: vote}
            for signer, encoded in db.execute(
                "SELECT signer,substr(body,1,16385) FROM cohort_admission_votes WHERE consent=?",
                (consent,),
            ):
                votes[signer] = self._vote(encoded, record, signer)
            selected, groups = [], set()
            for signer, value in sorted(votes.items()):
                if self.groups[signer] not in groups:
                    selected.append(value)
                    groups.add(self.groups[signer])
            if len(groups) >= self.policy.required_evaluator_groups:
                certified = certify_admission(selected, self.policy)
            with self._transaction(db):
                db.execute(
                    "INSERT OR IGNORE INTO cohort_admission_votes VALUES (?,?,?)",
                    (consent, author, canonical_json_bytes(vote)),
                )
                if certified is not None:
                    db.execute(
                        "INSERT INTO cohort_admission_certificates VALUES (?,?)",
                        (consent, canonical_json_bytes(certified)),
                    )
            return certified
