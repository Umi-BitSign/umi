"""Candidate worker backend selected by explicit authenticated storage profiles.

Selection requires version 2 host execution/storage inputs. Signed release,
package and historical-host authorization checks deliberately stay intact.
This class can operate on a prepared candidate or a fresh empty private journal;
it never migrates an existing legacy journal in place.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from dataclasses import asdict, dataclass

from .competition_evidence_continuity import (
    audit_continuity_transitions,
    record_continuity_transition,
)
from .competition_evidence_store import EvidenceBudget, EvidenceStore, observation_reservation
from .competition_weights import CompetitionWeightWorker
from .protocol import canonical_json_bytes

_TERMINAL = {"applied", "recovered_effect", "expired_unconsumed_nonce"}
_PROFILE_SQL = (
    "CREATE TABLE weight_proof_worker_profile "
    "(id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)"
)


@dataclass(frozen=True)
class EvidenceWorkerProfile:
    limits: EvidenceBudget
    recovery_observations: int

    def __post_init__(self):
        if type(self.recovery_observations) is not int or not 1 <= self.recovery_observations <= 32:
            raise ValueError("explicit bounded recovery observation allowance required")
        if not self.limits.contains(observation_reservation(3 + self.recovery_observations)):
            raise ValueError("storage profile cannot reserve a full new attempt and recovery")

    def encoded(self) -> bytes:
        return canonical_json_bytes(
            {"schema": "umi-weight-evidence-worker-profile/1", **asdict(self)}
        )


def bind_worker_profile(db, profile: EvidenceWorkerProfile, *, create=False):
    """Persist explicit selection on a fresh or offline-prepared candidate only."""
    if not db.in_transaction:
        raise ValueError("worker profile requires an owned transaction")
    if create:
        db.execute(_PROFILE_SQL)
        db.execute("INSERT INTO weight_proof_worker_profile VALUES (1,?)", (profile.encoded(),))
    schema = db.execute(
        "SELECT sql FROM sqlite_master WHERE name='weight_proof_worker_profile'"
    ).fetchone()
    if schema != (_PROFILE_SQL,):
        raise ValueError("candidate worker profile schema is missing or changed")
    if db.execute("SELECT id,length(body) FROM weight_proof_worker_profile").fetchall() != [
        (1, len(profile.encoded()))
    ] or db.execute("SELECT id,body FROM weight_proof_worker_profile").fetchall() != [
        (1, profile.encoded())
    ]:
        raise ValueError("candidate worker profile changed")


class ContentAddressedWeightWorker(CompetitionWeightWorker):
    def __init__(
        self,
        *args,
        evidence_profile: EvidenceWorkerProfile,
        maximum_database_bytes: int = 16 * 1024**3,
        **kwargs,
    ):
        if (
            type(maximum_database_bytes) is not int
            or not 1024**2 <= maximum_database_bytes <= 16 * 1024**3
        ):
            raise ValueError("explicit bounded evidence database capacity required")
        self.maximum_database_bytes = maximum_database_bytes
        self.evidence_profile = evidence_profile
        super().__init__(*args, **kwargs)

    @contextmanager
    def _db(self):
        with super()._db() as db:
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            pages = self.maximum_database_bytes // page_size
            if db.execute("PRAGMA page_count").fetchone()[0] > pages:
                raise ValueError("evidence database already exceeds its physical ceiling")
            if db.execute(f"PRAGMA max_page_count={pages}").fetchone()[0] != pages:
                raise ValueError("evidence database physical ceiling could not be installed")
            yield db

    def _initialize_evidence(self, db):
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='evidence'").fetchone():
            raise ValueError("legacy journal requires separately authorized stopped migration")
        binding = db.execute("SELECT * FROM binding").fetchall()
        if binding:
            self._store(db)

    def _record_continuity_handoff(self, db, *, activation, policy, before, after):
        record_continuity_transition(
            db, activation=activation, policy=policy, before=before, after=after
        )

    def _store(self, db, *, create=False):
        audit_continuity_transitions(db)
        binding = db.execute("SELECT * FROM binding").fetchall()
        if len(binding) != 1:
            raise ValueError("content addressed worker lacks its original owner binding")
        bind_worker_profile(db, self.evidence_profile, create=create)
        return EvidenceStore(
            db,
            owner_binding_sha256=hashlib.sha256(canonical_json_bytes(binding)).hexdigest(),
            limits=self.evidence_profile.limits,
            create=create,
        )

    def _check_journal_binding(self, db, validator_hotkey):
        empty = not db.execute("SELECT 1 FROM binding").fetchone()
        super()._check_journal_binding(db, validator_hotkey)
        self._store(db, create=empty)

    def _has_evidence(self, db, identity):
        return (
            db.execute("SELECT 1 FROM weight_proof_records WHERE sha256=?", (identity,)).fetchone()
            is not None
        )

    def _audit_evidence(self, db):
        usage = self._store(db).audit()
        known = {row[0] for row in db.execute("SELECT sha256 FROM weight_proof_records")}
        return known, usage.expanded_bytes

    def _append_observation(self, db, observation, known, total, *, authorization_id=None):
        store = self._store(db)
        reservation = (
            authorization_id
            if (
                authorization_id is not None
                and store.remaining_reservation(authorization_id) is not None
            )
            else None
        )
        store.put(observation.evidence, kind="proof", reservation=reservation)
        store.put(observation.runtime.metadata_bytes, kind="metadata", reservation=reservation)

    def _before_capture(self, db, authorization_id, attempt):
        store = self._store(db)
        # The caller holds the native global lock and has validated every
        # attempt. No durable intent means no possible signed effect. Release
        # only unused allowances from abandoned unsigned or terminal attempts;
        # never delete evidence, signed history, or an unknown effect's reserve.
        for identity in store._reservations():
            if identity == authorization_id:
                continue
            prior = db.execute("SELECT body FROM attempts WHERE id=?", (identity,)).fetchone()
            if prior is None or json.loads(prior[0])["phase"] in _TERMINAL:
                store.release_reservation(identity)
        if attempt is not None and attempt["phase"] in _TERMINAL:
            store.release_reservation(authorization_id)
            return
        count = 3 + self.evidence_profile.recovery_observations if attempt is None else 1
        # Unsigned retries reserve their complete future budget. Unknown/signed
        # attempts retain their allowance and can replenish one recovery proof
        # only if capacity permits. Neither path can resend existing signed bytes.
        store.ensure_reservation(authorization_id, observation_reservation(count))
        self._check_physical_reservations(db, store)

    def _check_physical_reservations(self, db, store):
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        occupied = db.execute("PRAGMA page_count").fetchone()[0] * page_size
        # Conservative allowance for payload/overflow plus table and index
        # pages for each reserved object/record, without counting free pages or
        # dedup savings. Host-wide rollback/disk reservation remains separate.
        allowance = sum(
            budget.stored_bytes * 2
            + budget.objects * 2 * page_size
            + budget.records * 4 * page_size
            for budget in store._reservations().values()
        )
        if occupied + allowance + 1024**2 > self.maximum_database_bytes:
            raise ValueError("evidence physical capacity cannot retain reserved recovery")

    def _save(self, attempt):
        with self._db() as db:
            if attempt["phase"] == "intent":
                remaining = self._store(db).remaining_reservation(attempt["authorization_id"])
                required = observation_reservation(2 + self.evidence_profile.recovery_observations)
                if remaining is None or not remaining.contains(required):
                    raise ValueError("post-signing and recovery evidence space is not reserved")
                self._check_physical_reservations(db, self._store(db))
            self._save_to_db(db, attempt)

    def _recover(self, attempt, body, hotkey, observation, row, *, database=None):
        result = super()._recover(attempt, body, hotkey, observation, row, database=database)
        if result.status in _TERMINAL:
            if database is None:
                with self._db() as db:
                    self._store(db).release_reservation(body.authorization_id)
            else:
                self._store(database).release_reservation(body.authorization_id)
        return result
