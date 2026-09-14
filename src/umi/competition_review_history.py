"""Evaluator-owned receipts for independently checked, quorum-certified rosters.

These record arrival time, never the coordinator's claimed admission time.
The store cannot accept miner enrollments or prepare coordinator settlements.
"""

from __future__ import annotations

import json

from .competition_publication import (
    PublicationReplayLimits,
    SignedCutoffPublication,
    verify_cutoff_publication,
)
from .competition_store import AdmissionCapacityError, CompetitionStore, _advance_block
from .open_competition import SignedSubmission, digest, identity
from .protocol import canonical_json_bytes


class EvaluatorReviewStore(CompetitionStore):
    def __init__(self, directory, policy, *, limits, **kwargs):
        self.limits = PublicationReplayLimits.model_validate_json(canonical_json_bytes(limits))
        super().__init__(directory, policy, role="evaluator_review", **kwargs)
        with self._transaction() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS reviewed_cutoffs "
                "(round TEXT PRIMARY KEY, observed_block INTEGER NOT NULL, body BLOB NOT NULL)"
            )
            prior = connection.execute(
                "SELECT value FROM metadata WHERE key='review_limits'"
            ).fetchone()
            bound = canonical_json_bytes(self.limits).decode()
            if prior is None:
                connection.execute("INSERT INTO metadata VALUES ('review_limits', ?)", (bound,))
            elif prior[0] != bound:
                raise ValueError("review history limits changed")
            usage = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(body)),0) FROM reviewed_cutoffs"
            ).fetchone()
            if usage[0] > self.preparation_capacity.maximum_records or (
                usage[1] > self.preparation_capacity.maximum_bytes
            ):
                raise ValueError("review history exceeds its capacity")
            for (round_id,) in connection.execute("SELECT digest FROM rounds").fetchall():
                self._read_cutoff(connection, round_id)

    @property
    def maximum_cutoff_bytes(self):
        return self.limits.maximum_certificate_bytes + self.limits.maximum_roster_bytes + 4096

    def _read_cutoff(self, connection, round_id):
        row = connection.execute(
            "SELECT observed_block,length(body) FROM reviewed_cutoffs WHERE round=?", (round_id,)
        ).fetchone()
        if row is None or row[1] > self.maximum_cutoff_bytes:
            raise ValueError("review cutoff receipt missing or oversized")
        raw = connection.execute(
            "SELECT body FROM reviewed_cutoffs WHERE round=?", (round_id,)
        ).fetchone()[0]
        body = json.loads(raw)
        if not isinstance(body, dict) or (
            canonical_json_bytes(body) != raw or set(body) != {"certificate", "submissions"}
        ):
            raise ValueError("review cutoff receipt is not canonical")
        certificate = SignedCutoffPublication.model_validate_json(
            canonical_json_bytes(body["certificate"])
        )
        submissions = tuple(
            SignedSubmission.model_validate_json(canonical_json_bytes(s))
            for s in body["submissions"]
        )
        publication = verify_cutoff_publication(
            certificate, policy=self.policy, submissions=submissions, limits=self.limits
        )
        round_ = publication.round
        if (
            type(row[0]) is not int
            or digest(round_) != round_id
            or not (round_.submission_close_block <= row[0] < round_.evaluation_close_block)
        ):
            raise ValueError("review cutoff has an invalid local receipt block")
        high_water = connection.execute(
            "SELECT value FROM metadata WHERE key='observed_block'"
        ).fetchone()
        if high_water is None or row[0] > int(high_water[0]):
            raise ValueError("review cutoff exceeds its local observation history")
        stored = connection.execute(
            "SELECT body FROM rounds WHERE digest=?", (round_id,)
        ).fetchone()
        if stored is None or stored[0] != canonical_json_bytes(round_):
            raise ValueError("review cutoff differs from local round history")
        for signed in submissions:
            stored = connection.execute(
                "SELECT body FROM submissions WHERE digest=?", (digest(signed.submission),)
            ).fetchone()
            if stored is None or stored[0] != canonical_json_bytes(signed):
                raise ValueError("review cutoff differs from local submission history")
        return publication, submissions, row[0]

    def _assert_action_allowed(self, connection, round_sha256):
        super()._assert_action_allowed(connection, round_sha256)
        self._read_cutoff(connection, round_sha256)

    def _fixed_cutoff(self, connection, round_sha256):
        publication, _, _ = self._read_cutoff(connection, round_sha256)
        return publication.cutoff_schedule

    def observe_cutoff(self, certificate, submissions, *, snapshot, observed_block):
        """Caller supplies its independently proved cutoff snapshot and current head."""
        publication = verify_cutoff_publication(
            certificate, policy=self.policy, submissions=submissions, limits=self.limits
        )
        round_ = publication.round
        if publication.registration_snapshot != snapshot:
            raise ValueError("review cutoff differs from the independently proved snapshot")
        body = canonical_json_bytes(
            {
                "certificate": certificate.model_dump(mode="json", by_alias=True),
                "submissions": [s.model_dump(mode="json", by_alias=True) for s in submissions],
            }
        )
        if len(body) > self.maximum_cutoff_bytes:
            raise ValueError("review cutoff exceeds its byte bound")
        round_id = digest(round_)
        with self._transaction() as connection:
            prior = connection.execute(
                "SELECT 1 FROM reviewed_cutoffs WHERE round=?", (round_id,)
            ).fetchone()
            if prior:
                old, roster, observed = self._read_cutoff(connection, round_id)
                if old != publication or roster != tuple(submissions):
                    raise ValueError("review cutoff retry changes its original decision")
                return observed
            if type(observed_block) is not int or not (
                round_.submission_close_block <= observed_block < round_.evaluation_close_block
            ):
                raise ValueError("review cutoff arrived outside its execution window")
            _advance_block(connection, observed_block)
            baseline = connection.execute(
                "SELECT model FROM promotions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if baseline is None or baseline[0] != round_.incumbent_model_sha256:
                raise ValueError("review cutoff incumbent is not the preserved local baseline")
            latest = connection.execute("SELECT MAX(sequence) FROM rounds").fetchone()[0]
            if latest is not None and latest >= round_.sequence:
                raise ValueError("review cutoff sequence did not advance")
            if connection.execute(
                "SELECT 1 FROM suite_usage WHERE suite=?", (round_.suite_sha256,)
            ).fetchone():
                raise ValueError("review cutoff reused a prior suite")
            count, size = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(body)),0) FROM reviewed_cutoffs"
            ).fetchone()
            if count + 1 > self.preparation_capacity.maximum_records or (
                size + len(body) > self.preparation_capacity.maximum_bytes
            ):
                raise AdmissionCapacityError("review cutoff capacity is exhausted")
            records, payload = connection.execute(
                "SELECT records,payload_bytes FROM admission_usage WHERE singleton=1"
            ).fetchone()
            for signed in submissions:
                sub = signed.submission
                sub_id = digest(sub)
                raw = canonical_json_bytes(signed)
                old = connection.execute(
                    "SELECT body FROM submissions WHERE digest=?", (sub_id,)
                ).fetchone()
                if old is not None:
                    if old[0] != raw:
                        raise ValueError("review submission history is corrupt")
                    continue
                receipt = canonical_json_bytes(
                    {
                        "schema": "umi-evaluator-roster-observation/1",
                        "submission_sha256": sub_id,
                        "round_sha256": round_id,
                        "first_observed_block": observed_block,
                        "admission_timing_proven": False,
                        "chain_submission_authorized": False,
                    }
                )
                records, payload = records + 1, payload + len(raw) + len(receipt)
                if records > self.admission_capacity.maximum_records or (
                    payload > self.admission_capacity.maximum_bytes
                ):
                    raise AdmissionCapacityError("review submission capacity is exhausted")
                self._insert_admission(
                    connection,
                    (
                        sub_id,
                        identity(sub.hotkey),
                        sub.track,
                        sub.sequence,
                        observed_block,
                        sub.valid_through_block,
                        raw,
                        receipt,
                    ),
                    records=records,
                    payload_bytes=payload,
                )
            connection.execute(
                "INSERT INTO rounds VALUES (?,?,?)",
                (round_id, round_.sequence, canonical_json_bytes(round_)),
            )
            connection.execute(
                "INSERT INTO suite_usage VALUES (?,?)", (round_.suite_sha256, round_id)
            )
            connection.execute(
                "INSERT INTO reviewed_cutoffs VALUES (?,?,?)", (round_id, observed_block, body)
            )
            return observed_block
