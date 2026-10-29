"""Owner-serialized durable cohort certification intents and independent votes."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .competition_cohort_intake_records import read_participation
from .competition_cohort_model_acceptance import (
    ModelAcceptanceBatchManifest,
    verify_model_acceptance_batch_manifest,
)
from .competition_cohort_model_acceptance_store import MAX_PUBLICATION_BYTES, PendingModelArtifacts
from .competition_cohort_model_batch import (
    CertifiedModelAcceptanceBatch,
    build_model_acceptance_batch,
    verify_model_acceptance_batch,
    verify_model_acceptance_batch_body,
    verify_model_batch_certification_adoption,
)
from .competition_cohort_model_batch_review import (
    ModelBatchArtifactVote,
    ModelBatchReviewRequest,
    check_model_batch_vote,
    model_batch_candidate_snapshot,
)
from .competition_execution import execution_boundary
from .competition_store import AdmissionCapacityError
from .open_competition import digest, identity
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class ModelBatchSelection:
    cohort: str
    history: object
    roster_sha256: str
    submissions: tuple
    retained: frozenset[str]


class CohortModelBatchStore:
    """Every connection remains inside one native owner call, never a worker."""

    def __init__(self, owner):
        self.owner, self.intake = owner, owner.intake
        with self.intake._connection() as (db, _):
            db.execute(
                "CREATE TABLE IF NOT EXISTS cohort_model_batch_records "
                "(cohort TEXT NOT NULL, kind TEXT NOT NULL, record_key TEXT NOT NULL, "
                "body BLOB NOT NULL, PRIMARY KEY(cohort,kind,record_key))"
            )

    @staticmethod
    def _read(db, cohort, kind, key):
        row = db.execute(
            "SELECT substr(body,1,?) FROM cohort_model_batch_records "
            "WHERE cohort=? AND kind=? AND record_key=?",
            (MAX_PUBLICATION_BYTES + 1, cohort, kind, key),
        ).fetchone()
        if row is None:
            return None
        if len(row[0]) > MAX_PUBLICATION_BYTES:
            raise ValueError("model batch retained record exceeds capacity")
        value = json.loads(row[0])
        if not isinstance(value, dict) or canonical_json_bytes(value) != row[0]:
            raise ValueError("model batch retained record changed canonical bytes")
        return value

    def _put(self, db, cohort, kind, key, body):
        raw = canonical_json_bytes(body)
        old = self._read(db, cohort, kind, key)
        if old is not None:
            if canonical_json_bytes(old) != raw:
                raise ValueError("model batch changes its durable original intent")
            return
        if len(raw) > MAX_PUBLICATION_BYTES or (
            self.intake.retained_bytes(db) + len(raw) > self.intake.capacity.maximum_bytes
        ):
            raise AdmissionCapacityError("model batch needs additional durable capacity")
        db.execute(
            "INSERT INTO cohort_model_batch_records VALUES (?,?,?,?)", (cohort, kind, key, raw)
        )

    def _selected(self, db, store, cohort, *, require_drained=False):
        history = store.published_history(cohort)
        state, pending = store.status(cohort)
        if state.phase != "intake" or pending is not None:
            raise PendingModelArtifacts("model batch awaits stable native intake authority")
        if require_drained:
            deadline = self.intake._admission_deadlines.get(cohort)
            if (
                deadline is None
                or time.time_ns() // 1_000_000 < deadline.close_new_admissions_at_unix_ms
            ):
                raise PendingModelArtifacts(
                    "final model batch awaits retained new-admission closure"
                )
            self.intake.require_admission_uploads_drained(db, history)
        rows = tuple(
            db.execute(
                "SELECT c.hotkey,c.sequence,substr(c.body,1,4194305),"
                "EXISTS (SELECT 1 FROM cohort_model_acceptances a WHERE a.cohort=c.cohort "
                "AND a.submission=json_extract(CAST(c.body AS TEXT),"
                "'$.request.consent.consent.submission_sha256')) "
                "FROM cohort_consents c WHERE c.cohort=? AND c.track='model' "
                "AND NOT EXISTS (SELECT 1 FROM cohort_consents newer WHERE newer.cohort=c.cohort "
                "AND newer.hotkey=c.hotkey AND newer.track=c.track AND newer.sequence>c.sequence) "
                "ORDER BY c.hotkey,c.consent LIMIT 513",
                (cohort,),
            )
        )
        if len(rows) > 512:
            raise ValueError("model batch exceeds supported candidate capacity")
        selected, identities, retained = [], [], set()
        for hotkey, sequence, raw, complete in rows:
            record = read_participation(raw)
            sub = record.request.signed_submission.submission
            key = digest(sub)
            if identity(sub.hotkey) != hotkey or sub.sequence != sequence or sub.track != "model":
                raise ValueError("model batch index changes original selected submission")
            identities.append([hotkey, sequence, key])
            selected.append(sub)
            if complete:
                retained.add(key)
        return ModelBatchSelection(
            cohort, history, digest(identities), tuple(selected), frozenset(retained)
        )

    def selected(self, cohort, *, require_drained=False):
        self.intake._allowed(cohort)
        with self.intake._connection() as (db, store):
            return self._selected(db, store, cohort, require_drained=require_drained)

    def retained_request(self, cohort, adoption):
        with self.intake._connection() as (db, store):
            raw = self._read(db, cohort, "request", "selected")
            if raw is None:
                return None
            if set(raw) != {"batch", "adoption", "submissions", "request_sha256"}:
                raise ValueError("model batch request binding is damaged; repair required")
            exported = tuple(
                db.execute(
                    "SELECT record_key FROM cohort_model_batch_records WHERE cohort=? AND kind=?",
                    (cohort, "export:" + digest(raw["batch"])),
                )
            )
            all_exported = {row[0] for row in exported} == set(raw["submissions"])
            selection = (
                None if all_exported else self._selected(db, store, cohort, require_drained=True)
            )
        requests = tuple(self.owner.review_request(cohort, key) for key in raw["submissions"])
        request = ModelBatchReviewRequest.model_validate_json(
            canonical_json_bytes(
                {
                    "batch": raw["batch"],
                    "adoption": raw["adoption"],
                    "requests": [r.model_dump(mode="json", by_alias=True) for r in requests],
                }
            )
        )
        if request.adoption != adoption or digest(request) != raw["request_sha256"]:
            raise ValueError("model batch recovery changes original request or selected adoption")
        if selection is not None:
            self._check_selection(selection, request)
        return request

    def _check_selection(self, selection, request):
        if selection.roster_sha256 != request.batch.roster_sha256 or tuple(
            sorted(digest(s) for s in selection.submissions)
        ) != tuple(r.acceptance.submission_sha256 for r in request.requests):
            raise ValueError(
                "model batch selected roster or authority changed; scoped repair required"
            )
        # The signed header remains exact. An authenticated later intake
        # amendment may extend its original history prefix without changing
        # selected participants, previously completed work or retained votes.
        verify_model_acceptance_batch_body(
            request.batch,
            request.adoption,
            selection.history,
            self.intake.policy,
            maximum_block=request.batch.certified_at_block,
        )

    def reserve(self, selection, adoption, capture):
        cohort = selection.cohort
        requests = tuple(
            self.owner.review_request(cohort, digest(sub))
            for sub in sorted(selection.submissions, key=digest)
        )
        block = execution_boundary(capture).block
        # Build the exact header first, then its request-bound candidate digest.
        batch = build_model_acceptance_batch(
            tuple(r.acceptance for r in requests),
            adoption,
            selection.history,
            self.intake.policy,
            candidate_snapshot_sha256="01" * 32,
            roster_sha256=selection.roster_sha256,
            certified_at_block=block,
        )
        batch = batch.model_copy(
            update={"candidate_snapshot_sha256": model_batch_candidate_snapshot(requests, batch)}
        )
        request = ModelBatchReviewRequest(batch=batch, adoption=adoption, requests=requests)
        with self.intake._connection() as (db, store):
            current = self._selected(db, store, cohort, require_drained=True)
            self._check_selection(current, request)
            verify_model_batch_certification_adoption(
                adoption, current.history, self.intake.policy, maximum_block=block
            )
            self._put(db, cohort, "adoption", "selected", adoption)
            self._put(
                db,
                cohort,
                "request",
                "selected",
                {
                    "batch": batch.model_dump(mode="json", by_alias=True),
                    "adoption": adoption.model_dump(mode="json", by_alias=True),
                    "submissions": [r.acceptance.submission_sha256 for r in requests],
                    "request_sha256": digest(request),
                },
            )
        return request

    def votes(self, request):
        with self.intake._connection() as (db, _):
            rows = tuple(
                db.execute(
                    "SELECT body FROM cohort_model_batch_records WHERE cohort=? AND kind=? "
                    "ORDER BY record_key",
                    (request.batch.cohort_sha256, "vote:" + digest(request.batch)),
                )
            )
        result = []
        for (raw,) in rows:
            vote = ModelBatchArtifactVote.model_validate_json(raw)
            if canonical_json_bytes(vote) != raw:
                raise ValueError("model batch vote changed canonical bytes")
            check_model_batch_vote(vote, request, self.intake.policy)
            result.append(vote)
        return tuple(result)

    def publish_vote(self, request, vote):
        check_model_batch_vote(vote, request, self.intake.policy)
        with self.intake._connection() as (db, _):
            old = self._read(
                db,
                request.batch.cohort_sha256,
                "vote:" + digest(request.batch),
                identity(vote.signature.hotkey),
            )
            if old is not None:
                check_model_batch_vote(
                    ModelBatchArtifactVote.model_validate_json(canonical_json_bytes(old)),
                    request,
                    self.intake.policy,
                )
                return
            self._put(
                db,
                request.batch.cohort_sha256,
                "vote:" + digest(request.batch),
                identity(vote.signature.hotkey),
                vote,
            )

    def certificate(self, request):
        with self.intake._connection() as (db, store):
            raw = self._read(db, request.batch.cohort_sha256, "manifest", digest(request.batch))
            if raw is not None:
                manifest = ModelAcceptanceBatchManifest.model_validate_json(
                    canonical_json_bytes(raw)
                )
                if (
                    manifest.certificate.batch != request.batch
                    or manifest.certificate.adoption != request.adoption
                ):
                    raise ValueError("retained batch certificate changed its original request")
                verify_model_acceptance_batch_manifest(
                    manifest,
                    store.published_history(request.batch.cohort_sha256),
                    self.intake.policy,
                    maximum_block=request.batch.certified_at_block,
                )
                return manifest
        groups = {identity(e.hotkey): e.control_group for e in self.intake.policy.evaluators}
        selected = {}
        for vote in self.votes(request):
            selected.setdefault(groups[identity(vote.signature.hotkey)], vote.signature)
        if len(selected) < self.intake.policy.required_evaluator_groups:
            raise PendingModelArtifacts("cohort model batch independent quorum is pending")
        certificate = CertifiedModelAcceptanceBatch(
            batch=request.batch,
            adoption=request.adoption,
            signatures=tuple(sorted(selected.values(), key=lambda s: identity(s.hotkey))),
        )
        with self.intake._connection() as (db, store):
            selection = self._selected(db, store, request.batch.cohort_sha256, require_drained=True)
            self._check_selection(selection, request)
            verify_model_acceptance_batch(
                certificate,
                selection.history,
                self.intake.policy,
                maximum_block=certificate.batch.certified_at_block,
            )
            manifest = ModelAcceptanceBatchManifest(
                schema="umi-cohort-model-acceptance-manifest/1",
                certificate=certificate,
                acceptances=tuple(r.acceptance for r in request.requests),
            )
            self._put(db, request.batch.cohort_sha256, "manifest", digest(request.batch), manifest)
        return manifest

    def exported(self, request, submission, destination):
        with self.intake._connection() as (db, _):
            value = self._read(
                db, request.batch.cohort_sha256, "export:" + digest(request.batch), submission
            )
        if value is None:
            return False
        self._check_export(value, digest(request.batch), submission, destination)
        return True

    @staticmethod
    def _check_export(value, batch, submission, destination):
        if (
            set(value) != {"destination", "submission_sha256", "publication_sha256", "batch_sha256"}
            or value.get("destination") != str(destination)
            or value.get("submission_sha256") != submission
            or value.get("batch_sha256") != batch
            or not isinstance(value.get("publication_sha256"), str)
            or len(value["publication_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in value["publication_sha256"])
        ):
            raise ValueError("model batch export checkpoint changed its consumer binding")

    def _exports(self, db, cohort, batch, submissions, destination):
        keys = {
            row[0]
            for row in db.execute(
                "SELECT record_key FROM cohort_model_batch_records WHERE cohort=? AND kind=?",
                (cohort, "export:" + batch),
            )
        }
        if keys != set(submissions):
            raise ValueError(
                "completed model batch lost its exact export inventory; repair required"
            )
        values = []
        for key in submissions:
            value = self._read(db, cohort, "export:" + batch, key)
            self._check_export(value, batch, key, destination)
            values.append(value)
        return values

    @staticmethod
    def _completion_report(cohort, batch, count):
        return {
            "cohort_sha256": cohort,
            "status": "completed",
            "completed": count,
            "total": count,
            "batch_sha256": batch,
            "eta_seconds": 0,
            "eta_basis": "retained_completed_batch_scope",
            "stalled_or_retrying": False,
        }

    def completed(self, cohort, adoption, destination):
        """Reuse durable completed work without capture, native replay or payload I/O.

        These compact owner records are checked for damaged/missing bindings.
        They are completion evidence, not an expiring payload cache.
        """
        with self.intake._connection(prefer_history=True) as (db, _):
            value = self._read(db, cohort, "completion", "selected")
            if value is None:
                return None
            raw = self._read(db, cohort, "request", "selected")
            if raw is None or set(raw) != {"batch", "adoption", "submissions", "request_sha256"}:
                raise ValueError("completed model batch lost its original request; repair required")
            batch = digest(raw["batch"])
            manifest = self._read(db, cohort, "manifest", batch)
            if manifest is None:
                raise ValueError("completed model batch lost its manifest; repair required")
            exports = self._exports(db, cohort, batch, raw["submissions"], destination)
            expected = {
                "batch_sha256": batch,
                "adoption_sha256": digest(adoption),
                "request_sha256": raw["request_sha256"],
                "manifest_sha256": digest(manifest),
                "exports_sha256": digest(exports),
                "destination": str(destination),
                "accepted_count": len(raw["submissions"]),
            }
            if value != expected or digest(raw["adoption"]) != digest(adoption):
                raise ValueError("completed model batch changed retained bindings; repair required")
        return self._completion_report(cohort, batch, value["accepted_count"])

    def mark_completed(self, request, manifest, destination):
        cohort, batch = request.batch.cohort_sha256, digest(request.batch)
        submissions = [r.acceptance.submission_sha256 for r in request.requests]
        with self.intake._connection() as (db, _):
            raw = self._read(db, cohort, "request", "selected")
            if raw is None or raw["request_sha256"] != digest(request):
                raise ValueError("completed model batch changes its retained request")
            retained = self._read(db, cohort, "manifest", batch)
            if retained is None or digest(retained) != digest(manifest):
                raise ValueError("completed model batch changes its retained manifest")
            exports = self._exports(db, cohort, batch, submissions, destination)
            self._put(
                db,
                cohort,
                "completion",
                "selected",
                {
                    "batch_sha256": batch,
                    "adoption_sha256": digest(request.adoption),
                    "request_sha256": digest(request),
                    "manifest_sha256": digest(manifest),
                    "exports_sha256": digest(exports),
                    "destination": str(destination),
                    "accepted_count": len(submissions),
                },
            )
        return self._completion_report(cohort, batch, len(submissions))

    def mark_exported(self, request, publication, destination):
        a = publication.certificate.acceptance
        if a not in tuple(r.acceptance for r in request.requests):
            raise ValueError("model export is outside its retained batch")
        with self.intake._connection() as (db, _):
            self._put(
                db,
                request.batch.cohort_sha256,
                "export:" + digest(request.batch),
                a.submission_sha256,
                {
                    "destination": str(destination),
                    "submission_sha256": a.submission_sha256,
                    "publication_sha256": digest(publication),
                    "batch_sha256": digest(request.batch),
                },
            )
