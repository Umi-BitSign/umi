"""Durable model acceptance under the intake owner's existing process lock.

An ordinal reserves a complete bundle and its original review documents. Only
an independent quorum can approve that proposal. Retries keep its original
ordinal and block; missing files or reviewers do not consume a new position.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import RootModel

from .competition_artifacts import verify_preserved_bundle
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake_records import read_participation, replay_participation
from .competition_cohort_model_acceptance import (
    ModelAcceptanceIntent,
    ModelAcceptancePublication,
    ModelArtifactAcceptance,
    ModelArtifactReviewInputs,
    verify_model_acceptance,
)
from .competition_cohort_participation import AttestedCohortParticipantAdmission
from .competition_cohort_recovery import ModelRewardCohortAuthority, verify_recovery_quorum
from .competition_execution import execution_boundary
from .competition_store import AdmissionCapacityError
from .open_competition import digest, model_content_digest
from .private_files import publish_private_model
from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    from .competition_cohort_intake import CohortIntake

MAX_PUBLICATION_BYTES = 33 * 1024**2


class PendingModelArtifacts(OSError):
    """Selected models still need a certified, preserved artifact acceptance."""


def acceptance_tables(db):
    for name in ("cohort_model_acceptance_intents", "cohort_model_acceptances"):
        db.execute(
            f"CREATE TABLE IF NOT EXISTS {name} "
            "(cohort TEXT NOT NULL, submission TEXT NOT NULL, body BLOB NOT NULL, "
            "PRIMARY KEY(cohort,submission))"
        )


def _read(db, table, cohort, submission):
    row = db.execute(
        f"SELECT substr(body,1,?) FROM {table} WHERE cohort=? AND submission=?",
        (MAX_PUBLICATION_BYTES + 1, cohort, submission),
    ).fetchone()
    if row is None:
        return None
    if len(row[0]) > MAX_PUBLICATION_BYTES:
        raise ValueError("model acceptance exceeds retained capacity")
    return row[0]


def read_publication(db, cohort, submission):
    raw = _read(db, "cohort_model_acceptances", cohort, submission)
    if raw is None:
        raise PendingModelArtifacts("selected model artifact acceptance is pending")
    publication = ModelAcceptancePublication.model_validate_json(raw)
    if canonical_json_bytes(publication) != raw:
        raise ValueError("retained model acceptance changed its canonical bytes")
    return publication


def model_acceptances_for_seal(db, seal, history, policy, records):
    """A missing or changed acceptance cannot close an opted-in cohort."""
    if not isinstance(history.authority.authority, ModelRewardCohortAuthority):
        return ()
    acceptance_tables(db)
    certificates = []
    for selected in seal.selected:
        if selected.track != "model":
            continue
        publication = read_publication(db, seal.cohort_sha256, selected.submission_sha256)
        certificates.append(publication.certificate)
    verify_sealed_model_acceptances(tuple(certificates), seal, history, policy, records)
    return tuple(certificates)


def verify_sealed_model_acceptances(certificates, seal, history, policy, records):
    retained = {key: read_participation(raw) for key, raw in records}
    selected_models = tuple(s for s in seal.selected if s.track == "model")
    if tuple(c.acceptance.submission_sha256 for c in certificates) != tuple(
        s.submission_sha256 for s in selected_models
    ):
        raise PendingModelArtifacts("model acceptances do not cover the entire sealed model roster")
    for certificate, selected in zip(certificates, selected_models, strict=True):
        verify_model_acceptance(
            certificate,
            retained[selected.consent_sha256],
            history,
            policy,
            maximum_block=seal.observation.block,
        )
    ordered = sorted(certificates, key=lambda c: c.acceptance.accepted_ordinal)
    if len({c.acceptance.accepted_ordinal for c in ordered}) != len(ordered):
        raise ValueError("model acceptances repeat a completion ordinal")
    blocks = [c.acceptance.accepted_at_block for c in ordered]
    if blocks != sorted(blocks):
        raise ValueError("model acceptance ordinals contradict their block order")


class CohortModelAcceptances:
    def __init__(self, intake: CohortIntake, archive: Path):
        self.intake, self.archive = intake, archive
        with intake._connection() as (db, _):
            acceptance_tables(db)

    def _record(self, db, history, submission):
        for _, raw in self.intake._records(db, history):
            record = read_participation(raw)
            if digest(record.request.signed_submission.submission) == submission:
                replay_participation(record, history, self.intake.policy)
                return record
        raise ValueError("model acceptance has no original intake record")

    def entries(self, cohort, *, after="", limit=16):
        self.intake._allowed(cohort)
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("model acceptance scan exceeds its page bound")
        with self.intake._connection() as (db, store):
            history = store.published_history(cohort)
            result = []
            for key, raw in db.execute(
                "SELECT consent,substr(body,1,4194305) FROM cohort_consents "
                "WHERE cohort=? AND track='model' AND consent>? ORDER BY consent LIMIT ?",
                (cohort, after, limit),
            ):
                record = read_participation(raw)
                replay_participation(record, history, self.intake.policy)
                if digest(record.request.consent.consent) != key:
                    raise ValueError("model intake index differs from original consent")
                result.append((key, record.request.signed_submission.submission))
            return tuple(result)

    def intent(self, cohort, submission):
        self.intake._allowed(cohort)
        with self.intake._connection() as (db, _):
            raw = _read(db, "cohort_model_acceptance_intents", cohort, submission)
            if raw is None:
                return None
            value = ModelAcceptanceIntent.model_validate_json(raw)
            if canonical_json_bytes(value) != raw:
                raise ValueError("retained model proposal changed canonical bytes")
            return value

    def retained(self, cohort, submission):
        self.intake._allowed(cohort)
        with self.intake._connection() as (db, store):
            publication = read_publication(db, cohort, submission)
            history = store.published_history(cohort)
            record = self._record(db, history, submission)
            verify_model_acceptance(
                publication.certificate,
                record,
                history,
                self.intake.policy,
                maximum_block=publication.certificate.acceptance.accepted_at_block,
            )
            return publication

    def _put(self, db, table, cohort, submission, body):
        raw = canonical_json_bytes(body)
        if len(raw) > MAX_PUBLICATION_BYTES:
            raise AdmissionCapacityError("model acceptance needs additional durable capacity")
        prior = _read(db, table, cohort, submission)
        if prior is not None:
            if prior != raw:
                raise ValueError("model acceptance conflicts with its retained original")
            return
        # Use the intake owner's common accounting, including review documents.
        used = self.intake.retained_bytes(db)
        if used + len(raw) > self.intake.capacity.maximum_bytes:
            raise AdmissionCapacityError("model acceptance needs additional durable capacity")
        db.execute(f"INSERT INTO {table} VALUES (?,?,?)", (cohort, submission, raw))

    def prepare(self, cohort, submission, inputs: ModelArtifactReviewInputs, capture):
        """Reserve a proposal after byte verification, before requesting any votes.

        The caller selects reviewed documents privately. This method does not
        approve rights, execute code or sign anything on a reviewer's behalf.
        """
        inputs = ModelArtifactReviewInputs.model_validate_json(canonical_json_bytes(inputs))
        self.intake._allowed(cohort)
        with self.intake._connection() as (db, store):
            history = store.published_history(cohort)
            record = self._record(db, history, submission)
            prior = _read(db, "cohort_model_acceptance_intents", cohort, submission)
        sub = record.request.signed_submission.submission
        if sub.track != "model" or inputs.model_sha256 != sub.model_revision:
            raise ValueError("model review inputs differ from the selected submission")
        if prior is not None:
            intent = ModelAcceptanceIntent.model_validate_json(prior)
            body = intent.acceptance
            if (
                canonical_json_bytes(intent) != prior
                or intent.inputs != inputs
                or body.model_sha256 != inputs.model_sha256
                or body.rights_evidence_sha256 != digest(inputs.rights_evidence)
                or body.reconstruction_evidence_sha256 != digest(inputs.reconstruction_evidence)
            ):
                raise ValueError("model proposal retry changes its original review")
            return body
        verify_preserved_bundle(sub.model_bundle, self.archive, self.intake.policy)
        observation = execution_boundary(capture)
        with self.intake._connection() as (db, store):
            current = store.published_history(cohort)
            if current != history or self._record(db, current, submission) != record:
                raise OSError("model intake changed during artifact verification; retry")
            # Another identical request may have committed while files were read.
            prior = _read(db, "cohort_model_acceptance_intents", cohort, submission)
            if prior is not None:
                intent = ModelAcceptanceIntent.model_validate_json(prior)
                if canonical_json_bytes(intent) != prior or intent.inputs != inputs:
                    raise ValueError("concurrent model proposal changes its original review")
                return intent.acceptance
            tip = digest(
                current.transitions[-1].transition if current.transitions else current.genesis
            )
            view = verify_cohort_history(
                current,
                self.intake.policy,
                expected_tip_sha256=tip,
                current_block=observation.block,
            )
            if (
                not isinstance(current.authority.authority, ModelRewardCohortAuthority)
                or view.state.phase != "intake"
                or observation.block < record.proposed_admission.admitted_at_block
                or self.intake._seal(db, current, tip) is not None
            ):
                raise ValueError("new model acceptance requires open native model-reward intake")
            # Membership is independently certified before reserving a payout identity.
            row = db.execute(
                "SELECT body FROM cohort_admission_certificates WHERE consent=?",
                (record.proposed_admission.consent_sha256,),
            ).fetchone()
            if row is None:
                raise PendingModelArtifacts("model participant admission is not certified")
            admission = AttestedCohortParticipantAdmission.model_validate_json(row[0])
            if admission.admission != record.proposed_admission:
                raise ValueError("model admission changed its original record")
            verify_recovery_quorum(admission.admission, admission.signatures, self.intake.policy)
            ordinal, latest = db.execute(
                "SELECT MAX(json_extract(CAST(body AS TEXT), '$.acceptance.accepted_ordinal')), "
                "MAX(json_extract(CAST(body AS TEXT), '$.acceptance.accepted_at_block')) "
                "FROM cohort_model_acceptance_intents WHERE cohort=?",
                (cohort,),
            ).fetchone()
            if latest is not None and latest > observation.block:
                raise ValueError("model acceptance observation regressed")
            body = ModelArtifactAcceptance(
                schema="umi-cohort-model-artifact-acceptance/1",
                policy_sha256=digest(self.intake.policy),
                cohort_sha256=cohort,
                authority_sha256=digest(history.authority.authority),
                submission_sha256=submission,
                model_sha256=digest(sub.model_bundle),
                content_sha256=model_content_digest(sub.model_bundle),
                recipient_hotkey=sub.hotkey,
                rights_evidence_sha256=digest(inputs.rights_evidence),
                reconstruction_evidence_sha256=digest(inputs.reconstruction_evidence),
                accepted_at_block=observation.block,
                accepted_ordinal=(ordinal or 0) + 1,
                rights_and_reconstruction_passed=True,
            )
            self._put(
                db,
                "cohort_model_acceptance_intents",
                cohort,
                submission,
                ModelAcceptanceIntent(acceptance=body, inputs=inputs),
            )
            return body

    def publish(self, publication: ModelAcceptancePublication, capture):
        publication = ModelAcceptancePublication.model_validate_json(
            canonical_json_bytes(publication)
        )
        a = publication.certificate.acceptance
        cohort, submission = a.cohort_sha256, a.submission_sha256
        self.intake._allowed(cohort)
        with self.intake._connection() as (db, store):
            history = store.published_history(cohort)
            record = self._record(db, history, submission)
            prior = _read(db, "cohort_model_acceptances", cohort, submission)
        if prior is not None:
            if prior != canonical_json_bytes(publication):
                raise ValueError("model acceptance retry changes its certified original")
            return publication
        verify_preserved_bundle(
            record.request.signed_submission.submission.model_bundle,
            self.archive,
            self.intake.policy,
        )
        block = execution_boundary(capture).block
        tip = digest(history.transitions[-1].transition if history.transitions else history.genesis)
        view = verify_cohort_history(
            history, self.intake.policy, expected_tip_sha256=tip, current_block=block
        )
        if view.state.phase != "intake":
            raise ValueError("new model acceptance requires open intake")
        verify_model_acceptance(
            publication.certificate, record, history, self.intake.policy, maximum_block=block
        )
        with self.intake._connection() as (db, store):
            if store.published_history(cohort) != history:
                raise OSError("model intake changed during artifact verification; retry")
            intent = _read(db, "cohort_model_acceptance_intents", cohort, submission)
            if intent != canonical_json_bytes(
                ModelAcceptanceIntent(acceptance=a, inputs=publication.inputs)
            ):
                raise ValueError("model acceptance differs from the owner's reserved proposal")
            self._put(db, "cohort_model_acceptances", cohort, submission, publication)
        return publication

    def export(self, cohort, submission, destination: Path):
        """Publish certificate and original documents for replication, certificate last."""
        self.intake._allowed(cohort)
        publication = self.retained(cohort, submission)
        for body in (
            publication.inputs.rights_evidence,
            publication.inputs.reconstruction_evidence,
        ):
            # The typed document wrapper is unnecessary in endpoint object exports.
            publish_private_model(
                destination / "objects" / (digest(body) + ".json"),
                RootModel(body),
                maximum_bytes=16 * 1024**2,
            )
        publish_private_model(
            destination / "model-reward-acceptances" / cohort / (submission + ".json"),
            publication.certificate,
            maximum_bytes=256 * 1024,
        )
        return publication
