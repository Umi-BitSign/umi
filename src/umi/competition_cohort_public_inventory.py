"""Bounded native intake export for public model discovery, including revisions."""

from __future__ import annotations

from .competition_cohort_model_acceptance import CertifiedModelArtifactAcceptance
from .competition_cohort_participation import AttestedCohortParticipantAdmission
from .competition_cohort_public_results import PublicModelInventory, project_models
from .competition_cohort_roster import RecoverableRosterParticipant
from .competition_work_progress import WorkProgress
from .open_competition import digest
from .protocol import canonical_json_bytes


def export_public_model_inventory(intake, cohort: str) -> PublicModelInventory:
    """Use one owned read snapshot; no proof collection, RPC or payload reads.

    The existing native retained-record decoder and indexed cohort binding remain
    authoritative. Pending participation is not certified admission. Artifact
    review may remain pending and is reported separately by the public catalog.
    """
    intake._allowed(cohort)
    with intake._connection(prefer_history=True) as (db, store):
        history = store.published_history(cohort)
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "cohort_admission_certificates" not in tables:
            raise ValueError("public model export requires retained admission certificates")
        total = db.execute(
            "SELECT count(*) FROM cohort_consents WHERE cohort=? AND track='model'", (cohort,)
        ).fetchone()[0]
        participants = {}
        with WorkProgress(
            "public_admitted_model_inventory", total, unit="records", cohort=cohort
        ) as progress:
            for consent, _, record in intake._parsed_records(db, history, track="model"):
                raw = db.execute(
                    "SELECT substr(body,1,65537) FROM cohort_admission_certificates "
                    "WHERE consent=?",
                    (consent,),
                ).fetchone()
                if raw is not None:
                    if len(raw[0]) > 65536:
                        raise ValueError(
                            "retained public admission certificate exceeds native capacity"
                        )
                    admission = AttestedCohortParticipantAdmission.model_validate_json(raw[0])
                    if (
                        admission.admission != record.proposed_admission
                        or canonical_json_bytes(admission) != raw[0]
                    ):
                        raise ValueError("retained public admission certificate differs")
                    participant = RecoverableRosterParticipant(record=record, admission=admission)
                    key = digest(record.request.signed_submission.submission)
                    prior = participants.get(key)
                    if (
                        prior is not None
                        and prior.admission.admission.uid != admission.admission.uid
                    ):
                        raise ValueError("repeated public submission changes its retained UID")
                    if (
                        prior is None
                        or admission.admission.admitted_at_block
                        < prior.admission.admission.admitted_at_block
                    ):
                        participants[key] = participant
                progress.advance()
        acceptances = []
        if "cohort_model_acceptances" in tables:
            for submission in sorted(participants):
                # Extract only the signed certificate, never confidential review
                # attachments or complete reconstruction evidence.
                row = db.execute(
                    "SELECT json_extract(body,'$.certificate') FROM cohort_model_acceptances "
                    "WHERE cohort=? AND submission=?",
                    (cohort, submission),
                ).fetchone()
                if row is not None:
                    if row[0] is None or len(row[0]) > 1024**2:
                        raise ValueError("retained public artifact certificate requires repair")
                    acceptances.append(CertifiedModelArtifactAcceptance.model_validate_json(row[0]))
        result = PublicModelInventory(
            schema="umi-native-public-model-inventory/1",
            scope="all_admitted_model_submissions",
            policy=intake.policy,
            history=history,
            participants=tuple(participants[k] for k in sorted(participants)),
            acceptances=tuple(acceptances),
        )
    # Signature/arithmetic work runs after the read transaction has released.
    project_models(result)
    return result
