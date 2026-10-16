"""Compare the complete original owner ledgers under their native intake fence.

Lock order matches legacy upload reservation: intake first, upload journal next.
The durable intake pending transition therefore also fences new upload keys.
No supplementary SQLite owner or mutable replacement inventory is introduced.
"""

from .competition_cohort_intake import history_tip
from .competition_cohort_intake_records import read_participation, replay_participation
from .competition_cohort_legacy_model_storage import MAX_ORIGINAL_BYTES, LegacyModelOriginals
from .competition_cohort_model_acceptance import ModelAcceptancePublication
from .competition_cohort_model_acceptance_store import acceptance_tables
from .competition_cohort_participation import CohortParticipationRequest
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .protocol import canonical_json_bytes, sha256_hex


def _pin(raw):
    return None if raw is None else sha256_hex(raw)


def _body(db, table, where, parameters):
    maximum = MAX_ORIGINAL_BYTES
    row = db.execute(
        f"SELECT substr(body,1,?) FROM {table} WHERE {where}", (maximum + 1, *parameters)
    ).fetchone()
    if row is not None and len(row[0]) > maximum:
        raise ValueError("model adoption original exceeds its native retained bound")
    return None if row is None else row[0]


def _compare(db, intake, uploads, history, authenticated, originals):
    """Called only while the original intake and upload journal locks are held."""
    cohort = digest(history.plan)
    legacy, preservation = authenticated.legacy, authenticated.preservation
    expected = {value.request_sha256: value for value in legacy.entries}
    models = {value.model_sha256 for value in preservation.models}
    retained, requests, uploaded = {}, set(), set()
    upload_keys = uploads.journal.keys("upload")
    participation_count = db.execute(
        "SELECT COUNT(*) FROM cohort_consents WHERE cohort=?", (cohort,)
    ).fetchone()[0]
    with TransferProgress(
        "model_delivery_adoption_census_scan",
        participation_count + len(upload_keys),
        unit="records",
        planning_unit_seconds=(0.001, 1),
    ) as scan:
        for consent, raw in intake._records(db, history):
            record = read_participation(raw)
            if record.request.signed_submission.submission.track == "model":
                replay_participation(record, history, intake.policy)
                key = digest(record.request)
                if key in retained:
                    raise ValueError("model adoption census repeats an original participation")
                # Keep only indexed identities, never an aggregate of model or
                # participation payloads. Every exact byte comparison below
                # reopens one bounded original under the same owner locks.
                retained[key] = (consent, digest(record.request.signed_submission.submission))
                requests.add(key)
            scan.advance(1)
        for key in upload_keys:
            raw = uploads.journal.get_raw("upload", key)
            request = CohortParticipationRequest.model_validate_json(raw)
            if digest(request) != key or raw != canonical_json_bytes(request):
                raise ValueError("model adoption census found changed original upload bytes")
            if request.consent.consent.cohort_sha256 == cohort:
                requests.add(key)
                uploaded.add(key)
            scan.advance(1)
    # Older supported intake may predate the managed upload journal. Its native
    # signed request remains an original, and cannot be omitted from the census.
    if requests != expected.keys():
        raise ValueError("model adoption census omits or adds original upload requests")
    acceptance_tables(db)
    submissions = {submission for _, submission in retained.values()}
    for table in ("cohort_model_acceptance_intents", "cohort_model_acceptances"):
        keys = {
            row[0]
            for row in db.execute(f"SELECT submission FROM {table} WHERE cohort=?", (cohort,))
        }
        if not keys <= submissions:
            raise ValueError("model adoption census has an orphaned original acceptance")
    with TransferProgress(
        "model_delivery_adoption_owner_census",
        len(requests),
        unit="requests",
        planning_unit_seconds=(0.001, 1),
    ) as progress:
        for key in sorted(requests):
            participation = admission = intent = certificate = None
            if key in retained:
                consent, _ = retained[key]
                participation = _body(
                    db, "cohort_consents", "cohort=? AND consent=?", (cohort, consent)
                )
                record = read_participation(participation)
                raw = canonical_json_bytes(record.request)
            else:
                raw = uploads.journal.get_raw("upload", key)
            if key in uploaded and uploads.journal.get_raw("upload", key) != raw:
                raise ValueError("model adoption upload changes original intake request")
            request = CohortParticipationRequest.model_validate_json(raw)
            sub = request.signed_submission.submission
            if key in retained:
                if record.observation.block > legacy.captured_at_block:
                    raise ValueError("model adoption inventory predates original participation")
                admission = _body(
                    db,
                    "cohort_admission_certificates",
                    "consent=?",
                    (record.proposed_admission.consent_sha256,),
                )
                intent = _body(
                    db,
                    "cohort_model_acceptance_intents",
                    "cohort=? AND submission=?",
                    (cohort, digest(sub)),
                )
                publication = _body(
                    db,
                    "cohort_model_acceptances",
                    "cohort=? AND submission=?",
                    (cohort, digest(sub)),
                )
                if publication is not None:
                    parsed = ModelAcceptancePublication.model_validate_json(publication)
                    if canonical_json_bytes(parsed) != publication:
                        raise ValueError("model adoption acceptance changed canonical bytes")
                    certificate = canonical_json_bytes(parsed.certificate)
            actual = LegacyModelOriginals(
                request_sha256=key,
                model_sha256=sub.model_revision,
                request_raw_sha256=_pin(raw),
                payload_state="preserved" if sub.model_revision in models else "incomplete_upload",
                participation_raw_sha256=_pin(participation),
                admission_raw_sha256=_pin(admission),
                intent_raw_sha256=_pin(intent),
                certificate_raw_sha256=_pin(certificate),
            )
            if actual != expected[key]:
                raise ValueError("model adoption census differs from original native records")
            for value in (raw, participation, admission, intent, certificate):
                if value is not None and originals(sha256_hex(value)) != value:
                    raise ValueError("model adoption selected copy changes original signed bytes")
            progress.advance(1)


def census_model_delivery(intake, uploads, transition, candidate, *, reserve=False):
    """Verify exact original census, optionally reserving its tip before unlocking.

    A crash after intake reservation is recovered into the existing lifecycle
    control journal. Retrying compares the same original bytes before returning.
    """
    if (
        transition.operation != "adopt_model_delivery"
        or uploads is None
        or uploads.intake is not intake
    ):
        raise ValueError("model delivery census requires its original native upload owner")
    cohort = transition.cohort_sha256
    intake._allowed(cohort)
    with intake._connection() as (db, store), uploads.journal.locked():
        history = store.published_history(cohort)
        state, pending = store.status(cohort)
        if history_tip(history) != transition.predecessor_sha256:
            raise ValueError("model delivery census lost its selected predecessor")
        if pending is not None and pending != transition:
            raise ValueError("model delivery census conflicts with pending owner decision")
        if state.phase != "intake" or intake._seal(db, history, state.tip_sha256) is not None:
            raise ValueError("model delivery adoption requires unsealed native intake")
        authenticated = candidate.authenticate(history, transition)
        _compare(db, intake, uploads, history, authenticated, candidate.originals)
        if reserve:
            store.reserve_exact(transition)
        return authenticated
