"""Unsigned private export of original metadata through its existing live owner.

This is a candidate-building observation, never an adoption, admission, remote
durability receipt or release capability. It reads no model payload, captures no
new finality, and invokes no signing or lifecycle initialization. Prepare and
reserve still compare their complete candidate against the current native census.
"""

import json
from typing import Literal

from pydantic import Field

from .competition_cohort_intake import history_tip
from .competition_cohort_intake_records import read_participation
from .competition_cohort_legacy_model_storage import MAX_ORIGINAL_BYTES
from .competition_cohort_model_acceptance import ModelAcceptancePublication
from .competition_cohort_participation import CohortParticipationRequest
from .competition_cohort_review_export import review_export_limits
from .competition_cohort_review_http import phase_review_routes
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex

PATH = "/internal/cohorts/model-delivery-preflight"


class ModelDeliveryPreflightRequest(StrictProtocolModel):
    schema_: Literal["umi-model-delivery-preflight-request/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    expected_predecessor_sha256: Hex32
    challenge: Hex32


class _Originals:
    def __init__(self, maximum_bytes):
        self.maximum_bytes = maximum_bytes
        self.size = 0
        self.values = {}

    def keep(self, raw):
        if raw is None:
            return None
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_ORIGINAL_BYTES:
            raise ValueError("model preflight original exceeds its retained bound")
        # Preserve the exact bytes, including any signed nested original.
        if canonical_json_bytes(json.loads(raw)) != raw:
            raise ValueError("model preflight original changed canonical bytes")
        key = sha256_hex(raw)
        if key not in self.values:
            value = {"raw_sha256": key, "raw_json": raw.decode("utf-8")}
            self.size += len(canonical_json_bytes(value))
            if self.size > self.maximum_bytes:
                raise OSError("complete model preflight exceeds export capacity")
            self.values[key] = value
        return key


def _body(db, tables, table, where, parameters):
    if table not in tables:
        return None
    row = db.execute(
        f"SELECT substr(body,1,?) FROM {table} WHERE {where}",
        (MAX_ORIGINAL_BYTES + 1, *parameters),
    ).fetchone()
    return None if row is None else row[0]


class ModelDeliveryPreflightExporter:
    def __init__(self, intake, uploads, *, maximum_bytes, timeout_seconds):
        review_export_limits(maximum_bytes, timeout_seconds)
        if uploads.intake is not intake:
            raise ValueError("model preflight requires its native upload owner")
        self.intake, self.uploads = intake, uploads
        self.maximum_bytes, self.timeout_seconds = maximum_bytes, timeout_seconds

    def export(self, request):
        request = ModelDeliveryPreflightRequest.model_validate_json(canonical_json_bytes(request))
        intake, uploads, cohort = self.intake, self.uploads, request.cohort_sha256
        intake._allowed(cohort)
        originals = _Originals(self.maximum_bytes)
        with intake.fenced_read_snapshot() as (db, store), uploads.journal.locked():
            history = store.published_history(cohort)
            state, pending = store.status(cohort)
            if (
                history_tip(history) != request.expected_predecessor_sha256
                or state.tip_sha256 != request.expected_predecessor_sha256
            ):
                raise ValueError("model preflight lost its expected predecessor")
            tables = {
                row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            retained, uploaded, submissions = {}, set(), set()
            keys = uploads.journal.keys("upload")
            retained_bytes = len(keys) * 128
            if retained_bytes > self.maximum_bytes:
                raise OSError("complete model preflight exceeds export capacity")
            count = db.execute(
                "SELECT COUNT(*) FROM cohort_consents WHERE cohort=? AND track='model'",
                (cohort,),
            ).fetchone()[0]
            with TransferProgress(
                "model_delivery_preflight_scan",
                count + len(keys),
                unit="records",
                planning_unit_seconds=(0.001, 0.1),
            ) as progress:
                for consent, raw in intake._records(db, history, track="model"):
                    record = read_participation(raw)
                    request_raw = canonical_json_bytes(record.request)
                    key = digest(record.request)
                    if key in retained:
                        raise ValueError("model preflight repeats an original participation")
                    retained_bytes += len(raw) + len(request_raw)
                    if retained_bytes > self.maximum_bytes:
                        raise OSError("complete model preflight exceeds export capacity")
                    retained[key] = (request_raw, consent, raw)
                    progress.advance(1)
                if len(retained) != count:
                    raise ValueError("model preflight has participation outside current history")
                for key in keys:
                    raw = uploads.journal.get_raw("upload", key)
                    signed = CohortParticipationRequest.model_validate_json(raw)
                    if digest(signed) != key or canonical_json_bytes(signed) != raw:
                        raise ValueError("model preflight upload index differs from original")
                    if signed.consent.consent.cohort_sha256 == cohort:
                        if key in retained and retained[key][0] != raw:
                            raise ValueError("model preflight upload differs from participation")
                        if key not in retained:
                            retained_bytes += len(raw)
                            if retained_bytes > self.maximum_bytes:
                                raise OSError("complete model preflight exceeds export capacity")
                        retained.setdefault(key, (raw, None, None))
                        uploaded.add(key)
                    progress.advance(1)
            entries = []
            entry_bytes = 0
            with TransferProgress(
                "model_delivery_preflight_originals",
                len(retained),
                unit="requests",
                planning_unit_seconds=(0.001, 0.1),
            ) as progress:
                for key, (raw, consent, participation) in sorted(retained.items()):
                    signed = CohortParticipationRequest.model_validate_json(raw)
                    sub = signed.signed_submission.submission
                    if sub.track != "model" or sub.model_bundle is None:
                        raise ValueError("model preflight found a non-model upload")
                    submission = digest(sub)
                    admission = (
                        _body(
                            db,
                            tables,
                            "cohort_admission_certificates",
                            "consent=?",
                            (consent,),
                        )
                        if consent is not None
                        else None
                    )
                    if admission is not None:
                        submissions.add(submission)
                    # Acceptance tables are submission-scoped. A second signed
                    # consent may share that submission without ever reaching
                    # admission; it must retain its own missing parent lineage.
                    intent = (
                        _body(
                            db,
                            tables,
                            "cohort_model_acceptance_intents",
                            "cohort=? AND submission=?",
                            (cohort, submission),
                        )
                        if admission is not None
                        else None
                    )
                    publication = (
                        _body(
                            db,
                            tables,
                            "cohort_model_acceptances",
                            "cohort=? AND submission=?",
                            (cohort, submission),
                        )
                        if admission is not None
                        else None
                    )
                    certificate = None
                    if publication is not None:
                        value = ModelAcceptancePublication.model_validate_json(publication)
                        if canonical_json_bytes(value) != publication:
                            raise ValueError("model preflight acceptance changed canonical bytes")
                        certificate = canonical_json_bytes(value.certificate)
                    preserved = uploads.journal.get_raw("preserved", sub.model_revision)
                    if preserved is not None and preserved != canonical_json_bytes(
                        {
                            "schema": "umi-cohort-model-delivery-preserved/1",
                            "model_sha256": sub.model_revision,
                        }
                    ):
                        raise ValueError("model preflight local preservation receipt changed")
                    entry = {
                        "request_sha256": key,
                        "model_sha256": sub.model_revision,
                        "upload_retained": key in uploaded,
                        "request_raw_sha256": originals.keep(raw),
                        "participation_raw_sha256": originals.keep(participation),
                        "admission_raw_sha256": originals.keep(admission),
                        "intent_raw_sha256": originals.keep(intent),
                        "certificate_raw_sha256": originals.keep(certificate),
                        "local_preserved_receipt_raw_sha256": originals.keep(preserved),
                    }
                    entry_bytes += len(canonical_json_bytes(entry))
                    if originals.size + entry_bytes > self.maximum_bytes:
                        raise OSError("complete model preflight exceeds export capacity")
                    entries.append(entry)
                    progress.advance(1)
            for table in ("cohort_model_acceptance_intents", "cohort_model_acceptances"):
                if table in tables and any(
                    row[0] not in submissions
                    for row in db.execute(
                        f"SELECT submission FROM {table} WHERE cohort=?", (cohort,)
                    )
                ):
                    raise ValueError("model preflight found an orphaned acceptance")
            result = {
                "schema": "umi-model-delivery-preflight/1",
                "challenge": request.challenge,
                "cohort_sha256": cohort,
                "policy_sha256": digest(intake.policy),
                "authority_sha256": intake.bindings[cohort],
                "predecessor_sha256": state.tip_sha256,
                "history_sha256": digest(history),
                "observed_at_block": state.observed_at_block,
                "phase": state.phase,
                "pending_transition_sha256": None if pending is None else digest(pending),
                "intake_sealed": db.execute(
                    "SELECT 1 FROM cohort_intake_seals WHERE cohort=? LIMIT 1",
                    (cohort,),
                ).fetchone()
                is not None,
                "entries": entries,
                "objects": [originals.values[key] for key in sorted(originals.values)],
                "legacy_allocations_all_cohorts": uploads.allocations.snapshot(),
                "observational_only": True,
            }
        raw = canonical_json_bytes(result)
        if len(raw) > self.maximum_bytes:
            raise OSError("complete model preflight exceeds export capacity")
        return raw

    async def respond(self, request):
        return await run_owned_thread(self.export, request)


def model_delivery_preflight_routes(intake, uploads, *, token, maximum_bytes, timeout_seconds):
    return phase_review_routes(
        ModelDeliveryPreflightExporter(
            intake,
            uploads,
            maximum_bytes=maximum_bytes,
            timeout_seconds=timeout_seconds,
        ),
        token=token,
        path=PATH,
        request_model=ModelDeliveryPreflightRequest,
        admission_lane="owner_export",
    )
