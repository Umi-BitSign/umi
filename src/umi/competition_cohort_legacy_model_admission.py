"""Owned grandfathering of exact frozen admissions onto authenticated R2 bytes.

Storage adoption does not admit a new participant or approve model rights. The
native owner checks its actual history and certified original at each boundary;
only payload verification is streamed and durably reused from R2.
"""

from .competition_cohort_intake_records import read_participation
from .competition_cohort_legacy_model_storage import authenticate_legacy_storage_inventories
from .competition_cohort_model_transport_selection import committed_model_delivery_selection
from .competition_cohort_participation import AttestedCohortParticipantAdmission
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes


class LegacyModelAdmissionPayloads:
    def __init__(self, intake, sources):
        if digest(intake.policy) != digest(sources.policy):
            raise ValueError("legacy admission source differs from owned policy")
        self.intake, self.sources = intake, sources
        self.verified = {}

    def contains(self, request):
        cohort = request.consent.consent.cohort_sha256
        selected = self.sources.authenticated.get(cohort)
        if selected is None:
            return False
        key = digest(request)
        return any(
            entry.request_sha256 == key
            and entry.payload_state == "preserved"
            and entry.participation_raw_sha256 is not None
            and entry.admission_raw_sha256 is not None
            for entry in selected.legacy.entries
        )

    def qualify(self, store, *, record, admission):
        """Called under the owner's lock before verification and reservation."""
        request = record.request
        if not self.contains(request):
            return False
        cohort = request.consent.consent.cohort_sha256
        original = self.sources.authenticated[cohort]
        selected = authenticate_legacy_storage_inventories(
            canonical_json_bytes(original.legacy),
            canonical_json_bytes(original.preservation),
            selection=committed_model_delivery_selection(store, cohort, self.intake.policy),
            policy=self.intake.policy,
            expected_baseline_sha256=original.legacy.baseline_model_sha256,
            expected_incumbent_sha256s=tuple(
                value.model_sha256 for value in original.legacy.incumbents
            ),
        )
        if selected != original:
            raise ValueError("legacy admission source changed its committed history")
        self.sources.admitted(cohort, record=record, admission=admission)
        return True

    async def ensure(self, request, *, completed_only=False):
        cohort, key = request.consent.consent.cohort_sha256, digest(request)
        resolution = self.sources.resolve(cohort, request_sha256=key)
        reader = self.sources.reader(resolution)
        # Invalidate a prior process-local capability before a failing retry.
        self.verified.pop(key, None)
        snapshot = (
            await reader.verify(completed_only=True) if completed_only else await reader.verify()
        )
        self.verified[key] = snapshot
        return snapshot

    def owned_original(self, request):
        """Reauthenticate an exact retained upload against the native owner."""
        if not self.contains(request):
            raise ValueError("remote retry is not a frozen certified original")
        cohort, consent = request.consent.consent.cohort_sha256, digest(request.consent.consent)
        with self.intake._connection() as (db, store):
            row = db.execute(
                "SELECT substr(body,1,4194305) FROM cohort_consents WHERE cohort=? AND consent=?",
                (cohort, consent),
            ).fetchone()
            if row is None or len(row[0]) > 4 * 1024**2:
                raise OSError("remote retry requires its retained original participation")
            record = read_participation(row[0])
            if record.request != request or canonical_json_bytes(record) != row[0]:
                raise ValueError("remote retry changed its original participation")
            row = db.execute(
                "SELECT substr(body,1,131073) FROM cohort_admission_certificates WHERE consent=?",
                (consent,),
            ).fetchone()
            if row is None or len(row[0]) > 128 * 1024:
                raise OSError("remote retry requires its original admission certificate")
            admission = AttestedCohortParticipantAdmission.model_validate_json(row[0])
            if canonical_json_bytes(admission) != row[0]:
                raise ValueError("remote retry changed its canonical admission")
            if not self.qualify(store, record=record, admission=admission):
                raise ValueError("remote retry lost its authenticated storage selection")
            state, _ = store.status(cohort)
            return state.tip_sha256, digest(record), digest(admission)

    async def ensure_owned(self, request, *, completed_only=False):
        key = digest(request)
        self.verified.pop(key, None)
        try:
            before = await run_owned_thread(self.owned_original, request)
            if completed_only:
                await self.ensure(request, completed_only=True)
            else:
                await self.ensure(request)
            if await run_owned_thread(self.owned_original, request) != before:
                raise OSError("model intake changed during remote retry verification")
        except BaseException:
            self.verified.pop(key, None)
            raise

    def require_owned_payload(self, request):
        self.owned_original(request)
        self.require_payload(request)

    async def compare_retry(self, request, *, file_index, offset, data):
        key = digest(request)
        try:
            before = await run_owned_thread(self.owned_original, request)
            snapshot = self.verified.get(key)
            if snapshot is None:
                snapshot = await self.ensure(request)
            resolution = self.sources.resolve(
                request.consent.consent.cohort_sha256, request_sha256=key
            )
            try:
                expected = await self.sources.reader(resolution).read_verified_range(
                    snapshot,
                    file_index=file_index,
                    offset=offset,
                    size_bytes=len(data),
                )
            except ValueError as error:
                raise OSError("remote model retry requires storage verification repair") from error
            if await run_owned_thread(self.owned_original, request) != before:
                raise OSError("model intake changed during remote retry comparison")
        except ValueError as error:
            self.verified.pop(key, None)
            raise OSError("remote model retry requires storage verification repair") from error
        except BaseException:
            self.verified.pop(key, None)
            raise
        if data != expected:
            self.verified.pop(key, None)
            raise ValueError("retry differs from the completed original file")

    def require_payload(self, request):
        key = digest(request)
        snapshot = self.verified.get(key)
        if not self.contains(request) or snapshot is None:
            raise OSError("legacy admission awaits owned R2 byte verification")
        resolution = self.sources.resolve(request.consent.consent.cohort_sha256, request_sha256=key)
        self.sources.reader(resolution).require_verified(snapshot)
