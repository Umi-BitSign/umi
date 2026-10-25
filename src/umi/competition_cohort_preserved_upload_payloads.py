"""Delivery-only access to a frozen upload's authenticated preserved R2 bytes.

An upload can be preserved before participation or artifact admission. Its exact
HTTP retries need byte availability, not invented admission evidence. This
adapter is deliberately unavailable to the admission/acceptance router.
"""

from .competition_cohort_legacy_model_admission import LegacyModelAdmissionPayloads
from .competition_cohort_legacy_model_storage import authenticate_legacy_storage_inventories
from .competition_cohort_model_transport_selection import committed_model_delivery_selection
from .open_competition import digest
from .protocol import canonical_json_bytes


class PreservedModelUploadPayloads(LegacyModelAdmissionPayloads):
    def __init__(self, uploads, sources):
        super().__init__(uploads.intake, sources)
        self.uploads = uploads

    def contains(self, request):
        original = self.sources.authenticated.get(request.consent.consent.cohort_sha256)
        return original is not None and any(
            entry.request_sha256 == digest(request) and entry.payload_state == "preserved"
            for entry in original.legacy.entries
        )

    def qualify(self, store, *, record, admission):
        raise ValueError("preserved upload delivery cannot qualify model admission")

    async def ensure(self, request, *, completed_only=True):
        # Retirement is not a reason to repeat previously completed byte work.
        # Missing retained facts require explicit repair or restoration.
        return await super().ensure(request, completed_only=True)

    def owned_original(self, request):
        key = digest(request)
        if self.uploads.retained(key) != request or not self.contains(request):
            raise ValueError("preserved upload differs from its retained original request")
        cohort = request.consent.consent.cohort_sha256
        original = self.sources.authenticated[cohort]
        with self.intake._connection(prefer_history=True) as (_, store):
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
                raise ValueError("preserved upload changed its committed storage selection")
            state, _ = store.status(cohort)
        resolution = self.sources.resolve(cohort, request_sha256=key)
        if resolution.selection.bundle != request.signed_submission.submission.model_bundle:
            raise ValueError("preserved upload differs from its authenticated R2 model")
        return state.tip_sha256, key, digest(resolution.selection)
