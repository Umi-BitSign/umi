"""Owned grandfathering of exact frozen admissions onto authenticated R2 bytes.

Storage adoption does not admit a new participant or approve model rights. The
native owner checks its actual history and certified original at each boundary;
only payload verification is streamed and durably reused from R2.
"""

from .competition_cohort_legacy_model_storage import authenticate_legacy_storage_inventories
from .competition_cohort_model_transport_selection import committed_model_delivery_selection
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

    async def ensure(self, request):
        cohort, key = request.consent.consent.cohort_sha256, digest(request)
        resolution = self.sources.resolve(cohort, request_sha256=key)
        reader = self.sources.reader(resolution)
        # Invalidate a prior process-local capability before a failing retry.
        self.verified.pop(key, None)
        snapshot = await reader.verify()
        self.verified[key] = snapshot

    def require_payload(self, request):
        key = digest(request)
        if not self.contains(request) or key not in self.verified:
            raise OSError("legacy admission awaits owned R2 byte verification")
        resolution = self.sources.resolve(request.consent.consent.cohort_sha256, request_sha256=key)
        self.sources.reader(resolution).require_verified(self.verified[key])
