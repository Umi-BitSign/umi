"""Series-bound replay selections, retained independently of the coordinator.

The selected policy binds reward rules and evaluation runtime; each cohort plan
binds its suite. This manifest selects the remaining service terms and catalogs.
It does not replace current control, reward-opportunity or execution checks.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_reward_decisions import StandingRewardControlReader, StandingRewardSeries
from .open_competition import CompetitionPolicy, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_REWARD_MANIFEST_BYTES = 4 * 1024**2


class RewardReplayRequirement(StrictProtocolModel):
    cohort_sha256: Hex32
    terms_sha256: Hex32
    catalog_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def catalogs(self):
        if self.catalog_sha256s != tuple(sorted(set(self.catalog_sha256s))):
            raise ValueError("reward catalogs must be unique and sorted")
        return self


class StandingRewardManifest(StrictProtocolModel):
    """Complete replay selections in series order, chosen before admission.

    Resource ceilings are host limits, not expiring reward authority. Increasing
    local replay/storage capacity does not change these immutable selections.
    """

    schema_: Literal["umi-standing-reward-manifest/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohorts: Annotated[tuple[RewardReplayRequirement, ...], Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def unique_cohorts(self):
        if len({c.cohort_sha256 for c in self.cohorts}) != len(self.cohorts):
            raise ValueError("reward manifest repeats a cohort")
        return self

    def requirement(self, cohort_sha256: str) -> RewardReplayRequirement:
        for requirement in self.cohorts:
            if requirement.cohort_sha256 == cohort_sha256:
                return requirement
        raise ValueError("cohort is absent from the approved reward manifest")


def verify_reward_manifest(
    raw: bytes, series: StandingRewardSeries, policy: CompetitionPolicy
) -> StandingRewardManifest:
    """Check bounded bytes against independently selected standing authority.

    No field is inferred from an offered package. Quorum and chain admission are
    checked by the standing reader, not asserted by this static input check.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_REWARD_MANIFEST_BYTES:
        raise ValueError("reward manifest exceeds its byte bound or has invalid bytes")
    manifest = StandingRewardManifest.model_validate_json(raw)
    series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if digest(manifest) != series.manifest_sha256:
        raise ValueError("reward manifest differs from the selected series")
    if manifest.policy_sha256 != digest(policy) or manifest.policy_sha256 != series.policy_sha256:
        raise ValueError("reward manifest policy differs from the selected policy")
    if tuple(c.cohort_sha256 for c in manifest.cohorts) != tuple(digest(p) for p in series.cohorts):
        raise ValueError("reward manifest must cover exactly the ordered series")
    return manifest


def retain_reward_manifest(
    reader: StandingRewardControlReader, manifest: StandingRewardManifest | None
) -> StandingRewardManifest:
    """Persist before replay; restart may use the original retained bytes.

    Missing or invalid data remains an error. Neither a new package nor elapsed
    time can fill in or replace the original approval selections.
    """
    if digest(reader.series) != reader.series_sha256:
        raise ValueError("standing reader authority changed")
    value = (
        reader.journal.get("reward_series_manifest", "approved") if manifest is None else manifest
    )
    if value is None:
        raise FileNotFoundError("approved reward manifest is unavailable")
    checked = verify_reward_manifest(canonical_json_bytes(value), reader.series, reader.policy)
    reader.journal.put("reward_series_manifest", "approved", checked)
    return checked
