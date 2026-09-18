"""Signed miner connection settings, separate from assignment authorization.

Verification is read-only. A profile names the reviewed feed and video origins;
it does not authorize requests, attest availability, or activate rewards.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_authorization import validate_transport_cohort
from .competition_client import validate_intake_origin
from .competition_launch import PublicLaunchIdentity
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_PROFILE_BYTES = 64 * 1024


class MinerFeedProfile(StrictProtocolModel):
    schema_: Literal["umi-miner-feed-profile/1"] = Field(alias="schema")
    policy_sha256: Hex32
    transport_policy_sha256: Hex32
    public_launch: PublicLaunchIdentity
    assignment_feed_origin: Annotated[str, Field(min_length=1, max_length=2048)]
    allowed_video_origins: Annotated[tuple[str, ...], Field(min_length=1, max_length=16)]
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def origins(self) -> Self:
        for origin in (self.assignment_feed_origin, *self.allowed_video_origins):
            if validate_intake_origin(origin) != origin:
                raise ValueError("profile origins must omit the trailing slash")
        if tuple(sorted(set(self.allowed_video_origins))) != self.allowed_video_origins:
            raise ValueError("profile video origins must be sorted and unique")
        if "endpoint" not in self.public_launch.eligible_tracks:
            raise ValueError("miner feed profile requires an endpoint launch")
        return self


class SignedMinerFeedProfile(StrictProtocolModel):
    profile: MinerFeedProfile
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def verify_miner_feed_profile(
    signed: SignedMinerFeedProfile,
    *,
    expected_profile_sha256: str,
    policy: CompetitionPolicy,
    transport: ScoringPolicy,
    public_launch: PublicLaunchIdentity,
    current_block: int,
) -> MinerFeedProfile:
    """Check the published digest, policy bindings, schedule and signer quorum.

    The caller supplies reviewed policy/launch inputs and a current block. This
    function performs no network or finality verification. Miner admission must
    still verify each assignment and its owned finalized-chain observations.
    """
    raw = canonical_json_bytes(signed)
    if len(raw) > MAX_PROFILE_BYTES:
        raise ValueError("miner feed profile exceeds its byte bound")
    signed = SignedMinerFeedProfile.model_validate_json(raw)
    profile = signed.profile
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
    public_launch = PublicLaunchIdentity.model_validate_json(canonical_json_bytes(public_launch))
    validate_transport_cohort(policy, transport)
    if digest(signed) != expected_profile_sha256:
        raise ValueError("miner feed profile differs from its published digest")
    if (
        profile.policy_sha256 != digest(policy)
        or profile.transport_policy_sha256 != scoring_policy_hash(transport)
        or profile.public_launch != public_launch
    ):
        raise ValueError("miner feed profile policy or launch binding differs")
    schedule = public_launch.round_schedule
    if not (
        policy.valid_from_block <= schedule.intake_opened_block
        and schedule.round_valid_through_block <= policy.valid_through_block
        and type(current_block) is int
        and schedule.intake_opened_block <= current_block <= schedule.evaluation_close_block
    ):
        raise ValueError("miner feed profile is outside its round or policy interval")
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    seen_keys: set[str] = set()
    seen_groups: set[str] = set()
    for signature in signed.signatures:
        key = identity(signature.hotkey)
        if key not in groups or key in seen_keys or groups[key] in seen_groups:
            raise ValueError("miner feed profile has unauthorized or duplicate signers")
        verify_signature(profile, signature)
        seen_keys.add(key)
        seen_groups.add(groups[key])
    if len(seen_groups) < policy.required_evaluator_groups:
        raise ValueError("miner feed profile lacks the policy evaluator quorum")
    return profile
