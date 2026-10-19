"""Authenticated runtime compatibility without replacing signed reward inputs.

The manifest's eligibility profile remains the original anchor. A separately
selected quorum contract can authorize an exact supported profile over a stated
block range. It cannot change clocks, allocations, series identity or already
completed verification. Runtime code and same-root consensus are still proved by
the native eligibility consumer; signatures are never a substitute for them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import pairwise
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_recovery import Block, verify_recovery_authority, verify_recovery_quorum
from .competition_reward_eligibility import (
    RewardEligibilityRuntime,
    validate_qualified_reward_runtime,
)
from .competition_reward_manifest import verify_reward_manifest
from .competition_transport_verification import TransferProgress
from .open_competition import Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RewardRuntimeAdoption(StrictProtocolModel):
    schema_: Literal[
        "umi-standing-reward-runtime-adoption/1",
        "umi-standing-reward-runtime-adoption/2",
    ] = Field(alias="schema")
    series_sha256: Hex32
    manifest_sha256: Hex32
    policy_sha256: Hex32
    authority_sha256: Hex32
    original_runtime_profile_sha256: Hex32
    effective_profile: RewardEligibilityRuntime
    first_block: Block
    last_block: Block
    issued_at_block: Block
    revision: Annotated[int, Field(ge=1, le=4096)]
    predecessor_adoption_sha256: Hex32 | None
    original_signed_inputs_unchanged: Literal[True]
    supersedes_adoption_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def original_signed_bytes(self, handler):
        value = handler(self)
        if self.supersedes_adoption_sha256 is None:
            value.pop("supersedes_adoption_sha256", None)
        return value

    @model_validator(mode="after")
    def scope(self):
        supersession = self.schema_ == "umi-standing-reward-runtime-adoption/2"
        if supersession != (self.supersedes_adoption_sha256 is not None):
            raise ValueError("runtime supersession requires its explicit versioned target")
        if supersession and self.revision == 1:
            raise ValueError("runtime supersession requires a retained predecessor")
        if self.first_block > self.last_block:
            raise ValueError("runtime adoption has an empty block scope")
        if (self.revision == 1) != (self.predecessor_adoption_sha256 is None):
            raise ValueError("runtime adoption requires its exact revision predecessor")
        if self.original_runtime_profile_sha256 == digest(self.effective_profile):
            raise ValueError("runtime adoption must name a distinct effective profile")
        if not self.effective_profile.requires_epoch_consensus_proof:
            raise ValueError(
                "new runtime adoption requires explicitly qualified versioned semantics"
            )
        return self


class SignedRewardRuntimeAdoption(StrictProtocolModel):
    adoption: RewardRuntimeAdoption
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class RewardRuntimeAdoptionSelection(StrictProtocolModel):
    # /1 retains its forward-only block ordering. /2 keeps the same signed
    # revision chain but can append a disjoint historical gap. Earlier signed
    # records are never edited, reordered or replaced to backdate a profile.
    schema_: Literal[
        "umi-standing-reward-runtime-adoption-selection/1",
        "umi-standing-reward-runtime-adoption-selection/2",
        "umi-standing-reward-runtime-adoption-selection/3",
    ] = Field(alias="schema")
    adoptions: Annotated[
        tuple[SignedRewardRuntimeAdoption, ...], Field(min_length=1, max_length=4096)
    ]

    @model_validator(mode="after")
    def lineage(self):
        previous = None
        retained = {}
        immutable = (
            "series_sha256",
            "manifest_sha256",
            "policy_sha256",
            "authority_sha256",
            "original_runtime_profile_sha256",
        )
        for signed in self.adoptions:
            body = signed.adoption
            if previous is None:
                if body.revision != 1:
                    raise ValueError("runtime adoption omits its original revision")
            elif (
                body.revision != previous.revision + 1
                or body.predecessor_adoption_sha256 != digest(previous)
                or (
                    self.schema_ == "umi-standing-reward-runtime-adoption-selection/1"
                    and body.first_block <= previous.last_block
                )
                or body.issued_at_block < previous.issued_at_block
                or any(getattr(body, name) != getattr(previous, name) for name in immutable)
            ):
                raise ValueError("runtime adoption changes lineage or overlaps an earlier scope")
            if body.supersedes_adoption_sha256 is not None:
                if self.schema_ != "umi-standing-reward-runtime-adoption-selection/3":
                    raise ValueError("runtime supersession requires selection format3")
                target = retained.get(body.supersedes_adoption_sha256)
                if target is None:
                    raise ValueError("runtime supersession target is not retained")
                if (
                    body.first_block < target.first_block
                    or body.last_block > target.last_block
                    or body.effective_profile.runtime_code_sha256
                    == target.effective_profile.runtime_code_sha256
                ):
                    raise ValueError("runtime supersession extends its target or keeps its code")
                ancestors = set()
                ancestor = target
                while ancestor is not None:
                    ancestors.add(digest(ancestor))
                    ancestor = retained.get(ancestor.supersedes_adoption_sha256)
                for key, old in retained.items():
                    overlaps = (
                        body.first_block <= old.last_block and old.first_block <= body.last_block
                    )
                    if overlaps and key not in ancestors:
                        raise ValueError("runtime supersession overlaps an unrelated signed scope")
            elif self.schema_ == "umi-standing-reward-runtime-adoption-selection/3":
                if any(
                    body.first_block <= old.last_block and old.first_block <= body.last_block
                    for old in retained.values()
                ):
                    raise ValueError(
                        "runtime overlap requires an explicit authenticated supersession"
                    )
            retained[digest(body)] = body
            previous = body
        if self.schema_ == "umi-standing-reward-runtime-adoption-selection/2":
            scopes = sorted((v.adoption.first_block, v.adoption.last_block) for v in self.adoptions)
            if any(right[0] <= left[1] for left, right in pairwise(scopes)):
                raise ValueError("runtime gap adoption overlaps a retained signed scope")
        return self


_ISSUER = object()


@dataclass(frozen=True, slots=True)
class SelectedRewardRuntime:
    """Process-local selection, authenticated independently of imported points."""

    original_profile: RewardEligibilityRuntime
    selection: RewardRuntimeAdoptionSelection | None
    series_sha256: str
    manifest_sha256: str
    policy_sha256: str
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    def _seal(self):
        return digest(
            [
                digest(self.original_profile),
                None if self.selection is None else digest(self.selection),
                self.series_sha256,
                self.manifest_sha256,
                self.policy_sha256,
            ]
        )

    def recheck(self):
        if (
            type(self) is not SelectedRewardRuntime
            or self._issuer is not _ISSUER
            or self._binding != self._seal()
        ):
            raise ValueError("runtime selection lacks authenticated original provenance")

    def selected(self, block: int):
        self.recheck()
        if type(block) is not int or block < 0:
            raise ValueError("runtime selection requires a native block height")
        if self.selection is not None:
            records = (
                reversed(self.selection.adoptions)
                if self.selection.schema_ == "umi-standing-reward-runtime-adoption-selection/3"
                else self.selection.adoptions
            )
            for signed in records:
                body = signed.adoption
                if body.first_block <= block <= body.last_block:
                    return body.effective_profile, digest(body)
        return self.original_profile, None

    def check(self, *, block, profile_sha256, adoption_sha256):
        self.recheck()
        # Previously completed or retained original proofs keep their exact
        # original semantics. Native archive review still proves the old code;
        # authorization never relabels those bytes as new-profile evidence.
        if adoption_sha256 is None and profile_sha256 == digest(self.original_profile):
            return self.original_profile
        if self.selection is not None and self.selection.schema_.endswith("/3"):
            # Retained native evidence keeps its original authenticated profile.
            # Replay must still prove that exact code at its own finalized root;
            # fresh capture always uses selected(), including the supersession.
            for signed in self.selection.adoptions:
                body = signed.adoption
                if (
                    body.first_block <= block <= body.last_block
                    and digest(body) == adoption_sha256
                    and digest(body.effective_profile) == profile_sha256
                ):
                    return body.effective_profile
        profile, adoption = self.selected(block)
        if digest(profile) != profile_sha256 or adoption != adoption_sha256:
            raise ValueError("runtime evidence differs from authenticated block selection")
        return profile


def select_reward_runtime(selection, *, series, manifest, policy, original_profile):
    """Authenticate exact compatibility contracts; never infer a profile from RPC."""
    manifest = verify_reward_manifest(canonical_json_bytes(manifest), series, policy)
    verify_recovery_authority(series.recovery, policy)
    original_profile = RewardEligibilityRuntime.model_validate_json(
        canonical_json_bytes(original_profile)
    )
    if manifest.opportunity.runtime_profile_sha256 != digest(original_profile):
        raise ValueError("runtime selection changes the original manifest profile")
    selected = (
        None
        if selection is None
        else RewardRuntimeAdoptionSelection.model_validate_json(canonical_json_bytes(selection))
    )
    if selected is not None:
        for signed in selected.adoptions:
            body = signed.adoption
            if (
                body.series_sha256 != digest(series)
                or body.manifest_sha256 != digest(manifest)
                or body.policy_sha256 != digest(policy)
                or body.authority_sha256 != digest(series.recovery.authority)
                or body.original_runtime_profile_sha256 != digest(original_profile)
                or body.issued_at_block < series.recovery.authority.issued_at_block
                or body.first_block < series.recovery.authority.issued_at_block
            ):
                raise ValueError("runtime adoption differs from selected standing authority")
            verify_recovery_quorum(body, signed.signatures, policy)
            validate_qualified_reward_runtime(body.effective_profile)
    result = SelectedRewardRuntime(
        original_profile, selected, digest(series), digest(manifest), digest(policy), _ISSUER
    )
    object.__setattr__(result, "_binding", result._seal())
    result.recheck()
    return result


def select_boot_runtime(config, *, predecessor=False):
    """The same authenticated boundary serves writer, reviewer and coordinator."""
    prefix = "predecessor_" if predecessor else ""
    selection = getattr(config, prefix + "runtime_adoptions")
    if selection is None:
        return None
    series = getattr(config, prefix + "series")
    manifest = getattr(config, prefix + "manifest")
    profile = getattr(config, prefix + "eligibility")
    if series is None or manifest is None or profile is None:
        raise ValueError("runtime adoption requires its original series, manifest and profile")
    return select_reward_runtime(
        selection, series=series, manifest=manifest, policy=config.policy, original_profile=profile
    )


def extend_boot_runtime_adoptions(config, selection, *, predecessor=False):
    """Prepare a repeatable additive upgrade; never rewrite existing signed inputs.

    This pure preparation step neither writes controls nor changes a service.
    The deployed owner still needs its independently qualified capacity/startup
    selection. Its existing journal paths and approved horizons stay unchanged.
    """
    name = ("predecessor_" if predecessor else "") + "runtime_adoptions"
    with TransferProgress("reward_runtime_adoption_prepare", 3, unit="checks") as progress:
        # Revalidate installed supported layouts before proposing any update.
        original = type(config).model_validate_json(canonical_json_bytes(config))
        candidate_selection = RewardRuntimeAdoptionSelection.model_validate_json(
            canonical_json_bytes(selection)
        )
        progress.advance(1)
        retained = getattr(original, name)
        if retained is not None and tuple(canonical_json_bytes(v) for v in retained.adoptions) != (
            tuple(
                canonical_json_bytes(v)
                for v in candidate_selection.adoptions[: len(retained.adoptions)]
            )
        ):
            raise ValueError("runtime upgrade removes or replaces retained signed adoption lineage")
        candidate = type(original).model_validate_json(
            canonical_json_bytes(original.model_copy(update={name: candidate_selection}))
        )
        select_boot_runtime(candidate, predecessor=predecessor)
        progress.advance(1)
        restored = candidate.model_copy(update={name: retained})
        if canonical_json_bytes(restored) != canonical_json_bytes(original):
            raise ValueError("runtime upgrade changes unrelated original controls or clocks")
        progress.advance(1)
        return candidate
