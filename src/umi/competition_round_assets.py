"""Resolve the incumbent frozen in a round from a local preserved archive.

This reads bounded manifest metadata only. Evaluators still verify all model
bytes before execution. No URL, current-head alias or model code is followed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, RootModel

from .competition_runner import OfflineRuntime
from .competition_work_plans import RoundWorkAssets
from .open_competition import EvaluationRound, ModelBundle, digest, validate_bundle_policy
from .private_files import read_private_model as _read
from .protocol import Hex32, StrictProtocolModel, Video, canonical_json_bytes


class ArchivedRoundWorkAssets(StrictProtocolModel):
    schema_: Literal["umi-round-work-assets/2"] = Field(alias="schema")
    suite_sha256: Hex32
    runtime: OfflineRuntime
    videos: Annotated[tuple[Video, ...], Field(min_length=3, max_length=2048)]


class RoundWorkAssetFile(
    RootModel[Annotated[RoundWorkAssets | ArchivedRoundWorkAssets, Field(discriminator="schema_")]]
):
    pass


def resolve_incumbent(assets, round_, *, policy, archive=None):
    assets = RoundWorkAssetFile.model_validate_json(canonical_json_bytes(assets)).root
    round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
    if assets.suite_sha256 != round_.suite_sha256 or round_.policy_sha256 != digest(policy):
        raise ValueError("round work assets differ from the frozen suite or policy")
    if isinstance(assets, RoundWorkAssets):
        bundle = assets.incumbent
    else:
        if archive is None:
            raise ValueError("archive-backed work requires reviewed promotion delivery")
        bundle = _read(Path(archive) / round_.incumbent_model_sha256 / "manifest.json", ModelBundle)
    validate_bundle_policy(bundle, policy)
    if digest(bundle) != round_.incumbent_model_sha256:
        raise ValueError("work incumbent differs from the frozen round")
    return bundle
