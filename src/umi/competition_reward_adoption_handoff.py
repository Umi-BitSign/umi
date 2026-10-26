"""Prepare matching native reward boot and publisher inputs from one signed selection.

This pure step changes neither installed configuration nor a reward hold. The
caller must retain the exact candidate bytes, select them through the supported
cooperative owner handoff, and verify each restarted consumer's selected bytes.
The publisher config must be installed private at mode 0600 and its selected
coordinator boot root-owned at mode 0444; the publisher must restart to reload it.
Package delivery must select the same new boot before its next start or restart.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .competition_reward_adoption import (
    RewardAdoptionSelection,
    SignedRewardModelAdoption,
    select_signed_initial_reward_adoption,
)
from .competition_reward_boot import StandingRewardBootConfig
from .competition_reward_coordinator_boot import RewardCoordinatorConfig
from .protocol import canonical_json_bytes

WRITER_SUPPLEMENTAL_MODE = 0o444
REFERENCE_PUBLISHER_CONFIG_MODE = 0o600


@dataclass(frozen=True)
class RewardAdoptionBootCandidates:
    selection: RewardAdoptionSelection
    coordinator: bytes
    writer: bytes
    writer_supplemental: bytes
    reviewers: tuple[bytes, ...] = ()
    reference_publisher_config: bytes | None = None
    package_delivery_config: bytes | None = None


def _candidate(original: bytes, selected: RewardAdoptionSelection, kind):
    value = json.loads(original)
    value["reward_adoptions"] = selected.model_dump(mode="json", by_alias=True)
    raw = canonical_json_bytes(value)
    parsed = kind.model_validate_json(raw)
    if parsed.reward_adoptions != selected:
        raise ValueError("reward boot candidate changed its signed selection")
    return raw


def prepare_reward_adoption_boot_candidates(
    coordinator_raw: bytes,
    writer_raw: bytes,
    signed: SignedRewardModelAdoption,
    *,
    reviewer_raws: tuple[bytes, ...] = (),
    reference_publisher_config_raw: bytes | None = None,
    reference_current_boot_raw: bytes | None = None,
    reference_current_boot_path: str | None = None,
    package_delivery_config_raw: bytes | None = None,
    package_delivery_current_boot_raw: bytes | None = None,
    package_delivery_current_boot_path: str | None = None,
    coordinator_candidate_path: str | None = None,
) -> RewardAdoptionBootCandidates:
    """Extend native reward boots and optional publisher pointer with one adoption.

    Inputs are compact native boot metadata. No package object, model payload,
    journal, key, RPC endpoint or installed service is opened here. The caller
    supplies each consumer's current boot bytes and configured path, then must
    install the candidates before restarting the publisher or package delivery.
    """
    coordinator = RewardCoordinatorConfig.model_validate_json(coordinator_raw)
    writer = StandingRewardBootConfig.model_validate_json(writer_raw)
    reviewers = tuple(RewardCoordinatorConfig.model_validate_json(raw) for raw in reviewer_raws)
    if (
        canonical_json_bytes(coordinator) != coordinator_raw
        or canonical_json_bytes(writer) != writer_raw
        or any(
            canonical_json_bytes(value) != raw
            for value, raw in zip(reviewers, reviewer_raws, strict=True)
        )
    ):
        raise ValueError("reward handoff requires canonical installed boot bytes")
    if (
        coordinator.role != "coordinator"
        or coordinator.series != writer.series
        or coordinator.policy != writer.policy
        or coordinator.reward_adoptions != writer.reward_adoptions
    ):
        raise ValueError("coordinator and writer disagree on signed reward lineage")
    if any(
        reviewer.role != "reviewer"
        or reviewer.series != coordinator.series
        or reviewer.policy != coordinator.policy
        or reviewer.reward_adoptions != coordinator.reward_adoptions
        for reviewer in reviewers
    ):
        raise ValueError("reviewer disagrees on signed reward lineage")
    reference_config = None
    if any(
        value is not None
        for value in (
            reference_publisher_config_raw,
            reference_current_boot_raw,
            reference_current_boot_path,
        )
    ):
        if (
            reference_publisher_config_raw is None
            or reference_current_boot_raw is None
            or reference_current_boot_path is None
            or coordinator_candidate_path is None
        ):
            raise ValueError(
                "reference publisher handoff requires config, current boot and target path"
            )
        from .translation_reference_config import ReferencePublisherConfig

        current_reference = RewardCoordinatorConfig.model_validate_json(reference_current_boot_raw)
        reference_config = ReferencePublisherConfig.model_validate_json(
            reference_publisher_config_raw
        )
        if (
            canonical_json_bytes(current_reference) != reference_current_boot_raw
            or canonical_json_bytes(reference_config) != reference_publisher_config_raw
            or current_reference.role != "coordinator"
            or current_reference.series != coordinator.series
            or current_reference.policy != coordinator.policy
            or current_reference.reward_adoptions != coordinator.reward_adoptions
        ):
            raise ValueError("reference publisher disagrees on signed reward lineage")
        if reference_config.coordinator_config != reference_current_boot_path:
            raise ValueError("reference publisher current boot path differs from config")
        if not Path(coordinator_candidate_path).is_absolute():
            raise ValueError("reference publisher target must be an absolute boot path")
    selected = select_signed_initial_reward_adoption(
        coordinator.reward_adoptions,
        signed,
        series=coordinator.series,
        policy=coordinator.policy,
    )
    publisher_candidate = None
    if reference_config is not None:
        value = json.loads(reference_publisher_config_raw)
        value["coordinator_config"] = coordinator_candidate_path
        publisher_candidate = canonical_json_bytes(value)
        parsed = ReferencePublisherConfig.model_validate_json(publisher_candidate)
        if parsed.coordinator_config != coordinator_candidate_path:
            raise ValueError("reference publisher candidate changed its boot path")
    delivery_candidate = None
    if any(
        value is not None
        for value in (
            package_delivery_config_raw,
            package_delivery_current_boot_raw,
            package_delivery_current_boot_path,
        )
    ):
        if (
            package_delivery_config_raw is None
            or package_delivery_current_boot_raw is None
            or package_delivery_current_boot_path is None
            or coordinator_candidate_path is None
        ):
            raise ValueError(
                "package delivery handoff requires config, current boot and target path"
            )
        current_delivery = RewardCoordinatorConfig.model_validate_json(
            package_delivery_current_boot_raw
        )
        if (
            canonical_json_bytes(current_delivery) != package_delivery_current_boot_raw
            or current_delivery.role != "coordinator"
            or current_delivery.series != coordinator.series
            or current_delivery.policy != coordinator.policy
            or current_delivery.reward_adoptions != coordinator.reward_adoptions
        ):
            raise ValueError("package delivery disagrees on signed reward lineage")
        delivery = json.loads(package_delivery_config_raw)
        if (
            not isinstance(delivery, dict)
            or set(delivery) != {
                "schema", "native_source", "producer_config", "coordinator_config",
                "state_directory",
            }
            or delivery["schema"] != "umi-native-reward-package-delivery/1"
            or delivery["coordinator_config"] != package_delivery_current_boot_path
            or not Path(package_delivery_current_boot_path).is_absolute()
            or not Path(coordinator_candidate_path).is_absolute()
        ):
            raise ValueError("package delivery current or target boot path differs")
        delivery["coordinator_config"] = coordinator_candidate_path
        delivery_candidate = canonical_json_bytes(delivery)
    return RewardAdoptionBootCandidates(
        selection=selected,
        coordinator=_candidate(coordinator_raw, selected, RewardCoordinatorConfig),
        writer=_candidate(writer_raw, selected, StandingRewardBootConfig),
        writer_supplemental=canonical_json_bytes(selected),
        reviewers=tuple(
            _candidate(raw, selected, RewardCoordinatorConfig) for raw in reviewer_raws
        ),
        reference_publisher_config=publisher_candidate,
        package_delivery_config=delivery_candidate,
    )
