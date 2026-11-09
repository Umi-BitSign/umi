"""Root-selected preparation scope and a bounded, durable outcome, never writer authority."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, model_validator

from .competition_host_activation import _read_regular_at, _read_root_control_path
from .competition_reward_handoff_preparation import LegacyHandoffPreparationResult
from .competition_worker import _open_directory_without_links, _verify_private_directory
from .open_competition import digest
from .private_files import Directory, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_host_activation import AuthenticatedSuccessorWorkerInputs
    from .competition_reward_boot import StandingRewardBootConfig

MAX_SELECTION_BYTES = 16 * 1024
MAX_OUTCOME_BYTES = 4096


class LegacyPreparationSelection(StrictProtocolModel):
    schema_: Literal["umi-legacy-preparation-selection/1"] = Field(alias="schema")
    # The maintenance request references this selection, so bind its preexisting
    # native transition ID rather than creating a circular request digest.
    transition_id: Hex32
    retained_intent_sha256: Hex32
    source_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    config_sha256: Hex32
    installation_receipt_sha256: Hex32
    standing_boot_sha256: Hex32
    provider_directory: Directory
    maximum_memory_bytes: Annotated[int, Field(strict=True, gt=0, lt=2**53)]
    background_cpus: Annotated[
        tuple[Annotated[int, Field(strict=True, ge=0, le=4095)], ...],
        Field(min_length=1, max_length=4096),
    ]

    @model_validator(mode="after")
    def ordered_cpus(self) -> LegacyPreparationSelection:
        if tuple(sorted(set(self.background_cpus))) != self.background_cpus:
            raise ValueError("preparation CPUs must be sorted and unique")
        return self


class LegacyPreparationOutcome(StrictProtocolModel):
    schema_: Literal["umi-legacy-preparation-outcome/1"] = Field(alias="schema")
    selection_sha256: Hex32
    status: Literal["legacy_prepared"]
    writer_authority: Literal[False]
    intent_sha256: Hex32
    inventory_sha256: Hex32
    attempts: Annotated[int, Field(strict=True, ge=0, lt=2**53)]
    through_block: Annotated[int, Field(strict=True, ge=0, lt=2**53)]


def legacy_preparation_selection_sha256(selection: LegacyPreparationSelection) -> str:
    """Control-file identity; native config and intent digests keep their domain."""
    return hashlib.sha256(canonical_json_bytes(selection)).hexdigest()


def load_legacy_preparation_selection(
    path: Path, expected_sha256: str
) -> LegacyPreparationSelection:
    raw = _read_root_control_path(path, MAX_SELECTION_BYTES, modes={0o444})
    value = LegacyPreparationSelection.model_validate_json(raw)
    if canonical_json_bytes(value) != raw or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("legacy preparation selection bytes differ")
    return value


def check_legacy_preparation_selection(
    selection: LegacyPreparationSelection,
    installation: AuthenticatedSuccessorWorkerInputs,
    standing: StandingRewardBootConfig,
    source: Path,
    directory: Path,
    intent_sha256: str,
) -> None:
    if type(selection) is not LegacyPreparationSelection or (
        selection.retained_intent_sha256 != intent_sha256
        or selection.config_sha256 != digest(installation.config)
        or selection.installation_receipt_sha256 != installation.receipt_sha256
        or selection.standing_boot_sha256 != digest(standing)
        or Path(source) != Path("/opt/umi-validator-supervisor-hosts") / selection.source_revision
        or Path(directory) != Path(selection.provider_directory)
    ):
        raise ValueError("legacy preparation selection differs from authenticated inputs")
    _verify_private_directory(Path(directory), "legacy preparation outcome root")


def legacy_preparation_outcome_path(selection: LegacyPreparationSelection) -> Path:
    return Path(selection.provider_directory) / (
        "completed-" + legacy_preparation_selection_sha256(selection) + ".json"
    )


def publish_legacy_preparation_outcome(
    selection: LegacyPreparationSelection, result: LegacyHandoffPreparationResult
) -> LegacyPreparationOutcome:
    if (
        type(selection) is not LegacyPreparationSelection
        or type(result) is not LegacyHandoffPreparationResult
    ):
        raise TypeError("native preparation selection and result required")
    if result.intent_sha256 != selection.retained_intent_sha256:
        raise ValueError("legacy preparation result belongs to another retained intent")
    directory = Path(selection.provider_directory)
    _verify_private_directory(directory, "legacy preparation outcome root")
    outcome = LegacyPreparationOutcome(
        schema="umi-legacy-preparation-outcome/1",
        selection_sha256=legacy_preparation_selection_sha256(selection),
        status="legacy_prepared",
        writer_authority=False,
        **asdict(result),
    )
    publish_private_model(
        legacy_preparation_outcome_path(selection), outcome, maximum_bytes=MAX_OUTCOME_BYTES
    )
    return outcome


def read_legacy_preparation_outcome(
    selection: LegacyPreparationSelection,
) -> LegacyPreparationOutcome:
    """Read a matching outcome; the controller must also check the selected service run.

    An outcome is not an input-stability or writer capability. Each preparation
    invocation rechecks native completion before republishing the same bytes.
    """
    _verify_private_directory(Path(selection.provider_directory), "legacy preparation outcome root")
    outcome = read_private_model(
        legacy_preparation_outcome_path(selection),
        LegacyPreparationOutcome,
        maximum_bytes=MAX_OUTCOME_BYTES,
    )
    return _check_outcome(selection, outcome)


def _check_outcome(selection, outcome):
    if (
        outcome.selection_sha256 != legacy_preparation_selection_sha256(selection)
        or outcome.intent_sha256 != selection.retained_intent_sha256
    ):
        raise ValueError("legacy preparation outcome belongs to another selection")
    return outcome


def read_service_legacy_preparation_outcome(
    selection: LegacyPreparationSelection, *, service_uid: int, mapped_directory: Path
) -> LegacyPreparationOutcome:
    """Root controller reads bounded output under the installed service UID.

    The caller must verify the service namespace maps mapped_directory to the
    selected provider directory, and check its exact successful invocation.
    This reader grants no authority and does not replace a fresh native check.
    """
    if os.geteuid() != 0 or type(service_uid) is not int or service_uid <= 0:
        raise ValueError("root controller and installed non-root service UID required")
    descriptor = _open_directory_without_links(mapped_directory)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != service_uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("preparation outcome directory differs from installed service owner")
        raw = _read_regular_at(
            descriptor,
            legacy_preparation_outcome_path(selection).name,
            MAX_OUTCOME_BYTES,
            owner=service_uid,
            modes={0o600},
        )
    finally:
        os.close(descriptor)
    outcome = LegacyPreparationOutcome.model_validate_json(raw)
    if canonical_json_bytes(outcome) != raw:
        raise ValueError("legacy preparation outcome bytes are not canonical")
    return _check_outcome(selection, outcome)
