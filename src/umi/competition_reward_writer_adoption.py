"""Explicit signed adoption input without changing original preparation controls."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .competition_reward_adoption import (
    MAX_REWARD_ADOPTION_BYTES,
    RewardAdoptionSelection,
    verify_adoption_selection,
)
from .competition_reward_history_preparation import _control
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class WriterAdoptionInput:
    selection: RewardAdoptionSelection | None
    control: tuple | None

    @property
    def journal_binding(self):
        if self.control is None:
            return None
        path, _, _, checksum = self.control
        return {"path": str(path), "raw_sha256": checksum}

    def recheck(self):
        if self.control is not None:
            path, maximum, _, _ = self.control
            if _control(path, maximum)[1] != self.control:
                raise ValueError("writer supplemental adoption control changed")


def select_writer_adoptions(config, history, path=None, *, expected_sha256=None):
    """Authenticate the full lineage against the ORIGINAL boot's authority.

    The supplemental input may extend an existing lineage, never remove or
    replace signed revisions. It affects native control review only: the boot,
    original approval, preparation scope and checkpoint owner remain unchanged.
    Root pins the exact bytes before launching the service-account child; both
    check the same immutable control throughout their ownership lifetime.
    """
    if history not in {"current", "predecessor"}:
        raise ValueError("writer adoption history is not configured")
    current = history == "current"
    series = config.series if current else config.predecessor_series
    if series is None:
        raise ValueError("writer adoption history is not configured")
    retained = config.reward_adoptions if current else config.predecessor_reward_adoptions
    if path is None:
        if expected_sha256 is not None:
            raise ValueError("writer adoption digest lacks its selected input")
        return WriterAdoptionInput(verify_adoption_selection(retained, series, config.policy), None)
    raw, control = _control(Path(path), MAX_REWARD_ADOPTION_BYTES)
    selected = RewardAdoptionSelection.model_validate_json(raw)
    if canonical_json_bytes(selected) != raw or (
        expected_sha256 is not None and control[3] != expected_sha256
    ):
        raise ValueError("writer supplemental adoption differs from root selection")
    selected = verify_adoption_selection(selected, series, config.policy)
    if retained is not None:
        verify_adoption_selection(retained, series, config.policy)
        available = {canonical_json_bytes(value) for value in selected.adoptions}
        if selected.maximum_decisions < retained.maximum_decisions or any(
            canonical_json_bytes(value) not in available for value in retained.adoptions
        ):
            raise ValueError("writer supplemental adoption changed retained signed lineage")
    return WriterAdoptionInput(selected, control)
