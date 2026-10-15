"""Root-selected artifact locations for an unchanged installed writer boot.

Preparation owns a different finality cache. Only its authenticated artifact
locations are portable; the writer always keeps its original state directory.
This selection supplies I/O, never finality, history or submission authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .competition_chain_resources import CompetitionChainResources
from .competition_reward_history_preparation import StandingHistoryPreparationApproval, _control
from .competition_reward_history_preparation_runtime import HistoryPreparationLaunch
from .open_competition import digest
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class WriterResourceInput:
    resources: CompetitionChainResources
    launch: HistoryPreparationLaunch | None = None
    approval: StandingHistoryPreparationApproval | None = None
    through_block: int | None = None
    controls: tuple = ()

    def recheck(self):
        for control in self.controls:
            if _control(control[0], control[1])[1] != control:
                raise ValueError("writer native resource controls changed")


def select_writer_resources(
    anchor,
    selected,
    history,
    *,
    launch_path=None,
    preparation_approval=None,
    expected_launch_sha256=None,
    expected_approval_sha256=None,
    through_block=None,
):
    """Reauthenticate the root's exact launch in the final service account/view."""
    selected.recheck()
    config = selected.config
    if history not in {"current", "predecessor"}:
        raise ValueError("writer resource history is not configured")
    series = config.series if history == "current" else config.predecessor_series
    if series is None:
        raise ValueError("writer resource history is not configured")
    if launch_path is None and preparation_approval is None:
        if expected_launch_sha256 is not None or expected_approval_sha256 is not None:
            raise ValueError("writer resource digest lacks selected controls")
        return WriterResourceInput(CompetitionChainResources.from_config(config.chain))
    if launch_path is None or preparation_approval is None:
        raise ValueError("writer resources require both launch and preparation approval")
    raw, launch_control = _control(Path(launch_path), 64 * 1024)
    approval_raw, approval_control = _control(Path(preparation_approval), 64 * 1024)
    launch = HistoryPreparationLaunch.model_validate_json(raw)
    approval = StandingHistoryPreparationApproval.model_validate_json(approval_raw)
    if (
        canonical_json_bytes(launch) != raw
        or canonical_json_bytes(approval) != approval_raw
        or launch.preparation_approval_sha256 != digest(approval)
        or approval.standing_boot_raw_sha256 != selected.boot_raw_sha256
        or approval.source_config_sha256 != digest(anchor.config)
        or approval.installation_receipt_sha256 != anchor.receipt_sha256
        or approval.history != history
        or approval.series_sha256 != digest(series)
        or approval.chain_config_sha256 != digest(config.chain)
        or (expected_launch_sha256 is not None and launch_control[3] != expected_launch_sha256)
        or (
            expected_approval_sha256 is not None and approval_control[3] != expected_approval_sha256
        )
    ):
        raise ValueError("writer launch differs from original authenticated preparation")
    target = approval.through_block if launch.through_block is None else launch.through_block
    if not series.recovery.authority.issued_at_block <= target <= approval.through_block or (
        through_block is not None
        and not series.recovery.authority.issued_at_block <= through_block <= target
    ):
        raise ValueError("writer selection target exceeds preparation scope")
    resources = launch.resources.model_copy(
        update={"state_directory": config.chain.state_directory}
    )
    resources.check(config.chain)
    result = WriterResourceInput(
        resources, launch, approval, target, (launch_control, approval_control)
    )
    result.recheck()
    return result
