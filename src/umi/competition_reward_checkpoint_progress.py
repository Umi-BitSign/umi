"""Count metadata checks separately from owned native verification/application."""

import logging
import time
from contextlib import suppress

logger = logging.getLogger(__name__)


class CheckpointMetadataProgress:
    def __init__(self, stage: str, first: int, last: int) -> None:
        self.stage, self.first = stage, first
        self.requested = last - first + 1
        self.completed = self.retained = 0
        self.started = self.last_emit = time.monotonic()

    def __enter__(self):
        self.report("running", force=self.requested >= 64)
        return self

    def checked(self, *, retained: bool = True) -> None:
        self.completed += 1
        self.retained += int(retained)
        self.report("running")

    def report(self, state: str, *, force: bool = False) -> None:
        now = time.monotonic()
        elapsed = now - self.started
        if not force and now - self.last_emit < 10:
            return
        self.last_emit = now
        complete = state == "completed"
        total = self.completed if complete else self.requested
        # Telemetry cannot change a verification or repair result.
        with suppress(Exception):
            logger.info(
                "reward_history_checkpoint_metadata_progress %s",
                {
                    "stage": self.stage,
                    "state": state,
                    "first_block": self.first,
                    "completed_block_checks": self.completed,
                    "total_block_checks": total,
                    "requested_block_checks": self.requested,
                    "retained_results": self.retained,
                    "elapsed_seconds": elapsed,
                    "percent": 100 if complete else self.completed * 100 / total,
                    "eta_seconds": 0
                    if complete
                    else (
                        (total - self.completed) * elapsed / self.completed
                        if self.completed and state == "running"
                        else None
                    ),
                    "planning_eta_seconds": [1, 300]
                    if not self.completed and state == "running"
                    else None,
                    "eta_basis": "withdrawn_failed_metadata_check"
                    if state != "running" and not complete
                    else "measured_metadata_block_checks_per_wall_second"
                    if self.completed
                    else "planning_local_metadata_or_contended_storage",
                    "eta_scope": "current_bounded_metadata_batch_only",
                    "stalled": False,
                    "retrying": False,
                    "native_verification_or_application_credit": False,
                },
            )

    def __exit__(self, kind, value, traceback):
        state = "completed" if kind is None else "repair_required"
        self.report(
            state,
            force=self.requested >= 64 or time.monotonic() - self.started >= 5 or kind is not None,
        )
