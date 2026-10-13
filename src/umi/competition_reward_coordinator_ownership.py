"""One owner for current and predecessor standing-reward state."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from .open_competition import digest
from .private_files import ensure_private_directory, lock_private_file

if TYPE_CHECKING:
    from .competition_reward_coordinator_boot import RewardCoordinatorConfig


@contextmanager
def owned_reward_state(config: RewardCoordinatorConfig) -> Iterator[Path]:
    """Acquire every affected service lock before opening any journal/provider.

    A successor also opens its predecessor journals. Lock both roots so an
    operator repair, reviewer or old-series service cannot overlap that owner.
    Existing coordinator deployments already hold the host control-writer lock.
    """
    state = Path(config.state_directory)
    root = state / digest(config.series)
    roots = {root}
    if config.predecessor_series is not None:
        roots.add(state / digest(config.predecessor_series))
    with ExitStack() as resources:
        for selected in sorted(roots):
            ensure_private_directory(selected)
            resources.callback(os.close, lock_private_file(selected / "service.lock"))
        if config.role == "coordinator":
            resources.callback(os.close, lock_private_file(state / "control-writer.lock"))
        yield root
