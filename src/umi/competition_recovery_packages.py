"""One-package replay reuse scoped to a single stopped-host recovery audit."""

from pathlib import Path

from .competition_package import VerifiedCompetitionPackage
from .competition_supervisor import (
    SuccessorSupervisorDirective,
    load_bound_successor_replay_package,
)
from .competition_weights import _recovery_package_snapshot
from .protocol import canonical_json_bytes


class RecoveryPackageReplay:
    """Retain at most one fully verified package, never a chain observation.

    Every selected directive and weight authorization is still checked by the
    adapter. Reuse requires the same complete target, release and sealed file
    identities. Nothing survives this audit or trusts metadata before replay.
    """

    def __init__(self) -> None:
        self._key: tuple[Path, bytes, bytes] | None = None
        self._snapshot: tuple | None = None
        self._package: VerifiedCompetitionPackage | None = None

    def load(
        self, path: Path, *, directive: SuccessorSupervisorDirective
    ) -> VerifiedCompetitionPackage:
        if (
            directive.mode == "hold"
            or directive.replay_package is None
            or directive.release is None
        ):
            raise ValueError("recovery package is not selected")
        key = (
            path,
            canonical_json_bytes(directive.replay_package),
            canonical_json_bytes(directive.release),
        )
        snapshot = _recovery_package_snapshot(path)
        if self._key == key:
            if snapshot != self._snapshot or self._package is None:
                raise ValueError("retained recovery package changed during audit")
            return self._package
        # Release the previous large evidence tree before loading a new round.
        self._key, self._snapshot, self._package = None, None, None
        package = load_bound_successor_replay_package(
            path,
            directive=directive,
            observed_release=directive.release.replay_release_identity,
        )
        if _recovery_package_snapshot(path) != snapshot:
            raise ValueError("retained recovery package changed during replay")
        self._key, self._snapshot, self._package = key, snapshot, package
        return package
