"""One explicit archive transport selection shared by native consumers and repair."""

from pathlib import Path

from .competition_proof_archive_migration import migrate_proof_archive
from .competition_remote_proof_store import (
    ProofArchiveR2Config,
    ProofArchiveStores,
    RemoteProofStore,
)
from .competition_reward_proof_archive import RewardProofArchive


def selected_proof_archive(
    directory: Path, remote: ProofArchiveR2Config | None = None
) -> RewardProofArchive:
    directory = Path(directory)
    store = None if remote is None else RemoteProofStore(directory / ".remote-state", remote)
    archive = RewardProofArchive(directory, remote=store)
    if store is not None and not remote.read_only:
        # Root-selected exporters adopt legacy /1 files before consumers start.
        # Preserve local originals until an explicit offline eviction is chosen.
        migrate_proof_archive(RewardProofArchive(directory), archive)
    return archive


def selected_proof_archives(
    imported: Path, exported: Path, stores: ProofArchiveStores | None = None
) -> tuple[RewardProofArchive, RewardProofArchive]:
    return (
        selected_proof_archive(imported, None if stores is None else stores.imported),
        selected_proof_archive(exported, None if stores is None else stores.exported),
    )
