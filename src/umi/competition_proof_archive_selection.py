"""One explicit archive transport selection shared by native consumers and repair."""

from pathlib import Path

from .competition_proof_archive_migration import migrate_proof_archive
from .competition_remote_proof_store import (
    ProofArchiveR2Config,
    ProofArchiveStores,
    RemoteProofStore,
)
from .competition_reward_proof_archive import RewardProofArchive
from .competition_transport_verification import TransferProgress


def selected_proof_archive(
    directory: Path, remote: ProofArchiveR2Config | None = None
) -> RewardProofArchive:
    directory = Path(directory)
    with TransferProgress(
        "proof_archive_transport_selection", 1, unit="archives", planning_unit_seconds=(0.01, 60)
    ) as progress:
        store = None if remote is None else RemoteProofStore(directory / ".remote-state", remote)
        archive = RewardProofArchive(
            directory,
            remote=store,
            legacy_read_through=remote is not None and remote.legacy_read_through,
        )
        if store is not None and not remote.read_only and not remote.legacy_read_through:
            # Preserve the original eager adoption boundary unless explicitly
            # selecting /2 retained local reads and remote-only new publication.
            migrate_proof_archive(RewardProofArchive(directory), archive)
        elif remote is not None and remote.legacy_read_through:
            progress.emit("running", reason="retained_local_history_remote_new_proofs")
        progress.advance(1)
    return archive


def selected_proof_archives(
    imported: Path, exported: Path, stores: ProofArchiveStores | None = None
) -> tuple[RewardProofArchive, RewardProofArchive]:
    return (
        selected_proof_archive(imported, None if stores is None else stores.imported),
        selected_proof_archive(exported, None if stores is None else stores.exported),
    )
