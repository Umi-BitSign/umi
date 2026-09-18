"""Test support for opening a retained intake store through its external fence."""

from pathlib import Path

from umi.competition_launch import PublicLaunchIdentity
from umi.competition_store import CompetitionStore


def bind_submission_checkpoint(
    store: CompetitionStore,
    public_launch: PublicLaunchIdentity,
    directory: Path,
) -> CompetitionStore:
    """Bind and initialize the exact external checkpoint for an existing test store."""

    directory.mkdir(mode=0o700, parents=True)
    baseline = store.baseline_summary()
    if baseline is None:
        raise AssertionError("checkpoint test store needs a retained baseline")
    with store._connection() as connection:
        submissions = tuple(
            row[0]
            for row in connection.execute(
                "SELECT digest FROM submissions ORDER BY digest"
            ).fetchall()
        )
    if not submissions:
        raise AssertionError("checkpoint test store needs retained submissions")
    return CompetitionStore(
        store.directory,
        store.policy,
        admission_capacity=store.admission_capacity,
        preparation_capacity=store.preparation_capacity,
        public_launch=public_launch,
        submission_head_checkpoint_directory=directory,
        initial_checkpoint_submission_sha256s=submissions,
        initial_checkpoint_baseline_promotion_sha256=baseline["promotion_sha256"],
        initialize_submission_checkpoint=True,
    )
