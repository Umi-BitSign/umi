"""Native prepared-byte reuse with restart, repair, conflicts and fresh authority."""

import logging
import os
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from umi import competition_cohort_preparation_publication as files
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_preparation import PreparedCohortRound
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_preparation_publisher import CohortPreparationPublisher
from umi.open_competition import digest_canonical_bytes
from umi.private_files import publish_private_model, read_private_model

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_preparation import preparation as preparation
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy


@pytest.fixture
def publication(preparation, tmp_path):
    h = preparation
    h.certify()
    h.snapshot = h.owner.prepare_publication(
        h.cohort, capture_at(330), expected_tip_sha256=history_tip(h.history)
    )
    h.output = tmp_path / "published"
    h.files = files.PreparedRoundFiles(h.output, maximum_bytes=h.owner.maximum_bytes)
    h.path = h.output / (h.cohort + ".json")
    h.receipt = h.output / ".prepared-publication" / (h.cohort + ".json")
    return h


def test_native_snapshot_is_immutable_and_does_not_expose_mutable_cached_graph(publication):
    h = publication
    assert digest_canonical_bytes(h.snapshot.raw) == h.snapshot.sha256
    with pytest.raises(FrozenInstanceError):
        h.snapshot.raw = b"{}"
    value = h.owner.retained(
        h.cohort, expected_tip_sha256=history_tip(h.history), current_block=340
    )
    object.__setattr__(value.observation, "block", 123)
    saved = h.owner.retained_publication(
        h.cohort, expected_tip_sha256=history_tip(h.history), current_block=350
    )
    assert saved == h.snapshot


async def test_lifecycle_republishes_without_model_copy_parse_serialization_or_payload_read(
    publication, monkeypatch
):
    h = publication
    provider = SimpleNamespace(
        policy=h.intake.policy,
        current_finalized_block=AsyncMock(return_value=340),
        ensure_observer_running=lambda: None,
    )
    publisher = CohortPreparationPublisher(h.owner, provider, h.output)
    await publisher.publish_history(h.history)
    inode = h.path.stat().st_ino
    original = files._read_bounded_private_bytes

    def metadata_only(path, **kwargs):
        assert path != h.path, "unchanged prepared payload must not be reread"
        return original(path, **kwargs)

    def forbidden(*args, **kwargs):
        raise AssertionError("immutable lifecycle publication must reuse its verified snapshot")

    monkeypatch.setattr(files, "_read_bounded_private_bytes", metadata_only)
    monkeypatch.setattr(PreparedCohortRound, "model_copy", forbidden)
    monkeypatch.setattr(PreparedCohortRound, "model_validate_json", forbidden)
    monkeypatch.setattr(h.owner, "_prepare", forbidden)
    await publisher.publish_history(h.history)
    # Restart the delivery owner, retaining its durable completion receipt.
    publisher = CohortPreparationPublisher(h.owner, provider, h.output)
    await publisher.publish_history(h.history)
    assert h.path.stat().st_ino == inode


@pytest.mark.parametrize(
    "damage",
    [
        "missing_receipt",
        "corrupt_receipt",
        "missing_output",
        "same_bytes_new_inode",
        "same_inode_changed_mtime",
    ],
)
def test_delivery_repairs_do_not_repeat_preparation_or_change_original_bytes(
    publication, monkeypatch, caplog, damage
):
    h = publication
    h.files.publish(h.cohort, h.snapshot)
    if damage == "missing_receipt":
        h.receipt.unlink()
    elif damage == "corrupt_receipt":
        h.receipt.write_bytes(b"broken")
    elif damage == "missing_output":
        h.path.unlink()
    elif damage == "same_bytes_new_inode":
        replacement = h.path.with_suffix(".replacement")
        replacement.write_bytes(h.snapshot.raw)
        replacement.chmod(0o600)
        os.replace(replacement, h.path)
    else:
        os.utime(h.path, ns=(1, 1))
    monkeypatch.setattr(h.owner, "_prepare", lambda *a, **k: pytest.fail("no proof replay"))
    caplog.set_level(logging.INFO, logger=files.__name__)
    files.PreparedRoundFiles(h.output, maximum_bytes=h.owner.maximum_bytes).publish(
        h.cohort, h.snapshot
    )
    assert h.path.read_bytes() == h.snapshot.raw
    assert "completed=0 total=1" in caplog.text and "completed=1 total=1" in caplog.text
    assert read_private_model(h.receipt, files._Completion).prepared_sha256 == h.snapshot.sha256


def test_conflicting_output_is_preserved_and_completion_is_not_rewritten(publication):
    h = publication
    h.files.publish(h.cohort, h.snapshot)
    receipt = h.receipt.read_bytes()
    h.path.write_bytes(b"{}")
    with pytest.raises(ValueError, match="different bytes"):
        h.files.publish(h.cohort, h.snapshot)
    assert h.path.read_bytes() == b"{}" and h.receipt.read_bytes() == receipt


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "fifo"])
def test_unsafe_output_cannot_borrow_completion(publication, kind):
    h = publication
    h.files.publish(h.cohort, h.snapshot)
    if kind == "symlink":
        original = h.path.with_suffix(".original")
        h.path.rename(original)
        h.path.symlink_to(original)
    elif kind == "hardlink":
        os.link(h.path, h.path.with_suffix(".link"))
    elif kind == "public":
        h.path.chmod(0o644)
    else:
        h.path.unlink()
        os.mkfifo(h.path, 0o600)
    with pytest.raises(ValueError):
        h.files.publish(h.cohort, h.snapshot)


def test_retry_after_directory_sync_failure_proves_durability_before_receipt(
    publication, monkeypatch
):
    h = publication
    with monkeypatch.context() as patch:
        patch.setattr(files, "_sync", lambda *_: (_ for _ in ()).throw(OSError("sync failed")))
        with pytest.raises(OSError, match="sync failed"):
            h.files.publish(h.cohort, h.snapshot)
    assert h.path.exists() and not h.receipt.exists()
    inode = h.path.stat().st_ino
    h.files.publish(h.cohort, h.snapshot)
    assert h.path.stat().st_ino == inode and h.receipt.exists()


def test_legacy_published_round_upgrades_without_rewriting_its_bytes(publication):
    h = publication
    publish_private_model(h.path, PreparedCohortRound.model_validate_json(h.snapshot.raw))
    inode = h.path.stat().st_ino
    h.files.publish(h.cohort, h.snapshot)
    assert h.path.stat().st_ino == inode and h.receipt.exists()
    # A restarted native preparation owner produces the original identity.
    owner = CohortPreparation(h.queue, h.store)
    restored = owner.retained_publication(
        h.cohort, expected_tip_sha256=history_tip(h.history), current_block=100_330
    )
    assert restored == h.snapshot
    restarted = files.PreparedRoundFiles(h.output, maximum_bytes=owner.maximum_bytes)
    restarted.publish(h.cohort, restored)


def test_snapshot_reuse_keeps_revocation_and_durable_source_fences(publication):
    h = publication
    with h.queue._connection() as (db, _):
        db.execute("UPDATE cohort_prepared_rounds SET body=?", (b"{}",))
    with pytest.raises(ValueError, match="retained preparation changed"):
        h.owner.retained_publication(
            h.cohort, expected_tip_sha256=history_tip(h.history), current_block=340
        )


async def test_publication_receipt_never_bypasses_revocation(publication):
    h = publication
    h.files.publish(h.cohort, h.snapshot)
    h.history = transition(h.history, h.intake.policy, "revoke", 350)
    h.intake.publish(h.history, capture_at(350), decision_inputs=(h.closing,))
    provider = SimpleNamespace(
        policy=h.intake.policy,
        current_finalized_block=AsyncMock(return_value=360),
        ensure_observer_running=lambda: None,
    )
    with pytest.raises(ValueError, match="active prepared authority"):
        await CohortPreparationPublisher(h.owner, provider, h.output).publish_history(h.history)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "fifo"])
def test_unsafe_receipt_is_rejected_before_metadata_repair(publication, kind):
    h = publication
    h.files.publish(h.cohort, h.snapshot)
    if kind == "symlink":
        saved = h.receipt.with_suffix(".original")
        h.receipt.rename(saved)
        h.receipt.symlink_to(saved)
    elif kind == "hardlink":
        os.link(h.receipt, h.receipt.with_suffix(".link"))
    elif kind == "public":
        h.receipt.chmod(0o644)
    else:
        h.receipt.unlink()
        os.mkfifo(h.receipt, 0o600)
    stamp = h.receipt.lstat()
    with pytest.raises(ValueError):
        h.files.publish(h.cohort, h.snapshot)
    assert h.receipt.lstat() == stamp and h.path.read_bytes() == h.snapshot.raw
