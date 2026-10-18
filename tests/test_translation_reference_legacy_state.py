"""Real original lock, retained-file identities and durable adoption records."""

import os

import pytest

from tests.test_translation_reference_legacy import (
    legacy_case,
    reference_case,
    signed_policy,
    signing_case,
)
from tests.test_translation_reference_state import read
from umi.translation_reference_legacy_state import ReferenceLegacyState
from umi.translation_reference_state import TranslationReferenceError
from umi.translation_reference_transactions import ReferenceWeightJournal

__all__ = ["legacy_case", "reference_case", "signed_policy", "signing_case"]


def original_files(root, files):
    root.mkdir(mode=0o700)
    for name, raw in files.items():
        path = root / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)


def approve(lease, state, case, journal):
    return lease.approve(
        state, case.policy, journal, verifier_semantics_sha256="a" * 64, now=case.now
    )


@pytest.mark.asyncio
async def test_legacy_adoption_restarts_without_rereading_payloads_or_rewriting_signed_bytes(
    legacy_case, tmp_path
):
    case = legacy_case
    root = tmp_path / "state"
    original_files(root, case.files)
    before = {name: (root / name).read_bytes() for name in case.files}
    with ReferenceLegacyState(root) as first:
        journal = ReferenceWeightJournal(
            first.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        state = await read(case)
        result = approve(first, state, case, journal)
        assert result["terminal_attempts"] == 2 and first.payload_reads > 0
        lock_inode = (root / "service.lock").stat().st_ino
        reads = first.payload_reads
        assert approve(first, state, case, journal) == result
        assert first.payload_reads == reads
    with ReferenceLegacyState(root) as second:
        assert approve(second, state, case, journal) == result
        assert second.payload_reads == 0
    assert (root / "service.lock").stat().st_ino == lock_inode
    assert {name: (root / name).read_bytes() for name in case.files} == before


@pytest.mark.asyncio
async def test_source_mutation_refuses_before_reusing_a_completed_verification(
    legacy_case, tmp_path
):
    case = legacy_case
    root = tmp_path / "state"
    original_files(root, case.files)
    with ReferenceLegacyState(root) as lease:
        journal = ReferenceWeightJournal(
            lease.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        state = await read(case)
        approve(lease, state, case, journal)
        path = root / "registration-bridge-journal.json"
        original = path.read_bytes()
        path.write_bytes(original)
        with pytest.raises(TranslationReferenceError, match="immutable_inputs_changed"):
            lease.require_owner()
    with ReferenceLegacyState(root) as resumed:
        with pytest.raises(TranslationReferenceError, match="verification_repair_required"):
            approve(resumed, state, case, journal)
        assert resumed.payload_reads == 0


@pytest.mark.asyncio
async def test_missing_verification_chunk_requires_repair_instead_of_full_replay(
    legacy_case, tmp_path
):
    case = legacy_case
    root = tmp_path / "state"
    original_files(root, case.files)
    with ReferenceLegacyState(root) as lease:
        journal = ReferenceWeightJournal(
            lease.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        state = await read(case)
        approve(lease, state, case, journal)
        with journal.journal.transaction() as db:
            db.execute("DELETE FROM records WHERE kind='reference_legacy_file_identities'")
        reads = lease.payload_reads
        with pytest.raises(TranslationReferenceError, match="verification_repair_required"):
            approve(lease, state, case, journal)
        assert lease.payload_reads == reads


def test_existing_service_lock_is_exclusive_and_cannot_be_replaced(tmp_path):
    root = tmp_path / "state"
    with ReferenceLegacyState(root) as first:
        with pytest.raises(BlockingIOError), ReferenceLegacyState(root):
            pytest.fail("another worker acquired the same owner lock")
        os.unlink(root / "service.lock")
        (root / "service.lock").write_bytes(b"")
        (root / "service.lock").chmod(0o600)
        with pytest.raises(TranslationReferenceError, match="lock_replaced"):
            first.require_owner()


def test_unknown_older_layout_is_retained_and_refused_before_wallet_or_follower_state(tmp_path):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    (root / "bootstrap-transactions").mkdir(mode=0o700)
    with (
        pytest.raises(TranslationReferenceError, match="requires_supported_recovery"),
        ReferenceLegacyState(root),
    ):
        pytest.fail("unsupported layout was accepted")
    assert (root / "bootstrap-transactions").is_dir()
    assert not (root / "reference-weights").exists()
    assert not (root / "service.lock").exists()
