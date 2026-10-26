"""Proof delivery preserves bytes; native finality review is a separate check."""

import json
import os
import shutil
import stat
from types import SimpleNamespace

import pytest

from umi.competition_cohort_settlement_proofs import SettlementRegistrationFiles
from umi.competition_execution import ExecutionBoundary
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


@pytest.fixture
def proof_case(tmp_path):
    observation = ExecutionBoundary(
        source="verifier_attested_finality",
        block=123,
        block_hash="0x" + "aa" * 32,
        state_root="0x" + "bb" * 32,
        snapshot_sha256="cc" * 32,
        evidence_sha256="dd" * 32,
    )
    calls = []

    async def retained(value):
        calls.append(value)
        assert value == observation
        return b"original-registration", b"original-metadata"

    files = SettlementRegistrationFiles(
        SimpleNamespace(retained_archive=retained),
        inbox=tmp_path / "input",
        outbox=tmp_path / "output",
    )
    # Managed service state is private even when the test runner's umask is022.
    files.outbox.root.mkdir(mode=0o700)
    return files, observation, calls


async def test_settlement_proof_export_reuses_files_when_original_provider_is_offline(proof_case):
    files, observation, calls = proof_case
    await files.publish(observation)
    before = {
        p.relative_to(files.outbox.root): p.read_bytes() for p in files.outbox.root.rglob("*.json")
    }

    async def unavailable(_):
        raise OSError("provider offline after original capture")

    files.provider.retained_archive = unavailable
    reopened = SettlementRegistrationFiles(
        files.provider,
        inbox=files.inbox.root,
        outbox=files.outbox.root,
    )
    await reopened.publish(observation)
    assert calls == [observation]
    assert before == {
        p.relative_to(files.outbox.root): p.read_bytes() for p in files.outbox.root.rglob("*.json")
    }
    shutil.copytree(files.outbox.root, files.inbox.root, dirs_exist_ok=True)
    assert await reopened.read(observation) == (b"original-registration", b"original-metadata")


async def test_completed_publication_survives_restart_without_payload_reads(
    proof_case, monkeypatch
):
    files, observation, calls = proof_case
    await files.ensure_published(observation)
    reopened = SettlementRegistrationFiles(
        files.provider, inbox=files.inbox.root, outbox=files.outbox.root
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("completed proof publication read or rewrote payloads")

    monkeypatch.setattr(reopened, "_read", forbidden)
    monkeypatch.setattr(reopened.outbox, "write", forbidden)
    await reopened.ensure_published(observation)
    assert calls == [observation]


async def test_local_frame_lost_directory_ack_retries_without_payload_republication(
    proof_case, monkeypatch
):
    from umi import private_files

    files, observation, calls = proof_case
    sync = private_files.os.fsync
    failed = []

    def fsync(fd):
        info = os.fstat(fd)
        directory = files.outbox.root / "registration"
        if (
            stat.S_ISDIR(info.st_mode)
            and directory.exists()
            and (info.st_dev, info.st_ino) == (directory.stat().st_dev, directory.stat().st_ino)
            and not failed
        ):
            failed.append(True)
            raise OSError("lost registration frame directory acknowledgement")
        return sync(fd)

    monkeypatch.setattr(private_files.os, "fsync", fsync)
    with pytest.raises(OSError, match="directory acknowledgement"):
        await files.ensure_published(observation)
    assert (files.outbox.root / "registration" / (digest(observation) + ".json")).exists()

    def forbidden(*args, **kwargs):
        raise AssertionError("lost frame acknowledgement repeated proof payload publication")

    monkeypatch.setattr(files, "_read", forbidden)
    monkeypatch.setattr(files.outbox, "write", forbidden)
    await files.ensure_published(observation)
    assert calls == [observation] and failed == [True]


async def test_completed_remote_publication_uses_selected_receipt_and_preserves_damage_hold(
    proof_case, monkeypatch
):
    files, observation, calls = proof_case
    paths = []

    def retained(path):
        paths.append(path)
        return {"durable": "selected-namespace"}

    def forbidden(*args, **kwargs):
        raise AssertionError("receipt reuse read or rewrote payloads")

    files.outbox.remote = SimpleNamespace(reference_for_path=retained)
    monkeypatch.setattr(files.outbox, "_frame", forbidden)
    await files.ensure_published(observation)
    assert paths == ["frames/registration/" + digest(observation)] and not calls

    def damaged(path):
        raise ValueError("remote proof requires explicit original-generation repair")

    files.outbox.remote.reference_for_path = damaged
    with pytest.raises(ValueError, match="explicit original-generation repair"):
        await files.ensure_published(observation)
    assert not calls


async def test_actual_remote_completion_reuses_durable_owner_metadata_after_restart(
    proof_case, tmp_path, monkeypatch
):
    from .test_competition_remote_proof_store import EvidenceServer, store

    files, observation, calls = proof_case
    server = EvidenceServer()
    files.outbox.remote = store(tmp_path / "remote-owner", server)
    await files.ensure_published(observation)
    assert calls == [observation] and server.objects
    files.outbox.remote = store(tmp_path / "remote-owner", server)
    server.calls.clear()

    def forbidden(*args, **kwargs):
        raise AssertionError("completed remote proof publication reread payloads")

    monkeypatch.setattr(files.outbox, "_frame", forbidden)
    await files.ensure_published(observation)
    assert not server.calls and calls == [observation]


@pytest.mark.parametrize("field", ["block_hash", "evidence_sha256", "source"])
async def test_settlement_proof_delivery_rejects_context_substitution(proof_case, field):
    files, observation, _ = proof_case
    await files.publish(observation)
    shutil.copytree(files.outbox.root, files.inbox.root, dirs_exist_ok=True)
    path = files.inbox.root / "registration" / (digest(observation) + ".json")
    value = json.loads(path.read_bytes())
    value["context"][field] = "modified"
    path.write_bytes(canonical_json_bytes(value))
    with pytest.raises(ValueError, match="original observation"):
        await files.read(observation)


async def test_settlement_partial_proof_export_never_publishes_a_frame(proof_case, monkeypatch):
    from umi import competition_reward_proof_archive as module

    files, observation, _ = proof_case
    original = module.publish_private_model

    def fail_frame(path, *args, **kwargs):
        if path.parent.name == "registration":
            raise OSError("disk full before frame")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module, "publish_private_model", fail_frame)
    with pytest.raises(OSError, match="disk full"):
        await files.ensure_published(observation)
    assert not tuple((files.outbox.root / "registration").glob("*.json"))
    monkeypatch.setattr(module, "publish_private_model", original)
    await files.ensure_published(observation)
    shutil.copytree(files.outbox.root, files.inbox.root, dirs_exist_ok=True)
    assert await files.read(observation) == (b"original-registration", b"original-metadata")


async def test_own_and_explicit_shared_proofs_need_no_archive_copy(proof_case, tmp_path):
    files, observation, calls = proof_case
    await files.publish(observation)
    assert await files.read(observation) == (b"original-registration", b"original-metadata")
    reader = SettlementRegistrationFiles(
        files.provider,
        inbox=tmp_path / "new-input",
        outbox=tmp_path / "new-output",
        shared_archives=(files.outbox.root,),
    )
    before = {str(p): p.stat().st_ino for p in files.outbox.root.rglob("*.json")}
    assert await reader.read(observation) == (b"original-registration", b"original-metadata")
    # Ordinary private-file readers may create empty lookup/lock directories;
    # no proof frame, encoded object or other payload may be copied there.
    assert not any(p.is_file() and p.stat().st_size for p in reader.inbox.root.rglob("*"))
    assert not any(p.is_file() and p.stat().st_size for p in reader.outbox.root.rglob("*"))
    assert before == {str(p): p.stat().st_ino for p in files.outbox.root.rglob("*.json")}
    assert calls == [observation]


async def test_present_damaged_import_is_not_hidden_by_valid_shared_source(proof_case, tmp_path):
    files, observation, _ = proof_case
    await files.publish(observation)
    shutil.copytree(files.outbox.root, files.inbox.root)
    frame = json.loads(
        (files.inbox.root / "registration" / (digest(observation) + ".json")).read_bytes()
    )
    recipe = frame["fields"]["proof"][0]["recipe_sha256"]
    (files.inbox.root / "objects" / (recipe + ".json")).unlink()
    reader = SettlementRegistrationFiles(
        files.provider,
        inbox=files.inbox.root,
        outbox=tmp_path / "reader-output",
        shared_archives=(files.outbox.root,),
    )
    with pytest.raises(FileNotFoundError):
        await reader.read(observation)


async def test_shared_proof_source_loss_and_permissions_are_explicit(proof_case, tmp_path):
    files, observation, _ = proof_case
    await files.publish(observation)
    reader = SettlementRegistrationFiles(
        files.provider,
        inbox=tmp_path / "new-input",
        outbox=tmp_path / "new-output",
        shared_archives=(files.outbox.root,),
    )
    files.outbox.root.chmod(0o755)
    with pytest.raises(ValueError, match="owned and private"):
        await reader.read(observation)
    files.outbox.root.chmod(0o700)
    shutil.rmtree(files.outbox.root)
    with pytest.raises(FileNotFoundError):
        await reader.read(observation)
