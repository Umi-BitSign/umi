"""Proof delivery preserves bytes; native finality review is a separate check."""

import json
import shutil
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
        await files.publish(observation)
    assert not tuple((files.outbox.root / "registration").glob("*.json"))
    monkeypatch.setattr(module, "publish_private_model", original)
    await files.publish(observation)
    shutil.copytree(files.outbox.root, files.inbox.root, dirs_exist_ok=True)
    assert await files.read(observation) == (b"original-registration", b"original-metadata")
