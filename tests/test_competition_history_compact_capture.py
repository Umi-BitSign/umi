"""Shared runtime bytes stay shared through source capture, export and recovery."""

import hashlib
from contextlib import contextmanager

import pytest

from umi.competition_evidence_codec import encode_evidence
from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key
from umi.protocol import canonical_json_bytes

from .test_competition_history_source_externalization import fresh_remote, reopen
from .test_competition_remote_proof_store import EvidenceServer, store
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


SHARED = b"immutable-runtime-code" * 8192


def fields(number):
    def evidence(role):
        return canonical_json_bytes(
            {
                "block": number,
                "role": role,
                "code": "0x" + SHARED.hex(),
                "proof": [
                    "0x" + hashlib.sha256(f"{number}-{i}".encode()).hexdigest() for i in range(24)
                ],
            }
        )

    return {
        "slot_evidence": evidence("slot"),
        "slot_metadata": b"metadata" * 1024,
        "evidence": evidence("writes"),
    }


def remote_reader(h, tmp_path, server):
    remote = store(tmp_path / "remote", server)
    reader = fresh_remote(h.reader, remote, tmp_path / "history")
    reader.export_archive = RewardProofArchive(tmp_path / "export", remote=remote)
    return reader, remote


def save_legacy(reader, height, values, *, literal):
    """Retain original released source records without a native-verdict claim."""
    records, refs = [], {}
    for name, raw in values.items():
        encoded = encode_evidence(raw, kind="proof", single_object=literal)
        records.extend(
            ("control_history_object", sha, {"hex": value.hex()})
            for sha, value in encoded.objects.items()
        )
        records.append(
            (
                "control_history_chunk",
                encoded.sha256,
                {"length": len(raw), "recipe_hex": encoded.recipe.hex()},
            )
        )
        refs[name] = [encoded.sha256]
    records.append(("control_history_block", str(height), refs))
    reader.remote_sources.capture(records, index=lambda db: None)


def chunk_recipes(reader, values):
    with reader.journal.read_transaction() as db:
        return {
            name: reader.remote_sources.get(
                "control_history_chunk", hashlib.sha256(raw).hexdigest(), db=db
            )
            for name, raw in values.items()
        }


def test_adjacent_capture_and_archive_export_share_large_payload(history_case, tmp_path):
    server = EvidenceServer()
    reader, _ = remote_reader(history_case, tmp_path, server)
    shared_path = "/objects/" + hashlib.sha256(SHARED).hexdigest()
    for number in range(2):
        height, values = reader.first_block + number, fields(number)
        before = sum(map(len, server.objects.values()))
        reader._save_fields(height, values)
        sources = set(server.objects)
        server.calls.clear()
        reader._export_fields(height, values, reader.export_archive)
        assert not any(
            method == "PUT" and path.removeprefix("/umi-proof-artifacts/") in sources
            for method, path in server.calls
        )
        if number:
            assert sum(map(len, server.objects.values())) - before < len(SHARED) // 4
        key = history_archive_key(reader.config_sha256, reader.hotkey, height)
        assert (
            reader.export_archive.read(
                "history", key, bounds={k: len(v) for k, v in values.items()}
            )[1]
            == values
        )
        assert reader._load(height) == values
        assert reader.checkpoints.load(height) is None
    assert len([key for key in server.objects if key.endswith(shared_path)]) == 1


@pytest.mark.parametrize("literal", [False, True])
def test_prior_recipes_and_source_tokens_survive_mixed_capture_restart(
    history_case, tmp_path, literal
):
    server = EvidenceServer()
    reader, _ = remote_reader(history_case, tmp_path, server)
    height, values = reader.first_block, fields(0)
    save_legacy(reader, height, values, literal=literal)
    original = chunk_recipes(reader, values)
    reader._save_fields(height, values)
    tokens = reader._source_tokens[height]
    assert chunk_recipes(reader, values) == original
    reader._export_fields(height, values, reader.export_archive)
    reader._save_fields(height + 1, fields(1))
    reader._export_fields(height + 1, fields(1), reader.export_archive)
    before = dict(server.objects)
    remote = store(tmp_path / "remote", server)
    reader = reopen(
        reader, remote, export_archive=RewardProofArchive(tmp_path / "export", remote=remote)
    )
    server.calls.clear()
    reader._save_fields(height, values)
    assert reader._source_tokens[height] == tokens
    assert chunk_recipes(reader, values) == original
    reader._export_fields(height, values, reader.export_archive)
    assert server.objects == before
    assert not any(method == "PUT" for method, _ in server.calls)
    assert reader._load(height) == values and reader._load(height + 1) == fields(1)


@pytest.mark.parametrize("interruption", ["put_ack", "before_commit", "after_commit"])
def test_compact_capture_retry_preserves_completed_objects(
    history_case, tmp_path, monkeypatch, interruption
):
    server = EvidenceServer()
    reader, _ = remote_reader(history_case, tmp_path, server)
    height, values = reader.first_block, fields(0)
    with monkeypatch.context() as patch:
        if interruption == "put_ack":
            server.lose_put_ack = True
        elif interruption == "before_commit":
            transaction = reader.journal.transaction

            @contextmanager
            def interrupted(**kwargs):
                with transaction(**kwargs) as db:
                    yield db
                    if db.execute(
                        "SELECT 1 FROM records WHERE kind='control_history_remote_source'"
                    ).fetchone():
                        raise OSError("interrupted source commit")

            patch.setattr(reader.journal, "transaction", interrupted)
        else:
            capture = reader.remote_sources.capture

            def interrupted(*args, **kwargs):
                capture(*args, **kwargs)
                raise OSError("lost source commit acknowledgement")

            patch.setattr(reader.remote_sources, "capture", interrupted)
        with pytest.raises(OSError):
            reader._save_fields(height, values)
    original = dict(server.objects)
    remote = store(tmp_path / "remote", server)
    reader = reopen(
        reader, remote, export_archive=RewardProofArchive(tmp_path / "export", remote=remote)
    )
    reader._save_fields(height, values)
    reader._export_fields(height, values, reader.export_archive)
    assert all(server.objects[key] == value for key, value in original.items())
    assert reader._load(height) == values
    assert reader.checkpoints.load(height) is None


async def test_native_success_restart_never_rescans_or_republishes_completed_sources(
    history_case, tmp_path, monkeypatch
):
    h, server = history_case, EvidenceServer()
    reader, _ = remote_reader(h, tmp_path, server)
    expected = await reader.advance(h.item.provider, through_block=h.end)
    saved = [reader.checkpoints.load(i) for i in range(reader.first_block, h.end + 1)]
    remote = store(tmp_path / "remote", server)
    reader = reopen(
        reader, remote, export_archive=RewardProofArchive(tmp_path / "export", remote=remote)
    )
    prohibit_proof_replay(monkeypatch, reader)

    def forbidden(*args, **kwargs):
        pytest.fail("completed native work reread or re-encoded source payloads")

    monkeypatch.setattr(reader, "_save_fields", forbidden)
    monkeypatch.setattr(reader, "_export_fields", forbidden)
    server.calls.clear()
    assert await reader.advance(h.item.provider, through_block=h.end) == expected
    assert [reader.checkpoints.load(i) for i in range(reader.first_block, h.end + 1)] == saved
    assert server.calls == [] and reader.progress.native_completed == 0
