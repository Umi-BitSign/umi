"""Real native history/checkpoints with explicitly substituted install OS ports.

These fixtures qualify retained effects, restart and local mutation fences.
They do not qualify the actual host's administrator-selected export provenance.
"""

import copy
import json
import os
from types import SimpleNamespace

import pytest

from umi import competition_reward_admission_provenance as provenance
from umi import competition_reward_history_origin as origin
from umi import competition_reward_history_origin_migration as migration
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.open_competition import digest

from .test_competition_reward_history_projection import chain as chain
from .test_competition_reward_history_projection import chain_config as chain_config
from .test_competition_reward_history_projection import control as control
from .test_competition_reward_history_projection import historical as historical
from .test_competition_reward_history_projection import original as original
from .test_competition_reward_history_projection import policy as policy
from .test_competition_reward_history_projection import series_case as series_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


@pytest.fixture
def selected(original, monkeypatch, tmp_path):
    h = original
    h.exports.root.chmod(0o700)
    uid = os.geteuid()
    monkeypatch.setattr(provenance, "_ROOT_UID", uid)
    monkeypatch.setattr(provenance, "_TRUST_ROOT", tmp_path)
    monkeypatch.setattr(provenance, "ORIGINAL_STARTED_NS", 1)
    monkeypatch.setattr(origin, "_EXPORT_ROOT", h.exports.root)
    path = tmp_path / "original-owner.json"
    config_path = tmp_path / "config.json"
    config = {
        "chain": h.item.config.model_dump(mode="json", by_alias=True),
        "proof_export_directory": str(h.exports.root),
        "proof_import_directory": str(tmp_path / "imports"),
    }
    config_path.write_bytes(provenance._canonical(config))
    config_path.chmod(0o444)
    process = {"pid": provenance.ORIGINAL_PID, "start_ticks": 100, "uid": uid}
    service = {
        "InvocationID": provenance.ORIGINAL_INVOCATION,
        "ActiveState": "active",
        "MainPID": str(provenance.ORIGINAL_PID),
    }
    running = [True]

    def live():
        if not running[0]:
            raise FileNotFoundError
        return process.copy()

    def systemd():
        return (
            service.copy() if running[0] else {**service, "ActiveState": "inactive", "MainPID": "0"}
        )

    monkeypatch.setattr(provenance, "_process", live)
    monkeypatch.setattr(provenance, "_systemd", systemd)
    monkeypatch.setattr(provenance, "_configuration", lambda: (config, {}))
    lock_paths = {"history_lock": h.reader.journal.root / "rounds.lock"}
    for name in ("service_lock", "control_writer_lock", "decisions_lock"):
        lock_paths[name] = tmp_path / (name + ".lock")
        lock_paths[name].write_bytes(b"")
        lock_paths[name].chmod(0o600)
    identities = {name: provenance._metadata(path, owner=uid) for name, path in lock_paths.items()}
    value = {
        "schema": provenance.SCHEMA,
        "source_semantics": provenance.SOURCE_SEMANTICS,
        "source_manifest_sha256": provenance.SOURCE_MANIFEST_SHA256,
        "native_completion_claimed": False,
        "process": process,
        "service": service,
        "owner_uid": uid,
        "first_block": h.old.height,
        "control_hotkey": h.item.hotkey,
        "chain_config_sha256": digest(h.item.config),
        "configuration": {"path": str(config_path)},
        "paths": {"history_root": str(h.reader.journal.root)},
        "identities": identities,
    }
    path.write_bytes(provenance._canonical(value))
    path.chmod(0o444)

    def validate(value, *, require_stopped, **kwargs):
        if require_stopped and running[0]:
            raise ValueError("original owner is still running")
        for key, stamp in identities.items():
            assert provenance._metadata(lock_paths[key], owner=uid) == stamp

    monkeypatch.setattr(provenance, "validate_provenance", validate)
    monkeypatch.setattr(migration, "validate_provenance", validate)
    selected_origin = origin.capture_original_export_origin(
        path, through_block=h.end, exclusive_original_namespace=True
    )
    origin_path = tmp_path / "origin.json"
    origin_path.write_bytes(provenance._canonical(selected_origin))
    origin_path.chmod(0o444)
    # Emulate only the legacy absence of durable success records. Raw signed
    # proof bytes, original identities and native expected effects are retained.
    with h.reader.journal.transaction() as db:
        for name in h.reader.checkpoints.triggers:
            db.execute("DROP TRIGGER " + name)
        for name in (
            "history_checkpoint_state",
            "history_checkpoint_index",
            "history_source_identity",
        ):
            db.execute("DROP TABLE " + name)
        db.execute(
            "DELETE FROM records WHERE kind IN ('control_history_verified',"
            "'control_history_checkpoint_owner','control_history_checkpoint_done')"
        )
    return SimpleNamespace(h=h, running=running, path=origin_path, origin=selected_origin)


def run(c, **kwargs):
    return migration.migrate_original_export_history(
        c.path, maximum_history_bytes=8 * 1024**2, **kwargs
    )


async def test_migration_refuses_live_owner_before_journal_initialization(selected):
    c = selected
    with pytest.raises(HistoryCheckpointRepairRequired, match="explicit repair"):
        run(c)
    with c.h.reader.journal.read_transaction() as db:
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='history_checkpoint_state'"
            ).fetchone()
            is None
        )


async def test_resume_repeat_native_restore_preserves_all_effects_without_rpc(
    selected, monkeypatch
):
    c, h = selected, selected.h
    c.running[0] = False
    first = run(c, maximum_blocks=2)
    assert first["status"] == "checkpointed" and first["completed_blocks"] == 2
    second = run(c)
    assert second["status"] == "semantic_checkpoints_complete" and second["restored_blocks"] == 2
    assert run(c)["restored_blocks"] == 5
    h.reader = h.new_reader()
    h.reader.export_archive = h.exports

    def no_payload(*args, **kwargs):
        pytest.fail("unchanged successful migration reread original proof payload")

    monkeypatch.setattr(h.reader, "_load", no_payload)
    before = list(h.body_requests)
    actual = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    assert actual == h.expected
    assert h.body_requests == before
    assert h.reader.progress.native_completed == 0
    assert actual.unresolved_blocks == (h.old.height + 3,)


async def test_interrupted_acknowledgement_keeps_completed_item(selected):
    c = selected
    c.running[0] = False

    def interrupt(value):
        if value["completed_blocks"] == 2:
            raise InterruptedError("after durable second checkpoint")

    with pytest.raises(HistoryCheckpointRepairRequired):
        run(c, progress=interrupt)
    assert run(c)["restored_blocks"] == 2


@pytest.mark.parametrize("damage", ["missing_checkpoint", "source", "seal", "frame"])
async def test_changed_completed_or_original_data_requires_repair(selected, damage):
    c, h = selected, selected.h
    c.running[0] = False
    run(c, maximum_blocks=2)
    if damage == "missing_checkpoint":
        with h.reader.journal.transaction() as db:
            db.execute("DELETE FROM history_checkpoint_index WHERE height=?", (h.old.height,))
    elif damage == "source":
        with h.reader.journal.transaction() as db:
            db.execute(
                "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                (str(h.old.height),),
            )
    elif damage == "seal":
        c.path.chmod(0o644)
        changed = copy.deepcopy(c.origin)
        changed["through_block"] -= 1
        c.path.write_bytes(provenance._canonical(changed))
        c.path.chmod(0o444)
    else:
        path = h.exports.root / "history"
        target = next(
            p
            for p in path.iterdir()
            if p.suffix == ".json" and json.loads(p.read_bytes())["context"]["block"] == h.end
        )
        target.write_bytes(target.read_bytes())
    with pytest.raises(HistoryCheckpointRepairRequired):
        run(c)


async def test_unsealed_or_generic_origin_refused(selected):
    c = selected
    c.running[0] = False
    c.path.chmod(0o644)
    with pytest.raises(HistoryCheckpointRepairRequired):
        run(c)


async def test_cli_sigterm_drains_current_checkpoint_then_resumes(selected, monkeypatch, capsys):
    import signal

    from umi import competition_reward_history_origin_cli as cli

    c = selected
    c.running[0] = False
    before = signal.getsignal(signal.SIGTERM)

    def request_stop(value):
        if value["completed_blocks"] == 2:
            os.kill(os.getpid(), signal.SIGTERM)

    def migrate(path, **kwargs):
        return migration.migrate_original_export_history(path, progress=request_stop, **kwargs)

    monkeypatch.setattr(cli, "migrate_original_export_history", migrate)
    cli.main(["migrate", "--origin", str(c.path), "--maximum-history-bytes", str(8 * 1024**2)])
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "interrupted"
    assert result["completed_blocks"] == 2
    assert result["next_action"] == "resume_original_export_migration"
    assert signal.getsignal(signal.SIGTERM) == before
    assert run(c)["restored_blocks"] == 2
