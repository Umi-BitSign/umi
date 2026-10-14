"""Local provenance fences with substituted root/process/systemd OS ports.

Real file identities, bounded reads, source hashing and flock are exercised.
These fixtures do not establish installed342 or production completion authority.
"""

import copy
import fcntl
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_admission_provenance as module
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_open_competition import wallet


@pytest.fixture
def owner(tmp_path, monkeypatch):
    uid = os.geteuid()
    monkeypatch.setattr(module, "_ROOT_UID", uid)
    monkeypatch.setattr(module, "_TRUST_ROOT", tmp_path)
    monkeypatch.setattr(module, "ORIGINAL_STARTED_NS", 10**20)
    source = tmp_path / "release/src/umi"
    source.mkdir(parents=True)
    for directory in (source, source.parent, source.parent.parent):
        directory.chmod(0o755)
    code = source / "native.py"
    code.write_bytes(b"pass\n")
    code.chmod(0o444)
    monkeypatch.setattr(module, "SOURCE_ROOT", source)
    monkeypatch.setattr(module, "SOURCE_FILES", 1)
    monkeypatch.setattr(module, "SOURCE_BYTES", 5)
    manifest = module._sha(module._canonical({"native.py": module._sha(b"pass\n")}))
    monkeypatch.setattr(module, "SOURCE_MANIFEST_SHA256", manifest)
    config_path = tmp_path / "installed.json"
    monkeypatch.setattr(module, "CONFIG_PATH", config_path)
    account = wallet("Charlie").hotkey.ss58_address
    config = {
        "role": "coordinator",
        "state_directory": str(tmp_path / "state"),
        "series": {"control_hotkey": account, "recovery": {"authority": {"issued_at_block": 123}}},
        "policy": {"selected": True},
        "manifest": {"selected": True},
        "chain": {"selected": True},
        "signer_hotkey": account,
        "signer_key_file": str(tmp_path / "DO_NOT_READ_WALLET"),
        "private_token": "DO_NOT_EMIT_SECRET",
    }
    config_path.write_bytes(module._canonical(config))
    config_path.chmod(0o444)
    state = tmp_path / "state"
    root = state / digest(config["series"])
    for directory in (state, root, root / "history", root / "decisions"):
        directory.mkdir(mode=0o700)
    for path in (
        root / "service.lock",
        state / "control-writer.lock",
        root / "history/rounds.lock",
        root / "history/rounds.sqlite3",
        root / "decisions/rounds.lock",
        root / "decisions/rounds.sqlite3",
    ):
        path.write_bytes(b"original")
        path.chmod(0o600)
    unit = tmp_path / "owner.service"
    unit.write_text("[Service]\nExecStart=selected\n")
    unit.chmod(0o444)
    process = {
        "pid": module.ORIGINAL_PID,
        "start_ticks": 100,
        "uid": uid,
        "gid": os.getegid(),
        "argv_sha256": "02" * 32,
        "executable": "/trusted/python",
        "cgroup": "0::/selected\n",
        "boot_id": "original",
    }
    service = {
        "Id": module.SERVICE,
        "MainPID": str(module.ORIGINAL_PID),
        "InvocationID": module.ORIGINAL_INVOCATION,
        "ControlGroup": "/selected",
        "FragmentPath": str(unit),
        "DropInPaths": "",
        "ExecMainStartTimestampMonotonic": str(100 * 1_000_000 // os.sysconf("SC_CLK_TCK")),
        "ActiveState": "active",
        "SubState": "running",
    }
    running = [True]

    def live():
        if not running[0]:
            raise FileNotFoundError
        return copy.deepcopy(process)

    def systemd():
        return (
            service.copy() if running[0] else {**service, "MainPID": "0", "ActiveState": "inactive"}
        )

    monkeypatch.setattr(module, "_process", live)
    monkeypatch.setattr(module, "_systemd", systemd)
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: pytest.fail("capture opened database"))
    selection = tmp_path / "selection.json"

    def seal():
        value = module.capture_provenance()
        selection.write_bytes(module._canonical(value))
        selection.chmod(0o444)
        return module.load_provenance(selection)

    return SimpleNamespace(
        root=root,
        state=state,
        source=source,
        code=code,
        config=config_path,
        unit=unit,
        process=process,
        service=service,
        running=running,
        selection=selection,
        seal=seal,
    )


def test_capture_retains_only_public_selection_and_does_not_assert_completion(owner):
    value = owner.seal()
    assert value["native_completion_claimed"] is False
    assert value["history_root"] == str(owner.root / "history")
    assert value["signing_root"] == str(owner.root / "decisions")
    assert value["signer"] == module.identity(wallet("Charlie").hotkey.ss58_address)
    assert value["first_block"] == 123
    assert b"DO_NOT_" not in module._canonical(value)
    module.validate_provenance(value, require_stopped=False)
    with pytest.raises(ValueError, match="still running"):
        module.validate_provenance(value, require_stopped=True)
    owner.running[0] = False
    module.validate_provenance(value, require_stopped=True)
    with module.open_existing_owner_locks(value):
        for name in ("service_lock", "control_writer_lock", "history_lock", "decisions_lock"):
            fd = os.open(value[name], os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)


def test_capture_uses_native_domain_separated_protocol_bindings(owner):
    config = json.loads(owner.config.read_bytes())
    value = owner.seal()
    for field, key in (
        ("series_sha256", "series"),
        ("policy_sha256", "policy"),
        ("manifest_sha256", "manifest"),
        ("chain_config_sha256", "chain"),
    ):
        expected = hashlib.sha256(
            b"umi-open-competition-v1\x00" + canonical_json_bytes(config[key])
        ).hexdigest()
        assert value[field] == expected == digest(config[key])
        assert value[field] != hashlib.sha256(canonical_json_bytes(config[key])).hexdigest()
    assert value["service_root"] == str(owner.state / value["series_sha256"])
    assert value["history_root"] == str(owner.state / value["series_sha256"] / "history")


def test_selection_digest_preserves_real_filesystem_nanoseconds(owner):
    value = owner.seal()
    metadata = owner.selection.stat()
    assert value["_seal"]["mtime_ns"] == metadata.st_mtime_ns > 2**53
    assert value["_seal"]["ctime_ns"] == metadata.st_ctime_ns > 2**53
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    expected = hashlib.sha256(encoded).hexdigest()
    assert module.provenance_selection_digest(value) == expected
    assert module.provenance_selection_digest(module.load_provenance(owner.selection)) == expected
    changed = copy.deepcopy(value)
    changed["_seal"]["mtime_ns"] += 1
    assert module.provenance_selection_digest(changed) != expected
    assert module.provenance_selection_digest(dict(reversed(list(value.items())))) == expected


def test_database_progress_and_new_boot_directory_preserve_mutable_identity(owner):
    value = owner.seal()
    database = Path(value["history_database"])
    database.write_bytes(b"original native journal grew")
    (owner.root / "new-supported-stage").mkdir(mode=0o700)
    module.validate_provenance(value, require_stopped=False)


@pytest.mark.parametrize(
    "name", ["history_database", "decisions_database", "service_lock", "history_lock"]
)
def test_replaced_or_missing_original_state_is_refused_without_recreation(owner, name):
    value = owner.seal()
    path = Path(value[name])
    path.rename(path.with_suffix(".saved"))
    owner.running[0] = False
    with pytest.raises(FileNotFoundError), module.open_existing_owner_locks(value):
        pytest.fail("missing original accepted")
    assert not path.exists()
    path.write_bytes(b"replacement")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="identity changed"):
        module.validate_provenance(value, require_stopped=False)


@pytest.mark.parametrize("change", ["body", "inode", "writable", "symlink"])
def test_root_seal_cannot_be_replaced_or_mutated(owner, change):
    value = owner.seal()
    if change == "body":
        owner.selection.chmod(0o600)
        owner.selection.write_bytes(module._canonical({**value, "first_block": 124}))
        owner.selection.chmod(0o444)
    elif change == "inode":
        owner.selection.rename(owner.selection.with_suffix(".old"))
        owner.selection.write_bytes(owner.selection.with_suffix(".old").read_bytes())
        owner.selection.chmod(0o444)
    elif change == "writable":
        owner.selection.chmod(0o644)
    else:
        owner.selection.rename(owner.selection.with_suffix(".old"))
        owner.selection.symlink_to(owner.selection.with_suffix(".old"))
    with pytest.raises(ValueError):
        module.validate_provenance(value, require_stopped=False)


@pytest.mark.parametrize("change", ["source", "config", "unit", "service", "credentials"])
def test_capture_refuses_changed_selected_installation(owner, change):
    if change == "source":
        owner.code.chmod(0o600)
        owner.code.write_bytes(b"fail\n")
        owner.code.chmod(0o444)
    elif change == "config":
        owner.config.chmod(0o644)
    elif change == "unit":
        owner.unit.chmod(0o666)
    elif change == "service":
        owner.service["InvocationID"] = "other"
    else:
        owner.process["uid"] += 1
    with pytest.raises(ValueError):
        module.capture_provenance()


def test_supported_new_installation_may_restore_only_unchanged_seal_and_state(owner):
    value = owner.seal()
    owner.config.rename(owner.config.with_suffix(".old"))
    owner.config.write_bytes(b'{"new":"supported"}')
    owner.config.chmod(0o444)
    with pytest.raises(ValueError):
        module.validate_provenance(value, require_stopped=False)
    module.validate_provenance(value, require_stopped=False, check_original_installation=False)
    Path(value["history_database"]).rename(Path(value["history_database"] + ".old"))
    with pytest.raises(FileNotFoundError):
        module.validate_provenance(value, require_stopped=False, check_original_installation=False)


def test_partial_lock_failure_releases_prior_locks(owner):
    value = owner.seal()
    owner.running[0] = False
    busy = os.open(value["history_lock"], os.O_RDWR)
    fcntl.flock(busy, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(BlockingIOError), module.open_existing_owner_locks(value):
            pytest.fail("busy owner lock accepted")
        for name in ("service_lock", "control_writer_lock"):
            fd = os.open(value[name], os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
    finally:
        os.close(busy)


@pytest.mark.parametrize("change", [None, "nonisolated", "other_config", "root", "mixed_uid"])
def test_process_capture_checks_exact_launch_without_reading_environment(
    tmp_path, monkeypatch, change
):
    monkeypatch.setattr(module, "_PROC", tmp_path)
    proc = tmp_path / str(module.ORIGINAL_PID)
    proc.mkdir()
    fields = ["S", *(["0"] * 18), "98765"]
    (proc / "stat").write_text(f"{module.ORIGINAL_PID} (python worker) " + " ".join(fields))
    uids = (
        "0 0 0 0"
        if change == "root"
        else "993 994 993 993"
        if change == "mixed_uid"
        else "993 993 993 993"
    )
    (proc / "status").write_text(f"Uid:\t{uids}\nGid:\t983 983 983 983\n")
    argv = [
        "/root-owned/python",
        "-I",
        "-B",
        "-c",
        module._LAUNCH,
        "run",
        "--config",
        str(module.CONFIG_PATH),
    ]
    if change == "nonisolated":
        argv[1] = "-E"
    elif change == "other_config":
        argv[-1] = "/unselected/config.json"
    (proc / "cmdline").write_bytes(b"\0".join(v.encode() for v in argv) + b"\0")
    (proc / "exe").symlink_to("/root-owned/python")
    (proc / "cgroup").write_text("0::/selected\n")
    boot = tmp_path / "sys/kernel/random"
    boot.mkdir(parents=True)
    (boot / "boot_id").write_text("original-boot\n")
    # No environ, wallet, state database or key file exists in this fixture.
    if change is not None:
        with pytest.raises(ValueError):
            module._process()
    else:
        value = module._process()
        assert value["uid"] == 993 and value["start_ticks"] == 98765
        assert value["boot_id"] == "original-boot"
