"""Opt-in root/systemd checks in the wallet-free rehearsal VM.

The candidate interpreter is an inert OS probe. These checks exercise the real
transient service and filesystem protections; signed controls and the actual
Podman rehearsal are covered separately. No validator or model runs here.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_initial_upgrade as upgrade
from umi.protocol import canonical_json_bytes

from .test_competition_service_linux import (
    _ROOT,
    _STATE,
    _USER,
    _account,
    _command,
    _owned_directory,
    _show_unit,
    _write,
)
from .test_validator_supervisor import _config

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_INITIAL_UPGRADE_REHEARSAL") != "1",
    reason="requires explicit root opt-in in the wallet-free service rehearsal VM",
)


@pytest.mark.parametrize("probe_failure", [False, True])
def test_real_initial_transient_service_hides_wallet_and_retains_inputs(tmp_path, probe_failure):
    assert os.geteuid() == 0
    assert Path("/var/lib") in tmp_path.parents
    _ROOT.mkdir(mode=0o755, exist_ok=True)
    user = _account()
    assert _show_unit().get("ActiveState") != "active"
    run = _ROOT / ("initial-" + secrets.token_hex(8))
    run.mkdir(mode=0o755)
    run.chmod(0o755)
    state, release, wallet = (run / item for item in ("state", "release", "inert-wallet"))
    for path in (state, release, wallet):
        _owned_directory(path, user)
    _write(wallet / "inert-marker", b"not a key", 0o444)
    config = _config(
        state_root=str(state),
        release_root=str(release),
        wallet={"path": str(wallet), "name": "none", "hotkey": "none"},
    )
    base = (
        Path(__file__).parents[1]
        / "deploy/linux-validator-supervisor/umi-validator-supervisor.service"
    ).read_text()
    lines = []
    for line in base.splitlines():
        if line.startswith("WorkingDirectory="):
            line = "WorkingDirectory=" + str(state)
        elif line.startswith("ReadOnlyPaths="):
            line = "ReadOnlyPaths=" + str(wallet)
        elif line.startswith("ReadWritePaths="):
            line = "ReadWritePaths=" + str(state)
        lines.append(line)
    fragment = run / "base.service"
    _write(fragment, "\n".join(lines) + "\n")
    code = run / "code"
    interpreter = code / ".venv/bin/python"
    status = state / "preflight-probe.json"
    program = (
        "#!/usr/bin/python3\nimport os,json,pathlib\n"
        f"assert os.geteuid() == {user.pw_uid}\n"
        f"assert os.environ['HOME'] == {user.pw_dir!r}\n"
        "assert 'PYTHONPATH' not in os.environ\n"
        f"try:\n pathlib.Path({str(wallet / 'inert-marker')!r}).read_bytes()\n"
        "except PermissionError:\n pass\nelse:\n raise SystemExit(7)\n"
        "try:\n pathlib.Path(__file__).write_bytes(b'changed')\n"
        "except OSError:\n pass\nelse:\n raise SystemExit(8)\n"
        f"pathlib.Path({str(status)!r}).write_text(json.dumps({{'uid':os.geteuid(),'wallet_hidden':True}}))\n"
        f"raise SystemExit({9 if probe_failure else 0})\n"
    )
    _write(interpreter, program, 0o555)
    target = SimpleNamespace(
        release_bundle_sha256=hashlib.sha256(b"inert OCI bytes").hexdigest(),
        release_bundle_size_bytes=len(b"inert OCI bytes"),
    )
    bundle = run / "release.bundle"
    _write(bundle, b"inert OCI bytes", 0o400)
    source = SimpleNamespace(payload=canonical_json_bytes(config))
    control = SimpleNamespace(
        config=config,
        sources={upgrade.activation.SOURCE_CONFIG_FILENAME: source},
        signed_host=SimpleNamespace(
            manifest=SimpleNamespace(
                files=[SimpleNamespace(path="src/umi/competition_initial_upgrade.py")]
            )
        ),
        page=SimpleNamespace(
            directives=[SimpleNamespace(directive=SimpleNamespace(release=target))]
        ),
        recheck=lambda: None,
    )
    tree = SimpleNamespace(path=code, recheck=lambda: None)
    _command("/usr/bin/loginctl", "enable-linger", _USER)
    _command("/usr/bin/systemctl", "start", f"user@{user.pw_uid}.service")
    before = _show_unit()
    unit = {"Id": "umi-validator-supervisor.service", "FragmentPath": str(fragment)}
    if probe_failure:
        with pytest.raises(ValueError, match="rehearsal failed before stop"):
            upgrade._rehearse_service(control, user, unit, tree, bundle)
    else:
        upgrade._rehearse_service(control, user, unit, tree, bundle)
    assert json.loads(status.read_bytes()) == {"uid": user.pw_uid, "wallet_hidden": True}
    assert _show_unit() == before
    own = upgrade._PREFLIGHT_PARENT / hashlib.sha256(canonical_json_bytes(config)).hexdigest()
    (retained,) = own.iterdir()
    copied = retained / "release.bundle"
    assert copied.read_bytes() == bundle.read_bytes()
    assert copied.stat().st_uid == user.pw_uid
    assert copied.stat().st_mode & 0o777 == 0o400
    assert (wallet / "inert-marker").read_bytes() == b"not a key"
    assert interpreter.read_text() == program
    assert not (_STATE / "initial-upgrade-was-started").exists()


def test_root_anchor_retention_resumes_after_process_exit_between_atomic_moves(tmp_path):
    assert os.geteuid() == 0 and Path("/var/lib") in tmp_path.parents
    _ROOT.mkdir(mode=0o755, exist_ok=True)
    user = _account()
    run = _ROOT / ("anchor-retention-" + secrets.token_hex(8))
    _owned_directory(run, user)
    parent = run / "successor-v4"
    _owned_directory(parent, user)
    source = parent / "activation-source"
    _owned_directory(source, user)
    names = [upgrade.anchors.ANCHOR_STAGING_PREFIX + f"{i:032x}" for i in (1, 2)]
    identities = {}
    for name, mode in zip(names, (0o700, 0o555), strict=True):
        path = source / name
        path.mkdir(mode=0o700)
        _write(path / "evidence", b"interrupted anchor evidence", 0o444)
        path.chmod(mode)
        identities[name] = (path.stat().st_ino, mode)
    source.chmod(0o555)
    config = _config(state_root=str(run))
    child = os.fork()
    if child == 0:
        rename = upgrade.anchors._rename_noreplace

        def exit_after_move(*args, **kwargs):
            rename(*args, **kwargs)
            # No finally block, fsync, Python teardown or lock cleanup runs.
            os._exit(73)

        upgrade.anchors._rename_noreplace = exit_after_move
        upgrade._retain_interrupted_anchors(config, user)
        os._exit(1)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 73
    assert not (source / names[0]).exists() and (source / names[1]).exists()
    upgrade._retain_interrupted_anchors(config, user)
    assert not list(source.iterdir())
    for name in names:
        path = parent / "retained-anchors" / name
        assert (path.stat().st_ino, path.stat().st_mode & 0o777) == identities[name]
        assert (path / "evidence").read_bytes() == b"interrupted anchor evidence"
        assert path.stat().st_uid == 0
    upgrade._retain_interrupted_anchors(config, user)
    assert not (source / upgrade.activation.ANCHOR_DIRECTORY_NAME).exists()
