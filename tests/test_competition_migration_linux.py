"""Complete signed bridge-to-successor migration on disposable Linux hosts.

Real boundaries: signed controls/host/OCI, rooted systemd units, old process
locks, journal reconciliation/archive, sealed anchor, publication and restart.
The finalized observation and long-running host are synthetic, so this test
cannot attest to GRANDPA, model inference or permission to submit weights.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_initial_upgrade as upgrade
from umi import competition_switch_recovery as restart
from umi import registration_bridge as bridge
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import advance_supervisor_directive_state
from umi.validator_supervisor_adapters import (
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
    SupervisorRegistrationBridgeInputBundle,
)

from .coordinator_rehearsal import LEGACY_FRAGMENT, coordinator_roots, fixture_validator_hotkey
from .test_competition_bridge_recovery import add_attempt
from .test_competition_chain import chain_config as chain_config
from .test_competition_initial_preflight_linux import _signed_preflight_case
from .test_competition_initial_preflight_linux import oci_release as oci_release
from .test_competition_initial_preflight_linux import release_identity as release_identity
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_recovery import limits as limits
from .test_competition_service_linux import _command, _owned_directory, _show_unit, _wait, _write
from .test_competition_upgrade import release as install_legacy_release
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy
from .test_registration_bridge import observation, policy_body
from .test_registration_bridge import signed_policy as signed_policy
from .test_validator_supervisor import _config

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_SIGNED_MIGRATION_REHEARSAL") != "1",
    reason="requires explicit root opt-in on a disposable wallet-free Linux host",
)

_CONFIG = Path("/etc/umi/validator-supervisor.json")
_LEGACY_PROBE = """#!/usr/bin/python3
import argparse, fcntl, json, os, pathlib, time
p = argparse.ArgumentParser()
p.add_argument('--config', required=True)
c = json.loads(pathlib.Path(p.parse_args().config).read_bytes())
state = pathlib.Path(c['state_root'])
with (state / 'supervisor-process.lock').open('r+b') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    (state / 'legacy-probe.json').write_text(json.dumps({'pid': os.getpid()}))
    while True:
        time.sleep(1)
"""


def _startup_probe(authority):
    return f"""import argparse, fcntl, json, os, pathlib, time
from umi import registration_bridge
from umi.competition_host_anchor import load_materialized_successor_anchor
registration_bridge.REGISTRATION_BRIDGE_COORDINATOR = {authority!r}
p = argparse.ArgumentParser()
p.add_argument('--config', required=True)
args = p.parse_args()
anchor = load_materialized_successor_anchor(pathlib.Path(args.config))
assert not anchor.receipt.chain_submission_authorized
assert anchor.initial_page.directives[-1].directive.mode == 'competition_replay'
state = pathlib.Path(anchor.config.state_root)
with (state / 'supervisor-process.lock').open('r+b') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    anchor.recheck()
    (state / 'successor-probe.json').write_text(json.dumps({{
        'pid': os.getpid(), 'receipt': anchor.receipt_sha256,
        'checkpoint': anchor.receipt.checkpoint_sha256,
        'hotkey': anchor.config.validator_hotkey, 'chain_submission_authorized': False,
    }}))
    while True:
        time.sleep(1)
"""


def _owned_tree(root, user):
    # Only newly constructed, marker-guarded, key-free fixture trees.
    for path in (root, *root.rglob("*")):
        assert not path.is_symlink()
        os.chown(path, user.pw_uid, user.pw_gid)


def _prepare_legacy(layout, user, target, signer):
    config = _config(
        validator_hotkey=fixture_validator_hotkey(layout.instance),
        target_platform=target,
        state_root="/var/lib/umi-validator-supervisor/state",
        release_root="/var/lib/umi-validator-supervisor/releases",
        worker_state_root="/var/lib/umi-validator-worker-state",
        operator_input_root="/var/lib/umi-validator-operator-inputs",
        worker_cpu_millis=1000,
        worker_memory_bytes=1024**3,
        wallet={"path": "/var/lib/umi-validator-runtime-wallets", "name": "none", "hotkey": "none"},
    )
    state = layout.physical(Path(config.state_root))
    worker = layout.physical(Path(config.worker_state_root))
    assert list(state.iterdir()) == [] and list(worker.iterdir()) == []
    authority = signer.body.coordinator_hotkey
    from .factories import dev_wallet

    signed = bridge.sign_registration_bridge_policy(
        policy_body(coordinator_hotkey=authority, valid_from_block=1),
        wallet=dev_wallet("//RegistrationBridgeAuthority"),
    )
    inputs = SupervisorRegistrationBridgeInputBundle(
        schema=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
        profile=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
        signed_policy=signed,
    )
    # Historical bytes are synthetic but use actual signed bridge schemas.
    base = observation()
    participants = [
        p.model_copy(update={"registered_at_block": 1, "last_update": 0}) for p in base.participants
    ]
    instance = int(layout.instance)
    participants[instance] = participants[instance].model_copy(
        update={"hotkey": config.validator_hotkey}
    )
    base = bridge.RegistrationBridgeObservation.model_validate(
        base.model_copy(
            update={
                "participants": participants,
                "block_number": 160,
                "validator_hotkey": config.validator_hotkey,
                "subnet_owner_hotkey": participants[0].hotkey,
                "owner_associated_hotkeys": [participants[0].hotkey],
            }
        ).model_dump(mode="python")
    )
    files = {"service.lock": b"original bridge service lock"}
    current = add_attempt(files, signed, base)
    for name, raw in files.items():
        _write(worker / name, raw, 0o600)
    _owned_tree(worker, user)
    releases = layout.physical(Path(config.release_root))
    stage = releases / "test-initial-stage"
    old = install_legacy_release(stage, config, inputs)
    stage.rename(releases / old.directive_sha256)
    _owned_tree(releases, user)
    highwater = advance_supervisor_directive_state(
        old, config=config, finalized_block=120, prior_state=None
    )
    for name, raw in (
        ("directive-state.json", canonical_json_bytes(highwater)),
        ("supervisor-process.lock", b"original supervisor process lock"),
    ):
        _write(state / name, raw, 0o600)
        os.chown(state / name, user.pw_uid, user.pw_gid)
    _write(layout.physical(_CONFIG), canonical_json_bytes(config), 0o440)
    os.chown(layout.physical(_CONFIG), -1, user.pw_gid)
    _write(layout.physical(Path("/etc/umi/migration-approved")), "synthetic fixture only", 0o444)
    _write(
        layout.physical(Path("/opt/umi-validator-supervisor/legacy-probe")), _LEGACY_PROBE, 0o555
    )
    evidence = canonical_json_bytes({"schema": "test-owned-chain-observation", "block": 180})
    owned = SimpleNamespace(
        validator_hotkey=config.validator_hotkey,
        validator_uid=instance,
        validator_row=tuple(tuple(pair) for pair in current.attempt.expected_row),
        validator_last_update=current.weight_call.block_number,
        block=180,
        block_hash="0x" + "18" * 32,
        genesis_hash=base.genesis_hash,
        chain_config_sha256="29" * 32,
        evidence=evidence,
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        commit_reveal_enabled=False,
        manifest_anchor_sha256=None,
        manifest_anchor_block=None,
    )
    return SimpleNamespace(
        config=config,
        signed=old,
        body=canonical_json_bytes(old),
        state=highwater,
        files=files,
        owned=owned,
        worker=worker,
        state_root=state,
        layout=layout,
        user=user,
    )


def _fork(run, label, action, *, exit_code=0):
    pid = os.fork()
    if pid == 0:
        try:
            action()
        except BaseException:
            _write(run / (label + "-failure.txt"), traceback.format_exc())
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    actual = os.waitstatus_to_exitcode(status)
    failure = run / (label + "-failure.txt")
    assert actual == exit_code, failure.read_text() if failure.exists() else str(actual)


def _probe(item, successor=False):
    unit = _show_unit(item.layout.unit_name)
    assert unit["ActiveState"] != "failed", "fixture service failed"
    path = item.state_root / ("successor-probe.json" if successor else "legacy-probe.json")
    if unit["ActiveState"] == "active" and path.exists():
        value = json.loads(path.read_bytes())
        if value["pid"] == int(unit["MainPID"]):
            return value
    return None


def test_signed_initial_migration_and_process_death_resume_preserve_both_bridges(
    tmp_path,
    oci_release,
    package_case,
    package_limits,
    policy,
    worker_capacity,
    chain_config,
    limits,
    signed_policy,
):
    assert os.geteuid() == 0 and Path("/var/lib") in tmp_path.parents
    run = tmp_path / ("signed-migration-" + secrets.token_hex(8))
    run.mkdir(mode=0o755)
    fragment = Path("/etc/systemd/system/umi-validator@.service")
    assert not fragment.exists()
    records = []
    with coordinator_roots() as accounts:
        try:
            for layout, user in accounts:
                item = _prepare_legacy(
                    layout, user, oci_release.target.target_platform, signed_policy
                )
                records.append(item)
                item.run = run / ("uid" + layout.instance)
                item.run.mkdir(mode=0o755)
                item.archives = item.run / "archives"
                _owned_directory(item.archives, user)
                _write(item.run / "recovery-limits.json", canonical_json_bytes(limits), 0o400)
                item.lock_inode = (item.state_root / "supervisor-process.lock").stat().st_ino
                _command("/usr/bin/loginctl", "enable-linger", user.pw_name)
                _command("/usr/bin/systemctl", "start", f"user@{user.pw_uid}.service")
            _write(
                fragment,
                LEGACY_FRAGMENT.replace(
                    "ExecStart=/bin/false",
                    "ExecStart=/opt/umi-validator-supervisor/legacy-probe --config " + str(_CONFIG),
                ),
            )
            _command("/usr/bin/systemctl", "daemon-reload")
            for item in records:
                _command("/usr/bin/systemctl", "start", item.layout.unit_name)
                item.legacy_probe = _wait(lambda item=item: _probe(item))

            for index, item in enumerate(records):
                other = records[1 - index]
                before_other = _probe(other, successor=index == 1)

                def migrate(item=item, index=index):
                    # Only the child gains aliases for this exact RootDirectory.
                    from umi.competition_coordinator_namespace import prepare_coordinator_host_view

                    prepare_coordinator_host_view(
                        unit_name=item.layout.unit_name, service_uid=item.user.pw_uid
                    )
                    case = _signed_preflight_case(
                        item.run,
                        item.config,
                        oci_release,
                        package_case,
                        package_limits,
                        policy,
                        worker_capacity,
                        chain_config,
                        predecessor=item,
                        startup_probe=_startup_probe(signed_policy.body.coordinator_hotkey),
                    )

                    from umi import competition_chain_state as chain_state
                    from umi import competition_host_observer as host_observer

                    selected = host_observer.parse_successor_host_observer_config(
                        case.control.sources[upgrade.activation.HOST_OBSERVER_FILENAME].payload
                    ).chain
                    item.owned.chain_config_sha256 = digest(selected)

                    class FinalityPort:
                        def __init__(self, chain, policy):
                            assert digest(chain) == item.owned.chain_config_sha256

                        async def start(self):
                            pass

                        async def wait_weights_ready(self, hotkey, recipients):
                            assert hotkey == item.config.validator_hotkey and recipients == ()
                            return item.owned

                        async def aclose(self):
                            pass

                    def check_owned(value):
                        assert value is item.owned

                    host_observer.FinalizedCompetitionWeightProvider = FinalityPort
                    host_observer.validate_owned_weight_observation = check_owned
                    chain_state.validate_owned_weight_observation = check_owned
                    if index == 1:
                        original = restart.publish_switch_intent

                        def die_after_intent(*args):
                            original(*args)
                            # No Python teardown, source switch or startup.
                            os._exit(73)

                        restart.publish_switch_intent = die_after_intent
                    result = upgrade.upgrade_successor_service(
                        config_path=_CONFIG,
                        unit_name=item.layout.unit_name,
                        controls_path=case.controls,
                        host_bundle=item.run / "host.bundle",
                        oci_bundle=case.bundle,
                        recovery_root=item.archives,
                        recovery_limits_path=item.run / "recovery-limits.json",
                    )
                    _write(item.run / "result.json", canonical_json_bytes(result))

                _fork(item.run, "migration", migrate, exit_code=0 if index == 0 else 73)
                if index == 1:
                    unit = _show_unit(item.layout.unit_name)
                    assert unit["ActiveState"] == "inactive" and unit["MainPID"] == "0"
                    marker = Path("/etc/systemd/system") / (item.layout.unit_name + ".d")
                    assert (marker / restart.INTENT_FILENAME).is_file()
                    assert not (marker / "50-umi-successor.conf").exists()
                    assert _probe(other, successor=True) == before_other

                    def resume(item=item):
                        result = restart.resume_and_start_successor_service(
                            config_path=_CONFIG, unit_name=item.layout.unit_name
                        )
                        _write(item.run / "result.json", canonical_json_bytes(result))

                    _fork(item.run, "resume", resume)
                result = json.loads((item.run / "result.json").read_bytes())
                assert result["status"] == "successor_service_running"
                assert not result["chain_submission_authorized"]
                started = _wait(lambda item=item: _probe(item, successor=True))
                assert started["pid"] == result["main_pid"]
                assert started["checkpoint"] == result["checkpoint_sha256"]
                assert started["hotkey"] == item.config.validator_hotkey
                assert started["pid"] != item.legacy_probe["pid"]
                assert _probe(other, successor=index == 1) == before_other
                assert (
                    item.state_root / "supervisor-process.lock"
                ).stat().st_ino == item.lock_inode
                assert (
                    item.state_root / "directive-state.json"
                ).read_bytes() == canonical_json_bytes(item.state)
                assert {
                    p.relative_to(item.worker).as_posix(): p.read_bytes()
                    for p in item.worker.rglob("*")
                    if p.is_file()
                } == item.files
                wallet = item.layout.physical(Path(item.config.wallet.path))
                assert sorted(p.name for p in wallet.iterdir()) == ["inert-marker"]
                assert (wallet / "inert-marker").read_bytes() == b"not a key\n"
        finally:
            # Stop only units whose names were admitted by the fixture guards.
            for item in records:
                _command("/usr/bin/systemctl", "stop", item.layout.unit_name, check=False)
                cleanup = (
                    item.layout.unit_name.removesuffix(".service") + "-successor-cleanup.service"
                )
                if Path("/etc/systemd/system", cleanup).exists():
                    _command("/usr/bin/systemctl", "start", cleanup, timeout=180)
                assert _show_unit(item.layout.unit_name)["MainPID"] == "0"
            for item in records:
                for suffix in (".d",):
                    path = Path("/etc/systemd/system", item.layout.unit_name + suffix)
                    if path.exists():
                        path.rename(item.run / path.name)
                cleanup = Path(
                    "/etc/systemd/system",
                    item.layout.unit_name.removesuffix(".service") + "-successor-cleanup.service",
                )
                if cleanup.exists():
                    cleanup.rename(item.run / cleanup.name)
            if fragment.exists():
                fragment.rename(run / fragment.name)
            _command("/usr/bin/systemctl", "daemon-reload")
