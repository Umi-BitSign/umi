"""Signed host and OCI preflight in both real coordinator RootDirectory layouts.

Only opt in on the wallet-free rehearsal VM. This uses the actual production
preflight child and container controls. It does not collect finality, stop a
legacy writer, publish successor authorization or submit weights.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import traceback
from pathlib import Path

import pytest

from umi import competition_coordinator_namespace as coordinator
from umi import competition_initial_upgrade as upgrade

from .coordinator_rehearsal import LEGACY_FRAGMENT, coordinator_roots, fixture_validator_hotkey
from .test_competition_chain import chain_config as chain_config
from .test_competition_initial_preflight_linux import (
    _signed_preflight_case,
)
from .test_competition_initial_preflight_linux import (
    oci_release as oci_release,
)
from .test_competition_initial_preflight_linux import (
    release_identity as release_identity,
)
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_service_linux import _command, _write
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy
from .test_validator_supervisor import _config

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_COORDINATOR_SERVICE_REHEARSAL") != "1",
    reason="requires explicit root opt-in to the wallet-free coordinator service rehearsal",
)


@pytest.mark.parametrize("instance", ["0", "54"])
def test_each_rooted_signed_host_stages_and_rehearses_without_cross_instance_state(
    tmp_path,
    instance,
    oci_release,
    package_case,
    package_limits,
    policy,
    worker_capacity,
    chain_config,
):
    assert os.geteuid() == 0 and Path("/var/lib") in tmp_path.parents
    run = tmp_path / ("coordinator-preflight-" + secrets.token_hex(8))
    run.mkdir(mode=0o755)
    fragment = run / "legacy-base.service"
    _write(fragment, LEGACY_FRAGMENT)
    with coordinator_roots() as accounts:
        (layout, user) = next(pair for pair in accounts if pair[0].instance == instance)
        other, _ = next(pair for pair in accounts if pair[0].instance != instance)
        config = _config(
            validator_hotkey=fixture_validator_hotkey(instance),
            target_platform=oci_release.target.target_platform,
            state_root="/var/lib/umi-validator-supervisor/state",
            release_root="/var/lib/umi-validator-supervisor/releases",
            worker_state_root="/var/lib/umi-validator-worker-state",
            operator_input_root="/var/lib/umi-validator-operator-inputs",
            worker_cpu_millis=1000,
            worker_memory_bytes=1024**3,
            wallet={
                "path": "/var/lib/umi-validator-runtime-wallets",
                "name": "none",
                "hotkey": "none",
            },
        )
        other_state = other.physical(Path(config.state_root))
        before_other = sorted(path.name for path in other_state.iterdir())
        _command("/usr/bin/loginctl", "enable-linger", user.pw_name)
        _command("/usr/bin/systemctl", "start", f"user@{user.pw_uid}.service")
        pid = os.fork()
        if pid == 0:
            try:
                view = coordinator.prepare_coordinator_host_view(
                    unit_name=layout.unit_name, service_uid=user.pw_uid
                )
                case = _signed_preflight_case(
                    run,
                    config,
                    oci_release,
                    package_case,
                    package_limits,
                    policy,
                    worker_capacity,
                    chain_config,
                )
                upgrade._rehearse_service(
                    case.control,
                    user,
                    {
                        "Id": layout.unit_name,
                        "User": user.pw_name,
                        "FragmentPath": str(fragment),
                        "RootDirectory": str(layout.root_directory),
                        "RootImage": "",
                        "Slice": "umi-validators.slice",
                    },
                    case.tree,
                    case.bundle,
                )
                view.recheck()
                case.tree.recheck()
                _write(run / "result.json", json.dumps({"preflight": "passed"}))
            except BaseException:
                _write(run / "failure.txt", traceback.format_exc())
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0, (run / "failure.txt").read_text()
        assert json.loads((run / "result.json").read_bytes()) == {"preflight": "passed"}
        assert sorted(path.name for path in other_state.iterdir()) == before_other
        wallet = layout.physical(Path(config.wallet.path))
        assert (wallet / "inert-marker").read_text() == "not a key\n"
        state = layout.physical(Path(config.state_root))
        assert not (state / "successor-v4").exists()
        assert not (state / "supervisor-process.lock").exists()
        assert any(layout.physical(Path(config.release_root)).iterdir())
