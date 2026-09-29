"""Rooted systemd selection and native service execution with public fixtures.

The selection case exercises default boot inputs and filesystem isolation. The
execution case joins native journal handoff, signing and restart with synthetic
package-selection and chain-proof ports. Neither proves on-chain rewards or a
physical reboot. No live unit, wallet or state is accessed.
"""

import json
import os
import secrets
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from umi.competition_reward_boot import BOOT_FILENAME
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import (
    chain as chain,
)
from .test_competition_reward_boot import (
    chain_config as chain_config,
)
from .test_competition_reward_boot import (
    control as control,
)
from .test_competition_reward_boot import (
    inputs as inputs,
)
from .test_competition_reward_boot import (
    policy as policy,
)
from .test_competition_reward_boot import (
    series_case as series_case,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_REWARD_BOOT_REHEARSAL") != "1",
    reason="requires explicit root opt-in for isolated systemd checks",
)

PROBE = """
import json, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from umi.competition_reward_boot import select_standing_boot
from umi.open_competition import digest
from umi.validator_supervisor import ValidatorSupervisorConfig
root = Path('/etc/umi')
record = json.loads((root / 'fixture-anchor.json').read_bytes())
anchor = SimpleNamespace(
    config=ValidatorSupervisorConfig.model_validate(record['config']),
    receipt_sha256=record['receipt_sha256'],
    receipt=SimpleNamespace(host_manifest_sha256=record['host_manifest_sha256']),
)
try:
    selected = select_standing_boot(root / 'validator-supervisor.json', anchor)
except (OSError, ValueError) as error:
    print(json.dumps({'status': 'rejected', 'error_type': type(error).__name__}))
    raise SystemExit(2)
print(json.dumps({'status': 'legacy' if selected is None else 'standing',
                  'series_sha256': None if selected is None else digest(selected.series)}))
"""


def test_rooted_service_selects_same_inputs_after_restart_and_rejects_invalid_approval(
    inputs, tmp_path
):
    assert os.geteuid() == 0 and Path("/var/lib") in tmp_path.parents
    # Only this disposable fixture ancestry is made traversable. Never chmod
    # arbitrary parents or use the real coordinator roots/accounts/unit names.
    for path in (tmp_path.parent, tmp_path):
        assert path.stat().st_uid == 0 and not path.is_symlink()
        path.chmod(0o755)
    root = tmp_path / "service-root"
    config = root / "etc/umi"
    config.mkdir(parents=True, mode=0o755)
    (root / "etc").chmod(0o755)
    root.chmod(0o755)
    i = inputs
    i.save(root / "etc/passwd", b"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n")
    i.save(root / "etc/group", b"nogroup:x:65534:\n")
    boot = i.value.model_copy(update={"approval_path": "/etc/umi/standing-approval.json"})
    i.save(config / BOOT_FILENAME, canonical_json_bytes(boot))
    i.save(config / "standing-approval.json", canonical_json_bytes(i.approval))
    i.save(config / "validator-supervisor.json", canonical_json_bytes(i.anchor.config))
    i.save(
        config / "fixture-anchor.json",
        canonical_json_bytes(
            {
                "config": i.anchor.config.model_dump(mode="json", by_alias=True),
                "receipt_sha256": i.anchor.receipt_sha256,
                "host_manifest_sha256": i.anchor.receipt.host_manifest_sha256,
            }
        ),
    )
    source = Path(__file__).resolve().parents[1]
    # The interpreter may be in the checkout's venv or a separate test venv.
    environment = Path(sys.prefix)
    binds = {source, environment, Path(sys.base_prefix)}
    binds.update(p for p in (Path("/usr"), Path("/lib"), Path("/lib64")) if p.exists())
    assert all(p.is_absolute() and p.exists() and p != Path("/") for p in binds)
    name = "umi-c5-boot-selection-" + secrets.token_hex(8) + ".service"

    def probe():
        command = [
            "/usr/bin/systemd-run",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--unit=" + name,
            "--property=Type=exec",
            "--property=User=nobody",
            "--property=Group=nogroup",
            "--property=RootDirectory=" + str(root),
            "--property=MountAPIVFS=yes",
            "--property=PrivateNetwork=yes",
            "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict",
            "--property=NoNewPrivileges=yes",
            "--property=RuntimeMaxSec=30s",
            "--property=TimeoutStopSec=5s",
            "--property=BindReadOnlyPaths=" + " ".join(sorted(map(str, binds))),
            "--property=ReadOnlyPaths=+/etc/umi",
            "--",
            sys.executable,
            "-I",
            "-B",
            "-c",
            PROBE,
            str(source / "src"),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        assert result.returncode in {0, 2}, result.stderr
        return result.returncode, json.loads(result.stdout)

    try:
        original = (config / BOOT_FILENAME).read_bytes()
        expected = {"status": "standing", "series_sha256": digest(boot.series)}
        for _ in range(2):
            assert probe() == (0, expected)
            assert (config / BOOT_FILENAME).read_bytes() == original
        approval = config / "standing-approval.json"
        approval.chmod(0o644)
        assert probe() == (2, {"status": "rejected", "error_type": "HostActivationError"})
        approval.chmod(0o444)
        assert probe() == (0, expected)
        (config / BOOT_FILENAME).unlink()
        assert probe() == (0, {"status": "legacy", "series_sha256": None})
        (config / BOOT_FILENAME).symlink_to(config / "absent-selection")
        assert probe() == (2, {"status": "rejected", "error_type": "HostActivationError"})
    finally:
        # Exact transient unit only, including when observation times out.
        subprocess.run(["/usr/bin/systemctl", "stop", name], capture_output=True, timeout=15)


def test_rooted_service_runs_native_handoff_executor_and_restart(tmp_path):
    """Real Linux process/isolation; chain and package review are fixture ports.

    The child runs the connected native handoff/service/executor cases for both
    C4 journal layouts. Restart reopens the runtime/journal inside that child;
    a physical reboot and full installed supervisor bootstrap are not implied.
    """
    assert os.geteuid() == 0 and Path("/var/lib") in tmp_path.parents
    for path in (tmp_path.parent, tmp_path):
        assert path.stat().st_uid == 0 and not path.is_symlink()
        path.chmod(0o755)
    root = tmp_path / "execution-root"
    (root / "etc").mkdir(parents=True, mode=0o755)
    (root / "etc/passwd").write_text("nobody:x:65534:65534::/work:/usr/sbin/nologin\n")
    (root / "etc/group").write_text("nogroup:x:65534:\n")
    work = root / "work"
    work.mkdir(mode=0o700)
    # Change ownership only inside this disposable service root.
    os.chown(work, 65534, 65534)
    source = Path(__file__).resolve().parents[1]
    binds = {source, Path(sys.prefix), Path(sys.base_prefix)}
    binds.update(p for p in (Path("/usr"), Path("/lib"), Path("/lib64")) if p.exists())
    assert all(p.is_absolute() and p.exists() and p != Path("/") for p in binds)
    name = "umi-c5-reward-execution-" + secrets.token_hex(8) + ".service"
    script = """
import sys
sys.path[:0] = [sys.argv[1] + '/src', sys.argv[1]]
import pytest
raise SystemExit(pytest.main([
    sys.argv[1] + '/tests/test_competition_reward_host.py',
    '-q', '-k', 'executes_original', '--basetemp=/work/tests',
    '-o', 'cache_dir=/work/cache', '--junitxml=/work/results.xml',
]))
"""
    command = [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--unit=" + name,
        "--property=Type=exec",
        "--property=User=nobody",
        "--property=Group=nogroup",
        "--property=RootDirectory=" + str(root),
        "--property=WorkingDirectory=/work",
        "--property=MountAPIVFS=yes",
        "--property=PrivateNetwork=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectSystem=strict",
        "--property=NoNewPrivileges=yes",
        "--property=RuntimeMaxSec=90s",
        "--property=TimeoutStopSec=5s",
        "--property=MemoryMax=2G",
        "--property=CPUQuota=200%",
        "--property=TasksMax=512",
        "--property=BindReadOnlyPaths=" + " ".join(sorted(map(str, binds))),
        "--property=ReadWritePaths=+/work",
        "--",
        sys.executable,
        "-I",
        "-B",
        "-c",
        script,
        str(source),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=105)
        assert result.returncode == 0, result.stdout + result.stderr
        suites = ET.fromstring((work / "results.xml").read_bytes()).findall("testsuite")
        assert sum(int(s.attrib["tests"]) for s in suites) == 2
        assert all(
            s.attrib[key] == "0" for s in suites for key in ("failures", "errors", "skipped")
        )
    finally:
        subprocess.run(["/usr/bin/systemctl", "stop", name], capture_output=True, timeout=15)
