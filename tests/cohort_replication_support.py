"""Exercise the deployed copy command with an explicitly selected rclone binary."""

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "deploy/standing-reward-replication"


class Replica:
    def __init__(self, root):
        self.binary = os.environ.get("UMI_TEST_RCLONE") or shutil.which("rclone")
        if not self.binary:
            pytest.skip("install rclone or select UMI_TEST_RCLONE for transfer integration")
        self.root = root
        root.mkdir(mode=0o700)
        (root / "rclone.conf").write_text("")
        self.command = next(
            line.split("=", 1)[1]
            for line in (ROOT / "umi-standing-reward-copy@.service.in").read_text().splitlines()
            if line.startswith("ExecStart=")
        )

    def copy(self, origin, target, profile):
        # Missing outboxes have not published anything; create only fixture
        # directories, as installed services do before starting their timers.
        origin.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.root / "filters").write_bytes(
            (ROOT / "profiles" / (profile + ".filters")).read_bytes()
        )
        replacements = {
            "@RCLONE@": self.binary,
            "${SOURCE}": str(origin),
            "${DESTINATION}": str(target),
        }
        args = [
            replacements.get(a, a.replace("%d", str(self.root))) for a in shlex.split(self.command)
        ]
        # Match the service's UMask without changing the test runner's process.
        result = subprocess.run(args, capture_output=True, timeout=60, umask=0o077)
        assert result.returncode == 0, result.stderr.decode(errors="replace")

    def settlement(self, case):
        def deliver():
            for sender, receiver in (("Charlie", "Dave"), ("Dave", "Charlie")):
                a, z = case.configs[sender], case.configs[receiver]
                self.copy(Path(a.proof_export_directory), Path(a.proof_import_directory), "reward")
                self.copy(Path(a.exchange_outbox), Path(z.exchange_inbox), "settlement")
                self.copy(Path(a.proof_export_directory), Path(z.proof_import_directory), "reward")
                if a.role == "coordinator":
                    self.copy(
                        Path(a.exchange_outbox) / "inputs", Path(z.inputs_directory), "documents"
                    )
                    self.copy(Path(a.history_directory), Path(z.history_directory), "documents")

        case.deliver = deliver
