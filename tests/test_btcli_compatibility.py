from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "arguments",
    (
        ("--help",),
        ("subnets", "register", "--help"),
        ("tx", "serve-axon", "--help"),
    ),
)
def test_locked_btcli_commands_exit_cleanly(arguments: tuple[str, ...]) -> None:
    executable = Path(sys.executable).with_name("btcli")
    assert executable.is_file()
    completed = subprocess.run(
        [str(executable), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "Usage:" in completed.stdout
