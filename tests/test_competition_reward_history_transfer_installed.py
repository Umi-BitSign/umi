"""Opt-in compatibility with an operator-selected already installed history reader."""

import json
import os
import subprocess

import pytest

from .test_competition_reward_history_transfer import chain as chain
from .test_competition_reward_history_transfer import chain_config as chain_config
from .test_competition_reward_history_transfer import control as control
from .test_competition_reward_history_transfer import historical as historical
from .test_competition_reward_history_transfer import history_case as history_case
from .test_competition_reward_history_transfer import policy as policy
from .test_competition_reward_history_transfer import series_case as series_case
from .test_competition_reward_history_transfer import transfer_case as transfer_case

_INTERPRETER = os.environ.get("UMI_TEST_INSTALLED_HISTORY_PYTHON")
pytestmark = [
    pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True),
    pytest.mark.skipif(
        not _INTERPRETER, reason="select an installed history interpreter explicitly"
    ),
]
_SCRIPT = r"""
import json,sys
from pathlib import Path
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import SOURCE_KINDS
from umi.competition_verification_rules import runtime_identity
v=json.loads(sys.argv[1])
r=RewardControlHistoryReader(Path(v["root"]), control_hotkey=v["hotkey"],
    chain_config_sha256=v["chain"], first_block=v["first"])
def forbidden(*args,**kwargs):
    raise AssertionError("installed receipt reader reloaded a completed proof")
r._load=forbidden
read=r.journal.get_raw
def bounded(kind,key,**kwargs):
    if kind in SOURCE_KINDS:
        forbidden()
    return read(kind,key,**kwargs)
r.journal.get_raw=bounded
facts=[r.checkpoints.load(n) for n in range(v["first"],v["last"]+1)]
print(json.dumps({"facts":facts,"owner":r.checkpoints.owner,"semantics":runtime_identity(),
    "next_block":r._next,"database_inode":r.journal.path.stat().st_ino}))
"""


async def test_transferred_native_receipts_load_in_unchanged_installed_reader(transfer_case):
    h = transfer_case
    h.transfer()
    args = {
        "root": str(h.target_root),
        "hotkey": h.source.hotkey,
        "chain": h.source.config_sha256,
        "first": h.source.first_block,
        "last": h.end,
    }
    observed = subprocess.run(
        [_INTERPRETER, "-I", "-B", "-c", _SCRIPT, json.dumps(args)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    result = json.loads(observed.stdout)
    assert result["facts"] == [
        h.target.checkpoints.load(n) for n in range(h.source.first_block, h.end + 1)
    ]
    assert result["owner"] == h.target.checkpoints.owner
    assert result["database_inode"] == h.target.journal.path.stat().st_ino
    assert result["next_block"] == h.source.first_block
