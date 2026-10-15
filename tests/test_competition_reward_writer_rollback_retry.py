"""Genuine preparation lease + native checkpoint writes across repeated rollback.

Synthetic linked chain/trie/SCALE ports; no serialized native acceptance authority.
The mechanical owner keeps real locks while native readers persist export receipts.
"""

import asyncio
import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from umi import competition_reward_writer_selection as selection
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_reward_history as history_fixtures
from .test_competition_reward_history import (  # noqa: F401
    chain,
    control,
    historical,
    policy,
    series_case,
)
from .test_competition_reward_history import (
    history_case as history_case,
)
from .test_competition_reward_writer_selection import (  # noqa: F401
    activation_case,
    anchor_case,
    boot_inputs,
    explicit,
    installed_case,
    limits,
    package_case,
    package_limits,
    release_identity,
    replay_limits,
    successor_release,
    trusted_ports,
    worker_capacity,
)
from .test_competition_reward_writer_selection import (
    staging_case as staging_case,
)

original_chain_config = history_fixtures.chain_config


@pytest.fixture
def chain_config(original_chain_config):
    return original_chain_config.model_copy(
        update={
            "proof_rpc_fallback_urls": (
                "wss://backup-one.example.org",
                "wss://backup-two.example.org",
            )
        }
    )


pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


@pytest.mark.parametrize("damage", [None, "completed_record", "source_record"])
async def test_native_export_receipt_survives_rollback_and_same_operation_retry(
    staging_case, history_case, tmp_path, damage
):
    case, h = staging_case, history_case
    # Align the actual signed fixture boot/preparation with the native historical
    # provider before its original lock scope is first created.
    case.config = case.config.model_copy(
        update={
            "chain": h.item.config,
            "legacy_chains": tuple(
                value.model_copy(
                    update={
                        "chain": value.chain.model_copy(
                            update={"state_directory": str(tmp_path / "legacy-chain-config")}
                        )
                    }
                )
                for value in case.config.legacy_chains
            ),
        }
    )
    case.save(case.boot, canonical_json_bytes(case.config))
    case.approval = case.approval.model_copy(
        update={
            "standing_boot_raw_sha256": hashlib.sha256(
                canonical_json_bytes(case.config)
            ).hexdigest(),
            "chain_config_sha256": digest(case.config.chain),
        }
    )
    case.save(case.path, canonical_json_bytes(case.approval))
    with case.open():
        pass
    original = (
        Path(case.anchor.config.state_root)
        / "standing-rewards"
        / digest(case.config.series)
        / "history"
    )
    original.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    original.parent.chmod(0o700)
    if os.getgid() == 0:
        os.chown(original.parent, os.getuid(), case.approval.service_gid)
    staged = case.root / "history"
    archive = RewardProofArchive(tmp_path / "ordinary-export")

    def reader(path, *, export=False):
        return RewardControlHistoryReader(
            path,
            control_hotkey=h.item.hotkey,
            chain_config_sha256=digest(h.item.config),
            first_block=h.old.height,
            maximum_bytes=case.config.maximum_history_bytes,
            export_archive=archive if export else None,
        )

    reader(original)
    saved = tmp_path / "original-before-preparation"
    original.rename(saved)
    staged.rename(original)
    candidate = reader(original)
    await candidate.advance(h.item.provider, through_block=h.end)
    original.rename(staged)
    saved.rename(original)
    if os.getgid() == 0:
        for root in (original, staged):
            os.chown(root, os.getuid(), case.approval.service_gid)
            for path in root.iterdir():
                os.chown(path, os.getuid(), case.approval.service_gid)
    original_inode = (original / "rounds.sqlite3").stat().st_ino
    candidate_inode = (staged / "rounds.sqlite3").stat().st_ino
    operation = "native-export-retry-v1"
    with (
        case.open() as lease,
        pytest.raises(asyncio.CancelledError),
        selection.hold_writer_history_selection(lease, operation=operation) as owned,
    ):
        owned.exchange()
        native = reader(original, export=True)
        await native.advance(h.item.provider, through_block=h.end)
        assert all(
            native.checkpoints.load(height)["exports"] for height in range(h.old.height, h.end + 1)
        )
        assert selection._content_stamps(original) != owned.value["staged_content"]
        raise asyncio.CancelledError
    assert (original / "rounds.sqlite3").stat().st_ino == original_inode
    assert (staged / "rounds.sqlite3").stat().st_ino == candidate_inode
    path = selection._journal_path(case.root, operation)
    retained = path.read_bytes()
    assert json.loads(retained)["phase"] == "rolled_back"
    if damage:
        with sqlite3.connect(staged / "rounds.sqlite3") as db:
            if damage == "completed_record":
                db.execute(
                    "DELETE FROM records WHERE kind='control_history_checkpoint_done' AND id=?",
                    (str(h.end),),
                )
            else:
                db.execute(
                    "UPDATE records SET body=? WHERE kind='control_history_block' AND id=?",
                    ('{"changed":true}', str(h.end)),
                )
    selection.recover_writer_history_selection(
        case.anchor, standing_boot=case.boot, approval_path=case.path, operation=operation
    )
    before = list(h.body_requests)
    with (
        case.open() as lease,
        selection.hold_writer_history_selection(lease, operation=operation) as retry,
    ):
        assert path.read_bytes() == retained
        retry.exchange()
        native = reader(original, export=True)
        if damage:
            with pytest.raises((ValueError, HistoryCheckpointRepairRequired)):
                await native.advance(h.item.provider, through_block=h.end)
            # Native failure never calls mechanical commit or releases hold.
        else:
            await native.advance(h.item.provider, through_block=h.end)
            assert native.checkpoints.load(h.end)["exports"]
            retry.commit()
    assert h.body_requests == before
    assert case.held.read_bytes() == case.hold_bytes
    assert not Path(case.config.approval_path).exists()
    assert json.loads(path.read_bytes())["phase"] == ("rolled_back" if damage else "committed")
