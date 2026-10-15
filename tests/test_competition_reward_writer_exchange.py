"""Native assembly with genuine original owners; synthetic chain + root OS exchange ports.

The real root packet peer performs only the transport/syscall boundary. These
checks do not qualify the installed coordinator namespace or source broker CLI.
"""

import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_writer_exchange as exchange
from umi.competition_cohort_recovery import SignedCohortRecoveryAuthority
from umi.competition_reward_decisions import StandingRewardControlReader
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_writer_broker_channel import WriterBrokerChannel
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_reward_history as history_fixtures
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_control import commitment
from .test_competition_reward_decisions import (
    control as control,
)
from .test_competition_reward_decisions import (
    series_case as series_case,
)
from .test_competition_reward_decisions import signatures, signed
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import make_history_case
from .test_competition_reward_transaction_recovery import (
    original as original,
)
from .test_competition_reward_writer_adoption import signed_adoptions
from .test_competition_reward_writer_reconciliation import (
    activation_case as activation_case,
)
from .test_competition_reward_writer_reconciliation import (
    anchor_case as anchor_case,
)
from .test_competition_reward_writer_reconciliation import (
    explicit as explicit,
)
from .test_competition_reward_writer_reconciliation import (
    limits as limits,
)
from .test_competition_reward_writer_reconciliation import (
    owner_case as owner_case,
)
from .test_competition_reward_writer_reconciliation import (
    package_case as package_case,
)
from .test_competition_reward_writer_reconciliation import (
    package_limits as package_limits,
)
from .test_competition_reward_writer_reconciliation import (
    policy as policy,
)
from .test_competition_reward_writer_reconciliation import (
    release_identity as release_identity,
)
from .test_competition_reward_writer_reconciliation import (
    replay_limits as replay_limits,
)
from .test_competition_reward_writer_reconciliation import (
    signed_case as signed_case,
)
from .test_competition_reward_writer_reconciliation import (
    successor_release as successor_release,
)
from .test_competition_reward_writer_reconciliation import (
    trusted_ports as trusted_ports,
)
from .test_competition_reward_writer_reconciliation import (
    worker_capacity as worker_capacity,
)
from .test_competition_reward_writer_review import selected_boot as selected_boot

original_chain = history_fixtures.chain
original_chain_config = history_fixtures.chain_config


@pytest.fixture
def chain_config(original_chain_config):
    return original_chain_config.model_copy(
        update={
            "minimum_finalized_block": 150,
            "proof_rpc_fallback_urls": (
                "wss://backup-one.example.org",
                "wss://backup-two.example.org",
            ),
            "finality_pin": original_chain_config.finality_pin.model_copy(
                update={"bootstrap_block_number": 149}
            ),
        }
    )


@pytest.fixture
def chain(original_chain):
    original_chain.finality.ref = replace(original_chain.finality.ref, block_number=160)
    return original_chain


pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)

ROOT_PEER = r"""
import array, ctypes, json, os, socket, stat, sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
s.connect(sys.argv[1]); original, staged=sys.argv[2:4]
held=[]; selected=False

def receive():
    raw, anc, flags, _=s.recvmsg(16385,socket.CMSG_SPACE(64))
    for level, kind, value in anc:
        if kind==socket.SCM_RIGHTS:
            fds=array.array('i');fds.frombytes(value);held.extend(fds)
    if not raw: raise RuntimeError('closed native child')
    return json.loads(raw)
def send(action, **payload):
    s.send(json.dumps({'action':action,'payload':payload}).encode())
def ids():
    result={}
    for name in ('.','rounds.sqlite3','rounds.lock'):
        v=os.stat(os.path.join(original,name))
        result[name]=[v.st_dev,v.st_ino,v.st_uid,v.st_gid,stat.S_IMODE(v.st_mode)]
    return result
def swap():
    lib=ctypes.CDLL(None,use_errno=True)
    if lib.renameat2(-100,os.fsencode(original),-100,os.fsencode(staged),2):
        raise OSError(ctypes.get_errno(),'exchange')
try:
    first=receive()
    if first['action']=='namespace_ready':
        assert not held;send('readiness')
        assert receive()['action']=='complete';sys.exit(0)
    assert first['action']=='owned';send('begin')
    message=receive()
    if message['action']=='failed':send('rolled_back',history_identities=ids());sys.exit(2)
    assert message['action']=='original_reviewed';swap();selected=True
    send('selected',history_identities=ids())
    message=receive()
    if message['action']=='failed':
        swap();selected=False;send('rolled_back',history_identities=ids());sys.exit(2)
    assert message['action']=='candidate_reviewed';send('committed')
    assert receive()['action']=='complete'
finally:
    for fd in held:os.close(fd)
    s.close()
"""


@pytest.mark.parametrize("original_blocks", [0, 2, "raw"])
@pytest.mark.parametrize(
    "fault,bootstrap",
    [
        ("none", False),
        ("candidate_gap", False),
        ("interrupted", False),
        ("namespace_readiness", False),
        ("none", True),
        ("partial", True),
        ("candidate_gap", True),
        ("interrupted", True),
        ("namespace_readiness", True),
        ("missing_adoption", True),
        ("wrong_hash", True),
        ("recommit", True),
        ("write", True),
        ("unresolved", True),
        ("retained_conflict", True),
    ],
)
async def test_native_empty_and_completed_original_assemble_control_and_absent_pending(
    selected_boot, historical, monkeypatch, tmp_path, original_blocks, fault, bootstrap
):
    from umi import competition_reward_history_preparation as preparation

    async def synthetic_resource_preflight(config, resources):
        # These assembly fixtures use explicitly synthetic finality/proof ports.
        # Artifact staging and early-failure ordering have separate real-file tests.
        assert resources.state_directory == config.state_directory
        return {"native_artifacts_checked": 4, "chain_submission_authorized": False}

    monkeypatch.setattr(exchange, "preflight_chain_resources", synthetic_resource_preflight)
    real_selection = exchange.select_writer_resources

    def relocated_selection(*args, **kwargs):
        value = real_selection(*args, **kwargs)
        return replace(
            value,
            resources=value.resources.model_copy(update={"proof_binary": "/selected/proof"}),
        )

    monkeypatch.setattr(exchange, "select_writer_resources", relocated_selection)
    monkeypatch.setattr(preparation, "_root_owner_uid", os.getuid)
    c, item = selected_boot
    h = historical
    first = h.old.height
    authority = item.value.series.recovery.authority.model_copy(update={"issued_at_block": first})
    series = item.value.series.model_copy(
        update={
            "recovery": SignedCohortRecoveryAuthority(
                authority=authority, signatures=signatures(authority)
            )
        }
    )
    config = item.value.model_copy(
        update={
            "series": series,
            "chain": h.item.config,
            "legacy_chains": tuple(
                value.model_copy(
                    update={
                        "chain": value.chain.model_copy(
                            update={"state_directory": str(tmp_path / "legacy-chain-config")}
                        )
                    }
                )
                for value in item.value.legacy_chains
            ),
            "handoff": item.value.handoff.model_copy(update={"series_sha256": digest(series)}),
        }
    )
    item.save(item.path, canonical_json_bytes(config))
    active = Path(config.approval_path)
    item.save(
        active,
        canonical_json_bytes(
            item.approval.model_copy(
                update={
                    "series_sha256": digest(series),
                    "chain_config_sha256": digest(config.chain),
                    "legacy_handoff_plan_sha256": digest(config.handoff),
                }
            )
        ),
    )
    held = active.with_suffix(".held")
    active.rename(held)
    h.c.control_writes = {height: () for height in range(first, first + 5)}
    adoptions, adoption_path = None, None
    if bootstrap:
        adoptions = signed_adoptions(config, h.c)
        anchor = adoptions.adoptions[0].adoption.bootstrap_predecessor
        h.c.initial_commitment = commitment(
            "aa" * 32 if fault == "wrong_hash" else anchor.control_sha256,
            anchor.committed_at_block + (1 if fault == "recommit" else 0),
        )
        if fault == "write":
            ordinary_genesis = signed(
                h.c.genesis.decision.model_copy(
                    update={
                        "series_sha256": digest(series),
                        "observed_at_block": first + 2,
                    }
                )
            )
            sha = digest(ordinary_genesis.decision)
            h.c.control_writes[first + 2] = (sha,)
            delivery = Path(config.delivery_directory) / "decisions"
            delivery.mkdir(parents=True, mode=0o700)
            item.save(delivery / (sha + ".json"), canonical_json_bytes(ordinary_genesis))
        elif fault == "unresolved":
            h.c.cleared_blocks = {first + 2}
        if fault != "missing_adoption":
            adoption_path = tmp_path / "supplemental-adoptions.json"
            item.save(adoption_path, canonical_json_bytes(adoptions))
    h = await make_history_case(h, monkeypatch, tmp_path)
    root = c.root / "standing-rewards" / digest(series)
    root.parent.mkdir(mode=0o700)
    root.mkdir(mode=0o700)

    def reader():
        return RewardControlHistoryReader(
            root / "history",
            control_hotkey=series.control_hotkey,
            chain_config_sha256=digest(config.chain),
            first_block=first,
            maximum_bytes=config.maximum_history_bytes,
        )

    original = reader()
    control_reader = StandingRewardControlReader(
        root / "control",
        series,
        config.policy,
        expected_series_sha256=digest(series),
        expected_chain_config_sha256=digest(config.chain),
        maximum_bytes=config.maximum_reader_bytes,
    )
    if fault == "retained_conflict":
        old_genesis = signed(
            h.c.genesis.decision.model_copy(update={"series_sha256": digest(series)})
        )
        control_reader.journal.put(
            "reward_control_decision", "0000000000000000", old_genesis.model_dump(by_alias=True)
        )
    if isinstance(original_blocks, int) and original_blocks:
        await original.advance(h.item.provider, through_block=first + original_blocks - 1)
    original_inode = original.journal.path.stat().st_ino
    saved = tmp_path / "original-history"
    staged = tmp_path / "candidate-history"
    (root / "history").rename(saved)
    candidate = reader()
    target = first + 2 if fault == "partial" else h.end
    await candidate.advance(h.item.provider, through_block=target)
    candidate_inode = candidate.journal.path.stat().st_ino
    if original_blocks == "raw":
        from umi.competition_reward_history_checkpoint import SOURCE_KINDS

        with candidate.journal.read_transaction() as db:
            binding = json.loads(db.execute("SELECT body FROM binding").fetchone()[0])
            records = [
                (kind, key, json.loads(body))
                for kind, key, body in db.execute("SELECT kind,id,body FROM records")
                if kind in SOURCE_KINDS
            ]
        raw_original = type(original.journal)(
            saved, binding, maximum_bytes=config.maximum_history_bytes
        )
        if fault == "source_mismatch":
            records = [
                (kind, key, {**body, "changed_source": True})
                if kind == "control_history_block" and key == str(first)
                else (kind, key, body)
                for kind, key, body in records
            ]
        raw_original.put_many(records)
    before_requests = list(h.body_requests)
    if fault == "candidate_gap":
        with candidate.journal.transaction() as db:
            db.execute(
                "DELETE FROM records WHERE kind='control_history_checkpoint_done' AND id=?",
                (str(h.end),),
            )
    if fault == "interrupted":

        def selected_reader(*args, **kwargs):
            value = RewardControlHistoryReader(*args, **kwargs)
            if value.journal.path.stat().st_ino == candidate_inode:

                async def interrupted_restore(*args, **kwargs):
                    raise asyncio.CancelledError

                value._restore_prefix = interrupted_restore
            return value

        monkeypatch.setattr(exchange, "RewardControlHistoryReader", selected_reader)
    (root / "history").rename(staged)
    saved.rename(root / "history")

    def provider_with_selected_resources(*args, **kwargs):
        assert kwargs["resources"].proof_binary == "/selected/proof"
        assert kwargs["resources"].state_directory == config.chain.state_directory
        return h.item.provider

    monkeypatch.setattr(
        exchange, "HistoricalRewardControlProvider", provider_with_selected_resources
    )
    monkeypatch.setattr(h.item.provider._finality, "run", lambda stop: stop.wait(), raising=False)
    h.item.provider._startup_floor = -1
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    address = tmp_path / "root-peer.sock"
    listener.bind(str(address))
    listener.listen(1)
    listener.setblocking(False)
    peer = subprocess.Popen(
        [
            "sudo",
            "-n",
            sys.executable,
            "-c",
            ROOT_PEER,
            str(address),
            str(root / "history"),
            str(staged),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    connection = None
    try:
        connection, _ = await asyncio.wait_for(asyncio.get_running_loop().sock_accept(listener), 10)
        pid, uid, _ = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        assert uid == 0
        channel = WriterBrokerChannel(connection, peer_pid=pid, peer_uid=0)
        args = SimpleNamespace(
            standing_boot=item.path,
            held_approval=held,
            history="current",
            through_block=target,
            reward_adoptions=adoption_path,
            unit=c.unit,
            config=c.config_path,
            readiness_only=fault == "namespace_readiness",
            preserve_unverified_original=original_blocks == "raw"
            and fault != "source_without_selection",
        )
        if fault == "namespace_readiness":
            from umi.competition_supervisor_runtime import hold_successor_startup_lease

            def forbidden(*args, **kwargs):
                raise AssertionError("namespace check touched original owners or journals")

            for name in (
                "hold_successor_startup_lease",
                "hold_stopped_standing_writer",
                "hold_stopped_writer_journals",
                "RewardControlHistoryReader",
                "StandingRewardControlReader",
                "HistoricalRewardControlProvider",
            ):
                monkeypatch.setattr(exchange, name, forbidden)
            with hold_successor_startup_lease(c.anchor):
                result = await asyncio.wait_for(
                    exchange.exchange_installed_standing_writer(c.anchor, args, channel), 30
                )
            assert result["status"] == "namespace_readiness_passed"
            for field in (
                "original_owner_checked",
                "original_locks_acquired",
                "original_journals_opened",
                "original_services_changed",
                "directory_exchange_performed",
                "chain_submission_authorized",
            ):
                assert result[field] is False
            assert result["approval_hold_preserved"] is True
            assert not active.exists()
            assert (root / "history" / "rounds.sqlite3").stat().st_ino == original_inode
            assert (staged / "rounds.sqlite3").stat().st_ino == candidate_inode
        elif fault in {"none", "partial"}:
            result = await asyncio.wait_for(
                exchange.exchange_installed_standing_writer(c.anchor, args, channel), 30
            )
            assert result["status"] == "selected"
            assert result["history"]["admission_status"] == "absent_in_verified_interval"
            assert result["history"]["original_history_empty"] is (original_blocks == 0)
            assert result["history"]["original_unverified_sources_preserved"] is (
                original_blocks == "raw"
            )
            if original_blocks == "raw":
                assert result["history"]["original_source_through_block"] == target
                assert result["history"]["original_through_block"] == first - 1
            assert (
                result["standing_attempt"]["status"]
                == "standing_journal_absent_requires_native_handoff_review"
            )
            assert not result["chain_submission_authorized"]
            assert not active.exists()
            assert (root / "history" / "rounds.sqlite3").stat().st_ino == candidate_inode
            assert (staged / "rounds.sqlite3").stat().st_ino == original_inode
        else:
            expected = (
                HistoryCheckpointRepairRequired
                if fault == "candidate_gap"
                else asyncio.CancelledError
                if fault == "interrupted"
                else ValueError
            )
            with pytest.raises(expected):
                await asyncio.wait_for(
                    exchange.exchange_installed_standing_writer(c.anchor, args, channel), 30
                )
            assert (root / "history" / "rounds.sqlite3").stat().st_ino == original_inode
            assert (staged / "rounds.sqlite3").stat().st_ino == candidate_inode
            assert not active.exists()
        assert h.body_requests == before_requests
        if fault == "partial":
            # The final writer continues ordinary native history from the
            # selected prefix; already completed blocks need no new body RPCs.
            await h.restart()
            resumed = reader()
            await resumed.advance(h.item.provider, through_block=h.end)
            assert h.body_requests == before_requests + list(range(target + 1, h.end + 1))

    finally:
        if connection is not None:
            connection.close()
        listener.close()
        if peer.poll() is None:
            try:
                await asyncio.wait_for(asyncio.to_thread(peer.wait), 5)
            except TimeoutError:
                peer.kill()
        _output, error = peer.communicate()
    assert peer.returncode == (0 if fault in {"none", "partial", "namespace_readiness"} else 2), (
        error.decode()
    )


@pytest.mark.parametrize("fault", ["source_mismatch", "source_without_selection"])
async def test_native_retained_sources_refuse_mismatch_and_missing_selection(
    selected_boot, historical, monkeypatch, tmp_path, fault
):
    await test_native_empty_and_completed_original_assemble_control_and_absent_pending(
        selected_boot,
        historical,
        monkeypatch,
        tmp_path,
        original_blocks="raw",
        fault=fault,
        bootstrap=True,
    )
