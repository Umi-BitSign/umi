"""Real stopped leases and filesystem locks with inert signed release fixtures."""

from __future__ import annotations

import fcntl
import os
from dataclasses import replace

import pytest

from tests.test_bridge_drain import drain as drain
from tests.test_bridge_drain import install_body
from tests.test_bridge_receipt_provider import provider as provider
from tests.test_bridge_receipts import history as history
from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import tx as tx
from tests.test_competition_bridge_recovery import add_attempt
from tests.test_competition_host_upgrade import hold
from tests.test_competition_recovery import limits as limits
from tests.test_competition_upgrade import installation, write
from tests.test_registration_bridge import observation
from tests.test_registration_bridge import signed_policy as signed_policy
from tests.test_registration_bridge_supervisor import _bridge_bundle
from umi import competition_host_upgrade as host
from umi import competition_legacy_drain as recovery
from umi.bridge.drain import MARKER_DOMAIN
from umi.competition_bridge_recovery import JOURNAL
from umi.protocol import canonical_json_bytes


@pytest.fixture
def installed(tmp_path, signed_policy, monkeypatch):
    obs = observation()
    value = installation(
        tmp_path / "installed",
        _bridge_bundle(signed_policy),
        "linux/amd64",
        hotkey=obs.validator_hotkey,
    )
    write(value.root / "state" / "supervisor-process.lock", b"", 0o600)
    files = {"service.lock": b""}
    value.current_journal = add_attempt(files, signed_policy, obs, phase="submitting")
    for name, raw in files.items():
        write(value.root / "worker" / name, raw, 0o600)
    # Only OS boundaries and the audited test release identity are substituted.
    # Signed artifacts, original lock inodes and snapshots use production code.
    monkeypatch.setattr(host, "_require_root_linux", lambda: None)
    monkeypatch.setattr(host, "_root_file", lambda path: None)
    monkeypatch.setattr(host, "_check_unit", lambda *args: {"FragmentPath": str(value.config_path)})
    monkeypatch.setattr(recovery, "_AUDITED_DIRECTIVES", frozenset({value.signed.directive_sha256}))
    return value


def test_entropy_is_created_after_both_locks_and_original_state_is_preserved(
    installed, limits, monkeypatch
):
    root = installed.root
    before = {p: p.read_bytes() for p in (root / "worker").rglob("*") if p.is_file()}
    entropy_calls = []

    def entropy(length):
        assert length == 32
        for path in (root / "state" / "supervisor-process.lock", root / "worker" / "service.lock"):
            fd = os.open(path, os.O_RDONLY)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        entropy_calls.append(length)
        return b"x" * 32

    monkeypatch.setattr(recovery.secrets, "token_bytes", entropy)
    with hold(installed) as stopped:
        with recovery.hold_legacy_drain(stopped, limits=limits) as session:
            assert session.marker == MARKER_DOMAIN + b"x" * 32
            session.recheck()
        with pytest.raises(host.HostUpgradeError, match="closed"):
            session.recheck()
    assert entropy_calls == [32]
    assert all(p.read_bytes() == raw for p, raw in before.items())
    assert not (root / "wallets-must-not-be-opened").exists()


def test_unknown_release_cannot_issue_a_challenge(installed, limits, monkeypatch):
    monkeypatch.setattr(recovery, "_AUDITED_DIRECTIVES", frozenset())
    with (
        hold(installed) as stopped,
        pytest.raises(host.HostUpgradeError, match="audited"),
        recovery.hold_legacy_drain(stopped, limits=limits),
    ):
        pytest.fail("unaudited release")


def test_json_cannot_replace_stopped_lease(limits):
    with (
        pytest.raises(ValueError, match="owned stopped-host"),
        recovery.hold_legacy_drain({"service_stopped": True}, limits=limits),
    ):
        pytest.fail("operator assertion is not a stopped lease")


def test_a_live_worker_lock_rejects_challenge_before_entropy(installed, limits, monkeypatch):
    def forbidden(*args):
        pytest.fail("generated challenge before worker lock")

    monkeypatch.setattr(recovery.secrets, "token_bytes", forbidden)
    fd = os.open(installed.root / "worker" / "service.lock", os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (
            hold(installed) as stopped,
            pytest.raises(BlockingIOError),
            recovery.hold_legacy_drain(stopped, limits=limits),
        ):
            pytest.fail("live worker")
    finally:
        os.close(fd)


def test_another_in_process_session_cannot_replay_the_challenge(installed, limits):
    with hold(installed) as stopped:
        with recovery.hold_legacy_drain(stopped, limits=limits) as session:
            copied = replace(session)
            with pytest.raises(host.HostUpgradeError, match="absent"):
                copied.recheck()
        with recovery.hold_legacy_drain(stopped, limits=limits) as retry:
            assert retry.marker != session.marker
            retry.recheck()
            with pytest.raises(host.HostUpgradeError, match="closed"):
                session.recheck()


def test_changed_journal_invalidates_challenge(installed, limits):
    with (
        pytest.raises(ValueError, match="changed"),
        hold(installed) as stopped,
        recovery.hold_legacy_drain(stopped, limits=limits) as session,
    ):
        path = installed.root / "worker" / JOURNAL
        write(path, canonical_json_bytes(installed.current_journal) + b"\n", 0o600)
        session.recheck()


def test_service_restart_invalidates_challenge(installed, limits, monkeypatch):
    with (
        pytest.raises(host.HostUpgradeError, match="not stopped"),
        hold(installed) as stopped,
        recovery.hold_legacy_drain(stopped, limits=limits) as session,
    ):

        def running(*args):
            raise host.HostUpgradeError("unit not stopped")

        monkeypatch.setattr(host, "_check_unit", running)
        session.recheck()


async def test_live_proof_is_bound_to_session_and_cannot_be_forged(
    installed, limits, provider, drain
):
    with hold(installed) as stopped:
        with recovery.hold_legacy_drain(stopped, limits=limits) as session:
            number = drain.birth + 2
            install_body(drain, number, (b"inherent", b"remark:" + session.marker))
            proof = await session.collect(
                provider, block_number=number, block_hash=drain.hashes[number]
            )
            proof.recheck()
            copied = replace(proof)
            with pytest.raises(host.HostUpgradeError, match="absent"):
                copied.recheck()
            object.__setattr__(proof.result, "marker_sha256", "00" * 32)
            with pytest.raises(host.HostUpgradeError, match="altered"):
                proof.recheck()
        with pytest.raises(host.HostUpgradeError, match="closed"):
            session.recheck()
