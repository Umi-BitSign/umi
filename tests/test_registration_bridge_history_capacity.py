"""Resource headroom must not remove boundedness or recovery checks."""

import pytest

import umi.registration_bridge as bridge
from tests.test_registration_bridge_runtime import (
    Chain,
    applied_observation,
    run,
    signed_policy,  # noqa: F401
    wallet,  # noqa: F401
    writer_observation,
)


def test_snapshot_retains_more_than_old_byte_limit(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "state"
    root.mkdir(mode=0o700)
    history = root / "registration-bridge-history"
    history.mkdir(mode=0o700)
    payload = b"x" * (1024 * 1024)
    for index in range(65):
        path = history / f"{index}.json"
        path.write_bytes(payload)
        path.chmod(0o600)
    with bridge.RegistrationBridgeState(root) as state:
        state.require_unchanged()
        assert len(list(history.iterdir())) == 65
    monkeypatch.setattr(bridge, "MAX_HISTORY_BYTES", 64 * 1024 * 1024)
    with (
        pytest.raises(bridge.RegistrationBridgeError, match="history_byte_capacity_reached"),
        bridge.RegistrationBridgeState(root),
    ):
        pass
    assert len(list(history.iterdir())) == 65


def test_archive_write_keeps_byte_ceiling_and_existing_receipt(
    tmp_path, monkeypatch, signed_policy, wallet  # noqa: F811
):
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        before = writer_observation(wallet)
        chain = Chain(state, [before, before, applied_observation(wallet, signed_policy)])
        assert run(signed_policy, wallet, chain, state)["status"] == "submitted"
        original = state.path.read_bytes()
        journal = state.load()
        history = state.root / "registration-bridge-history"
        retained = {p.name: p.read_bytes() for p in history.iterdir()}
        total = sum(len(value) for value in retained.values()) + len(original)
        monkeypatch.setattr(bridge, "MAX_HISTORY_BYTES", total)
        # Snapshot permits the exact ceiling. An additional archived payload
        # must still fail, even with an already existing destination record.
        oversized = journal.model_copy(update={"last_observed_block": 10**12})
        with pytest.raises(bridge.RegistrationBridgeError, match="history_byte_capacity_reached"):
            state.store(oversized, archive=True)
        assert state.path.read_bytes() == original
        assert {p.name: p.read_bytes() for p in history.iterdir()} == retained


def test_file_count_ceiling_is_still_enforced(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "state"
    root.mkdir(mode=0o700)
    history = root / "registration-bridge-history"
    history.mkdir(mode=0o700)
    for index in range(2):
        path = history / f"{index}.json"
        path.write_bytes(b"{}")
        path.chmod(0o600)
    monkeypatch.setattr(bridge, "MAX_HISTORY_FILES", 1)
    with (
        pytest.raises(bridge.RegistrationBridgeError, match="history_capacity_reached"),
        bridge.RegistrationBridgeState(root),
    ):
        pass
