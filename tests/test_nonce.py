from __future__ import annotations

import hashlib
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import bittensor as bt
import pytest

import umi.nonce as nonce_module
from umi.auth import RequestAuthenticator
from umi.nonce import (
    NonceStoreAuthorizationError,
    NonceStoreCapacityError,
    NonceStoreError,
    SQLiteNonceStore,
)

from .factories import dev_wallet


def test_nonce_store_persists_replay_state_across_reopened_instances(tmp_path) -> None:
    path = tmp_path / "state" / "nonces.sqlite3"
    first = SQLiteNonceStore(path)
    assert first.check_and_store("hotkey-a", 123)

    reopened = SQLiteNonceStore(path)
    assert not reopened.check_and_store("hotkey-a", 123)
    assert reopened.check_and_store("hotkey-b", 123)
    assert reopened.check_and_store("hotkey-a", 124)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_concurrent_same_nonce_accepts_exactly_once_across_store_instances(tmp_path) -> None:
    path = tmp_path / "nonces.sqlite3"
    stores = tuple(SQLiteNonceStore(path) for _ in range(4))

    def submit(index: int) -> bool:
        return stores[index % len(stores)].check_and_store("shared-hotkey", 999)

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = tuple(executor.map(submit, range(32)))

    assert results.count(True) == 1
    assert results.count(False) == 31


def test_expired_nonce_is_pruned_and_can_be_accepted_again(tmp_path, monkeypatch) -> None:
    path = tmp_path / "nonces.sqlite3"
    store = SQLiteNonceStore(path, retention_seconds=1.0)
    now_values = iter((1_000_000_000, 2_000_000_001))
    monkeypatch.setattr(nonce_module.time, "time_ns", lambda: next(now_values))

    assert store.check_and_store("hotkey", 1)
    assert store.check_and_store("hotkey", 1)


def test_nonce_store_rejects_invalid_keys_nonces_and_symlink_database(tmp_path) -> None:
    store = SQLiteNonceStore(tmp_path / "nonces.sqlite3")
    with pytest.raises(ValueError, match="hotkey"):
        store.check_and_store("", 1)
    for nonce in (-1, True, 1.5):
        with pytest.raises(ValueError, match="nonce"):
            store.check_and_store("hotkey", nonce)  # type: ignore[arg-type]

    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"not a database")
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="non-symlink"):
        SQLiteNonceStore(link)


def test_nonce_store_rejects_nonpositive_retention(tmp_path) -> None:
    with pytest.raises(ValueError, match="retention"):
        SQLiteNonceStore(tmp_path / "nonces.sqlite3", retention_seconds=0)


def test_policy_bound_store_rejects_unlisted_account_without_a_row(tmp_path) -> None:
    allowed = dev_wallet("//NonceAllowed")
    unlisted = dev_wallet("//NonceUnlisted")
    store = SQLiteNonceStore(
        tmp_path / "nonces.sqlite3",
        allowed_hotkeys=(allowed.hotkey.ss58_address,),
        maximum_nonces_per_hotkey=2,
        maximum_total_nonces=2,
        maximum_database_bytes=128 * 1024,
    )

    with pytest.raises(NonceStoreAuthorizationError, match="nonce_unlisted_account"):
        store.check_and_store(unlisted.hotkey.ss58_address, 1)
    assert store.row_count() == 0


def test_nonce_capacity_is_atomic_and_survives_restart(tmp_path) -> None:
    validator = dev_wallet("//NonceCapacity")
    path = tmp_path / "nonces.sqlite3"
    arguments = {
        "allowed_hotkeys": (validator.hotkey.ss58_address,),
        "maximum_nonces_per_hotkey": 2,
        "maximum_total_nonces": 2,
        "maximum_database_bytes": 128 * 1024,
    }
    store = SQLiteNonceStore(path, **arguments)
    assert store.check_and_store(validator.hotkey.ss58_address, 1)
    assert store.check_and_store(validator.hotkey.ss58_address, 2)
    assert not store.check_and_store(validator.hotkey.ss58_address, 1)
    with pytest.raises(NonceStoreCapacityError, match="nonce_store_capacity"):
        store.check_and_store(validator.hotkey.ss58_address, 3)
    assert store.row_count() == 2

    reopened = SQLiteNonceStore(path, **arguments)
    assert reopened.row_count() == 2
    with pytest.raises(NonceStoreCapacityError, match="nonce_store_capacity"):
        reopened.check_and_store(validator.hotkey.ss58_address, 4)
    assert not Path(f"{path}-wal").exists()
    assert not Path(f"{path}-shm").exists()


def test_nonce_store_fails_closed_on_corruption_or_binding_change(tmp_path) -> None:
    first = dev_wallet("//NonceFirst")
    second = dev_wallet("//NonceSecond")
    path = tmp_path / "nonces.sqlite3"
    arguments = {
        "allowed_hotkeys": (first.hotkey.ss58_address,),
        "maximum_nonces_per_hotkey": 2,
        "maximum_total_nonces": 2,
        "maximum_database_bytes": 128 * 1024,
    }
    SQLiteNonceStore(path, **arguments)
    with pytest.raises(NonceStoreError, match="metadata_mismatch"):
        SQLiteNonceStore(
            path,
            allowed_hotkeys=(second.hotkey.ss58_address,),
            maximum_nonces_per_hotkey=2,
            maximum_total_nonces=2,
            maximum_database_bytes=128 * 1024,
        )

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not sqlite")
    corrupt.chmod(0o600)
    with pytest.raises(NonceStoreError, match="nonce_database_failure"):
        SQLiteNonceStore(corrupt)


def test_nonce_store_exposes_retention_to_btauth_window_guard(tmp_path) -> None:
    validator = dev_wallet("//NonceValidator")
    miner = dev_wallet("//NonceMiner")
    body = b"{}"
    headers = bt.http_auth.sign(
        validator,
        method="POST",
        path="/v1/translate",
        body=body,
        receiver_ss58=miner.hotkey.ss58_address,
        nonce_ns=time.time_ns(),
    )
    store = SQLiteNonceStore(tmp_path / "short.sqlite3", retention_seconds=1.0)
    authenticator = RequestAuthenticator(
        self_hotkey_ss58=miner.hotkey.ss58_address,
        nonce_store=store,
        max_age_seconds=10.0,
        allowed_skew_seconds=2.0,
    )

    assert store.retention == 1.0
    with pytest.raises(ValueError, match="freshness window"):
        authenticator.verify(headers, body, method="POST", path="/v1/translate")


def test_declared_body_digest_authentication_is_nonmutating_until_commit(tmp_path) -> None:
    validator = dev_wallet("//DigestValidator")
    miner = dev_wallet("//DigestMiner")
    body = b'{"request":"exact bytes"}'
    nonce = time.time_ns()
    headers = bt.http_auth.sign(
        validator,
        method="POST",
        path="/v1/translate",
        body=body,
        receiver_ss58=miner.hotkey.ss58_address,
        nonce_ns=nonce,
    )
    authenticator = RequestAuthenticator.sqlite(
        miner.hotkey.ss58_address,
        tmp_path / "nonces.sqlite3",
        max_age_seconds=10.0,
        allowed_skew_seconds=2.0,
        allowed_hotkeys=(validator.hotkey.ss58_address,),
        maximum_nonces_per_hotkey=2,
        maximum_total_nonces=2,
        maximum_database_bytes=128 * 1024,
    )
    store = authenticator.nonce_store

    with pytest.raises(bt.http_auth.BadSignature):
        authenticator.verify_declared_body_digest(
            headers,
            "00" * 32,
            method="POST",
            path="/v1/translate",
        )
    assert store.row_count() == 0

    caller = authenticator.verify_declared_body_digest(
        headers,
        hashlib.sha256(body).hexdigest(),
        method="POST",
        path="/v1/translate",
    )
    assert store.row_count() == 0
    authenticator.commit_replay(caller)
    assert store.row_count() == 1
    with pytest.raises(bt.http_auth.ReplayedRequest):
        authenticator.commit_replay(caller)
