"""Fixed production driver with real journals/signatures and synthetic chain ports.

No public policy, production wallet, chain transaction or installed rollout.
"""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_translation_reference_execution import execution_case, reference_case, signing_case
from tests.test_translation_reference_policy import case as policy_case
from tests.test_translation_reference_state import read
from tests.test_validator_supervisor_worker import _environment, _FinalityReader
from umi.crypto import sign_response_digest
from umi.protocol import canonical_json_bytes
from umi.translation_reference_legacy_state import ReferenceLegacyState
from umi.translation_reference_policy import (
    SignedTranslationReferencePolicy,
    reference_policy_sha256,
    reference_policy_signature_digest,
)
from umi.translation_reference_state import TranslationReferenceError
from umi.translation_reference_worker import LeaseFinality, _under_lease, load_reference_policy
from umi.validator_supervisor_adapters import OwnedFinalizedBlock
from umi.validator_supervisor_worker import OwnedFinalityLease

__all__ = ["execution_case", "reference_case", "signing_case"]


def test_translation_observer_wait_is_separate_from_legacy_timeout_and_signing_freshness(
    monkeypatch, tmp_path
):
    import umi.validator_supervisor_worker as supervisor

    monkeypatch.setattr(supervisor, "Path", lambda _value: tmp_path / "staging")
    monkeypatch.setattr(
        supervisor,
        "_sha256_regular_file",
        lambda _path, *, executable: (
            "a" * 64 if executable else supervisor.FINNEY_CHAIN_SPEC_SHA256
        ),
    )
    monkeypatch.setattr(
        supervisor, "GrandpaFinalityObserver", lambda **options: SimpleNamespace(**options)
    )
    legacy = supervisor._production_finality_reader()
    translation = supervisor._production_translation_finality_reader()
    assert legacy.timeout_seconds == legacy.observer.record_timeout_seconds == 30
    assert translation.timeout_seconds == translation.observer.record_timeout_seconds == 120
    assert supervisor.WORKER_FINALITY_FRESHNESS_SECONDS == 30


@pytest.mark.asyncio
async def test_longer_observer_recovery_never_authorizes_a_stale_signing_head():
    from umi.validator_supervisor_worker import SupervisorWorkerError

    reader = _FinalityReader()
    now = [0.0]
    lease = OwnedFinalityLease(
        reader, valid_from_block=120, valid_through_block=1000, monotonic=lambda: now[0]
    )
    task = asyncio.create_task(lease.run())
    try:
        await lease.wait_ready(timeout_seconds=1)
        now[0] = 45.0
        with pytest.raises(SupervisorWorkerError, match="worker_finality_stale"):
            lease.require_headroom(0)
        reader.blocks.put_nowait(OwnedFinalizedBlock(126, "0x" + "a" * 64))
        await asyncio.sleep(0)
        assert lease.require_headroom(0).number == 126
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def signed_http(policy, monkeypatch):
    import umi.translation_reference_worker as worker

    authority, _, _ = policy_case()
    monkeypatch.setattr(worker, "COMMON_SUPERVISOR_AUTHORITY_HOTKEY", authority.hotkey.ss58_address)
    signed = SignedTranslationReferencePolicy(
        schema="umi-signed-translation-reference-policy/1",
        policy=policy,
        authority_hotkey=authority.hotkey.ss58_address,
        signature_scheme="sr25519",
        signature=sign_response_digest(authority, reference_policy_signature_digest(policy))[1],
    )
    calls = []

    class Http:
        async def fetch_bytes(self, url, *, maximum_bytes):
            calls.append((url, maximum_bytes))
            return canonical_json_bytes(signed)

    return Http(), calls


@pytest.mark.asyncio
async def test_fixed_download_authenticates_hash_and_approved_row_not_remote_key(
    execution_case, monkeypatch
):
    case = execution_case
    http, calls = signed_http(case.policy, monkeypatch)
    env = replace(
        _environment(
            case.obs.validator_hotkey,
            policy_sha256=reference_policy_sha256(case.policy),
            release_manifest_sha256="a" * 64,
        ),
        mode="translation_weights",
    )
    assert await load_reference_policy(env, http=http) == case.policy
    assert calls == [
        (
            "https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/"
            f"translation-reference-policies/{env.policy_sha256}.json",
            16 * 1024,
        )
    ]
    with pytest.raises(ValueError, match="authenticated release authority"):
        await load_reference_policy(replace(env, policy_sha256="f" * 64), http=http)
    _, _, v1 = policy_case()
    http, _ = signed_http(v1.policy, monkeypatch)
    with pytest.raises(TranslationReferenceError, match="approved_row_required"):
        await load_reference_policy(
            replace(env, policy_sha256=reference_policy_sha256(v1.policy)), http=http
        )


@pytest.mark.asyncio
async def test_cached_owned_head_does_not_consume_extra_stream_heads():
    reader = _FinalityReader()
    lease = OwnedFinalityLease(reader, valid_from_block=120, valid_through_block=200)
    task = asyncio.create_task(lease.run())
    try:
        first = await lease.wait_ready()
        port = LeaseFinality(lease)
        for _ in range(20):
            assert await port.read_finalized_identity() == first
        # A newly accepted head is available immediately to all native guards.
        await reader.blocks.put(OwnedFinalizedBlock(126, "0x" + "11" * 32))
        await lease.require_snapshot(126, "0x" + "11" * 32, 0)
        assert (await port.read_finalized_identity()).number == 126
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_lease_cancellation_drains_child_despite_repeated_cancel():
    entered, cleanup, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    class Lease:
        async def wait_terminal(self):
            await asyncio.Event().wait()

    async def operation():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleanup.set()
            await release.wait()

    task = asyncio.create_task(_under_lease(Lease(), operation()))
    await entered.wait()
    task.cancel()
    await cleanup.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_container_sigterm_drains_once_and_exits_cleanly(monkeypatch):
    import signal

    import umi.translation_reference_worker as worker

    entered, draining, released = asyncio.Event(), asyncio.Event(), asyncio.Event()
    callbacks, removed = {}, []
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(
        loop, "add_signal_handler", lambda sig, callback: callbacks.update({sig: callback})
    )
    monkeypatch.setattr(loop, "remove_signal_handler", removed.append)

    async def driver(*_, **__):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            draining.set()
            await released.wait()

    monkeypatch.setattr(worker, "run_translation_worker", driver)
    service = asyncio.create_task(worker.run_translation_service(object()))
    await entered.wait()
    callbacks[signal.SIGTERM]()
    await draining.wait()
    callbacks[signal.SIGTERM]()
    await asyncio.sleep(0)
    assert not service.done()
    released.set()
    await service
    assert removed == [signal.SIGTERM]


@pytest.mark.asyncio
@pytest.mark.parametrize("lost_reply", [False, True])
@pytest.mark.parametrize("retry_reason", [None, "proof_rpc_rate_limited", "worker_finality_stale"])
async def test_fixed_session_keeps_original_lock_and_signed_bytes_across_restart(
    execution_case, monkeypatch, tmp_path, lost_reply, retry_reason
):
    import umi.translation_reference_worker as worker

    case = execution_case
    root = tmp_path / "installed-original-state"
    case.updates[54] = 0
    case.set_value("LastUpdate", case.updates)
    http, _ = signed_http(case.policy, monkeypatch)
    env = replace(
        _environment(
            case.obs.validator_hotkey,
            policy_sha256=reference_policy_sha256(case.policy),
            release_manifest_sha256="a" * 64,
        ),
        mode="translation_weights",
        valid_from_block=case.head.number - 1,
        valid_through_block=case.head.number + 1000,
    )
    completed = asyncio.Event()
    calls, progress, wallets = [], [], []
    original_journal = worker.ReferenceWeightJournal
    failed_once = False
    original_sleep = asyncio.sleep

    async def retry_clock(delay, *args, **kwargs):
        # Advance only this test's twelve-second scheduler pause. Native proof
        # and transaction ownership still run through the real fixed driver.
        return await original_sleep(0 if delay == 12 else delay, *args, **kwargs)

    if retry_reason:
        monkeypatch.setattr(worker.asyncio, "sleep", retry_clock)

    def journal_factory(*args, **kwargs):
        journal = original_journal(*args, **kwargs)
        case.journal = journal
        return journal

    monkeypatch.setattr(worker, "ReferenceWeightJournal", journal_factory)

    class Client:
        def __init__(self, network):
            assert network == "finney"
            self._substrate = self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def submit_signed(self, exact, signer, **options):
            assert options == {"wait_for_inclusion": True, "wait_for_finalization": True}
            assert case.journal.pending().signed.encoded == exact.data.hex()
            calls.append(exact.data)
            with pytest.raises(BlockingIOError), ReferenceLegacyState(root):
                pytest.fail("released original owner before submission drained")
            case.ports.no_receipt = True
            await case.ports.submit(exact.data, signer, 60)
            if lost_reply:
                raise TimeoutError("private endpoint diagnostic")

    def readers(**_):
        async def state(*_):
            nonlocal failed_once
            if retry_reason and not failed_once:
                from umi.validator_chain import ValidatorChainError
                from umi.validator_supervisor_worker import SupervisorWorkerError

                failed_once = True
                assert not wallets and not calls
                error = (
                    ValidatorChainError
                    if retry_reason == "proof_rpc_rate_limited"
                    else SupervisorWorkerError
                )
                raise error(retry_reason)
            return await read(case)

        async def signing(*_):
            return (await read(case)).signing

        return (
            SimpleNamespace(read=state),
            SimpleNamespace(read=signing),
            SimpleNamespace(find=case.ports.receipt),
            "a" * 64,
        )

    def wallet_loader(_):
        assert case.journal.pending() is not None
        wallets.append(True)
        return case.wallet

    def emit(event):
        progress.append(event)
        if event["stage"] == "reference_iteration":
            completed.set()

    async def one_session():
        reader = _FinalityReader(OwnedFinalizedBlock(case.head.number, case.head.block_hash))
        lease = OwnedFinalityLease(
            reader,
            valid_from_block=env.valid_from_block,
            valid_through_block=env.valid_through_block,
        )
        task = asyncio.create_task(
            worker.run_translation_worker(
                env,
                state_root=root,
                lease=lease,
                finality_reader=reader,
                wallet_loader=wallet_loader,
                http=http,
                client_factory=Client,
                readers_factory=readers,
                progress=emit,
                clock=lambda: case.now,
            )
        )
        waiter = asyncio.create_task(completed.wait())
        done, _ = await asyncio.wait(
            (task, waiter), timeout=10, return_when=asyncio.FIRST_COMPLETED
        )
        try:
            assert done
            if task in done:
                task.result()
        finally:
            task.cancel()
            waiter.cancel()
            await asyncio.gather(task, waiter, return_exceptions=True)
        assert reader.stopped

    await one_session()
    pending = case.journal.pending()
    assert pending.signed is not None and len(calls) == len(wallets) == 1
    lock = (root / "service.lock").stat().st_ino
    completed.clear()
    await one_session()
    assert case.journal.pending() == pending
    assert len(calls) == len(wallets) == 1  # Retained unknown attempt never retransmits.
    assert (root / "service.lock").stat().st_ino == lock
    if retry_reason:
        retries = [event for event in progress if event["stage"] == "reference_native_retry"]
        assert len(retries) == 1 and retries[0]["reason_code"] == retry_reason
    assert "private endpoint diagnostic" not in str(progress)
    assert all("elapsed_seconds" in e and "eta_basis" in e for e in progress)
