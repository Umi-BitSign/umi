from __future__ import annotations

import asyncio
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
from bittensor import Wallet

import umi.registration_bridge as bridge
from tests.factories import dev_wallet
from tests.test_registration_bridge import (
    BLOCK,
    LIVE,
    NOW,
    NOW_MS,
    REVISION,
    decision,
    observation,
    policy_body,
    replace_participant,
)
from umi.protocol import canonical_json_bytes


@pytest.fixture
def signed_policy(monkeypatch):
    wallet = dev_wallet("//RegistrationBridgeAuthority")
    monkeypatch.setattr(bridge, "REGISTRATION_BRIDGE_COORDINATOR", wallet.hotkey.ss58_address)
    return bridge.sign_registration_bridge_policy(
        policy_body(coordinator_hotkey=wallet.hotkey.ss58_address), wallet=wallet
    )


@pytest.fixture
def wallet():
    class HotkeyOnly(Wallet):
        # Exercise the SDK's concrete-wallet route. Python 3.10 protocol
        # isinstance checks invoke properties on structural test doubles.
        hotkey = dev_wallet("//RegistrationBridgeValidator").hotkey
        hotkeypub = hotkey

        def __init__(self):
            pass  # No filesystem wallet is created by this in-memory double.

        @property
        def coldkey(self):
            raise AssertionError("bridge must never read coldkey")

        @property
        def coldkeypub(self):
            raise AssertionError("bridge must never read coldkeypub")

    return HotkeyOnly()


def writer_observation(wallet, **changes):
    obs = observation(**changes)
    participants = list(obs.participants)
    participants[54] = participants[54].model_copy(update={"hotkey": wallet.hotkey.ss58_address})
    return bridge.RegistrationBridgeObservation.model_validate(
        obs.model_copy(
            update={
                "participants": participants,
                "validator_hotkey": wallet.hotkey.ss58_address,
            }
        ).model_dump(mode="python")
    )


def applied_observation(wallet, policy, *, block=BLOCK + 1):
    obs = writer_observation(wallet, block_number=block, block_hash="0x" + "22" * 32)
    obs = obs.model_copy(update={"validator_row": decision(policy, obs).expected_row})
    return replace_participant(obs, 54, last_update=block)


class Client:
    def __init__(self, state, *, error=None):
        self.state, self.error, self.calls = state, error, []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def submit_call(self, call, wallet, **kwargs):
        durable = self.state.load()
        assert durable.phase == "submitting"
        assert durable.attempt.expected_row == [
            [uid, weight] for uid, weight in enumerate(call.params["weights"])
        ]
        assert (
            self.state.root
            / "registration-bridge-history"
            / f"{durable.attempt.attempt_id}-submitting.json"
        ).is_file()
        assert kwargs == {
            "signer": "hotkey",
            "period": 8,
            "wait_for_inclusion": True,
            "wait_for_finalization": True,
        }
        self.calls.append(call)
        if self.error:
            raise self.error
        return SimpleNamespace(
            success=True, extrinsic_id=f"{BLOCK + 1}-0002", block_hash="0x" + "22" * 32
        )


class Chain:
    def __init__(self, state, observations, *, error=None, hook=None):
        self.client = Client(state, error=error)
        self.observations = iter(observations)
        self.hook, self.reads, self.receipts = hook, 0, []
        self.now = NOW

    def clock(self):
        return self.now

    def client_factory(self, network):
        assert network == "finney"
        return self.client

    async def observation_with_client(self, client, *, validator_hotkey):
        self.reads += 1
        if self.hook:
            self.hook(self.reads)
        result = next(self.observations)
        if isinstance(result, BaseException):
            raise result
        assert result.validator_hotkey == validator_hotkey
        return result

    async def verify_finalized_receipt_with_client(self, client, receipt, *, observation):
        self.receipts.append(receipt)
        assert observation.block_number >= receipt.block_number


async def healthy(origin):
    return b'{"ok":false}'  # Deliberately HTTP200 reachability, not JSON/model health.


def run(policy, wallet, chain, state, request=healthy, **kwargs):
    return asyncio.run(
        bridge.run_registration_bridge_iteration(
            policy,
            wallet=wallet,
            chain=chain,
            state=state,
            expected_revision=REVISION,
            directive_valid_from=policy.body.valid_from_block,
            directive_valid_through=policy.body.hard_sunset_block - 1,
            request=request,
            **kwargs,
        )
    )


@pytest.mark.parametrize("runtime_after_probe", [455, 458, 459, 1000])
def test_exact_real_sdk_call_intent_before_submit_and_retained_final_receipt(
    tmp_path, signed_policy, wallet, runtime_after_probe
):
    before = writer_observation(wallet)
    refreshed = before.model_copy(update={"runtime_spec_version": runtime_after_probe})
    after = applied_observation(wallet, signed_policy).model_copy(
        update={"runtime_spec_version": runtime_after_probe}
    )
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        chain = Chain(state, [before, refreshed, after])
        result = run(signed_policy, wallet, chain, state)
        assert result["status"] == "submitted" and result["eligible_count"] == len(LIVE)
        assert len(chain.client.calls) == 1 and len(chain.receipts) == 1
        journal = state.load()
        assert journal.phase == "applied" and journal.weight_call.block_number == BLOCK + 1
        phases = {
            path.name.rsplit("-", 1)[1]
            for path in (state.root / "registration-bridge-history").iterdir()
        }
        assert phases == {"submitting.json", "receipt_returned.json", "applied.json"}
        assert not (state.root / "journal.json").exists()


def test_runtime_upgrade_with_changed_chain_settings_holds_before_send(
    tmp_path, signed_policy, wallet
):
    before = writer_observation(wallet)
    refreshed = before.model_copy(
        update={"runtime_spec_version": 1000, "commit_reveal_enabled": True}
    )
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        chain = Chain(state, [before, refreshed])
        with pytest.raises(bridge.RegistrationBridgeError, match="commit_reveal_enabled_changed"):
            run(signed_policy, wallet, chain, state)
        assert not chain.client.calls
        assert state.load().phase == "idle"


@pytest.mark.parametrize(
    "failure", [TimeoutError(), RuntimeError("RPC disconnected"), asyncio.CancelledError()]
)
def test_unknown_never_retries_even_if_another_writer_lands_equal_row(
    tmp_path, signed_policy, wallet, failure
):
    before = writer_observation(wallet)
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before, before], error=failure)
        with pytest.raises(type(failure)):
            run(signed_policy, wallet, chain, state)
        assert state.load().phase == "outcome_unknown"
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [applied_observation(wallet, signed_policy)])
        with pytest.raises(
            bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"
        ):
            run(signed_policy, wallet, chain, state)
        assert not chain.client.calls


def test_returned_receipt_survives_post_submit_rpc_failure_and_recovers_without_send(
    tmp_path, signed_policy, wallet
):
    before = writer_observation(wallet)
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before, before, TimeoutError("post-submit RPC")])
        with pytest.raises(TimeoutError):
            run(signed_policy, wallet, chain, state)
        assert state.load().phase == "receipt_returned"
        assert state.load().weight_call.block_number == BLOCK + 1
    with bridge.RegistrationBridgeState(root) as state:
        after = applied_observation(wallet, signed_policy)
        chain = Chain(state, [after, after])
        assert run(signed_policy, wallet, chain, state)["status"] == "wait"
        assert state.load().phase == "applied"
        assert len(chain.receipts) == 1 and not chain.client.calls


@pytest.mark.parametrize(
    "change", ["hotkey", "coldkey", "origin", "permit", "registration", "owner"]
)
def test_changed_roster_after_probe_holds_without_any_send(tmp_path, signed_policy, wallet, change):
    before = writer_observation(wallet)
    changes = {
        "hotkey": {"hotkey": dev_wallet("//ReplacementMiner").hotkey.ss58_address},
        "coldkey": {"coldkey": dev_wallet("//ReplacementOwner").hotkey.ss58_address},
        "origin": {"origin": "https://9.9.9.9:9000"},
        "permit": {"validator_permit": True},
        "registration": {"registered_at_block": BLOCK - 1},
    }
    after = (
        before.model_copy(
            update={
                "owner_associated_hotkeys": sorted(
                    [before.subnet_owner_hotkey, before.participants[6].hotkey],
                    key=bridge.account_id32,
                )
            }
        )
        if change == "owner"
        else replace_participant(before, 6, **changes[change])
    )
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        chain = Chain(state, [before, after])
        with pytest.raises(
            bridge.RegistrationBridgeError, match="roster_changed_during_health_checks"
        ):
            run(signed_policy, wallet, chain, state)
        assert not chain.client.calls and state.load().phase == "idle"


@pytest.mark.parametrize("mutation", ["delete", "replace", "rootmode", "lockmode", "archive"])
@pytest.mark.parametrize("phase", ["probe", "finalized"])
def test_state_mutation_across_await_is_preserved_and_never_overwritten(
    tmp_path, signed_policy, wallet, mutation, phase
):
    before = writer_observation(wallet)
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        changed = False

        def mutate():
            nonlocal changed
            if changed:
                return
            changed = True
            if mutation == "delete":
                state.path.unlink()
            elif mutation == "replace":
                state.path.write_bytes(b'{"changed":true}')
            elif mutation == "rootmode":
                state.root.chmod(0o750)
            elif mutation == "lockmode":
                (state.root / "service.lock").chmod(0o644)
            else:
                bridge._write_new(
                    state.root / "registration-bridge-legacy-journal.json", b'{"unexpected":true}'
                )

        async def requester(origin):
            if phase == "probe":
                mutate()
            return b"ok"

        chain = Chain(
            state,
            [before, before],
            hook=lambda count: mutate() if count == 2 and phase == "finalized" else None,
        )
        with pytest.raises(bridge.RegistrationBridgeError):
            run(signed_policy, wallet, chain, state, request=requester)
        assert not chain.client.calls
        if mutation == "delete":
            assert not state.path.exists()
        if mutation == "replace":
            assert state.path.read_bytes() == b'{"changed":true}'


@pytest.mark.parametrize("rollback", ["idle", "submitting", "missing", "receipt"])
def test_restart_rejects_current_rollback_against_retained_history(
    tmp_path, signed_policy, wallet, rollback
):
    before = writer_observation(wallet)
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        idle = state.initialize(before, now=NOW)
        chain = Chain(state, [before, before, applied_observation(wallet, signed_policy)])
        run(signed_policy, wallet, chain, state)
        history = list((root / "registration-bridge-history").iterdir())
    path = root / "registration-bridge-journal.json"
    if rollback == "missing":
        path.unlink()
    elif rollback == "idle":
        path.write_bytes(canonical_json_bytes(idle))
    else:
        phase = "receipt_returned" if rollback == "receipt" else "submitting"
        path.write_bytes(
            next(item for item in history if item.name.endswith(f"-{phase}.json")).read_bytes()
        )
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [applied_observation(wallet, signed_policy)])
        with pytest.raises(bridge.RegistrationBridgeError):
            run(signed_policy, wallet, chain, state)
        assert not chain.client.calls


def test_same_lock_blocks_other_worker_and_does_not_truncate_lock(tmp_path):
    root = tmp_path.resolve() / "state"
    root.mkdir(mode=0o700)
    bridge._write_new(root / "service.lock", b"retained lock bytes")
    with (
        bridge.RegistrationBridgeState(root),
        pytest.raises(BlockingIOError),
        bridge.RegistrationBridgeState(root),
    ):
        pytest.fail("second worker acquired lock")
    assert (root / "service.lock").read_bytes() == b"retained lock bytes"


@pytest.mark.parametrize("age,kind", [(61, "head"), (61, "health")])
def test_submission_reserves_sdk_timeout_inside_original_freshness(
    tmp_path, signed_policy, wallet, age, kind
):
    before = writer_observation(wallet)
    after = (
        before.model_copy(update={"block_timestamp_ms": NOW_MS - age * 1000})
        if kind == "head"
        else before
    )
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        chain = Chain(state, [before, after])
        if kind == "health":
            chain.hook = lambda count: (
                setattr(chain, "now", NOW + timedelta(seconds=age)) if count == 2 else None
            )
        with pytest.raises(
            bridge.RegistrationBridgeError, match=r"submission_.*_headroom_insufficient"
        ):
            run(signed_policy, wallet, chain, state)
        assert not chain.client.calls


def test_endpoint_failure_excludes_only_that_uid_and_zero_success_holds(signed_policy, wallet):
    before = writer_observation(wallet)

    async def one_failure(origin):
        if origin.endswith(":8006"):
            raise httpx.ConnectError("offline")
        return b"ok"

    receipts = asyncio.run(
        bridge.probe_registration_bridge_health(before, clock=lambda: NOW, request=one_failure)
    )
    result = decision(signed_policy, before, receipts)
    assert result.eligible_count == 15 and result.expected_row[6] == [6, 0]

    async def all_failed(origin):
        raise httpx.ConnectError("offline")

    receipts = asyncio.run(
        bridge.probe_registration_bridge_health(before, clock=lambda: NOW, request=all_failed)
    )
    with pytest.raises(bridge.RegistrationBridgeError, match="no_live_eligible_miners"):
        decision(signed_policy, before, receipts)


def test_batch_cancellation_produces_no_partial_result(wallet):
    async def scenario():
        async def hang(origin):
            await asyncio.Event().wait()

        task = asyncio.create_task(
            bridge.probe_registration_bridge_health(
                writer_observation(wallet), clock=lambda: NOW, request=hang
            )
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())


def test_directive_expiry_and_invalid_interval_never_send(tmp_path, signed_policy, wallet):
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        chain = Chain(state, [writer_observation(wallet)])
        result = asyncio.run(
            bridge.run_registration_bridge_iteration(
                signed_policy,
                wallet=wallet,
                chain=chain,
                state=state,
                expected_revision=REVISION,
                directive_valid_from=BLOCK - 100,
                directive_valid_through=BLOCK + 63,
                request=healthy,
            )
        )
        assert result["status"] == "retiring" and not chain.client.calls
    with pytest.raises(bridge.RegistrationBridgeError, match="supervisor_interval_mismatch"):
        bridge._validate_directive_interval(signed_policy, BLOCK, 0)


def test_unattributed_existing_row_without_legacy_journal_is_not_fresh_install(
    tmp_path, signed_policy, wallet
):
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        chain = Chain(state, [applied_observation(wallet, signed_policy)])
        with pytest.raises(
            bridge.RegistrationBridgeError, match="legacy_journal_missing_for_existing_writer"
        ):
            run(signed_policy, wallet, chain, state)
        assert not chain.client.calls


def old_applied(wallet, *, phase="applied"):
    from umi.simple_bootstrap_validator import SIMPLE_BOOTSTRAP_JOURNAL_SCHEMA

    return bridge.SimpleBootstrapJournal(
        schema=SIMPLE_BOOTSTRAP_JOURNAL_SCHEMA,
        phase=phase,
        lease_sha256="33" * 32,
        manifest_sha256=bridge.SIMPLE_BOOTSTRAP_MANIFEST_SHA256,
        validator_hotkey=wallet.hotkey.ss58_address,
        attempt_id="44" * 32,
        preflight_block=BLOCK - 600,
        prior_last_update=BLOCK - 1000,
        manifest_anchor_block=BLOCK - 700,
        weight_call=bridge.BootstrapExtrinsicReference(
            extrinsic_id=f"{BLOCK - 500}-0002",
            block_number=BLOCK - 500,
            extrinsic_index=2,
            block_hash="0x" + "55" * 32,
        )
        if phase == "applied"
        else None,
        observation_block=BLOCK - 499 if phase in {"applied", "recovered_applied"} else None,
        updated_at=NOW,
    )


def legacy_observation(wallet):
    return writer_observation(
        wallet, validator_row=[[uid, 65535 if uid in {6, 247} else 0] for uid in range(256)]
    )


def test_actual_known_legacy_receipt_handoff_preserves_old_bytes(tmp_path, signed_policy, wallet):
    root = tmp_path.resolve() / "state"
    root.mkdir(mode=0o700)
    raw = canonical_json_bytes(old_applied(wallet))
    bridge._write_new(root / "journal.json", raw)
    before = legacy_observation(wallet)
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [before, before, applied_observation(wallet, signed_policy)])
        assert run(signed_policy, wallet, chain, state)["status"] == "submitted"
        assert (root / "journal.json").read_bytes() == raw
        assert (root / "registration-bridge-legacy-journal.json").read_bytes() == raw
    with bridge.RegistrationBridgeState(root) as state:
        after = applied_observation(wallet, signed_policy)
        assert run(signed_policy, wallet, Chain(state, [after, after]), state)["status"] == "wait"
        assert (root / "journal.json").read_bytes() == raw


@pytest.mark.parametrize("phase", ["submitting", "outcome_unknown", "recovered_applied"])
def test_legacy_without_exact_known_terminal_receipt_holds(tmp_path, signed_policy, wallet, phase):
    root = tmp_path.resolve() / "state"
    root.mkdir(mode=0o700)
    raw = canonical_json_bytes(old_applied(wallet, phase=phase))
    bridge._write_new(root / "journal.json", raw)
    with bridge.RegistrationBridgeState(root) as state:
        chain = Chain(state, [legacy_observation(wallet)])
        with pytest.raises(
            bridge.RegistrationBridgeError, match="legacy_attempt_not_proven_terminal"
        ):
            run(signed_policy, wallet, chain, state)
        assert not chain.client.calls and (root / "journal.json").read_bytes() == raw


def test_changed_legacy_during_probe_is_held_and_never_overwritten(tmp_path, signed_policy, wallet):
    root = tmp_path.resolve() / "state"
    root.mkdir(mode=0o700)
    raw = canonical_json_bytes(old_applied(wallet))
    bridge._write_new(root / "journal.json", raw)
    before = legacy_observation(wallet)
    with bridge.RegistrationBridgeState(root) as state:

        async def changed(origin):
            (root / "journal.json").write_bytes(b'{"changed":true}')
            return b"ok"

        chain = Chain(state, [before, before])
        with pytest.raises(bridge.RegistrationBridgeError, match="retained_state_changed"):
            run(signed_policy, wallet, chain, state, request=changed)
        assert not chain.client.calls
        assert (root / "journal.json").read_bytes() == b'{"changed":true}'
        assert (root / "registration-bridge-legacy-journal.json").read_bytes() == raw


def test_installed_console_entrypoint_supports_wallet_free_help(monkeypatch, capsys):
    import importlib
    import sys
    from pathlib import Path

    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib

    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    module, name = project["project"]["scripts"]["umi-registration-bridge"].split(":")
    entrypoint = getattr(importlib.import_module(module), name)
    monkeypatch.setattr(sys, "argv", ["umi-registration-bridge", "--help"])
    with pytest.raises(SystemExit) as result:
        entrypoint()
    assert result.value.code == 0
    assert "check" in capsys.readouterr().out
