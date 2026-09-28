"""Native nonce collection/archive consumers with synthetic trie/chain ports."""

import json
from dataclasses import replace

import pytest

from umi.competition_reward_control_signing import (
    collect_control_signing_state,
    review_control_signing_state,
    validate_control_signing_state,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_control_archive import historical as historical
from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case


async def test_nonce_and_control_share_exact_proven_root(control):
    c = control
    c.rpc.values[("System", "Account", (c.hotkey,))] = {"nonce": 64}
    state = await collect_control_signing_state(c.provider, c.hotkey)
    assert state.nonce == 64 and state.control.snapshot == state.runtime.snapshot
    record = json.loads(state.nonce_evidence)
    assert record["control_evidence_sha256"] == state.control.evidence_sha256
    assert not any(method.startswith("author_") for method, _ in c.rpc.calls)
    for changed in (replace(state, nonce=65), replace(state, _issuer=None)):
        with pytest.raises(ValueError, match="provenance"):
            validate_control_signing_state(changed, hotkey=c.hotkey, config_sha256=digest(c.config))


@pytest.mark.parametrize("account", [None, {}, {"nonce": True}, {"nonce": -1}, {"nonce": 2**32}])
async def test_unproved_or_invalid_nonce_never_authorizes_signing(control, account):
    c = control
    c.rpc.values[("System", "Account", (c.hotkey,))] = account
    with pytest.raises(ValueError):
        await collect_control_signing_state(c.provider, c.hotkey)


async def test_nonce_read_cannot_age_out_finality(control, monkeypatch):
    c = control
    c.rpc.values[("System", "Account", (c.hotkey,))] = {"nonce": 3}
    read = c.provider._weight_read

    async def slow(runtime, specs):
        result = await read(runtime, specs)
        if specs[0].pallet == "System":
            c.finality.advance_after_reads = 1_000_000
        return result

    monkeypatch.setattr(c.provider, "_weight_read", slow)
    with pytest.raises(ValueError, match="became stale"):
        await collect_control_signing_state(c.provider, c.hotkey)


async def test_original_nonce_replays_after_outage_without_historical_state_rpc(historical):
    h, c = historical, historical.item
    c.rpc.values[("System", "Account", (c.hotkey,))] = {"nonce": 3}
    state = await collect_control_signing_state(c.provider, c.hotkey)
    h.advance(1_000_000)
    c.rpc.values[("System", "Account", (c.hotkey,))] = {"nonce": 999}
    await c.provider.aclose()
    c.provider = h.reopen()
    before = len(c.rpc.calls)
    replay = await review_control_signing_state(
        c.provider,
        hotkey=c.hotkey,
        control_evidence=state.control.evidence,
        nonce_evidence=state.nonce_evidence,
        metadata=state.runtime.metadata_bytes,
    )
    assert replay.nonce == 3 and replay.control.snapshot == state.control.snapshot
    assert {method for method, _ in c.rpc.calls[before:]} <= {
        "chain_getHeader",
        "chain_getBlockHash",
    }
    with pytest.raises(ValueError):
        validate_control_signing_state(replay, hotkey=c.hotkey, config_sha256=digest(c.config))
    for field, value in (
        ("control_evidence_sha256", "ff" * 32),
        ("key", "0x00"),
        ("proof", ["0x00"]),
    ):
        mutated = canonical_json_bytes(json.loads(state.nonce_evidence) | {field: value})
        with pytest.raises((ValueError, RuntimeError)):
            await review_control_signing_state(
                c.provider,
                hotkey=c.hotkey,
                control_evidence=state.control.evidence,
                nonce_evidence=mutated,
                metadata=state.runtime.metadata_bytes,
            )
