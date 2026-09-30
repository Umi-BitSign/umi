"""Retained native replay through synthetic finalized-header, Wasm and trie ports."""

import asyncio
import hashlib
import json
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_control_archive import HistoricalRewardControlProvider
from umi.competition_reward_eligibility import (
    validate_reward_eligibility,
)
from umi.competition_reward_eligibility_archive import (
    review_reward_eligibility,
    validate_historical_reward_eligibility,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_chain import ValidatorChainError

from . import test_open_competition as competition_tests
from .test_competition_historical_registration import change_block
from .test_competition_model_burn import burn_policy
from .test_competition_reward_control import commitment
from .test_competition_reward_eligibility import chain as chain
from .test_competition_reward_eligibility import chain_config as chain_config
from .test_competition_reward_eligibility import eligibility_case as eligibility_case
from .test_competition_reward_eligibility import registered_case as registered_case

base_policy = competition_tests.policy


@pytest.fixture
def policy(base_policy):
    return burn_policy(base_policy, owner="Burn")


@pytest.fixture
async def retained(eligibility_case, tmp_path, monkeypatch, request):
    t = eligibility_case
    runtime_proofs = t.provider._runtime_proofs
    await t.provider.aclose()
    providers = []

    def reopen():
        p = HistoricalRewardControlProvider(
            t.config,
            t.policy,
            finality=t.finality,
            proofs=t.proofs,
            now_ms=lambda: t.clock.now,
            historical_header_directory=tmp_path / "headers",
        )
        p._runtime_proofs = runtime_proofs
        providers.append(p)
        return p

    original_at = t.finality.verified_block_at
    blocks = {}

    async def finalize(height):
        header = change_block(t, height)
        old = await original_at(height)
        raw = canonical_json_bytes(
            {**json.loads(old.finality_evidence), "block": {"scale_header": header}}
        )
        value = replace(
            old, finality_evidence=raw, finality_evidence_sha256=hashlib.sha256(raw).hexdigest()
        )
        blocks[height] = value
        return value

    async def at(height):
        return blocks.get(height)

    old = await finalize(t.finality.ref.block_number)
    monkeypatch.setattr(t.finality, "verified_block_at", at)
    t.rpc.values[("Commitments", "CommitmentOf", (78, t.hotkey))] = commitment(
        "ab" * 32, old.height - 1
    )
    t.provider = reopen()
    control = await t.provider.collect_control(t.hotkey)
    current = await t.capture()
    raw_values = {
        canonical_json_bytes([pallet, item, params]): None
        if value is None
        else json.dumps(value).encode()
        for (pallet, item, params), value in t.rpc.values.items()
    }
    checked = []

    def verify_many(**kw):
        checked.append(kw)
        return (
            kw["state_root"] == bytes.fromhex(old.state_root[2:])
            and kw["proof"] == (b"proof",)
            and all(raw_values.get(k) == v for k, v in kw["items"])
        )

    monkeypatch.setattr(t.verifier, "verify_many", verify_many)
    for claim in json.loads(control.evidence)["claims"]:
        key = bytes.fromhex(claim["key"][2:])
        value = None if claim["value"] is None else bytes.fromhex(claim["value"][2:])
        assert raw_values[key] == value
    archive = tmp_path / "retained"
    archive.mkdir()
    for name, raw in (
        ("control", control.evidence),
        ("chain", current.chain.evidence),
        ("eligibility", current.evidence),
        ("metadata", current.chain.runtime.metadata_bytes),
    ):
        (archive / name).write_bytes(raw)
    before = {p.name: p.read_bytes() for p in archive.iterdir()}
    await t.provider.aclose()
    t.clock.now += getattr(request, "param", 10 * 60 * 60 * 1000)
    fresh = await finalize(old.height + 3000)
    calls = []
    original_request = t.rpc.request

    async def current_only(method, params):
        calls.append(method)
        if method == "chain_getBlockHash":
            assert tuple(params) == (fresh.height,), "old header RPC unavailable"
        else:
            assert params[-1] == fresh.block_hash, "old state RPC unavailable"
        assert method in {"chain_getHeader", "chain_getBlockHash"}, "state RPC is disabled"
        return await original_request(method, params)

    monkeypatch.setattr(t.rpc, "request", current_only)
    t.provider = reopen()
    h = SimpleNamespace(
        t=t,
        archive=archive,
        before=before,
        old=old,
        current=current,
        checked=checked,
        calls=calls,
        reopen=reopen,
    )

    async def review(**changes):
        options = dict(
            provider=t.provider,
            **{p.name: p.read_bytes() for p in archive.iterdir()},
            validator_hotkey=t.hotkey,
            control_hotkey=t.hotkey,
            profile=t.profile,
            expected_runtime_profile_sha256=digest(t.profile),
        )
        options.update(changes)
        return await review_reward_eligibility(**options)

    h.review = review
    try:
        yield h
    finally:
        for provider in reversed(providers):
            await provider.aclose()


@pytest.mark.parametrize("retained", [10 * 60 * 60 * 1000, 30 * 86400 * 1000], indirect=True)
async def test_replay_survives_outage_restart_and_missing_historical_rpc(retained):
    h = retained
    result = await h.review()
    validate_historical_reward_eligibility(
        result,
        expected_control_hotkey=h.t.hotkey,
        expected_chain_config_sha256=digest(h.t.config),
        expected_runtime_profile_sha256=digest(h.t.profile),
        expected_policy_sha256=digest(h.t.policy),
    )
    assert result.eligible == h.current.eligible
    assert result.timestamp_ms == h.current.chain.timestamp_ms
    assert result.subject.registrations == h.current.chain.registrations
    assert result.subject.validator_row == h.current.chain.validator_row
    assert result.subject.block == h.old.height
    assert result.policy_sha256 == digest(h.t.policy)
    assert result.burn_destination == h.current.chain.burn_destination
    assert result.burn_destination is not None
    assert not result.chain_submission_authorized
    with pytest.raises(ValueError):
        validate_reward_eligibility(
            result,
            expected_chain_config_sha256=digest(h.t.config),
            expected_runtime_profile_sha256=digest(h.t.profile),
        )
    assert set(h.calls) <= {"chain_getHeader", "chain_getBlockHash"}
    assert h.checked
    assert {p.name: p.read_bytes() for p in h.archive.iterdir()} == h.before


@pytest.mark.parametrize(
    "change",
    [
        "eligibility_proof",
        "eligibility_value",
        "eligibility_root",
        "eligibility_context",
        "eligibility_batch_missing",
        "eligibility_batch_reordered",
        "eligibility_duplicate",
        "eligibility_unused",
        "weight_proof",
        "weight_value",
        "weight_runtime",
        "partial_registry",
        "control_proof",
        "metadata",
        "profile",
        "validator",
    ],
)
async def test_altered_or_incomplete_archives_are_rejected_without_repair(retained, change):
    h = retained
    options = {}
    target = (
        "eligibility"
        if change.startswith("eligibility")
        else "chain"
        if change.startswith("weight") or change == "partial_registry"
        else "control"
    )
    body = (
        json.loads(h.before[target]) if change not in {"metadata", "profile", "validator"} else None
    )
    if change == "eligibility_proof" or change == "weight_proof":
        body["storage_batches"][0]["proof"] = ["0x0001"]
    elif change == "eligibility_value" or change == "weight_value":
        body["storage_batches"][0]["claims"][0]["value"] = "0x0001"
    elif change == "eligibility_root":
        body["storage_batches"][0]["state_root"] = "0x" + "ff" * 32
    elif change == "eligibility_context":
        body["chain_evidence_sha256"] = "ff" * 32
    elif change == "eligibility_batch_missing":
        body["storage_batches"].pop()
    elif change == "eligibility_batch_reordered":
        body["storage_batches"][0]["claims"].reverse()
    elif change == "eligibility_duplicate":
        body["storage_batches"].append(body["storage_batches"][0])
    elif change == "eligibility_unused":
        body["storage_batches"].append(
            {
                "state_root": h.old.state_root,
                "claims": [{"key": "0xabcd", "value": None}],
                "proof": ["0x" + b"proof".hex()],
            }
        )
    elif change == "weight_runtime":
        body["runtime_execution"]["proof"] = ["0x0001"]
    elif change == "partial_registry":
        body.pop("registrations_complete")
    elif change == "control_proof":
        body["proof"] = ["0x0001"]
    elif change == "metadata":
        options["metadata"] = b"altered"
    elif change == "profile":
        options["profile"] = h.t.profile.model_copy(update={"runtime_code_sha256": "ff" * 32})
        options["expected_runtime_profile_sha256"] = digest(options["profile"])
    elif change == "validator":
        options["validator_hotkey"] = h.t.members[1]
    if body is not None:
        options[target] = canonical_json_bytes(body)
        if target == "chain":
            eligibility = json.loads(h.before["eligibility"])
            eligibility["chain_evidence_sha256"] = hashlib.sha256(options[target]).hexdigest()
            options["eligibility"] = canonical_json_bytes(eligibility)
    with pytest.raises((ValueError, ValidatorChainError)):
        await h.review(**options)
    assert (await h.review()).eligible
    assert {p.name: p.read_bytes() for p in h.archive.iterdir()} == h.before


async def test_returned_history_cannot_be_mutated_or_rebound(retained):
    h = retained
    original = await h.review()
    for altered in (
        replace(original, reason="inactive"),
        replace(original, policy_sha256="ef" * 32),
        replace(original, burn_destination=None),
        replace(original, timestamp_ms=1),
        replace(original, chain_evidence=b"{}"),
        replace(original, eligibility_evidence=b"{}"),
        replace(original, _issuer=None),
        replace(original, chain_submission_authorized=True),
        replace(original, subject=replace(original.subject, validator_row=((0, 65535),))),
    ):
        with pytest.raises(ValueError):
            validate_historical_reward_eligibility(
                altered,
                expected_control_hotkey=h.t.hotkey,
                expected_chain_config_sha256=digest(h.t.config),
                expected_runtime_profile_sha256=digest(h.t.profile),
                expected_policy_sha256=digest(h.t.policy),
            )


async def test_historical_burn_state_is_required_and_policy_cannot_drift(retained):
    h = retained
    chain = json.loads(h.before["chain"])
    for batch in chain["storage_batches"]:
        batch["claims"] = [
            claim
            for claim in batch["claims"]
            if json.loads(bytes.fromhex(claim["key"][2:]))[1] != "RecycleOrBurn"
        ]
    with pytest.raises(ValueError, match="burn state"):
        await h.review(chain=canonical_json_bytes(chain))
    h.t.provider.policy = h.t.policy.model_copy(update={"unallocated_model_burn": None})
    with pytest.raises(ValueError, match="selected native inputs"):
        await h.review()


async def test_native_replay_cancellation_drains_before_close(retained, monkeypatch):
    h = retained
    entered, release = threading.Event(), threading.Event()
    original = h.t.verifier.verify_many

    def blocked(**kwargs):
        entered.set()
        assert release.wait(10)
        return original(**kwargs)

    monkeypatch.setattr(h.t.verifier, "verify_many", blocked)
    task = asyncio.create_task(h.review())
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        closing = asyncio.create_task(h.t.provider.aclose())
        await asyncio.sleep(0.02)
        assert not task.done() and not closing.done() and h.t.provider._lock.locked()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await closing
    monkeypatch.setattr(h.t.verifier, "verify_many", original)
    h.t.provider = h.reopen()
    assert (await h.review()).eligible
