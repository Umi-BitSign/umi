from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import time
from dataclasses import replace
from fractions import Fraction
from types import SimpleNamespace

import pytest

from umi.competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    validate_owned_weight_observation,
)
from umi.competition_package import load_competition_package
from umi.competition_weights import (
    BittensorCompetitionWeightTransport,
    CompetitionWeightAuthorizationBody,
    CompetitionWeightWorker,
    build_competition_weight_call,
    competition_weight_authorization_digest,
    sign_competition_weight_authorization,
    verify_competition_weight_authorization,
)
from umi.competition_worker import CompetitionReplayWorker
from umi.open_competition import Registration, digest
from umi.protocol import canonical_json_bytes
from umi.validator_chain import ValidatorChainError

from .test_competition_chain import _hash, _Runtime
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_worker import _record_cutoff_conflict
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def stopped_weight_case(weight_case, monkeypatch):
    from umi import competition_host_activation as host

    item = weight_case
    # Explicit host-capability fixture port. Package signatures, owned chain
    # proofs, journal locking and recovery all use their production paths.
    installation = SimpleNamespace(
        config=SimpleNamespace(
            validator_hotkey=item.hotkey,
            trusted_authorities=[SimpleNamespace(hotkey=item.signed.signature.hotkey)],
        ),
        checkpoint_sha256=item.context.checkpoint_sha256,
        checkpoint_finalized_block=160,
        valid=True,
    )

    def verify(value):
        if value is not installation or not value.valid:
            raise ValueError("fixture installation changed")

    monkeypatch.setattr(host, "validate_authenticated_successor_installation", verify)
    item.installation = installation
    item.provider.config = item.config = item.config.model_copy(
        update={
            "finality_pin": item.config.finality_pin.model_copy(
                update={"bootstrap_block_number": 100}
            )
        }
    )
    return item


def _recover_stopped(item, initial, observe):
    return item.worker.reconcile_stopped(
        item.case.path,
        authorization=item.signed,
        installation=item.installation,
        release=item.context.release_identity,
        chain_config=item.config,
        observe=observe,
        finalized_floor=(initial.block, initial.block_hash),
    )


async def _unknown_stopped_attempt(item):
    item.behavior = "disconnect"
    with pytest.raises(ConnectionError):
        await _run(item)
    _advance(item, 187)
    return await item.provider.collect_weights(item.hotkey, item.recipients)


class _SigningRuntime(_Runtime):
    def compose_call(self, module, function, params):
        assert (module, function) == ("SubtensorModule", "set_mechanism_weights")
        assert params["dests"] == list(range(256))
        assert len(params["weights"]) == 256
        return canonical_json_bytes(params)

    def signature_payload(self, call, **kwargs):
        assert kwargs["era"] == {"period": 16, "current": 170}
        assert kwargs["nonce"] == 4
        assert kwargs["tip"] == 0 and kwargs["tip_asset_id"] is None
        assert kwargs["era_block_hash"] == bytes.fromhex(_hash(170)[2:])
        return hashlib.blake2b(call, digest_size=32).digest()

    def encode_signed_extrinsic(self, call, **kwargs):
        assert kwargs["signature_version"] == 1
        assert kwargs["public_key"] == wallet("Eve").hotkey.public_key
        assert len(kwargs["signature"]) == 64 and kwargs["nonce"] == 4
        encoded = b"fixture-scale:" + call + kwargs["signature"]
        return encoded, hashlib.blake2b(encoded, digest_size=32).digest()


@pytest.fixture
def weight_case(
    chain, package_case, package_limits, release_identity, worker_capacity, tmp_path, monkeypatch
):
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", _SigningRuntime)
    item = chain
    hotkey = wallet("Eve").hotkey.ss58_address
    provider = FinalizedCompetitionWeightProvider(
        item.config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    # Small fixture heights only: production construction enforces the real
    # checkpoint floor. All remaining reads still pass the proof collector.
    provider.config = item.config.model_copy(update={"minimum_finalized_block": 100})
    item.config = provider.config
    item.finality.ref = replace(item.finality.ref, block_number=170, block_hash=_hash(170))
    values = {
        "ValidatorPermit": [False] * 54 + [True] + [False] * 201,
        "LastUpdate": [0] * 256,
        "MechanismCountCurrent": 1,
        "CommitRevealWeightsEnabled": False,
        "WeightsVersionKey": 2**32,
        "MinAllowedWeights": 256,
        "MaxAllowedUids": 256,
        "MaxWeightsLimit": 65535,
        "WeightsSetRateLimit": 10,
        "SubnetworkN": 256,
    }
    item.rpc.values.update(
        {("SubtensorModule", key, (78,)): value for key, value in values.items()}
    )
    item.rpc.values.update(
        {
            ("SubtensorModule", "Uids", (78, hotkey)): 54,
            ("SubtensorModule", "Keys", (78, 54)): hotkey,
            ("SubtensorModule", "Weights", (78, 54)): [],
            ("System", "Account", (hotkey,)): {"nonce": 4, "providers": 1},
            ("Commitments", "CommitmentOf", (78, hotkey)): None,
        }
    )
    package = load_competition_package(
        package_case.path,
        expected_package_sha256=package_case.prepared.package_sha256,
        expected_policy_sha256=digest(item.policy),
        observed_release=release_identity,
        limits=package_limits,
    )
    recipients = tuple(
        Registration(uid=e.uid, hotkey=e.hotkey)
        for e in package.retained_settlement.projection.allocations
    )
    for entry in recipients:
        item.rpc.values[("SubtensorModule", "Keys", (78, entry.uid))] = entry.hotkey
        item.rpc.values[("SubtensorModule", "Uids", (78, entry.hotkey))] = entry.uid
    body = CompetitionWeightAuthorizationBody(
        schema="umi-competition-weight-authorization/1",
        authorization_id="12" * 32,
        validator_scope="any_permitted_sn78",
        policy_sha256=digest(item.policy),
        package_sha256=package.package_sha256,
        settlement_sha256=package.manifest.settlement_sha256,
        projection_sha256=package.manifest.projection_sha256,
        release_identity_sha256=package.manifest.release_identity_sha256,
        predecessor_directive_sha256="34" * 32,
        required_recovery_profile="stopped_bootstrap_recovery/1",
        chain_pin=item.config.chain_pin,
        required_finality_verifier_sha256_by_target={"aarch64-apple-darwin": "a2" * 32},
        required_storage_proof_verifier_sha256_by_target={"aarch64-apple-darwin": "a3" * 32},
        network="finney",
        netuid=78,
        mechanism_id=0,
        signed_at_block=160,
        valid_from_block=160,
        valid_through_block=200,
        weights_version_key=2**32,
        required_min_allowed_weights=256,
        required_max_allowed_uids=256,
        required_max_weights_limit=65535,
        required_weights_rate_limit=10,
        required_mechanism_count=1,
        required_commit_reveal_enabled=False,
        mortality_period=16,
        late_conflict_action="hold_no_automatic_correction",
    )
    signed = sign_competition_weight_authorization(body, wallet("Ferdie"))
    replay = CompetitionReplayWorker(
        tmp_path / "replay", package_limits=package_limits, capacity=worker_capacity
    )
    worker = CompetitionWeightWorker(
        tmp_path / "weights",
        package_limits=package_limits,
        replay_worker=replay,
        maximum_attempts=20,
        maximum_evidence_bytes=50_000_000,
        submission_timeout_seconds=10,
    )
    context = SimpleNamespace(
        validator_hotkey=hotkey,
        directive_sha256="56" * 32,
        release_identity=release_identity,
        authority_hotkeys=(wallet("Ferdie").hotkey.ss58_address,),
        checkpoint_sha256="78" * 32,
        validate_retained_recovery=lambda checkpoint, hotkey, predecessor: SimpleNamespace(
            finalized_block=160
        ),
    )

    def validate_host(capability, **bindings):
        assert capability is context and bindings["expected_profile"] == "competition_weights"
        if getattr(context, "observation", None) is not None:
            validate_owned_weight_observation(context.observation)

    def refresh(*, owned_observation):
        validate_owned_weight_observation(owned_observation)
        context.observation = owned_observation
        return context

    context.refresh = refresh

    # Explicit fake host port. No fixture JSON can mint production activation.
    monkeypatch.setitem(
        sys.modules,
        "umi.competition_host_upgrade",
        SimpleNamespace(validate_authenticated_successor_activation=validate_host),
    )
    item.provider = provider
    item.package, item.case, item.body, item.signed = package, package_case, body, signed
    item.worker, item.context, item.recipients, item.hotkey = worker, context, recipients, hotkey
    item.encoded, item.behavior = [], "apply"

    class Transport(BittensorCompetitionWeightTransport):
        def __init__(self):
            pass

        async def submit(self, encoded, signer):
            with sqlite3.connect(worker.path) as db:
                stored = json.loads(db.execute("SELECT body FROM attempts").fetchone()[0])
                assert stored["phase"] == "signed"
                assert bytes.fromhex(stored["signed_extrinsic"][2:]) == encoded
            item.encoded.append(encoded)
            if item.behavior == "disconnect":
                raise ConnectionError("fixture connection lost after send")
            if item.behavior == "apply":
                _advance(item, 171, applied=True)
            return SimpleNamespace(success=True)

    item.transport = Transport()
    return item


def _advance(item, height, *, applied=False, nonce=None):
    item.finality.ref = replace(item.finality.ref, block_number=height, block_hash=_hash(height))
    if applied:
        row = item.package.retained_settlement.projection
        item.rpc.values[("SubtensorModule", "Weights", (78, 54))] = list(
            zip(row.uids, row.weights, strict=True)
        )
        item.rpc.values[("SubtensorModule", "LastUpdate", (78,))][54] = height
        nonce = 5 if nonce is None else nonce
    if nonce is not None:
        item.rpc.values[("System", "Account", (item.hotkey,))]["nonce"] = nonce


async def _run(item, **changes):
    options = dict(
        authorization=item.signed,
        activation=item.context,
        wallet=wallet("Eve").hotkey,
        chain=item.provider,
        transport=item.transport,
    )
    options.update(changes)
    return await item.worker.run(item.case.path, **options)


async def test_actual_proof_collection_then_durable_exact_sdk_row(weight_case):
    item = weight_case
    # The package fixture includes a preserved, reviewed promotion and two
    # synthetic evaluator groups. Keep this full submission path on the
    # approved joint allocation, even when other tests use endpoint-only policy.
    assert (item.policy.endpoint_reward_bps, item.policy.model_reward_bps) == (7000, 3000)
    assert {
        entry.uid: Fraction(int(entry.numerator), int(entry.denominator))
        for entry in item.package.retained_settlement.projection.allocations
    } == {6: Fraction(3, 10), 247: Fraction(7, 10)}
    outcome = await _run(item)
    assert outcome.status == "recovered_effect" and outcome.exact_row_currently_applied
    assert outcome.submitted_by_this_attempt and len(item.encoded) == 1
    assert not (await _run(item)).submitted_by_this_attempt
    assert len(item.encoded) == 1 and len(item.verifier.checked) >= 9


async def test_unknown_effect_never_resubmits_and_recovers_after_expiry(weight_case):
    item = weight_case
    item.behavior = "disconnect"
    with pytest.raises(ConnectionError):
        await _run(item)
    assert (await _run(item)).status == "unknown"
    _advance(item, 180, applied=True)
    _advance(item, 201)
    assert (await _run(item)).status == "recovered_effect"
    assert len(item.encoded) == 1


async def test_sdk_success_without_proven_row_is_unknown(weight_case):
    item = weight_case
    item.behavior = "noop"
    assert (await _run(item)).status == "unknown"
    assert (await _run(item)).status == "unknown"
    assert len(item.encoded) == 1


async def test_mortal_expiry_with_unchanged_nonce_is_terminal_without_retry(weight_case):
    item = weight_case
    item.behavior = "noop"
    await _run(item)
    _advance(item, 187)
    result = await _run(item)
    assert result.status == "expired_unconsumed_nonce" and not result.automatic_retry_permitted
    assert len(item.encoded) == 1


@pytest.mark.parametrize("mutation", ["permit", "version", "rate", "recipient", "proof", "nonce"])
async def test_preflight_failure_never_signs_or_submits(weight_case, mutation):
    item = weight_case
    if mutation == "permit":
        item.rpc.values[("SubtensorModule", "ValidatorPermit", (78,))][54] = False
    elif mutation == "version":
        item.rpc.values[("SubtensorModule", "WeightsVersionKey", (78,))] = 1
    elif mutation == "rate":
        item.rpc.values[("SubtensorModule", "LastUpdate", (78,))][54] = 169
    elif mutation == "recipient":
        item.rpc.values[("SubtensorModule", "Keys", (78, 6))] = wallet("Eve").hotkey.ss58_address
    elif mutation == "proof":
        item.rpc.bad_proof = True
    else:
        item.rpc.values[("System", "Account", (item.hotkey,))]["nonce"] = True
    with pytest.raises((ValueError, ValidatorChainError)):
        await _run(item)
    assert not item.encoded


async def test_single_use_binding_and_global_unknown_fence(weight_case):
    item = weight_case
    item.behavior = "noop"
    await _run(item)
    changed = item.body.model_copy(update={"authorization_id": "98" * 32})
    with pytest.raises(ValueError, match="unresolved"):
        await _run(
            item, authorization=sign_competition_weight_authorization(changed, wallet("Ferdie"))
        )
    changed = item.body.model_copy(update={"valid_through_block": 199})
    with pytest.raises(ValueError, match="binding changed"):
        await _run(
            item, authorization=sign_competition_weight_authorization(changed, wallet("Ferdie"))
        )
    assert len(item.encoded) == 1


async def test_late_publication_conflict_holds_without_corrective_write(weight_case, replay_limits):
    item = weight_case
    await _run(item)
    _record_cutoff_conflict(item.worker.replay_worker, item.case, item.policy, replay_limits)
    assert (await _run(item)).status == "held_conflict"
    assert len(item.encoded) == 1


async def test_observation_cannot_be_deserialized_rebound_or_expired(weight_case):
    item = weight_case
    observed = await item.provider.collect_weights(item.hotkey, item.recipients)
    validate_owned_weight_observation(observed)
    assert observed.pending_commitments is None
    for changed in (
        replace(observed, validator_nonce=22),
        replace(observed, _issuer=None),
        replace(observed, expires_monotonic_ns=0),
    ):
        with pytest.raises(ValueError, match="owned proof"):
            validate_owned_weight_observation(changed)


def test_authorization_domain_and_scope_binding(weight_case):
    item = weight_case
    verify_competition_weight_authorization(
        item.signed, trusted_authority_hotkeys=item.context.authority_hotkeys, package=item.package
    )
    assert competition_weight_authorization_digest(item.body) != digest(item.body)
    with pytest.raises(ValueError, match="not trusted"):
        verify_competition_weight_authorization(
            item.signed,
            trusted_authority_hotkeys=(wallet("Alice").hotkey.ss58_address,),
            package=item.package,
        )
    call = build_competition_weight_call(item.package, item.body)
    assert call.params["weights"][0] == 0
    assert call.params["weights"][6] > 0 and call.params["weights"][247] > 0


async def test_pinned_bittensor_transport_sends_exact_bytes_without_wallet_lookup():
    sent, signer = [], wallet("Eve").hotkey

    async def submit(extrinsic, selected, **options):
        assert selected is signer
        assert options == {"wait_for_inclusion": True, "wait_for_finalization": True}
        sent.append(extrinsic)
        return "fixture-result"

    class Client:
        _substrate = SimpleNamespace(submit_signed=submit)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    def factory(endpoint, **options):
        assert endpoint == "wss://rpc.example" and options == {"retry_forever": False}
        return Client()

    transport = BittensorCompetitionWeightTransport(
        endpoint="wss://rpc.example", client_factory=factory
    )
    assert await transport.submit(b"exact-signed-bytes", signer) == "fixture-result"
    assert sent[0].data == b"exact-signed-bytes"
    assert (
        sent[0].extrinsic_hash
        == "0x" + hashlib.blake2b(b"exact-signed-bytes", digest_size=32).hexdigest()
    )


async def test_process_restart_retains_single_use_attempt_and_proofs(weight_case):
    item = weight_case
    await _run(item)
    old = item.worker
    item.worker = CompetitionWeightWorker(
        old.state_root,
        package_limits=old.package_limits,
        replay_worker=old.replay_worker,
        maximum_attempts=old.maximum_attempts,
        maximum_evidence_bytes=old.maximum_evidence_bytes,
        submission_timeout_seconds=old.submission_timeout_seconds,
    )
    outcome = await _run(item)
    assert outcome.exact_row_currently_applied and len(item.encoded) == 1
    with sqlite3.connect(item.worker.path) as db:
        evidence = db.execute("SELECT sha256, body FROM evidence").fetchall()
    assert len(evidence) >= 3
    assert all(hashlib.sha256(raw).hexdigest() == identity for identity, raw in evidence)


@pytest.mark.parametrize("corruption", ["attempt", "missing_evidence", "proof", "oversize"])
async def test_corrupt_durable_state_never_retries(weight_case, corruption):
    item = weight_case
    item.behavior = "noop"
    await _run(item)
    with sqlite3.connect(item.worker.path) as db:
        if corruption == "attempt":
            db.execute("UPDATE attempts SET body=?", (b"{}",))
        elif corruption == "missing_evidence":
            db.execute("DELETE FROM evidence")
        elif corruption == "proof":
            db.execute("UPDATE evidence SET body=?", (b"changed",))
        else:
            db.execute("UPDATE attempts SET body=zeroblob(?)", (256 * 1024 + 1,))
    with pytest.raises(ValueError):
        await _run(item)
    assert len(item.encoded) == 1


async def test_signing_failure_leaves_durable_intent_and_no_automatic_retry(
    weight_case, monkeypatch
):
    item = weight_case

    def fail_encode(*args, **kwargs):
        with sqlite3.connect(item.worker.path) as db:
            record = json.loads(db.execute("SELECT body FROM attempts").fetchone()[0])
        assert record["phase"] == "intent"
        raise RuntimeError("fixture signer unavailable")

    monkeypatch.setattr(item.transport, "encode", fail_encode)
    with pytest.raises(RuntimeError, match="signer unavailable"):
        await _run(item)
    assert (await _run(item)).status == "unknown"
    assert not item.encoded


async def test_storage_only_codec_never_signs_a_transaction(weight_case, monkeypatch):
    from umi.validator_chain import PinnedRuntimeContext

    monkeypatch.setattr(
        PinnedRuntimeContext,
        "storage_codec_mode",
        property(lambda self: "reviewed_storage_codec/1"),
    )
    with pytest.raises(ValueError, match="storage-only codec"):
        await _run(weight_case)
    assert not weight_case.encoded


async def test_other_nonce_use_without_exact_row_stays_unknown_even_after_expiry(weight_case):
    item = weight_case
    item.behavior = "noop"
    await _run(item)
    _advance(item, 201, nonce=5)
    assert (await _run(item)).status == "unknown"
    assert len(item.encoded) == 1


async def test_old_equal_row_is_not_misattributed_to_new_attempt(weight_case):
    item = weight_case
    item.behavior = "noop"
    row = item.package.retained_settlement.projection
    item.rpc.values[("SubtensorModule", "Weights", (78, 54))] = list(
        zip(row.uids, row.weights, strict=True)
    )
    item.rpc.values[("SubtensorModule", "LastUpdate", (78,))][54] = 100
    await _run(item)
    _advance(item, 171, nonce=5)
    assert (await _run(item)).status == "unknown"


async def test_short_authorization_window_refuses_before_signing(weight_case):
    item = weight_case
    _advance(item, 190)
    with pytest.raises(ValueError, match="headroom"):
        await _run(item)
    assert not item.encoded


async def test_smaller_registered_uid_domain_refuses_full_row(weight_case):
    item = weight_case
    item.rpc.values[("SubtensorModule", "SubnetworkN", (78,))] = 255
    with pytest.raises(ValueError, match="chain bounds"):
        await _run(item)
    assert not item.encoded


async def test_private_journal_lock_blocks_parallel_writer(weight_case):
    item = weight_case
    with item.worker._lock(), pytest.raises(BlockingIOError):
        await _run(item)
    assert not item.encoded


async def test_nonce_change_during_signing_refuses_broadcast(weight_case, monkeypatch):
    item = weight_case
    encode = item.transport.encode

    def changed_nonce(*args, **kwargs):
        encoded = encode(*args, **kwargs)
        _advance(item, 171, nonce=5)
        return encoded

    monkeypatch.setattr(item.transport, "encode", changed_nonce)
    with pytest.raises(ValueError, match="changed before broadcast"):
        await _run(item)
    assert not item.encoded


async def test_conflict_arriving_during_signing_refuses_broadcast(
    weight_case, replay_limits, monkeypatch
):
    item = weight_case
    encode = item.transport.encode

    def conflicted(*args, **kwargs):
        encoded = encode(*args, **kwargs)
        _record_cutoff_conflict(item.worker.replay_worker, item.case, item.policy, replay_limits)
        return encoded

    monkeypatch.setattr(item.transport, "encode", conflicted)
    assert (await _run(item)).status == "held_conflict"
    assert not item.encoded


async def test_slow_package_and_publication_replay_use_new_owned_proofs(weight_case, monkeypatch):
    from umi import competition_chain_state as chain_state
    from umi import competition_weights as weights

    item = weight_case
    now = chain_state.time.monotonic_ns
    elapsed = [0]
    monkeypatch.setattr(chain_state.time, "monotonic_ns", lambda: now() + elapsed[0])
    initial = await item.provider.collect_weights(item.hotkey, item.recipients)
    item.context.observation = initial
    package_load = weights.load_competition_package
    replay = item.worker.replay_worker.run
    encode = item.transport.encode
    replay_count = []

    def slow_package(*args, **kwargs):
        result = package_load(*args, **kwargs)
        elapsed[0] += 120 * 10**9
        return result

    def slow_replay(*args, **kwargs):
        result = replay(*args, **kwargs)
        replay_count.append(result)
        elapsed[0] += 120 * 10**9
        return result

    def slow_sign(*args, **kwargs):
        result = encode(*args, **kwargs)
        elapsed[0] += 120 * 10**9
        return result

    monkeypatch.setattr(weights, "load_competition_package", slow_package)
    monkeypatch.setattr(item.worker.replay_worker, "run", slow_replay)
    monkeypatch.setattr(item.transport, "encode", slow_sign)
    submit = item.transport.submit

    async def require_current_proof(encoded, signer):
        validate_owned_weight_observation(item.context.observation)
        assert item.context.observation is not initial
        assert item.context.observation.captured_monotonic_ns > initial.expires_monotonic_ns
        return await submit(encoded, signer)

    monkeypatch.setattr(item.transport, "submit", require_current_proof)
    outcome = await _run(item)
    assert outcome.submitted_by_this_attempt and len(item.encoded) == 1
    assert len(replay_count) == 1  # No full replay spends the signed mortal era.
    with pytest.raises(ValueError, match="owned proof"):
        validate_owned_weight_observation(initial)
    # Restart/re-entry still cannot resend the single-use signed bytes.
    assert not (await _run(item)).submitted_by_this_attempt
    assert len(item.encoded) == 1


@pytest.mark.parametrize("slow_phase", ["package", "journal"])
async def test_stopped_recovery_captures_after_slow_verification(
    stopped_weight_case, monkeypatch, slow_phase
):
    from umi import competition_weights as weights

    item = stopped_weight_case
    initial = await _unknown_stopped_attempt(item)
    now = time.monotonic_ns
    elapsed = [0]
    monkeypatch.setattr(time, "monotonic_ns", lambda: now() + elapsed[0])
    target, name = (
        (weights, "load_competition_package")
        if slow_phase == "package"
        else (item.worker, "_audit_evidence")
    )
    original = getattr(target, name)
    verified = []

    def slow(*args, **kwargs):
        result = original(*args, **kwargs)
        elapsed[0] += 121 * 10**9
        verified.append(True)
        return result

    monkeypatch.setattr(target, name, slow)

    async def observe():
        assert verified
        with pytest.raises(ValueError, match="owned proof"):
            validate_owned_weight_observation(initial)
        return await item.provider.collect_weights(item.hotkey, item.recipients)

    outcome, current = await _recover_stopped(item, initial, observe)
    validate_owned_weight_observation(current)
    assert current.captured_monotonic_ns > initial.expires_monotonic_ns
    assert outcome.status == "expired_unconsumed_nonce"
    assert not outcome.submitted_by_this_attempt and len(item.encoded) == 1
    with sqlite3.connect(item.worker.path) as db:
        retained = json.loads(db.execute("SELECT body FROM attempts").fetchone()[0])
    assert retained["phase"] == "expired_unconsumed_nonce"
    assert bytes.fromhex(retained["signed_extrinsic"][2:]) == item.encoded[0]


@pytest.mark.parametrize(
    "fault", ["expired", "forged", "rollback", "fork", "package", "journal", "lock", "installation"]
)
async def test_stopped_recovery_rejects_changed_inputs_and_bad_fresh_proof(
    stopped_weight_case, monkeypatch, fault
):
    item = stopped_weight_case
    initial = await _unknown_stopped_attempt(item)
    before = item.worker.path.read_bytes()

    async def observe():
        if fault == "rollback":
            _advance(item, 186)
        if fault == "fork":
            item.finality.ref = replace(item.finality.ref, block_hash=_hash(188))
        current = await item.provider.collect_weights(item.hotkey, item.recipients)
        if fault == "expired":
            monkeypatch.setattr(time, "monotonic_ns", lambda: current.expires_monotonic_ns + 1)
        elif fault == "forged":
            current = replace(current, validator_nonce=current.validator_nonce + 1)
        elif fault in {"package", "journal", "lock"}:
            path = {
                "package": item.case.path / "manifest.json",
                "journal": item.worker.path,
                "lock": item.worker.lock_path,
            }[fault]
            info, raw = path.stat(), path.read_bytes()
            path.chmod(0o600)
            path.write_bytes(raw)  # Same bytes and restored mtime still change ctime.
            path.chmod(0o400 if fault == "package" else 0o600)
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        elif fault == "installation":
            item.installation.valid = False
        return current

    with pytest.raises(ValueError):
        await _recover_stopped(item, initial, observe)
    assert item.worker.path.read_bytes() == before
    assert len(item.encoded) == 1
    with sqlite3.connect(item.worker.path) as db:
        assert (
            json.loads(db.execute("SELECT body FROM attempts").fetchone()[0])["phase"] == "unknown"
        )


async def test_stopped_recovery_keeps_journal_lock_across_capture_and_cancellation(
    stopped_weight_case,
):
    item = stopped_weight_case
    initial = await _unknown_stopped_attempt(item)
    before = item.worker.path.read_bytes()

    async def cancelled():
        with pytest.raises(BlockingIOError), item.worker._lock():
            pytest.fail("second stopped recovery acquired the held lock")
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await _recover_stopped(item, initial, cancelled)
    assert item.worker.path.read_bytes() == before
    with item.worker._lock():
        pass
    assert len(item.encoded) == 1


@pytest.mark.parametrize("source", ["package", "journal"])
async def test_stopped_recovery_brackets_slow_input_audit_with_integrity_checks(
    stopped_weight_case, monkeypatch, source
):
    from umi import competition_weights as weights

    item = stopped_weight_case
    initial = await _unknown_stopped_attempt(item)
    target, name = (
        (weights, "load_competition_package")
        if source == "package"
        else (item.worker, "_audit_evidence")
    )
    original = getattr(target, name)

    def changed(*args, **kwargs):
        value = original(*args, **kwargs)
        path = item.case.path / "manifest.json" if source == "package" else item.worker.path
        raw, info = path.read_bytes(), path.stat()
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400 if source == "package" else 0o600)
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        return value

    async def observe():
        pytest.fail("changed recovery input reached the proof capture")

    monkeypatch.setattr(target, name, changed)
    with pytest.raises(ValueError, match="changed during verification"):
        await _recover_stopped(item, initial, observe)
    assert len(item.encoded) == 1


@pytest.mark.parametrize("capture", [1, 2])
async def test_conflict_during_fresh_capture_refuses_effect(
    weight_case, replay_limits, monkeypatch, capture
):
    item = weight_case
    collect = item.provider.collect_weights
    calls = 0

    async def conflicted(*args, **kwargs):
        nonlocal calls
        observation = await collect(*args, **kwargs)
        calls += 1
        if calls == capture:
            _record_cutoff_conflict(
                item.worker.replay_worker, item.case, item.policy, replay_limits
            )
        return observation

    monkeypatch.setattr(item.provider, "collect_weights", conflicted)
    with pytest.raises(ValueError, match="publication journal changed"):
        await _run(item)
    assert not item.encoded
    with sqlite3.connect(item.worker.path) as db:
        retained = db.execute("SELECT body FROM attempts").fetchall()
    if capture == 1:
        assert retained == []
    else:
        assert json.loads(retained[0][0])["phase"] == "signed"
        assert json.loads(retained[0][0])["signed_extrinsic"] is not None


def test_publication_snapshot_is_local_and_detects_restored_database_bytes(weight_case):
    item = weight_case
    worker = item.worker.replay_worker
    replay = worker.run(
        item.case.path,
        expected_package_sha256=item.body.package_sha256,
        expected_policy_sha256=item.body.policy_sha256,
        observed_release=item.context.release_identity,
    )
    worker.verify_publication_unchanged(replay)
    with pytest.raises(ValueError, match="changed"):
        worker.verify_publication_unchanged(replay.model_copy())
    path = worker.publication_root / item.body.policy_sha256 / "competition-publication.sqlite3"
    before = path.stat()
    content = path.read_bytes()
    path.write_bytes(b"x" * len(content))
    path.write_bytes(content)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ValueError, match="changed"):
        worker.verify_publication_unchanged(replay)


async def test_chain_evidence_quota_refuses_before_signing(weight_case):
    item = weight_case
    item.worker.maximum_evidence_bytes = 1024
    with pytest.raises(ValueError, match="evidence capacity"):
        await _run(item)
    assert not item.encoded


async def test_attempt_quota_does_not_evict_completed_authorizations(weight_case):
    item = weight_case
    item.worker.maximum_attempts = 1
    await _run(item)
    renewed = item.body.model_copy(update={"authorization_id": "98" * 32})
    with pytest.raises(ValueError, match="capacity is exhausted"):
        await _run(
            item, authorization=sign_competition_weight_authorization(renewed, wallet("Ferdie"))
        )
    assert len(item.encoded) == 1


async def test_weight_startup_retries_only_owned_observer_warmup(weight_case, monkeypatch):
    from umi.competition_chain import _AwaitingFinality

    item = weight_case
    collect = item.provider.collect_weights
    attempts = 0

    async def warmup(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise _AwaitingFinality("fixture initial head absent")
        return await collect(*args, **kwargs)

    monkeypatch.setattr(item.provider, "collect_weights", warmup)
    observation = await item.provider.wait_weights_ready(item.hotkey, item.recipients)
    validate_owned_weight_observation(observation)
    assert attempts == 2 and not item.encoded


async def test_weight_startup_does_not_hide_proof_failure(weight_case, monkeypatch):
    item = weight_case
    attempts = 0

    async def failed(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        raise ValueError("fixture proof invalid")

    monkeypatch.setattr(item.provider, "collect_weights", failed)
    with pytest.raises(ValueError, match="proof invalid"):
        await item.provider.wait_weights_ready(item.hotkey, item.recipients)
    assert attempts == 1 and not item.encoded
