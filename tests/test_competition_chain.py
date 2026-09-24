from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_chain import (
    CompetitionChainConfig,
    FinalizedRegistrationProvider,
    RegistrationProviderTimeout,
    _PrefetchRpc,
    _RegistrationRpc,
)
from umi.grandpa_finality import (
    CARGO_LOCK_SHA256,
    FINNEY_BOOTSTRAP_BLOCK_HASH,
    FINNEY_BOOTSTRAP_BLOCK_NUMBER,
    FINNEY_CHAIN_SPEC_SHA256,
    FINNEY_CHAIN_SPEC_SOURCE_REVISION,
    FINNEY_GENESIS_HASH,
    FIXTURE_SET_SHA256,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
)
from umi.grandpa_finality_supervisor import (
    GrandpaFinalityStoreCorruption,
    GrandpaFinalitySupervisorError,
)
from umi.open_competition import digest
from umi.policy import FinalityVerifierPin, LiveChainObservationPin
from umi.protocol import canonical_json_bytes
from umi.validator_chain import FinalizedProofCollector, ValidatorChainError
from umi.validator_plans import VerifiedFinalizedBlock

from .test_open_competition import (
    policy as policy,
)
from .test_open_competition import wallet

_NOW = 1_800_000_000_000
_HEIGHT = FINNEY_BOOTSTRAP_BLOCK_NUMBER + 20


def test_successor_sources_keep_python310_syntax_and_asyncio_helpers():
    source_directory = Path(__file__).resolve().parents[1] / "src" / "umi"
    for source in source_directory.glob("competition_*.py"):
        tree = ast.parse(source.read_text(), filename=str(source), feature_version=(3, 10))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "asyncio"
            ):
                assert node.attr not in {"timeout", "timeout_at", "TaskGroup"}, (
                    f"{source.name}:{node.lineno} requires Python 3.11 asyncio"
                )


def _hash(value):
    return "0x" + f"{value:02x}" * 32


@pytest.fixture
def chain_config(policy, tmp_path):
    return CompetitionChainConfig(
        schema="umi-competition-chain-config/1",
        policy_sha256=digest(policy),
        rpc_url="wss://proofs.example.org",
        chain_pin=LiveChainObservationPin(
            network="finney",
            genesis_block_hash=FINNEY_GENESIS_HASH,
            runtime_spec_version=452,
            transaction_version=1,
            state_version=1,
            metadata_sha256=hashlib.sha256(b"metadata").hexdigest(),
            subtensor_revision="test-runtime",
            live_chain_fixture_set_sha256="a1" * 32,
        ),
        finality_pin=FinalityVerifierPin(
            profile="smoldot-verifier-attested-finality/1",
            evidence_class="verifier_attested_finality",
            offline_finality_proof=False,
            source_revision=SOURCE_REVISION,
            source_tree_sha256=SOURCE_TREE_SHA256,
            cargo_lock_sha256=CARGO_LOCK_SHA256,
            finality_fixture_set_sha256=FIXTURE_SET_SHA256,
            release_sha256_by_target={"aarch64-apple-darwin": "a2" * 32},
            chain_spec_source_revision=FINNEY_CHAIN_SPEC_SOURCE_REVISION,
            chain_spec_sha256=FINNEY_CHAIN_SPEC_SHA256,
            expected_genesis_hash=FINNEY_GENESIS_HASH,
            bootstrap_kind="grandpa_warp_sync_checkpoint",
            bootstrap_block_number=FINNEY_BOOTSTRAP_BLOCK_NUMBER,
            bootstrap_block_hash=FINNEY_BOOTSTRAP_BLOCK_HASH,
        ),
        target_triple="aarch64-apple-darwin",
        finality_binary=str(tmp_path / "observer"),
        chain_spec=str(tmp_path / "chain-spec.json"),
        proof_binary=str(tmp_path / "proof-verifier"),
        proof_binary_sha256="a3" * 32,
        state_directory=str(tmp_path / "state"),
        minimum_finalized_block=FINNEY_BOOTSTRAP_BLOCK_NUMBER,
    )


class _Runtime:
    def __init__(self, metadata, spec_version, transaction_version, *, ss58_format):
        assert metadata == b"metadata"
        assert (spec_version, transaction_version, ss58_format) == (452, 1, 42)
        self.spec_version = spec_version
        self.transaction_version = transaction_version

    def constant(self, pallet, item):
        assert (pallet, item) == ("System", "SS58Prefix")
        return 42

    @staticmethod
    def storage_key(pallet, item, params):
        return canonical_json_bytes([pallet, item, params])

    def storage_entry(self, pallet, item):
        return SimpleNamespace(modifier="Optional", default_bytes=b"null", value_type="json")

    def decode(self, value_type, data, *, strict):
        assert value_type == "json" and strict is True
        return json.loads(data)


class _Finality:
    def __init__(self, config, policy):
        self.config, self.policy = config, policy
        self.ref = FinalizedSnapshotRef(_HEIGHT, _hash(1), _hash(2), _hash(3))
        self.timestamp = _NOW - 1000
        self.genesis = "0x" + FINNEY_GENESIS_HASH
        self.evidence_class = "verifier_attested_finality"
        self.calls = 0
        self.advance_after_reads = 0

    async def verified_finalized_snapshot(self):
        self.calls += 1
        if self.calls > 1 and self.advance_after_reads:
            return replace(self.ref, block_number=self.ref.block_number + self.advance_after_reads)
        return self.ref

    async def verified_block_at(self, height):
        assert height == self.ref.block_number
        evidence = canonical_json_bytes(
            {
                "evidence_class": self.evidence_class,
                "offline_finality_proof": False,
                "genesis_hash": self.genesis,
            }
        )
        return VerifiedFinalizedBlock(
            height=self.ref.block_number,
            block_hash=self.ref.block_hash,
            state_root=self.ref.state_root,
            timestamp_ms=self.timestamp,
            scoring_policy_hash=digest(self.policy),
            chain_observation=self.config.chain_pin,
            finality_verifier_sha256="a2" * 32,
            finality_evidence=evidence,
            finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )


class _Rpc:
    def __init__(self, finality):
        self.finality = finality
        self.calls = []
        self.metadata = b"metadata"
        self.header_root = None
        self.bad_proof = False
        self.values = {
            ("Timestamp", "Now", ()): finality.timestamp,
            ("SubtensorModule", "NetworksAdded", (78,)): True,
            ("SubtensorModule", "SubnetworkN", (78,)): 2,
        }
        for uid, name in enumerate(("Alice", "Bob")):
            hotkey = wallet(name).hotkey.ss58_address
            self.values[("SubtensorModule", "Keys", (78, uid))] = hotkey
            self.values[("SubtensorModule", "Uids", (78, hotkey))] = uid

    async def request(self, method, params):
        self.calls.append((method, tuple(params)))
        ref = self.finality.ref
        if method == "chain_getHeader":
            assert tuple(params) == (ref.block_hash,)
            return {
                "number": hex(ref.block_number),
                "parentHash": ref.parent_hash,
                "stateRoot": self.header_root or ref.state_root,
            }
        if method == "chain_getBlockHash":
            assert tuple(params) == (ref.block_number,)
            return ref.block_hash
        if method == "state_getRuntimeVersion":
            assert tuple(params) == (ref.block_hash,)
            return {"specVersion": 452, "transactionVersion": 1, "stateVersion": 1}
        if method == "state_getMetadata":
            assert tuple(params) == (ref.block_hash,)
            return "0x" + self.metadata.hex()
        if method == "state_getStorageAt":
            assert params[1] == ref.block_hash
            pallet, item, arguments = json.loads(bytes.fromhex(params[0][2:]))
            value = self.values.get((pallet, item, tuple(arguments)))
            return None if value is None else "0x" + canonical_json_bytes(value).hex()
        if method == "state_getReadProof":
            assert params[1] == ref.block_hash
            return {
                "at": ref.block_hash,
                "proof": ["0x" + (b"bad" if self.bad_proof else b"proof").hex()],
            }
        raise AssertionError("unexpected RPC capability: " + method)


class _Verifier:
    def __init__(self, finality):
        self.finality = finality
        self.checked = []

    def __call__(self, **kwargs):
        raise AssertionError("registration collection must use multiproofs")

    def verify_many(self, **kwargs):
        self.checked.append(kwargs)
        assert kwargs["state_root"] == bytes.fromhex(self.finality.ref.state_root[2:])
        return kwargs["proof"] == (b"proof",)


@pytest.fixture
def chain(chain_config, policy, monkeypatch):
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", _Runtime)
    finality = _Finality(chain_config, policy)
    rpc = _Rpc(finality)
    verifier = _Verifier(finality)
    proofs = FinalizedProofCollector(rpc, finality=finality, verifier=verifier)
    clock = SimpleNamespace(now=_NOW)
    provider = FinalizedRegistrationProvider(
        chain_config, policy, finality=finality, proofs=proofs, now_ms=lambda: clock.now
    )
    return SimpleNamespace(
        config=chain_config,
        policy=policy,
        finality=finality,
        rpc=rpc,
        verifier=verifier,
        proofs=proofs,
        clock=clock,
        provider=provider,
    )


async def test_complete_registration_uses_one_owned_state_root_and_retains_evidence(chain):
    capture = await chain.provider.collect()
    assert capture.snapshot.block == _HEIGHT
    assert [entry.uid for entry in capture.snapshot.registrations] == [0, 1]
    assert [entry.hotkey for entry in capture.snapshot.registrations] == [
        wallet(name).hotkey.ss58_address for name in ("Alice", "Bob")
    ]
    assert len(chain.verifier.checked) == 3
    provenance = capture.provenance
    assert provenance["evidence_class"] == "verifier_attested_finality"
    assert provenance["offline_finality_proof"] is False
    assert provenance["chain_submission_authorized"] is False
    assert provenance["snapshot_sha256"] == digest(capture.snapshot)
    assert "rpc_url" not in provenance and "state_directory" not in provenance
    with sqlite3.connect(chain.provider._path) as connection:
        evidence = connection.execute("SELECT evidence FROM captures").fetchone()[0]
        assert connection.execute("SELECT body FROM artifacts").fetchone()[0] == b"metadata"
    assert hashlib.sha256(evidence).hexdigest() == provenance["evidence_sha256"]
    retained = json.loads(evidence)
    assert len(retained["storage_batches"]) == 3
    assert retained["runtime_metadata_sha256"] == hashlib.sha256(b"metadata").hexdigest()
    count = len(chain.verifier.checked)
    assert await chain.provider() == capture.snapshot
    assert len(chain.verifier.checked) == count
    assert "chain_getFinalizedHead" not in {method for method, _ in chain.rpc.calls}


@pytest.mark.parametrize(
    "mutation",
    [
        "stale",
        "future",
        "genesis",
        "evidence_class",
        "root",
        "metadata",
        "proof",
        "network",
        "count",
        "duplicate",
        "missing_key",
        "inverse",
        "timestamp",
    ],
)
async def test_invalid_chain_evidence_never_yields_registration(chain, mutation):
    if mutation == "stale":
        chain.clock.now += 120_001
    elif mutation == "future":
        chain.clock.now -= 31_002
    elif mutation == "genesis":
        chain.finality.genesis = _hash(99)
    elif mutation == "evidence_class":
        chain.finality.evidence_class = "rpc_finalized"
    elif mutation == "root":
        chain.rpc.header_root = _hash(99)
    elif mutation == "metadata":
        chain.rpc.metadata = b"different metadata"
    elif mutation == "proof":
        chain.rpc.bad_proof = True
    elif mutation == "network":
        chain.rpc.values[("SubtensorModule", "NetworksAdded", (78,))] = False
    elif mutation == "count":
        chain.rpc.values[("SubtensorModule", "SubnetworkN", (78,))] = 257
    elif mutation == "duplicate":
        chain.rpc.values[("SubtensorModule", "Keys", (78, 1))] = wallet("Alice").hotkey.ss58_address
    elif mutation == "missing_key":
        del chain.rpc.values[("SubtensorModule", "Keys", (78, 1))]
    elif mutation == "inverse":
        chain.rpc.values[("SubtensorModule", "Uids", (78, wallet("Alice").hotkey.ss58_address))] = 1
    elif mutation == "timestamp":
        chain.rpc.values[("Timestamp", "Now", ())] += 1
    with pytest.raises((ValueError, RuntimeError)):
        await chain.provider.collect()
    with sqlite3.connect(chain.provider._path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 0


@pytest.mark.parametrize("during_proofs", ["time", "blocks"])
async def test_freshness_is_rechecked_after_proofs(chain, monkeypatch, during_proofs):
    original = chain.proofs.storage_reads

    async def delayed(runtime, specs):
        result = await original(runtime, specs)
        if during_proofs == "time":
            chain.clock.now = _NOW + 120_001
        else:
            chain.finality.advance_after_reads = chain.policy.maximum_snapshot_age_blocks + 1
        return result

    monkeypatch.setattr(chain.proofs, "storage_reads", delayed)
    with pytest.raises(ValueError, match="stale"):
        await chain.provider.collect()


@pytest.mark.parametrize("change", ["rollback", "same_height_hash"])
async def test_rollback_guard_survives_provider_restart(chain, change):
    await chain.provider.collect()
    await chain.provider.aclose()
    chain.finality.ref = replace(
        chain.finality.ref,
        **({"block_number": _HEIGHT - 1} if change == "rollback" else {"block_hash": _hash(99)}),
    )
    restarted = FinalizedRegistrationProvider(
        chain.config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: _NOW,
    )
    with pytest.raises(ValueError, match="rolled back or changed"):
        await restarted.collect()


async def test_cached_snapshot_still_checks_wall_clock_freshness(chain):
    await chain.provider.collect()
    chain.clock.now += 120_001
    with pytest.raises(ValueError, match="stale"):
        await chain.provider()


async def test_collection_timeout_is_bounded(chain, monkeypatch):
    async def stalled():
        await asyncio.Event().wait()

    monkeypatch.setattr(chain.proofs, "finalized_snapshot", stalled)
    provider = FinalizedRegistrationProvider(
        chain.config.model_copy(
            update={
                "collection_timeout_seconds": 1,
                "state_directory": chain.config.state_directory + "-timeout",
            }
        ),
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: _NOW,
    )
    with pytest.raises(RegistrationProviderTimeout, match="timed out"):
        await provider.collect()
    await provider.aclose()
    with pytest.raises(ValueError, match="closed"):
        await provider.collect()


@pytest.mark.parametrize(
    "updates",
    [
        {"netuid": 79},
        {"network": "test"},
        {"rpc_url": "https://example.org"},
        {"rpc_url": "wss://user:secret@example.org"},
        {"finality_binary": "observer"},
    ],
)
def test_config_rejects_wrong_network_or_ambient_paths(chain_config, updates):
    body = chain_config.model_dump(mode="json", by_alias=True)
    body.update(updates)
    with pytest.raises(ValueError):
        CompetitionChainConfig.model_validate(body)


def test_config_rejects_wrong_genesis(chain_config):
    body = chain_config.model_dump(mode="json", by_alias=True)
    body["chain_pin"]["genesis_block_hash"] = "99" * 32
    with pytest.raises(ValueError, match="Finney"):
        CompetitionChainConfig.model_validate(body)


def test_cache_binds_the_chain_configuration_not_the_policy(chain):
    # The registration cache holds verified registrations and finality heads, none of
    # which depend on the competition policy: a policy change alone reopens it, so a
    # deal-preserving successor keeps its warm cache instead of a cold finality sync.
    policy = chain.policy.model_copy(update={"sequence": 2})
    config = chain.config.model_copy(update={"policy_sha256": digest(policy)})
    FinalizedRegistrationProvider(config, policy, finality=chain.finality, proofs=chain.proofs)
    # A config that names a different policy than the one supplied is still refused.
    with pytest.raises(ValueError, match="another competition policy"):
        FinalizedRegistrationProvider(
            config, chain.policy, finality=chain.finality, proofs=chain.proofs
        )
    # Any other chain-configuration change still invalidates the cache.
    other = chain.config.model_copy(
        update={"minimum_finalized_block": chain.config.minimum_finalized_block + 1}
    )
    with pytest.raises(ValueError, match="another chain configuration"):
        FinalizedRegistrationProvider(
            other, chain.policy, finality=chain.finality, proofs=chain.proofs
        )


def test_legacy_per_policy_cache_binding_is_upgraded_in_place(chain):
    import sqlite3
    from pathlib import Path

    # Simulate a cache written by the previous release, whose binding was digest(config)
    # including policy_sha256, then reopen under the same policy and under a successor.
    path = Path(chain.config.state_directory) / "registrations.sqlite3"
    legacy = digest(chain.config)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE binding SET digest=?", (legacy,))
    FinalizedRegistrationProvider(
        chain.config, chain.policy, finality=chain.finality, proofs=chain.proofs
    )
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT digest FROM binding").fetchone()[0] != legacy
    successor = chain.policy.model_copy(
        update={"sequence": 2, "predecessor_sha256": digest(chain.policy)}
    )
    config = chain.config.model_copy(update={"policy_sha256": digest(successor)})
    FinalizedRegistrationProvider(config, successor, finality=chain.finality, proofs=chain.proofs)


async def test_prefetch_cancellation_drains_bounded_child_reads():
    started = asyncio.Event()
    state = SimpleNamespace(active=0, peak=0)

    class BlockedRpc:
        async def request(self, method, params):
            assert method == "state_getStorageAt"
            state.active += 1
            state.peak = max(state.peak, state.active)
            if state.active == 8:
                started.set()
            try:
                await asyncio.Event().wait()
            finally:
                state.active -= 1

    rpc = _PrefetchRpc(BlockedRpc())
    task = asyncio.create_task(rpc.prefetch(_hash(1), tuple(bytes([i]) for i in range(32))))
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state.peak == 8
    assert state.active == 0
    assert rpc.values == {}


@pytest.mark.parametrize(
    ("method", "ceiling"),
    [
        ("state_getStorageAt", 2048),
        ("state_getReadProof", 17 * 1024**2),
        ("state_getMetadata", 33 * 1024**2),
    ],
)
async def test_registration_rpc_limits_messages_before_json_parse(
    chain_config, monkeypatch, method, ceiling
):
    class Socket:
        async def send(self, request):
            assert json.loads(request)["method"] == method

        async def recv(self):
            return '{"jsonrpc":"2.0","id":1,"result":"0x00"}'

    class Connection:
        async def __aenter__(self):
            return Socket()

        async def __aexit__(self, *args):
            return None

    def connect(endpoint, **kwargs):
        assert endpoint == chain_config.rpc_url
        assert kwargs["max_size"] == ceiling
        assert kwargs["proxy"] is None
        return Connection()

    monkeypatch.setattr("umi.competition_chain.websocket_connect", connect)
    assert await _RegistrationRpc(chain_config).request(method, ()) == "0x00"


async def test_cache_ceiling_preserves_prior_evidence_and_deduplicated_metadata(chain):
    await chain.provider.collect()
    with sqlite3.connect(chain.provider._path) as connection:
        size = connection.execute("SELECT SUM(length(evidence)) FROM captures").fetchone()[0]
        size += connection.execute("SELECT SUM(length(body)) FROM artifacts").fetchone()[0]
    config = chain.config.model_copy(
        update={
            "maximum_cache_bytes": size + 1,
            "state_directory": chain.config.state_directory + "-bounded",
        }
    )
    bounded = FinalizedRegistrationProvider(
        config, chain.policy, finality=chain.finality, proofs=chain.proofs, now_ms=lambda: _NOW
    )
    first = await bounded.collect()
    chain.finality.ref = replace(chain.finality.ref, block_number=_HEIGHT + 1, block_hash=_hash(98))
    with pytest.raises(ValueError, match="cache is full"):
        await bounded.collect()
    with sqlite3.connect(bounded._path) as connection:
        assert connection.execute("SELECT block FROM captures").fetchall() == [
            (first.snapshot.block,)
        ]
        assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 1


async def test_two_heads_reuse_one_retained_runtime_artifact(chain):
    await chain.provider.collect()
    chain.finality.ref = replace(chain.finality.ref, block_number=_HEIGHT + 1, block_hash=_hash(98))
    await chain.provider.collect()
    with sqlite3.connect(chain.provider._path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 2


@pytest.mark.parametrize(
    "startup_seconds,head_age_ms,record_timeout",
    [(600, 120_000, 15.0), (30, 10_000, 5.0), (60, 60_000, 15.0)],
)
async def test_owned_lifecycle_requires_new_process_observation_and_stops_cleanly(
    chain, monkeypatch, startup_seconds, head_age_ms, record_timeout
):
    chain.config = chain.config.model_copy(
        update={
            "startup_timeout_seconds": startup_seconds,
            "maximum_head_age_ms": head_age_ms,
            "state_directory": chain.config.state_directory + "-owned",
        }
    )
    started, stopped = asyncio.Event(), asyncio.Event()

    async def run(stop):
        started.set()
        try:
            await stop.wait()
        finally:
            stopped.set()

    monkeypatch.setattr(chain.finality, "run", run, raising=False)
    monkeypatch.setattr(
        chain.finality, "persisted_head", lambda: SimpleNamespace(height=_HEIGHT), raising=False
    )

    def observer_from_pin(pin, **kwargs):
        assert pin == chain.config.finality_pin
        assert kwargs["binary_path"] == chain.config.finality_binary
        assert kwargs["chain_spec_path"] == chain.config.chain_spec
        assert kwargs["first_record_timeout_seconds"] == chain.config.startup_timeout_seconds
        assert kwargs["record_timeout_seconds"] == record_timeout
        assert kwargs["record_timeout_seconds"] < chain.config.maximum_head_age_ms / 1000
        return "pinned-test-observer"

    def durable_port(**kwargs):
        assert kwargs["observer"] == "pinned-test-observer"
        assert kwargs["scoring_policy_digest"] == digest(chain.policy)
        assert kwargs["chain_observation"] == chain.config.chain_pin
        return chain.finality

    def proof_verifier(**kwargs):
        assert kwargs["binary_path"] == chain.config.proof_binary
        assert kwargs["expected_sha256"] == chain.config.proof_binary_sha256
        return chain.verifier

    monkeypatch.setattr(
        "umi.competition_chain.GrandpaFinalityObserver.from_policy_pin", observer_from_pin
    )
    monkeypatch.setattr("umi.competition_chain.DurableGrandpaFinalityPort", durable_port)
    monkeypatch.setattr("umi.competition_chain.SubprocessStorageProofVerifier", proof_verifier)

    async def close_rpc():
        pass

    monkeypatch.setattr(chain.rpc, "aclose", close_rpc, raising=False)
    monkeypatch.setattr(
        "umi.competition_chain._RegistrationRpc", lambda config, **kwargs: chain.rpc
    )
    owned = FinalizedRegistrationProvider(
        chain.config, chain.policy, now_ms=lambda: chain.clock.now
    )
    assert owned._proofs._limits.maximum_proof_node_bytes == 2 * 1024**2
    assert owned._proofs._limits.maximum_proof_bytes == 8 * 1024**2
    with pytest.raises(ValueError, match="not running"):
        await owned.collect()
    await owned.start()
    await asyncio.wait_for(started.wait(), 1)
    with pytest.raises(ValueError, match="this observer process"):
        await owned.collect()
    chain.finality.ref = replace(chain.finality.ref, block_number=_HEIGHT + 1, block_hash=_hash(98))
    assert (await owned.collect()).snapshot.block == _HEIGHT + 1
    task = owned._task
    chain.clock.now += head_age_ms + 1
    with pytest.raises(ValueError, match="stale"):
        await owned.collect()
    owned.ensure_observer_running()
    assert not stopped.is_set()
    chain.finality.ref = replace(chain.finality.ref, block_number=_HEIGHT + 2, block_hash=_hash(99))
    chain.finality.timestamp = chain.clock.now - 1000
    chain.rpc.values[("Timestamp", "Now", ())] = chain.finality.timestamp
    assert (await owned.collect()).snapshot.block == _HEIGHT + 2
    assert owned._task is task  # Recovery must not replace the observer or its journal.
    await owned.aclose()
    assert stopped.is_set()
    assert owned._task.done()
    with pytest.raises(ValueError, match="closed"):
        await owned.start()


async def test_wait_ready_retries_only_missing_owned_head_then_returns_capture(chain, monkeypatch):
    original = chain.finality.verified_finalized_snapshot
    calls = 0

    async def first_head():
        nonlocal calls
        calls += 1
        if calls <= 2:
            raise GrandpaFinalitySupervisorError("no_verified_finalized_head")
        return await original()

    monkeypatch.setattr(chain.finality, "verified_finalized_snapshot", first_head)
    monkeypatch.setattr("umi.competition_chain._STARTUP_POLL_SECONDS", 0)
    capture = await chain.provider.wait_ready()
    assert capture.snapshot.block == _HEIGHT
    assert calls == 4  # Two startup polls, capture head, then final freshness check.
    assert capture.provenance["evidence_class"] == "verifier_attested_finality"


@pytest.mark.parametrize("state", ["minimum", "new_owned_head"])
async def test_wait_ready_waits_for_configured_and_post_start_head(chain, monkeypatch, state):
    original = chain.proofs.finalized_snapshot
    calls = 0

    async def source():
        nonlocal calls
        calls += 1
        if calls == 1:
            if state == "minimum":
                return replace(
                    chain.finality.ref, block_number=chain.config.minimum_finalized_block - 1
                )
            return chain.finality.ref
        if state == "new_owned_head":
            chain.finality.ref = replace(
                chain.finality.ref, block_number=_HEIGHT + 1, block_hash=_hash(98)
            )
        return await original()

    async def run(stop):
        await stop.wait()

    if state == "new_owned_head":
        chain.provider._owned = True
        chain.provider._startup_floor = _HEIGHT
        monkeypatch.setattr(chain.finality, "run", run, raising=False)
        await chain.provider.start()
    monkeypatch.setattr(chain.proofs, "finalized_snapshot", source)
    monkeypatch.setattr("umi.competition_chain._STARTUP_POLL_SECONDS", 0)
    try:
        capture = await chain.provider.wait_ready()
        assert calls == 2
        assert capture.snapshot.block == _HEIGHT + (state == "new_owned_head")
    finally:
        await chain.provider.aclose()


@pytest.mark.parametrize(
    "kind",
    ["pin", "corruption", "wrong_wrapper", "plain_absence", "text_lookalike", "transport_timeout"],
)
async def test_wait_ready_does_not_retry_fatal_or_similarly_named_errors(chain, monkeypatch, kind):
    errors = {
        "pin": ValidatorChainError("runtime_metadata_pin_mismatch"),
        "corruption": ValidatorChainError("owned_finality_unavailable"),
        "wrong_wrapper": ValidatorChainError("finalized_snapshot_rpc_failed"),
        "plain_absence": GrandpaFinalitySupervisorError("no_verified_finalized_head"),
        "text_lookalike": ValueError("awaiting a head verified by this observer process"),
        "transport_timeout": ValueError("registration collection timed out"),
    }
    error = errors[kind]
    if kind == "corruption":
        error.__cause__ = GrandpaFinalityStoreCorruption("no_verified_finalized_head")
    elif kind == "wrong_wrapper":
        error.__cause__ = GrandpaFinalitySupervisorError("no_verified_finalized_head")
    calls = 0

    async def broken():
        nonlocal calls
        calls += 1
        raise error

    monkeypatch.setattr(chain.proofs, "finalized_snapshot", broken)
    with pytest.raises(type(error)) as caught:
        await chain.provider.wait_ready()
    assert caught.value is error
    assert calls == 1


async def test_wait_ready_does_not_hide_invalid_storage_proof(chain):
    chain.rpc.bad_proof = True
    with pytest.raises(ValidatorChainError, match="proof"):
        await chain.provider.wait_ready()
    assert len(chain.verifier.checked) == 1


async def test_wait_ready_has_total_startup_deadline(chain, monkeypatch):
    config = chain.config.model_copy(
        update={
            "state_directory": chain.config.state_directory + "-startup-timeout",
            "startup_timeout_seconds": 1,
        }
    )
    provider = FinalizedRegistrationProvider(
        config, chain.policy, finality=chain.finality, proofs=chain.proofs, now_ms=lambda: _NOW
    )
    calls = 0

    async def absent():
        nonlocal calls
        calls += 1
        raise GrandpaFinalitySupervisorError("no_verified_finalized_head")

    monkeypatch.setattr(chain.finality, "verified_finalized_snapshot", absent)
    with pytest.raises(RegistrationProviderTimeout, match="startup timed out"):
        await asyncio.wait_for(provider.wait_ready(), 2)
    assert 2 <= calls <= 5
    await provider.aclose()


async def test_wait_ready_cancellation_drains_inflight_collection(chain, monkeypatch):
    started, drained = asyncio.Event(), asyncio.Event()

    async def blocked():
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            drained.set()

    monkeypatch.setattr(chain.proofs, "finalized_snapshot", blocked)
    task = asyncio.create_task(chain.provider.wait_ready())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert drained.is_set()
    await chain.provider.aclose()


async def test_wait_ready_propagates_owned_observer_failure(chain, monkeypatch):
    failure = GrandpaFinalityStoreCorruption("retained_attestation_corrupt")

    async def broken(stop):
        raise failure

    chain.provider._owned = True
    chain.provider._startup_floor = _HEIGHT
    monkeypatch.setattr(chain.finality, "run", broken, raising=False)
    await chain.provider.start()
    await asyncio.sleep(0)
    with pytest.raises(GrandpaFinalityStoreCorruption) as caught:
        await chain.provider.wait_ready()
    assert caught.value is failure
    await chain.provider.aclose()


@pytest.fixture
def pooled_sockets(monkeypatch):
    state = SimpleNamespace(connections=[], requests=0, blocked=False, invalid_next=False)
    started = asyncio.Event()

    class Socket:
        def __init__(self):
            self.busy = False

        async def send(self, request):
            assert not self.busy
            assert json.loads(request)["id"] == 1
            self.busy = True
            state.requests += 1
            if state.requests >= 8:
                started.set()

        async def recv(self):
            try:
                if state.blocked:
                    await asyncio.Event().wait()
                await asyncio.sleep(0)
                if state.invalid_next:
                    state.invalid_next = False
                    return '{"jsonrpc":"2.0","id":99,"result":"0x00"}'
                return '{"jsonrpc":"2.0","id":1,"result":"0x00"}'
            finally:
                self.busy = False

    class Connection:
        def __init__(self):
            self.socket = Socket()
            self.closed = False

        async def __aenter__(self):
            return self.socket

        async def __aexit__(self, *args):
            await asyncio.sleep(0)
            self.closed = True

    def connect(endpoint, **kwargs):
        assert kwargs["max_size"] in (2048, 17 * 1024**2, 33 * 1024**2, 1024**2)
        assert kwargs["proxy"] is None
        connection = Connection()
        connection.max_size = kwargs["max_size"]
        state.connections.append(connection)
        return connection

    monkeypatch.setattr("umi.competition_chain.websocket_connect", connect)
    return state, started


async def test_storage_batch_reuses_exclusive_bounded_connections(chain_config, pooled_sockets):
    state, _ = pooled_sockets
    rpc = _PrefetchRpc(_RegistrationRpc(chain_config))
    await rpc.prefetch(_hash(1), tuple(bytes([i]) for i in range(64)))
    assert len(rpc.values) == state.requests == 64
    assert 1 <= len(state.connections) <= 8
    assert all(connection.closed for connection in state.connections)


async def test_protocol_error_discards_pooled_connection(chain_config, pooled_sockets):
    state, _ = pooled_sockets
    rpc = _RegistrationRpc(chain_config)
    async with rpc.batch():
        state.invalid_next = True
        with pytest.raises(RuntimeError, match="proof_rpc_response_invalid"):
            await rpc.request("state_getStorageAt", ("0x01", _hash(1)))
        assert state.connections[0].closed
        assert await rpc.request("state_getStorageAt", ("0x02", _hash(1))) == "0x00"
        assert len(state.connections) == 2
    assert all(connection.closed for connection in state.connections)


async def test_cancelled_batch_closes_all_leased_sockets(chain_config, pooled_sockets):
    state, started = pooled_sockets
    state.blocked = True
    rpc = _PrefetchRpc(_RegistrationRpc(chain_config))
    task = asyncio.create_task(rpc.prefetch(_hash(1), tuple(bytes([i]) for i in range(64))))
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(state.connections) == 8
    assert all(connection.closed for connection in state.connections)
    assert not any(connection.socket.busy for connection in state.connections)
    assert rpc.values == {}


async def test_persistent_storage_connections_survive_batches_until_close(
    chain_config, pooled_sockets
):
    state, _ = pooled_sockets
    transport = _RegistrationRpc(chain_config, persistent=True)
    rpc = _PrefetchRpc(transport)
    for block in (1, 2, 3):
        await rpc.prefetch(_hash(block), tuple(bytes([i]) for i in range(64)))
        assert len(rpc.values) == 64
    assert state.requests == 192
    assert 1 <= len(state.connections) <= 8
    assert not any(connection.closed for connection in state.connections)
    await transport.aclose()
    assert all(connection.closed for connection in state.connections)
    with pytest.raises(ValueError, match="closed"):
        await transport.request("state_getStorageAt", ("0x01", _hash(1)))


async def test_persistent_rpc_discards_protocol_error_without_retry(chain_config, pooled_sockets):
    state, _ = pooled_sockets
    transport = _RegistrationRpc(chain_config, persistent=True)
    state.invalid_next = True
    with pytest.raises(RuntimeError, match="proof_rpc_response_invalid"):
        await transport.request("state_getStorageAt", ("0x01", _hash(1)))
    assert state.requests == 1 and state.connections[0].closed
    assert await transport.request("state_getStorageAt", ("0x02", _hash(1))) == "0x00"
    assert len(state.connections) == 2
    await transport.aclose()
    assert all(connection.closed for connection in state.connections)


async def test_persistent_rpc_keeps_method_receive_limits_separate(chain_config, pooled_sockets):
    state, _ = pooled_sockets
    transport = _RegistrationRpc(chain_config, persistent=True)
    methods = ("state_getStorageAt", "state_getReadProof", "state_getMetadata")
    for _ in range(3):
        for method in methods:
            assert await transport.request(method, ()) == "0x00"
    assert len(state.connections) == 3
    assert [c.max_size for c in state.connections] == [2048, 17 * 1024**2, 33 * 1024**2]
    await transport.aclose()
    assert all(connection.closed for connection in state.connections)


async def test_persistent_rpc_cancelled_reads_close_and_can_reconnect(chain_config, pooled_sockets):
    state, started = pooled_sockets
    transport = _RegistrationRpc(chain_config, persistent=True)
    rpc = _PrefetchRpc(transport)
    state.blocked = True
    task = asyncio.create_task(rpc.prefetch(_hash(1), tuple(bytes([i]) for i in range(64))))
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(connection.closed for connection in state.connections)
    state.blocked = False
    await rpc.prefetch(_hash(2), (b"a",))
    assert len(rpc.values) == 1
    await transport.aclose()
    assert all(connection.closed for connection in state.connections)


async def test_bulk_prefetch_uses_one_exact_block_request(chain_config, monkeypatch):
    rpc = _RegistrationRpc(chain_config, bulk_storage_reads=True)
    calls = []

    async def request(method, params):
        calls.append((method, params))
        return [{"block": _hash(1), "changes": [["0x62", None], ["0x61", "0x01"]]}]

    monkeypatch.setattr(rpc, "request", request)
    prefetch = _PrefetchRpc(rpc)
    await prefetch.prefetch(_hash(1), (b"a", b"b"))
    assert calls == [("state_queryStorageAt", (("0x61", "0x62"), _hash(1)))]
    assert await prefetch.request("state_getStorageAt", ("0x61", _hash(1))) == "0x01"
    assert await prefetch.request("state_getStorageAt", ("0x62", _hash(1))) is None
    assert len(calls) == 1


@pytest.mark.parametrize(
    "result",
    [
        [],
        [{"block": _hash(2), "changes": [["0x61", "0x01"]]}],
        [{"block": _hash(1), "changes": []}],
        [{"block": _hash(1), "changes": [["0x62", "0x01"]]}],
        [{"block": _hash(1), "changes": [["0x61", "0x01"]], "extra": True}],
        [{"block": _hash(1), "changes": [["0x61", 1]]}],
        [{"block": _hash(1), "changes": [["0x61", "0x" + "00" * 513]]}],
        [{"block": _hash(1), "changes": [["0x61"]]}],
        [{"block": _hash(1), "changes": [[[], "0x01"]]}],
    ],
)
async def test_bulk_prefetch_rejects_malformed_or_mismatched_results(
    chain_config, monkeypatch, result
):
    rpc = _RegistrationRpc(chain_config, bulk_storage_reads=True)

    async def request(method, params):
        return result

    monkeypatch.setattr(rpc, "request", request)
    prefetch = _PrefetchRpc(rpc)
    prefetch.values["0x61", _hash(0)] = "0xff"
    with pytest.raises(ValueError):
        await prefetch.prefetch(_hash(1), (b"a",))
    assert prefetch.values == {}


async def test_bulk_prefetch_rejects_duplicate_result_keys(chain_config, monkeypatch):
    rpc = _RegistrationRpc(chain_config, bulk_storage_reads=True)

    async def request(method, params):
        return [{"block": _hash(1), "changes": [["0x61", "0x01"], ["0x61", "0x01"]]}]

    monkeypatch.setattr(rpc, "request", request)
    with pytest.raises(ValueError, match="duplicated"):
        await rpc.storage_values(_hash(1), (b"a", b"b"))


@pytest.mark.parametrize(
    "keys", [(), (b"a", b"a"), (b"",), (b"a" * 513,), tuple(bytes([i % 256]) for i in range(257))]
)
async def test_bulk_prefetch_rejects_invalid_keys_before_network(chain_config, monkeypatch, keys):
    rpc = _RegistrationRpc(chain_config, bulk_storage_reads=True)

    async def request(method, params):
        pytest.fail("invalid keys reached RPC")

    monkeypatch.setattr(rpc, "request", request)
    with pytest.raises(ValueError):
        await rpc.storage_values(_hash(1), keys)
