from __future__ import annotations

import asyncio
import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import signed_policy as signed_policy
from tests.test_bridge_transactions import tx as tx
from umi import competition_host_anchor as anchor
from umi import competition_host_artifacts as artifacts
from umi import competition_host_observer as observer_module
from umi.bridge.receipts import VerifiedBridgeExpiry
from umi.bridge.transactions import evolve_journal
from umi.competition_bridge_recovery import JOURNAL, BridgeHistoryAudit
from umi.competition_chain import CompetitionChainConfig
from umi.competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    validate_owned_weight_observation,
)
from umi.competition_host_observer import StoppedUpgradeObserver
from umi.competition_host_upgrade import HostUpgradeError
from umi.competition_supervisor_observer import SuccessorHostObserverConfig
from umi.competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from .test_competition_chain import _hash, _Runtime
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_host_artifacts import sign as sign_host_artifact
from .test_competition_host_upgrade import hold
from .test_competition_host_upgrade import inputs as inputs
from .test_competition_host_upgrade import installed as installed
from .test_competition_supervisor import _consent
from .test_open_competition import policy as policy

_FINALITY_BYTES = b"inert signed finality observer"
_PROOF_BYTES = b"inert signed storage proof verifier"
_SPEC_BYTES = b"inert signed Finney chain specification"
_HELPERS = {
    "artifacts/umi-grandpa-finality-observer": (_FINALITY_BYTES, 0o555),
    "artifacts/umi-substrate-proof-verifier": (_PROOF_BYTES, 0o555),
    "artifacts/raw_spec_finney.json": (_SPEC_BYTES, 0o444),
}


def _write(path: Path, value, mode: int = 0o400) -> bytes:
    payload = value if isinstance(value, bytes) else canonical_json_bytes(value)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)
    return payload


def _replace_control(path: Path, value) -> None:
    path.chmod(0o600)
    path.write_bytes(value if isinstance(value, bytes) else canonical_json_bytes(value))
    path.chmod(0o400)


def _restore_writable(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)
    root.chmod(0o700)


def _verified_host_tree(tmp_path, monkeypatch, config):
    revision = "73" * 20
    parent = tmp_path / "signed-hosts"
    root = parent / revision
    parent.mkdir(mode=0o700)
    root.mkdir()
    files = []
    for name in sorted(artifacts._REQUIRED_FILES | set(_HELPERS)):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        default_mode = 0o555 if name.startswith(".venv/bin/") else 0o444
        body, mode = _HELPERS.get(
            name,
            (("inert successor source: " + name).encode(), default_mode),
        )
        path.write_bytes(body)
        path.chmod(mode)
        files.append(
            artifacts.HostArtifactFile(
                path=name,
                sha256=hashlib.sha256(body).hexdigest(),
                size_bytes=len(body),
                mode=mode,
            )
        )
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
    root.chmod(0o555)
    manifest = artifacts.SuccessorHostArtifactManifest(
        schema=artifacts.HOST_ARTIFACT_SCHEMA,
        channel_id=config.channel_id,
        umi_git_revision=revision,
        target_platform=config.target_platform,
        host_entrypoint_profile="umi-competition-supervisor-host/1",
        total_size_bytes=sum(item.size_bytes for item in files),
        files=files,
    )
    signed = sign_host_artifact(manifest)
    monkeypatch.setattr(artifacts, "_STAGE_PARENT", parent)
    monkeypatch.setattr(artifacts, "_ancestor_paths", lambda _root: (parent,))
    monkeypatch.setattr(artifacts, "_current_platform", lambda: config.target_platform)
    original_owner = artifacts._immutable_owner

    def root_owner(info, mode, *, directory):
        original_owner(
            SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink),
            mode,
            directory=directory,
        )

    monkeypatch.setattr(artifacts, "_immutable_owner", root_owner)
    original_ancestor_owner = artifacts._ancestor_owner
    monkeypatch.setattr(
        artifacts,
        "_ancestor_owner",
        lambda info: original_ancestor_owner(SimpleNamespace(st_uid=0, st_mode=info.st_mode)),
    )
    tree = artifacts.verify_staged_host_tree(
        signed,
        config=config,
        expected_manifest_sha256=signed.manifest_sha256,
        stage_root=root,
    )
    return SimpleNamespace(root=root, signed=signed, tree=tree)


@pytest.fixture
def owned_chain(chain):
    item = chain
    provider = FinalizedCompetitionWeightProvider(
        item.config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    item.finality.ref = replace(item.finality.ref, block_number=170, block_hash=_hash(170))
    item.provider = provider

    def configure_hotkey(value):
        item.rpc.values.update(
            {
                ("SubtensorModule", "ValidatorPermit", (78,)): [False] * 54
                + [True]
                + [False] * 201,
                ("SubtensorModule", "LastUpdate", (78,)): [0] * 256,
                ("SubtensorModule", "MechanismCountCurrent", (78,)): 1,
                ("SubtensorModule", "CommitRevealWeightsEnabled", (78,)): False,
                ("SubtensorModule", "WeightsVersionKey", (78,)): 2**32,
                ("SubtensorModule", "MinAllowedWeights", (78,)): 256,
                ("SubtensorModule", "MaxAllowedUids", (78,)): 256,
                ("SubtensorModule", "MaxWeightsLimit", (78,)): 65_535,
                ("SubtensorModule", "WeightsSetRateLimit", (78,)): 10,
                ("SubtensorModule", "SubnetworkN", (78,)): 256,
                ("SubtensorModule", "Uids", (78, value)): 54,
                ("SubtensorModule", "Keys", (78, 54)): value,
                ("SubtensorModule", "Weights", (78, 54)): [],
                ("System", "Account", (value,)): {"nonce": 4, "providers": 1},
                ("Commitments", "CommitmentOf", (78, value)): None,
            }
        )

    item.configure_hotkey = configure_hotkey
    return item


@pytest.fixture
def observer_case(tmp_path, monkeypatch, installed, owned_chain):
    owned_chain.configure_hotkey(installed.config.validator_hotkey)
    finality_sha256 = hashlib.sha256(_FINALITY_BYTES).hexdigest()
    proof_sha256 = hashlib.sha256(_PROOF_BYTES).hexdigest()
    spec_sha256 = hashlib.sha256(_SPEC_BYTES).hexdigest()
    finality_pin = owned_chain.config.finality_pin.model_copy(
        update={
            "release_sha256_by_target": {"x86_64-unknown-linux-gnu": finality_sha256},
            "chain_spec_sha256": spec_sha256,
            "bootstrap_block_number": 100,
        }
    )
    selected_chain = CompetitionChainConfig.model_validate(
        {
            **owned_chain.config.model_dump(mode="python", by_alias=True),
            "policy_sha256": digest(owned_chain.policy),
            "finality_pin": finality_pin,
            "target_triple": "x86_64-unknown-linux-gnu",
            "finality_binary": str(WORKER_FINALITY_BINARY),
            "proof_binary": str(WORKER_PROOF_BINARY),
            "proof_binary_sha256": proof_sha256,
            "chain_spec": str(WORKER_CHAIN_SPEC),
            "state_directory": str(WORKER_FINALITY_STATE_ROOT),
            "minimum_finalized_block": 100,
        }
    )
    selected = SuccessorHostObserverConfig(
        schema="umi-successor-host-observer-config/1",
        policy=owned_chain.policy,
        chain=selected_chain,
    )
    original_block = owned_chain.finality.verified_block_at

    async def verified_block_at(height):
        return replace(
            await original_block(height),
            finality_verifier_sha256=finality_sha256,
        )

    owned_chain.finality.verified_block_at = verified_block_at
    host = _verified_host_tree(tmp_path, monkeypatch, installed.config)
    predecessor = SimpleNamespace(
        config=installed.config,
        signed=installed.signed,
        body=canonical_json_bytes(installed.signed),
        state=installed.state,
    )
    consent = _consent(
        predecessor,
        approved_host_manifest_sha256=host.signed.manifest_sha256,
    )
    controls = tmp_path / "root-private-observer-controls"
    controls.mkdir(mode=0o700)
    consent_path = controls / "operator-consent.json"
    observer_path = controls / "observer-config.json"
    _write(consent_path, consent)
    _write(observer_path, selected)
    cache = controls / "finality-state"
    cache.mkdir(mode=0o700)

    monkeypatch.setattr(observer_module, "_require_root_linux", lambda: None)
    monkeypatch.setattr(anchor, "_root_owner_uid", os.geteuid)
    state = SimpleNamespace(calls=[], fault=None)
    expected_mounts = {
        (host.root / "artifacts/umi-grandpa-finality-observer", WORKER_FINALITY_BINARY): (
            False,
            0o555,
        ),
        (host.root / "artifacts/umi-substrate-proof-verifier", WORKER_PROOF_BINARY): (
            False,
            0o555,
        ),
        (host.root / "artifacts/raw_spec_finney.json", WORKER_CHAIN_SPEC): (False, 0o444),
        (cache, WORKER_FINALITY_STATE_ROOT): (True, 0o700),
    }

    def same_mount(source, mounted, *, directory, mode):
        state.calls.append((source, mounted, directory, mode))
        if state.fault is not None:
            raise HostUpgradeError(state.fault)
        assert expected_mounts[(source, mounted)] == (directory, mode)
        info = source.stat()
        assert source.is_dir() if directory else source.is_file()
        assert info.st_mode & 0o777 == mode

    monkeypatch.setattr(observer_module, "_same_mount", same_mount)
    providers = []
    behavior = SimpleNamespace(result="valid", entered=None, release=None)

    class Provider:
        """Mock only process ownership; returned proofs use the real collector fixture."""

        def __init__(self, config, selected_policy):
            self.config = config
            self.policy = selected_policy
            self.closed = False
            providers.append(self)

        async def start(self):
            if behavior.result == "start_error":
                raise ValueError("injected observer startup failure")

        async def wait_weights_ready(self, hotkey, recipients, *, manifest_anchor_sha256=None):
            assert recipients == ()
            if behavior.entered is not None:
                behavior.entered.set()
                await behavior.release.wait()
            if behavior.result == "capture_error":
                raise ValueError("injected proof capture failure")
            if behavior.result == "malformed":
                return SimpleNamespace(validator_hotkey=hotkey)
            config = self.config
            if behavior.result == "wrong_config":
                config = config.model_copy(
                    update={"collection_timeout_seconds": config.collection_timeout_seconds + 1}
                )
            owned_chain.provider.config = config
            owned_chain.provider.policy = self.policy
            owned_chain.finality.config = config
            owned_chain.finality.policy = self.policy
            return await owned_chain.provider.wait_weights_ready(
                hotkey, recipients, manifest_anchor_sha256=manifest_anchor_sha256
            )

        async def aclose(self):
            self.closed = True

    monkeypatch.setattr(observer_module, "FinalizedCompetitionWeightProvider", Provider)

    with hold(installed) as stopped:
        assert (
            stopped.accepted_signed_directive_sha256
            == hashlib.sha256(canonical_json_bytes(installed.signed)).hexdigest()
        )
        case = SimpleNamespace(
            installed=installed,
            stopped=stopped,
            chain=owned_chain,
            selected=selected,
            consent=consent,
            consent_path=consent_path,
            observer_path=observer_path,
            cache=cache,
            host=host,
            mounts=state,
            expected_mounts=expected_mounts,
            providers=providers,
            behavior=behavior,
        )

        def build(**changes):
            return StoppedUpgradeObserver(
                stopped=changes.get("stopped", stopped),
                host_tree=changes.get("host_tree", host.tree),
                signed_host=changes.get("signed_host", host.signed),
                operator_consent_path=changes.get("operator_consent_path", consent_path),
                observer_config_path=changes.get("observer_config_path", observer_path),
            )

        case.build = build
        yield case
    _restore_writable(host.root)
    _restore_writable(controls)


async def test_capture_uses_exact_mocked_mounts_and_genuine_owned_proof(observer_case):
    case = observer_case
    before = {path.name: path.read_bytes() for path in (case.consent_path, case.observer_path)}
    observer = case.build()
    observation = await observer.observe()
    validate_owned_weight_observation(observation)
    assert observation.validator_hotkey == case.installed.config.validator_hotkey
    assert observation.chain_config_sha256 == digest(case.selected.chain)
    assert observation.block >= case.stopped.accepted_at_finalized_block
    assert set(case.mounts.calls) >= {
        (source, mounted, directory, mode)
        for (source, mounted), (directory, mode) in case.expected_mounts.items()
    }
    assert case.providers[-1].closed
    assert list(case.cache.iterdir()) == []
    assert before == {
        path.name: path.read_bytes() for path in (case.consent_path, case.observer_path)
    }
    assert not hasattr(observation, "chain_submission_authorized")


def _preparing_for_observer(tx, hotkey):
    """Rebind a synthetic journal to the real stopped-host fixture's test key."""
    journal = tx.preparing
    payload = journal.attempt.model_dump(mode="json", by_alias=True, exclude={"attempt_id"})
    assert payload["health_observation"] is None
    old = payload["validator_hotkey"]
    payload["validator_hotkey"] = hotkey
    payload["signing"]["validator_hotkey"] = hotkey
    for participant in payload["roster"]:
        if participant["hotkey"] == old:
            participant["hotkey"] = hotkey
    payload["roster_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {
                "participants": [
                    {k: v for k, v in p.items() if k != "last_update"} for p in payload["roster"]
                ],
                "owner_associated_hotkeys": payload["owner_associated_hotkeys"],
            }
        )
    ).hexdigest()
    payload["attempt_id"] = hashlib.sha256(
        journal.attempt._identity_domain + canonical_json_bytes(payload)
    ).hexdigest()
    attempt = type(journal.attempt).model_validate(payload)
    return evolve_journal(journal, validator_hotkey=hotkey, attempt=attempt)


@pytest.mark.parametrize("failure", [False, True])
async def test_bridge_collector_issues_only_after_owned_observation_and_closes_provider(
    observer_case, tx, monkeypatch, failure
):
    item = observer_case
    journal = _preparing_for_observer(tx, item.stopped.validator_hotkey)
    # Journal preparation uses the signing fixture's narrow codec. Restore the
    # chain fixture's codec before its genuine owned-observation collection.
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", _Runtime)
    block = journal.attempt.era_death + 20
    item.chain.finality.ref = replace(
        item.chain.finality.ref,
        block_number=block,
        block_hash="0x" + hashlib.sha256(str(block).encode()).hexdigest(),
    )
    audit = BridgeHistoryAudit(
        journal,
        ((JOURNAL, journal),),
        frozenset({JOURNAL}),
        ("registration_bridge_transaction_proof_required",),
    )
    calls = []

    async def read_outcome(provider, retained):
        calls.append(retained)
        assert not provider.closed and retained == journal
        if failure:
            raise ValueError("injected bridge proof failure")
        # Reader ports are synthetic; the final observation and stopped lease
        # are issued by the same production collectors used in the tests above.
        return VerifiedBridgeExpiry(
            item.chain.finality.ref, retained.attempt.signing.nonce, item.chain.finality.ref
        )

    monkeypatch.setattr(
        observer_module.FinalizedCompetitionWeightProvider,
        "read_bridge_outcome",
        read_outcome,
        raising=False,
    )
    observer = item.build()
    anchor_sha256 = "da" * 32
    item.chain.rpc.values[("Commitments", "CommitmentOf", (78, item.stopped.validator_hotkey))] = {
        "block": block - 100,
        "info": {"fields": [{"Sha256": "0x" + anchor_sha256}]},
    }
    try:
        if failure:
            with pytest.raises(ValueError, match="bridge proof failure"):
                await observer.observe_bridge(audit, "ab" * 32)
        else:
            value = await observer.observe_bridge(
                audit, "ab" * 32, manifest_anchor_sha256=anchor_sha256
            )
            assert value.observation.manifest_anchor_sha256 == anchor_sha256
            assert value.observation.manifest_anchor_block == block - 100
            kwargs = dict(
                stopped=item.stopped, observation=value.observation, snapshot_sha256="ab" * 32
            )
            outcomes = observer_module.validate_stopped_bridge_observation(value, **kwargs)
            assert len(outcomes) == 1 and outcomes[0].disposition == "expired_nonce_available"
            validate_owned_weight_observation(value.observation)
            with pytest.raises(ValueError, match="absent, altered or misbound"):
                observer_module.validate_stopped_bridge_observation(replace(value), **kwargs)
            with pytest.raises(ValueError, match="absent, altered or misbound"):
                observer_module.validate_stopped_bridge_observation(
                    value, **{**kwargs, "snapshot_sha256": "cd" * 32}
                )
        assert calls == [journal]
        assert item.providers[-1].closed
    finally:
        await observer.aclose()


@pytest.mark.parametrize("control", ["consent", "observer"])
def test_noncanonical_or_oversized_controls_reject_before_provider(observer_case, control):
    case = observer_case
    path = case.consent_path if control == "consent" else case.observer_path
    payload = path.read_bytes() + b"\n"
    if control == "observer":
        payload = b"x" * (observer_module.MAX_HOST_OBSERVER_CONFIG_BYTES + 1)
    _replace_control(path, payload)
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        case.build()
    assert case.providers == []


def test_controls_require_fixed_names_and_one_private_parent(observer_case, tmp_path):
    case = observer_case
    wrong_name = case.observer_path.with_name("uploaded-observer.json")
    _write(wrong_name, case.selected)
    with pytest.raises(HostUpgradeError, match="fixed private paths"):
        case.build(observer_config_path=wrong_name)
    other_parent = tmp_path / "other-root-controls"
    other_parent.mkdir(mode=0o700)
    split = other_parent / "observer-config.json"
    _write(split, case.selected)
    with pytest.raises(HostUpgradeError, match="fixed private paths"):
        case.build(observer_config_path=split)
    assert case.providers == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_config_sha256", "81" * 32),
        ("predecessor_directive_sha256", "82" * 32),
        ("predecessor_signed_directive_sha256", "83" * 32),
        ("predecessor_accepted_at_finalized_block", 121),
        ("approved_host_manifest_sha256", "84" * 32),
        ("target_platform", "linux/arm64"),
    ],
)
def test_consent_cross_binding_rejects_before_provider(observer_case, field, value):
    case = observer_case
    _replace_control(case.consent_path, case.consent.model_copy(update={field: value}))
    with pytest.raises(HostUpgradeError):
        case.build()
    assert case.providers == []


def test_observer_platform_cross_binding_rejects_before_provider(observer_case):
    case = observer_case
    finality = case.selected.chain.finality_pin.model_copy(
        update={
            "release_sha256_by_target": {
                "aarch64-unknown-linux-gnu": hashlib.sha256(_FINALITY_BYTES).hexdigest()
            }
        }
    )
    chain = case.selected.chain.model_copy(
        update={"target_triple": "aarch64-unknown-linux-gnu", "finality_pin": finality}
    )
    _replace_control(
        case.observer_path,
        case.selected.model_copy(update={"chain": chain}),
    )
    with pytest.raises(HostUpgradeError, match="another installation"):
        case.build()
    assert case.providers == []


def test_unsigned_or_wrong_helper_binding_rejects_before_provider(observer_case):
    case = observer_case
    changed = case.selected.chain.model_copy(update={"proof_binary_sha256": "85" * 32})
    _replace_control(
        case.observer_path,
        case.selected.model_copy(update={"chain": changed}),
    )
    with pytest.raises(HostUpgradeError, match="absent from the signed host"):
        case.build()
    assert case.providers == []


@pytest.mark.parametrize("target", ["control", "tree", "cache", "mount"])
async def test_post_construction_tamper_rejects_before_capture(observer_case, target):
    case = observer_case
    observer = case.build()
    if target == "control":
        changed = case.consent.model_copy(update={"predecessor_sequence": 9})
        _replace_control(case.consent_path, changed)
    elif target == "tree":
        path = case.host.root / "artifacts/umi-substrate-proof-verifier"
        path.chmod(0o755)
        path.write_bytes(b"x" * len(_PROOF_BYTES))
        path.chmod(0o555)
    elif target == "cache":
        retained = case.cache.with_name("retained-finality-state")
        case.cache.rename(retained)
        case.cache.mkdir(mode=0o700)
    else:
        case.mounts.fault = "injected fixed-mount replacement"
    with pytest.raises(ValueError):
        await observer.observe()
    assert case.providers == []


@pytest.mark.parametrize("target", ["observer_source", "stopped", "tree"])
async def test_private_constructor_binding_cannot_be_retargeted(observer_case, target, tmp_path):
    case = observer_case
    observer = case.build()
    if target == "observer_source":
        alternate_parent = tmp_path / "alternate-root-controls"
        alternate_parent.mkdir(mode=0o700)
        alternate = alternate_parent / "observer-config.json"
        changed_chain = case.selected.chain.model_copy(update={"rpc_url": "wss://other.example"})
        _write(alternate, case.selected.model_copy(update={"chain": changed_chain}))
        observer._observer = anchor._read_source(
            alternate,
            maximum_bytes=observer_module.MAX_HOST_OBSERVER_CONFIG_BYTES,
            modes=frozenset({0o400}),
        )
    elif target == "stopped":
        observer._stopped = SimpleNamespace(
            _binding=case.stopped._binding,
            validator_hotkey=case.stopped.validator_hotkey,
            accepted_at_finalized_block=case.stopped.accepted_at_finalized_block,
            recheck_stopped=lambda: None,
        )
    else:
        observer._tree = SimpleNamespace(_binding=case.host.tree._binding, recheck=lambda: None)
    with pytest.raises((HostUpgradeError, AttributeError)):
        await observer.observe()
    assert case.providers == []


@pytest.mark.parametrize("result", ["malformed", "wrong_config"])
async def test_malformed_or_cross_bound_owned_proof_is_closed_and_rejected(observer_case, result):
    case = observer_case
    case.behavior.result = result
    observer = case.build()
    with pytest.raises((HostUpgradeError, ValueError)):
        await observer.observe()
    assert len(case.providers) == 1 and case.providers[0].closed


@pytest.mark.parametrize("result", ["start_error", "capture_error", "cancel"])
async def test_provider_is_closed_on_start_capture_error_and_cancellation(observer_case, result):
    case = observer_case
    case.behavior.result = result
    observer = case.build()
    if result == "cancel":
        case.behavior.entered = asyncio.Event()
        case.behavior.release = asyncio.Event()
        task = asyncio.create_task(observer.observe())
        await case.behavior.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(ValueError, match="injected"):
            await observer.observe()
    assert len(case.providers) == 1 and case.providers[0].closed


async def test_closed_state_is_idempotent_and_cannot_be_reset_by_caller(observer_case):
    case = observer_case
    observer = case.build()
    await observer.aclose()
    await observer.aclose()
    observer._closed = False
    with pytest.raises(HostUpgradeError, match="closed"):
        await observer.observe()
    assert case.providers == []


def test_fake_stopped_or_host_tree_capability_is_rejected(observer_case):
    case = observer_case
    with pytest.raises(TypeError, match="genuine"):
        case.build(stopped=SimpleNamespace())
    with pytest.raises(TypeError, match="genuine"):
        case.build(host_tree=SimpleNamespace())
    assert case.providers == []
