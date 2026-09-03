from __future__ import annotations

import asyncio
import inspect
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import pytest

from tests.factories import dev_wallet
from tests.test_policy import make_policy
from tests.test_publisher_availability import (
    _candidate_material,
    _fake_inspect_factory,
    _window,
)
from tests.test_publisher_availability_authority import _proof_material
from tests.test_validator_closing_snapshot import _FakeProofs, _Finality, _values
from tests.test_validator_plans import (
    ReadinessPort,
)
from tests.test_validator_plans import (
    _block as _plan_block,
)
from tests.test_validator_plans import (
    _checkpoint as _plan_checkpoint,
)
from tests.test_validator_plans import (
    _live_policy as _plan_policy,
)
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.publisher_availability import AvailabilityWindow, AvailabilityWorkflowError
from umi.publisher_availability_authority import (
    VerifiedQualificationObservation,
    protocol_state_genesis_evidence,
)
from umi.publisher_availability_cli import (
    ANNOUNCEMENT_PROOF_FILENAME,
    ANNOUNCEMENT_SET_FILENAME,
    ASSEMBLY_CONFIG_SCHEMA,
    AUTHORITY_COLLECTION_FILENAME,
    COLLECTION_OBSERVATION_AFTER_FILENAME,
    COLLECTION_OBSERVATION_BEFORE_FILENAME,
    QUALIFICATION_AUTHORITY_CONFIG_SCHEMA,
    QualificationAuthorityConfig,
    _replay_protocol_state_authority,
    run,
)
from umi.validator_journal import ValidatorStageJournal
from umi.validator_live import LiveValidatorPaths
from umi.validator_plans import DeterministicWindowPlanSource
from umi.validator_protocol_state import (
    ValidatorProtocolStateStore,
    encode_protocol_state_snapshot,
)
from umi.validator_state import TerminalOutcome, ValidatorControlPlane


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _assembly_config(tmp_path: Path, policy, window) -> Path:
    bodies, public, envelopes, videos = _candidate_material(policy, window)
    inputs = tmp_path / "inputs"
    pool_paths = [
        str(_write(inputs / f"pool-{index}.json", raw).absolute())
        for index, raw in enumerate(bodies)
    ]
    public_paths = [
        str(_write(inputs / f"public-{batch_id}.json", raw).absolute())
        for batch_id, raw in public.items()
    ]
    envelope_rows = [
        {
            "batch_id": batch_id,
            "path": str(_write(inputs / f"envelope-{batch_id}.bin", raw).absolute()),
        }
        for batch_id, raw in sorted(envelopes.items(), key=lambda item: item[0])
    ]
    video_rows = [
        {
            "batch_id": batch_id,
            "challenge_id": challenge_id,
            "path": str(
                _write(
                    inputs / f"video-{batch_id}-{challenge_id}.mp4",
                    raw,
                ).absolute()
            ),
        }
        for (batch_id, challenge_id), raw in sorted(videos.items())
    ]
    document = {
        "schema": ASSEMBLY_CONFIG_SCHEMA,
        "protocol": "umi-asl/0.1",
        "window": AvailabilityWindow.from_plan(window).model_dump(mode="json"),
        "pool_body_paths": sorted(pool_paths),
        "public_manifest_paths": sorted(public_paths),
        "ground_truth_envelopes": envelope_rows,
        "videos": video_rows,
    }
    return _write(tmp_path / "assembly.json", canonical_json_bytes(document))


def _authority_config(tmp_path: Path, _protocol_database: Path) -> Path:
    binaries = tmp_path / "authority-inputs"
    proof = _write(binaries / "proof-verifier", b"proof")
    finality = _write(binaries / "finality-verifier", b"finality")
    chain_spec = _write(binaries / "chain-spec.json", b"{}")
    state_root = (tmp_path / "validator-state").absolute()
    state_root.mkdir(mode=0o700)
    paths = LiveValidatorPaths.below(state_root)
    _write(paths.control_plane, b"state")
    _write(paths.plan_observations, b"state")
    _write(paths.finality_state, b"state")
    paths.stage_journal.mkdir()
    with ValidatorProtocolStateStore(paths.protocol_state):
        pass
    document = {
        "schema": QUALIFICATION_AUTHORITY_CONFIG_SCHEMA,
        "protocol": "umi-asl/0.1",
        "network": "finney",
        "target_triple": "aarch64-apple-darwin",
        "storage_proof_verifier_binary": str(proof.absolute()),
        "finality_verifier_binary": str(finality.absolute()),
        "finality_chain_spec_path": str(chain_spec.absolute()),
        "validator_state_root": str(state_root),
        "finality_startup_timeout_seconds": 1,
    }
    return _write(tmp_path / "authority.json", canonical_json_bytes(document))


def _mock_authority_runtime(monkeypatch: pytest.MonkeyPatch, observation) -> None:
    monkeypatch.setattr(
        "umi.publisher_availability_cli.validate_live_shadow_runtime",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        "umi.publisher_availability_cli.SubprocessStorageProofVerifier",
        lambda **_kwargs: lambda **_proof_kwargs: True,
    )
    monkeypatch.setattr(
        "umi.publisher_availability_cli.GrandpaFinalityObserver.from_policy_pin",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        "umi.publisher_availability_cli.GrandpaFinalityReplayVerifier",
        lambda _observer: lambda **_kwargs: True,
    )
    monkeypatch.setattr(
        "umi.publisher_availability_cli._capture_qualification_observation",
        lambda *_args, **_kwargs: observation,
    )

    async def replay_protocol_state(*, policy, paths, window, **_kwargs):
        with ValidatorProtocolStateStore(paths.protocol_state) as store:
            state = store.audit()
            state_bytes = encode_protocol_state_snapshot(state)
        return state_bytes, protocol_state_genesis_evidence(
            protocol_state_bytes=state_bytes,
            protocol_state=state,
            window_id=window.window_id,
            policy_hash=scoring_policy_hash(policy),
        )

    monkeypatch.setattr(
        "umi.publisher_availability_cli._replay_protocol_state_authority",
        replay_protocol_state,
    )


class _ReadOnlyCollectionFinality:
    def __init__(self, delegate, *, persisted_height: int) -> None:
        self.delegate = delegate
        self.persisted_height = persisted_height
        self.closed = False

    def __getattr__(self, name: str):
        return getattr(self.delegate, name)

    def audit(self) -> None:
        return None

    def persisted_head(self):
        return SimpleNamespace(height=self.persisted_height)

    def close(self) -> None:
        self.closed = True


class _ReadOnlyClient:
    def __init__(self, network: str) -> None:
        self.network = network
        self.endpoint = "wss://entrypoint-finney.opentensor.ai:443"
        self.closed = False

    async def connect(self):
        return self

    async def close(self) -> None:
        self.closed = True


class _AuthorityStateFinality:
    def __init__(self, policy, blocks) -> None:
        self.chain_observation = policy.implementation_pins.live_chain
        pin = policy.implementation_pins.finality_verifier
        assert pin is not None
        self.finality_verifier_sha256 = next(iter(pin.release_sha256_by_target.values()))
        self.blocks = {block.height: block for block in blocks}
        self.closed = False

    def audit(self) -> None:
        return None

    async def finalized_head_height(self) -> int:
        return max(self.blocks)

    async def verified_block_at(self, height: int):
        return self.blocks.get(height)

    def close(self) -> None:
        self.closed = True


class _UnusedBundleVerifier:
    async def verify(self, _root):
        raise AssertionError("a missing prior bundle must not be synthesized")


def _mock_collection_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    policy,
    work,
    observation,
    announcement_timestamp_ms: int | None = None,
):
    _mock_authority_runtime(monkeypatch, observation)
    values, _hotkeys, _root = _values(policy, work)
    delegate = _Finality(policy, work)
    if announcement_timestamp_ms is not None:
        height = work.window.plan.announcement_block
        delegate.blocks[height] = replace(
            delegate.blocks[height],
            timestamp_ms=announcement_timestamp_ms,
        )
    finality = _ReadOnlyCollectionFinality(
        delegate,
        persisted_height=work.window.plan.announcement_block,
    )
    monkeypatch.setattr(
        "umi.publisher_availability_cli.DurableGrandpaFinalityPort.from_policy",
        lambda *_args, **_kwargs: finality,
    )
    monkeypatch.setattr(
        "umi.publisher_availability_cli.FinalizedProofCollector",
        lambda *_args, **_kwargs: _FakeProofs(values),
    )
    return finality


def _continuity_state(
    tmp_path: Path,
    *,
    policy,
    later_window: bool,
):
    state_root = (tmp_path / "continuity-validator-state").absolute()
    state_root.mkdir(mode=0o700)
    paths = LiveValidatorPaths.below(state_root)
    with ValidatorProtocolStateStore(paths.protocol_state):
        pass
    ValidatorStageJournal(paths.stage_journal)
    _write(paths.finality_state, b"test-finality-state")
    paths.bundles.mkdir()
    paths.incident_bundles.mkdir()
    control = ValidatorControlPlane(paths.control_plane)
    blocks = [_plan_block(policy, 0)]
    finality = _AuthorityStateFinality(policy, blocks)
    source = DeterministicWindowPlanSource(
        policy=policy,
        control_plane=control,
        finalized_blocks=finality,
        prior_readiness=ReadinessPort(),
        observation_cache_path=paths.plan_observations,
    )
    plan0 = asyncio.run(source.next_plan())
    assert plan0 is not None
    control.start_window(plan0, operation_id="start-window-0")
    if not later_window:
        return paths, control, finality, plan0

    control.terminate_window(
        plan0.window_id,
        outcome=TerminalOutcome.VOID,
        reason_code="test_prior_void",
        evidence_sha256="aa" * 32,
        audit_release_block=plan0.closing_block + 10,
        operation_id="terminate-window-0",
    )
    previous = control.get_window(plan0.window_id)
    block1 = _plan_block(policy, 1)
    finality.blocks[block1.height] = block1
    source = DeterministicWindowPlanSource(
        policy=policy,
        control_plane=control,
        finalized_blocks=finality,
        prior_readiness=ReadinessPort([_plan_checkpoint(previous)]),
        observation_cache_path=paths.plan_observations,
    )
    plan1 = asyncio.run(source.next_plan())
    assert plan1 is not None
    control.start_window(plan1, operation_id="start-window-1")
    return paths, control, finality, plan1


def _continuity_config(tmp_path: Path, paths: LiveValidatorPaths) -> QualificationAuthorityConfig:
    inputs = tmp_path / "continuity-authority-inputs"
    proof = _write(inputs / "proof-verifier", b"proof")
    finality = _write(inputs / "finality-verifier", b"finality")
    chain_spec = _write(inputs / "chain-spec.json", b"{}")
    return QualificationAuthorityConfig(
        schema=QUALIFICATION_AUTHORITY_CONFIG_SCHEMA,
        protocol="umi-asl/0.1",
        network="finney",
        target_triple="aarch64-apple-darwin",
        storage_proof_verifier_binary=str(proof.absolute()),
        finality_verifier_binary=str(finality.absolute()),
        finality_chain_spec_path=str(chain_spec.absolute()),
        validator_state_root=str(paths.root),
        finality_startup_timeout_seconds=1,
    )


def _mock_continuity_composition(
    monkeypatch: pytest.MonkeyPatch,
    *,
    finality: _AuthorityStateFinality,
) -> None:
    monkeypatch.setattr(
        "umi.publisher_availability_cli.DurableGrandpaFinalityPort.from_policy",
        lambda *_args, **_kwargs: finality,
    )
    monkeypatch.setattr(
        "umi.publisher_availability_cli.build_production_calibration_bundle_verifier",
        lambda **_kwargs: SimpleNamespace(ports=object()),
    )
    monkeypatch.setattr(
        "umi.publisher_availability_cli.ReplayPublishedBundleVerifier",
        lambda _ports: _UnusedBundleVerifier(),
    )


def test_assemble_check_performs_no_output_or_state_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    policy_path = _write(tmp_path / "policy.json", canonical_json_bytes(policy))
    assembly = _assembly_config(tmp_path, policy, window)
    output = tmp_path / "must-not-exist"
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )

    assert (
        run(
            [
                "assemble",
                "--policy",
                str(policy_path),
                "--assembly",
                str(assembly),
                "--output",
                str(output),
                "--check",
            ]
        )
        == 0
    )
    assert not output.exists()
    assert '"state_mutated":false' in capsys.readouterr().out


def test_collect_authority_materializes_exact_early_proof_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy, work, loaded, collected, observation = asyncio.run(
        _proof_material(tmp_path, monkeypatch)
    )
    policy_path = _write(tmp_path / "policy.json", canonical_json_bytes(policy))
    protocol_database = (tmp_path / "protocol-state.sqlite3").absolute()
    with ValidatorProtocolStateStore(protocol_database):
        pass
    authority_config = _authority_config(tmp_path, protocol_database)
    finality = _mock_collection_runtime(
        monkeypatch,
        policy=policy,
        work=work,
        observation=observation,
        announcement_timestamp_ms=(collected.announcement_snapshot.announcement_block_timestamp_ms),
    )
    clients: list[_ReadOnlyClient] = []

    def client_factory(network: str):
        client = _ReadOnlyClient(network)
        clients.append(client)
        return client

    output = (tmp_path / "announcement-authority").absolute()
    assert (
        run(
            [
                "collect-authority",
                "--policy",
                str(policy_path),
                "--candidate-bundle",
                str(loaded.root),
                "--authority-config",
                str(authority_config),
                "--output",
                str(output),
            ],
            client_factory=client_factory,
        )
        == 0
    )

    assert (output / ANNOUNCEMENT_SET_FILENAME).read_bytes() == (
        collected.announcement_snapshot_bytes
    )
    assert (output / ANNOUNCEMENT_PROOF_FILENAME).read_bytes() == (
        collected.announcement_proof_evidence_bytes
    )
    assert (output / COLLECTION_OBSERVATION_BEFORE_FILENAME).read_bytes() == (
        observation.finality_evidence_bytes
    )
    assert (output / COLLECTION_OBSERVATION_AFTER_FILENAME).read_bytes() == (
        observation.finality_evidence_bytes
    )
    assert (output / AUTHORITY_COLLECTION_FILENAME).is_file()
    assert clients and clients[0].network == "finney" and clients[0].closed
    assert finality.closed
    result = capsys.readouterr().out
    assert '"status":"collected"' in result
    assert '"broadcast_performed":false' in result


def test_collect_authority_check_is_read_only_and_rejects_late_head_before_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy, work, loaded, _collected, observation = asyncio.run(
        _proof_material(tmp_path, monkeypatch)
    )
    policy_path = _write(tmp_path / "policy.json", canonical_json_bytes(policy))
    protocol_database = (tmp_path / "protocol-state.sqlite3").absolute()
    with ValidatorProtocolStateStore(protocol_database):
        pass
    authority_config = _authority_config(tmp_path, protocol_database)
    late = VerifiedQualificationObservation(
        block_number=work.window.plan.proposal_close_block,
        block_hash=observation.block_hash,
        finality_evidence_bytes=observation.finality_evidence_bytes,
    )
    _mock_authority_runtime(monkeypatch, late)

    def forbidden_client(_network: str):
        raise AssertionError("late collection must stop before proof RPC")

    output = (tmp_path / "must-not-exist").absolute()
    assert (
        run(
            [
                "collect-authority",
                "--policy",
                str(policy_path),
                "--candidate-bundle",
                str(loaded.root),
                "--authority-config",
                str(authority_config),
                "--output",
                str(output),
                "--check",
            ],
            client_factory=forbidden_client,
        )
        == 2
    )
    assert not output.exists()
    assert "authority_collection_outside_proposal_interval" in capsys.readouterr().err


def test_collect_authority_discards_proofs_if_proposal_closes_during_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy, work, loaded, _collected, observation = asyncio.run(
        _proof_material(tmp_path, monkeypatch)
    )
    policy_path = _write(tmp_path / "policy.json", canonical_json_bytes(policy))
    protocol_database = (tmp_path / "protocol-state.sqlite3").absolute()
    with ValidatorProtocolStateStore(protocol_database):
        pass
    authority_config = _authority_config(tmp_path, protocol_database)
    _mock_collection_runtime(
        monkeypatch,
        policy=policy,
        work=work,
        observation=observation,
    )
    late = VerifiedQualificationObservation(
        block_number=work.window.plan.proposal_close_block,
        block_hash="0x" + "bb" * 32,
        finality_evidence_bytes=canonical_json_bytes({"schema": "test-finality", "sequence": 1}),
    )
    observations = iter((observation, late))
    monkeypatch.setattr(
        "umi.publisher_availability_cli._capture_qualification_observation",
        lambda *_args, **_kwargs: next(observations),
    )

    output = (tmp_path / "must-not-exist").absolute()
    assert (
        run(
            [
                "collect-authority",
                "--policy",
                str(policy_path),
                "--candidate-bundle",
                str(loaded.root),
                "--authority-config",
                str(authority_config),
                "--output",
                str(output),
            ],
            client_factory=_ReadOnlyClient,
        )
        == 2
    )
    assert not output.exists()
    assert "authority_collection_outside_proposal_interval" in capsys.readouterr().err


def test_protocol_state_authority_accepts_only_exact_first_window_genesis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _plan_policy()
    paths, _control, finality, plan = _continuity_state(
        tmp_path,
        policy=policy,
        later_window=False,
    )
    config = _continuity_config(tmp_path, paths)
    _mock_continuity_composition(monkeypatch, finality=finality)

    state_bytes, continuity = asyncio.run(
        _replay_protocol_state_authority(
            policy=policy,
            config=config,
            paths=paths,
            window=plan,
            storage_verifier=object(),  # composition is isolated; no proof is read at genesis
        )
    )

    assert b'"last_window_index":-1' in state_bytes
    assert b'"schema":"umi-availability-protocol-state-genesis/1"' in continuity
    assert finality.closed


def test_protocol_state_authority_rejects_fresh_database_after_prior_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _plan_policy()
    paths, _control, finality, plan = _continuity_state(
        tmp_path,
        policy=policy,
        later_window=True,
    )
    config = _continuity_config(tmp_path, paths)
    _mock_continuity_composition(monkeypatch, finality=finality)

    with pytest.raises(
        AvailabilityWorkflowError,
        match="qualification_prior_window_not_ready",
    ):
        asyncio.run(
            _replay_protocol_state_authority(
                policy=policy,
                config=config,
                paths=paths,
                window=plan,
                storage_verifier=object(),
            )
        )
    assert finality.closed


def test_qualification_check_does_not_open_wallet_or_create_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy, _work_item, loaded, collected, observation = asyncio.run(
        _proof_material(tmp_path, monkeypatch)
    )
    policy_path = _write(tmp_path / "policy.json", canonical_json_bytes(policy))
    snapshot_path = _write(
        tmp_path / "announcement-snapshot.json",
        collected.announcement_snapshot_bytes,
    )
    proof_path = _write(
        tmp_path / "announcement-proof.json",
        collected.announcement_proof_evidence_bytes,
    )
    protocol_database = (tmp_path / "protocol-state.sqlite3").absolute()
    with ValidatorProtocolStateStore(protocol_database):
        pass
    authority_config = _authority_config(tmp_path, protocol_database)
    validator_hotkey = next(
        item.validator_hotkey
        for item in collected.announcement_snapshot.validators
        if item.validator_permit
    )
    _mock_authority_runtime(monkeypatch, observation)
    state = tmp_path / "must-not-exist"
    receipt = tmp_path / "must-not-exist-receipt.json"
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )

    def forbidden_wallet(*_args, **_kwargs):
        raise AssertionError("--check must not open a wallet")

    monkeypatch.setattr("umi.publisher_availability_cli.bt.Wallet", forbidden_wallet)
    assert (
        run(
            [
                "qualify",
                "--policy",
                str(policy_path),
                "--candidate-bundle",
                str(loaded.root),
                "--announcement-snapshot",
                str(snapshot_path),
                "--announcement-proof",
                str(proof_path),
                "--authority-config",
                str(authority_config),
                "--validator-hotkey",
                validator_hotkey,
                "--state-root",
                str(state),
                "--receipt-output",
                str(receipt),
                "--wallet-name",
                "validator",
                "--wallet-hotkey-name",
                "default",
                "--wallet-path",
                str(tmp_path / "wallet"),
                "--check",
            ]
        )
        == 0
    )
    assert not state.exists()
    assert not receipt.exists()
    output = capsys.readouterr().out
    assert '"signature_created":false' in output
    assert '"state_mutated":false' in output


def test_installed_workflow_signs_then_aggregate_check_remains_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy, _work_item, loaded, collected, observation = asyncio.run(
        _proof_material(tmp_path, monkeypatch)
    )
    policy_path = _write(tmp_path / "policy.json", canonical_json_bytes(policy))
    snapshot_path = _write(
        tmp_path / "announcement-snapshot.json",
        collected.announcement_snapshot_bytes,
    )
    proof_path = _write(
        tmp_path / "announcement-proof.json",
        collected.announcement_proof_evidence_bytes,
    )
    protocol_database = (tmp_path / "protocol-state.sqlite3").absolute()
    with ValidatorProtocolStateStore(protocol_database):
        pass
    authority_config = _authority_config(tmp_path, protocol_database)
    _mock_authority_runtime(monkeypatch, observation)
    receipt_paths: list[Path] = []
    for index in range(3):
        receipt_path = tmp_path / f"receipt-{index}.json"
        receipt_paths.append(receipt_path)
        monkeypatch.setattr(
            "umi.publisher_availability_cli.bt.Wallet",
            lambda index=index, **_kwargs: dev_wallet(f"//Validator{index}"),
        )
        assert (
            run(
                [
                    "qualify",
                    "--policy",
                    str(policy_path),
                    "--candidate-bundle",
                    str(loaded.root),
                    "--announcement-snapshot",
                    str(snapshot_path),
                    "--announcement-proof",
                    str(proof_path),
                    "--authority-config",
                    str(authority_config),
                    "--validator-hotkey",
                    dev_wallet(f"//Validator{index}").hotkey.ss58_address,
                    "--state-root",
                    str((tmp_path / f"state-{index}").absolute()),
                    "--receipt-output",
                    str(receipt_path.absolute()),
                    "--wallet-name",
                    "validator",
                    "--wallet-hotkey-name",
                    "default",
                    "--wallet-path",
                    str((tmp_path / f"wallet-{index}").absolute()),
                ]
            )
            == 0
        )
        assert receipt_path.exists()
    capsys.readouterr()

    output = tmp_path / "must-not-exist-release"
    arguments = [
        "aggregate",
        "--policy",
        str(policy_path),
        "--candidate-bundle",
        str(loaded.root),
        "--output",
        str(output),
        "--check",
    ]
    for receipt in receipt_paths:
        arguments.extend(("--receipt", str(receipt)))
    assert run(arguments) == 0
    assert not output.exists()
    result = capsys.readouterr().out
    assert '"broadcast_performed":false' in result
    assert '"state_mutated":false' in result

    import umi.publisher_availability_cli as cli

    source = inspect.getsource(cli)
    assert "commit_timelocked_mechanism_weights" not in source
    assert "Commitments.set_commitment" not in source
    assert "commit_timelocked" not in source
    assert "set_weights" not in source
