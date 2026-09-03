from __future__ import annotations

import hashlib

import bittensor as bt
import pytest

import umi.grandpa_finality as grandpa_finality
from umi.calibration_bundle import STAGE_IDS, GrandpaFinalityReplayVerifier
from umi.grandpa_finality import (
    CARGO_LOCK_SHA256,
    FIXTURE_SET_SHA256,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
)
from umi.policy import ScoringPolicy
from umi.substrate_proof import SubprocessStorageProofVerifier
from umi.validator_bundle_ports import (
    BittensorManifestSignatureVerifier,
    BundlePortCompositionError,
    build_production_calibration_bundle_verifier,
)
from umi.validator_pool_replay import ProofBackedPoolStageReplayHook
from umi.validator_terminal_effect import ReplayCalibrationBundleVerifier

from .factories import dev_wallet
from .test_substrate_proof import FAKE_SIDECAR
from .test_validator_closing_snapshot import _live_policy

TARGET = "aarch64-apple-darwin"


def _policy_for_files(proof_digest: str, finality_digest: str, chain_digest: str):
    data = _live_policy().model_dump(mode="json", by_alias=True)
    proof = data["implementation_pins"]["storage_proof_verifier"]
    proof["release_sha256_by_target"] = {TARGET: proof_digest}
    finality = data["implementation_pins"]["finality_verifier"]
    finality.update(
        {
            "source_revision": SOURCE_REVISION,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "cargo_lock_sha256": CARGO_LOCK_SHA256,
            "finality_fixture_set_sha256": FIXTURE_SET_SHA256,
            "release_sha256_by_target": {TARGET: finality_digest},
            "chain_spec_sha256": chain_digest,
        }
    )
    return ScoringPolicy.model_validate(data)


def test_production_bundle_builder_constructs_exact_seven_stage_replay_surface(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = FAKE_SIDECAR.resolve()
    binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    chain = tmp_path / "chain-spec.json"
    chain.write_bytes(b'{"name":"test"}\n')
    chain.chmod(0o600)
    chain_digest = hashlib.sha256(chain.read_bytes()).hexdigest()
    policy = _policy_for_files(binary_digest, binary_digest, chain_digest)
    pin = policy.implementation_pins.finality_verifier
    assert pin is not None
    monkeypatch.setattr(
        grandpa_finality,
        "FINNEY_CHAIN_SPEC_SOURCE_REVISION",
        pin.chain_spec_source_revision,
    )
    monkeypatch.setattr(grandpa_finality, "FINNEY_CHAIN_SPEC_SHA256", pin.chain_spec_sha256)
    monkeypatch.setattr(grandpa_finality, "FINNEY_GENESIS_HASH", pin.expected_genesis_hash)
    monkeypatch.setattr(
        grandpa_finality,
        "FINNEY_BOOTSTRAP_BLOCK_NUMBER",
        pin.bootstrap_block_number,
    )
    monkeypatch.setattr(
        grandpa_finality,
        "FINNEY_BOOTSTRAP_BLOCK_HASH",
        pin.bootstrap_block_hash,
    )
    proof = SubprocessStorageProofVerifier(
        binary_path=binary,
        expected_sha256=binary_digest,
    )

    verifier = build_production_calibration_bundle_verifier(
        policy=policy,
        target_triple=TARGET,
        finality_verifier_binary=binary,
        finality_chain_spec=chain,
        storage_proof_verifier=proof,
    )
    assert isinstance(verifier, ReplayCalibrationBundleVerifier)
    assert isinstance(verifier.ports.finality_verifier, GrandpaFinalityReplayVerifier)
    assert verifier.ports.event_proof_verifier is proof
    assert getattr(verifier.ports.extrinsics_root_verifier, "__self__", None) is proof
    assert len(verifier.ports.stage_replay_hooks) == len(STAGE_IDS)
    assert isinstance(
        next(iter(verifier.ports.stage_replay_hooks.values())),
        ProofBackedPoolStageReplayHook,
    )
    assert verifier.ports.storage_proof_verifier_sha256 == binary_digest
    assert verifier.ports.finality_verifier_sha256 == binary_digest


def test_builder_rejects_a_proof_verifier_from_another_release(tmp_path) -> None:
    binary = FAKE_SIDECAR.resolve()
    binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    chain = tmp_path / "chain-spec.json"
    chain.write_bytes(b"{}")
    chain.chmod(0o600)
    policy = _policy_for_files("11" * 32, binary_digest, hashlib.sha256(b"{}").hexdigest())
    proof = SubprocessStorageProofVerifier(
        binary_path=binary,
        expected_sha256=binary_digest,
    )
    with pytest.raises(BundlePortCompositionError, match="proof verifier pin mismatch"):
        build_production_calibration_bundle_verifier(
            policy=policy,
            target_triple=TARGET,
            finality_verifier_binary=binary,
            finality_chain_spec=chain,
            storage_proof_verifier=proof,
        )


def test_manifest_signature_verifier_checks_the_declared_hotkey_scheme() -> None:
    wallet = dev_wallet("//BundleVerifier")
    digest = hashlib.sha256(b"manifest").digest()
    signature = bytes(wallet.hotkey.sign(digest))
    scheme = bt.wallets.format_crypto_type(wallet.hotkey.crypto_type)
    verifier = BittensorManifestSignatureVerifier()
    account = bytes(wallet.hotkey.public_key)
    assert verifier(
        account_id32=account,
        scheme=scheme,
        digest=digest,
        signature=signature,
    )
    other = "ed25519" if scheme == "sr25519" else "sr25519"
    assert not verifier(
        account_id32=account,
        scheme=other,
        digest=digest,
        signature=signature,
    )
