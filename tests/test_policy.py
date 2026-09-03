from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import bittensor as bt
import pytest
from pydantic import ValidationError

from umi.encoding import account_id32
from umi.policy import (
    SCORING_POLICY_SCHEMA,
    ExactRatio,
    PolicyImplementationPins,
    PublisherControlGroup,
    PublisherRegistryEntry,
    ScoringPolicy,
    ValidatorRegistryEntry,
    activation_equivalence_digest,
    require_live_chain_observation,
    scoring_policy_hash,
    umi_source_tree_sha256,
    validate_live_shadow_runtime,
    validate_scoring_runtime,
)
from umi.protocol import canonical_json_bytes
from umi.validator_delivery import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    MIRROR_DISCOVERY_SCHEMA,
    MirrorDiscoveryRule,
)


def _address(uri: str) -> str:
    return bt.sp_core.Keypair.create_from_uri(uri).ss58_address


def make_policy(
    *,
    active: bool = False,
    activation_block: int = 1_000,
) -> ScoringPolicy:
    group_rows = [(f"{index:064x}", _address(f"//Group{index}")) for index in range(1, 4)]
    groups = [
        PublisherControlGroup(control_group_id=group_id, administrator=administrator)
        for group_id, administrator in group_rows
    ]
    publishers = [
        PublisherRegistryEntry(
            publisher_hotkey=_address(f"//Publisher{index}"),
            owner_coldkey=administrator,
            control_group_id=group_id,
        )
        for index, (group_id, administrator) in enumerate(group_rows, start=1)
    ]
    publishers.sort(key=lambda item: account_id32(item.publisher_hotkey))
    validators = [
        ValidatorRegistryEntry(
            validator_hotkey=_address(f"//Validator{index}"),
            administrator_id=f"{100 + index:064x}",
        )
        for index in range(4)
    ]
    validators.sort(key=lambda item: account_id32(item.validator_hotkey))
    return ScoringPolicy.launch(
        translation_weights_active=active,
        activation_block=activation_block,
        minimum_publisher_collateral_alpha_rao=1_000_000_000,
        soak_start_window_index=7,
        validator_capacity_set_root="aa" * 32,
        validator_cost_schedule_hash="bb" * 32,
        implementation_pins=PolicyImplementationPins.local_rehearsal(),
        validator_registry=validators,
        control_group_registry=groups,
        publisher_registry=publishers,
    )


def test_launch_policy_is_complete_strict_and_canonical() -> None:
    policy = make_policy()

    assert policy.schema_ == SCORING_POLICY_SCHEMA
    assert policy.limits.emission_bearing_clips_per_batch == 12
    assert policy.limits.max_candidate_batches_total == 3
    assert policy.limits.btauth_max_age_seconds == 360
    assert policy.clock.issue_allowance_seconds == 300
    assert policy.clock.response_window_seconds == 300
    assert policy.limits.btauth_allowed_skew_seconds == 2
    assert policy.clock.window_stride_blocks == 360
    assert policy.thresholds.canary_fraction.fraction.numerator == 1
    assert policy.thresholds.canary_fraction.fraction.denominator == 10
    assert len(policy.publisher_registry) == len(policy.control_group_registry) == 3
    assert len(policy.validator_registry) == 4
    validate_scoring_runtime(policy)

    expected = hashlib.sha256(canonical_json_bytes(policy)).hexdigest()
    assert scoring_policy_hash(policy) == expected

    data = policy.model_dump(mode="json", by_alias=True)
    data["unexpected"] = True
    with pytest.raises(ValidationError):
        ScoringPolicy.model_validate(data)


@pytest.mark.parametrize(
    "field",
    ("activation_block", "minimum_publisher_collateral_alpha_rao"),
)
def test_policy_rejects_integer_values_outside_the_canonical_json_domain(field: str) -> None:
    data = make_policy().model_dump(mode="json", by_alias=True)
    data[field] = 2**53
    with pytest.raises(ValidationError, match="RFC 8785 JSON domain"):
        ScoringPolicy.model_validate(data)


def test_source_tree_integrity_hash_is_recomputed_after_mutation() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src" / "umi"
    probe = source_root / f"runtime_integrity_probe_{os.getpid()}.py"
    before = umi_source_tree_sha256()
    try:
        probe.write_bytes(b"RUNTIME_INTEGRITY_PROBE = True\n")
        assert umi_source_tree_sha256() != before
    finally:
        probe.unlink(missing_ok=True)
    assert umi_source_tree_sha256() == before


def test_runtime_rejects_a_shadowed_imported_module(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(make_policy()))
    shadow_root = tmp_path / "shadow"
    shadow_root.mkdir()
    (shadow_root / "rfc8785.py").write_text(
        "class CanonicalizationError(Exception):\n"
        "    pass\n"
        "class IntegerDomainError(CanonicalizationError):\n"
        "    pass\n"
        "class FloatDomainError(CanonicalizationError):\n"
        "    pass\n"
        "def dumps(value):\n"
        "    return b'{}'\n",
        encoding="utf-8",
    )
    source_root = Path(__file__).resolve().parents[1] / "src"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(shadow_root), str(source_root), environment.get("PYTHONPATH", "")]
    )
    script = """
from pathlib import Path
import sys
from umi.policy import ScoringPolicy, validate_rehearsal_runtime

policy = ScoringPolicy.model_validate_json(Path(sys.argv[1]).read_bytes())
try:
    validate_rehearsal_runtime(policy)
except RuntimeError as error:
    if "outside the pinned distribution: rfc8785" in str(error):
        raise SystemExit(0)
    raise
raise SystemExit("shadowed rfc8785 module was accepted")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(policy_path)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_activation_equivalence_removes_exactly_two_fields() -> None:
    shadow = make_policy(active=False, activation_block=1_000)
    later = make_policy(active=False, activation_block=9_000)

    assert scoring_policy_hash(shadow) != scoring_policy_hash(later)
    assert activation_equivalence_digest(shadow) == activation_equivalence_digest(later)

    changed_data = later.model_dump(mode="json", by_alias=True)
    changed_data["validator_capacity_set_root"] = "cc" * 32
    changed = ScoringPolicy.model_validate(changed_data)
    assert activation_equivalence_digest(changed) != activation_equivalence_digest(shadow)

    runtime_changed_data = later.model_dump(mode="json", by_alias=True)
    runtime_changed_data["implementation_pins"]["scoring"]["unicode_data_version"] = "0.0.0"
    runtime_changed = ScoringPolicy.model_validate(runtime_changed_data)
    with pytest.raises(RuntimeError, match="unicode_data_version"):
        validate_scoring_runtime(runtime_changed)

    local_active_data = make_policy().model_dump(mode="json", by_alias=True)
    local_active_data["translation_weights_active"] = True
    with pytest.raises(ValidationError, match="Input should be False"):
        ScoringPolicy.model_validate(local_active_data)


def test_policy_rejects_registry_ambiguity_and_nonlaunch_parameters() -> None:
    policy = make_policy()
    unsorted = policy.model_dump(mode="json", by_alias=True)
    unsorted["publisher_registry"] = list(reversed(unsorted["publisher_registry"]))
    with pytest.raises(ValidationError, match="sorted by hotkey"):
        ScoringPolicy.model_validate(unsorted)

    duplicate_group = policy.model_dump(mode="json", by_alias=True)
    duplicate_group["publisher_registry"][1]["control_group_id"] = duplicate_group[
        "publisher_registry"
    ][0]["control_group_id"]
    with pytest.raises(ValidationError, match="every launch control group"):
        ScoringPolicy.model_validate(duplicate_group)

    changed_limit = policy.model_dump(mode="json", by_alias=True)
    changed_limit["limits"]["emission_bearing_clips_per_batch"] = 13
    with pytest.raises(ValidationError, match="initial launch profile"):
        ScoringPolicy.model_validate(changed_limit)

    short_auth_window = policy.model_dump(mode="json", by_alias=True)
    short_auth_window["limits"]["btauth_max_age_seconds"] = 30
    with pytest.raises(ValidationError, match="shorter than the issue allowance"):
        ScoringPolicy.model_validate(short_auth_window)

    duplicate_validator_admin = policy.model_dump(mode="json", by_alias=True)
    duplicate_validator_admin["validator_registry"][1]["administrator_id"] = (
        duplicate_validator_admin["validator_registry"][0]["administrator_id"]
    )
    with pytest.raises(ValidationError, match="administrator IDs"):
        ScoringPolicy.model_validate(duplicate_validator_admin)


def test_exact_ratio_requires_reduced_integer_arithmetic() -> None:
    assert ExactRatio(numerator=1, denominator=10).fraction.numerator == 1
    with pytest.raises(ValidationError, match="reduced"):
        ExactRatio(numerator=2, denominator=20)
    with pytest.raises(ValidationError):
        ExactRatio.model_validate({"numerator": 0.1, "denominator": 1})


def _live_shadow_policy_data() -> dict:
    data = make_policy().model_dump(mode="json", by_alias=True)
    pins = data["implementation_pins"]
    pins["pin_profile"] = "live_shadow_calibration"
    pins["conformance_fixtures_verified"] = True
    pins["conformance_execution_report_sha256"] = "0f" * 32
    pins["scoring"]["normalization_fixture_set_sha256"] = "10" * 32
    pins["media"]["frame_digest_fixture_set_sha256"] = "11" * 32
    pins["timelock"]["portable_envelope_fixture_set_sha256"] = "12" * 32
    pins["chain"]["chain_fixture_set_sha256"] = "13" * 32
    discovery = MirrorDiscoveryRule(
        schema=MIRROR_DISCOVERY_SCHEMA,
        protocol="umi-asl/0.1",
        authentication_profile=pins["rules"]["mirror_authentication_profile"],
        index_path_template=DEFAULT_MIRROR_INDEX_PATH,
        delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
        origins=[
            "https://mirror.example",
            "https://mirror1.example",
            "https://mirror2.example",
        ],
        delivery_origins=[
            "https://delivery.example",
            "https://delivery1.example",
            "https://delivery2.example",
        ],
    )
    pins["rules"]["mirror_discovery_rule_sha256"] = hashlib.sha256(
        canonical_json_bytes(discovery)
    ).hexdigest()
    pins["live_chain"] = {
        "network": "finney",
        "genesis_block_hash": "15" * 32,
        "runtime_spec_version": 452,
        "transaction_version": 1,
        "state_version": 1,
        "metadata_sha256": "16" * 32,
        "subtensor_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
        "live_chain_fixture_set_sha256": "17" * 32,
    }
    pins["storage_proof_verifier"] = {
        "protocol": "umi-substrate-proof-verifier/1",
        "polkadot_sdk_revision": "cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a",
        "source_tree_sha256": "18" * 32,
        "cargo_lock_sha256": "19" * 32,
        "proof_fixture_set_sha256": "1a" * 32,
        "release_sha256_by_target": {
            "aarch64-apple-darwin": "1b" * 32,
            "x86_64-unknown-linux-gnu": "1c" * 32,
        },
    }
    pins["finality_verifier"] = {
        "profile": "smoldot-verifier-attested-finality/1",
        "evidence_class": "verifier_attested_finality",
        "offline_finality_proof": False,
        "source_revision": "finality-verifier-v1",
        "source_tree_sha256": "1d" * 32,
        "cargo_lock_sha256": "1e" * 32,
        "finality_fixture_set_sha256": "1f" * 32,
        "release_sha256_by_target": {
            "aarch64-apple-darwin": "20" * 32,
            "x86_64-unknown-linux-gnu": "21" * 32,
        },
        "chain_spec_source_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
        "chain_spec_sha256": "22" * 32,
        "expected_genesis_hash": "15" * 32,
        "bootstrap_kind": "grandpa_warp_sync_checkpoint",
        "bootstrap_block_number": 1,
        "bootstrap_block_hash": "24" * 32,
    }
    return data


def test_live_shadow_profile_requires_all_verified_runtime_boundaries() -> None:
    policy = ScoringPolicy.model_validate(_live_shadow_policy_data())
    assert policy.implementation_pins.pin_profile == "live_shadow_calibration"
    assert policy.implementation_pins.conformance_fixtures_verified
    assert policy.implementation_pins.storage_proof_verifier is not None
    assert policy.translation_weights_active is False

    missing = _live_shadow_policy_data()
    missing["implementation_pins"]["finality_verifier"] = None
    with pytest.raises(ValidationError, match="requires chain, storage-proof, and finality"):
        ScoringPolicy.model_validate(missing)

    unverified = _live_shadow_policy_data()
    unverified["implementation_pins"]["conformance_fixtures_verified"] = False
    with pytest.raises(ValidationError, match="requires verified conformance fixtures"):
        ScoringPolicy.model_validate(unverified)

    missing_report = _live_shadow_policy_data()
    missing_report["implementation_pins"]["conformance_execution_report_sha256"] = None
    with pytest.raises(ValidationError, match="requires a conformance execution report"):
        ScoringPolicy.model_validate(missing_report)


def test_live_shadow_profile_rejects_rehearsal_placeholders_and_invalid_targets() -> None:
    placeholder = _live_shadow_policy_data()
    placeholder["implementation_pins"]["chain"]["chain_fixture_set_sha256"] = hashlib.sha256(
        b"umi-rehearsal-placeholder-v1\0chain-schedule-and-calls"
    ).hexdigest()
    with pytest.raises(ValidationError, match="rehearsal placeholder"):
        ScoringPolicy.model_validate(placeholder)

    invalid_target = _live_shadow_policy_data()
    releases = invalid_target["implementation_pins"]["storage_proof_verifier"][
        "release_sha256_by_target"
    ]
    releases["../../not-a-target"] = releases.pop("x86_64-unknown-linux-gnu")
    with pytest.raises(ValidationError, match="canonical target triples"):
        ScoringPolicy.model_validate(invalid_target)

    local_with_live_pin = make_policy().model_dump(mode="json", by_alias=True)
    local_with_live_pin["implementation_pins"]["live_chain"] = _live_shadow_policy_data()[
        "implementation_pins"
    ]["live_chain"]
    with pytest.raises(ValidationError, match="cannot carry live-chain"):
        ScoringPolicy.model_validate(local_with_live_pin)


def test_live_shadow_finality_checkpoint_and_genesis_are_policy_bound() -> None:
    mismatch = _live_shadow_policy_data()
    mismatch["implementation_pins"]["finality_verifier"]["expected_genesis_hash"] = "23" * 32
    with pytest.raises(ValidationError, match="genesis hashes must match"):
        ScoringPolicy.model_validate(mismatch)

    invalid_checkpoint = _live_shadow_policy_data()
    invalid_checkpoint["implementation_pins"]["finality_verifier"]["bootstrap_block_number"] = 0
    with pytest.raises(ValidationError, match="must be above genesis"):
        ScoringPolicy.model_validate(invalid_checkpoint)

    legacy_checkpoint = _live_shadow_policy_data()
    finality = legacy_checkpoint["implementation_pins"]["finality_verifier"]
    finality["bootstrap_kind"] = "light_sync_state"
    with pytest.raises(ValidationError, match="grandpa_warp_sync_checkpoint"):
        ScoringPolicy.model_validate(legacy_checkpoint)


def test_live_shadow_runtime_selects_and_verifies_exact_target_binaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = (tmp_path / "proof-verifier").resolve()
    finality = (tmp_path / "finality-verifier").resolve()
    chain_spec = (tmp_path / "finney.json").resolve()
    proof.write_bytes(b"proof release")
    finality.write_bytes(b"finality release")
    chain_spec.write_bytes(b'{"name":"finney"}')
    proof.chmod(0o700)
    finality.chmod(0o700)
    chain_spec.chmod(0o600)
    data = _live_shadow_policy_data()
    target = "aarch64-apple-darwin"
    pins = data["implementation_pins"]
    pins["storage_proof_verifier"]["release_sha256_by_target"][target] = hashlib.sha256(
        proof.read_bytes()
    ).hexdigest()
    pins["finality_verifier"]["release_sha256_by_target"][target] = hashlib.sha256(
        finality.read_bytes()
    ).hexdigest()
    pins["finality_verifier"]["chain_spec_sha256"] = hashlib.sha256(
        chain_spec.read_bytes()
    ).hexdigest()
    policy = ScoringPolicy.model_validate(data)

    selected = validate_live_shadow_runtime(
        policy,
        target_triple=target,
        storage_proof_verifier_binary=proof,
        finality_verifier_binary=finality,
        finality_chain_spec_path=chain_spec,
    )
    assert selected == {
        "target_triple": target,
        "storage_proof_verifier_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
        "finality_verifier_sha256": hashlib.sha256(finality.read_bytes()).hexdigest(),
        "finality_chain_spec_sha256": hashlib.sha256(chain_spec.read_bytes()).hexdigest(),
        "finality_evidence_class": "verifier_attested_finality",
        "finality_bootstrap_kind": "grandpa_warp_sync_checkpoint",
        "finality_bootstrap_block_number": "1",
        "finality_bootstrap_block_hash": "24" * 32,
    }
    assert policy.implementation_pins.live_chain is not None
    require_live_chain_observation(policy, policy.implementation_pins.live_chain)

    proof.write_bytes(b"tampered release")
    with pytest.raises(RuntimeError, match="storage-proof verifier binary"):
        validate_live_shadow_runtime(
            policy,
            target_triple=target,
            storage_proof_verifier_binary=proof,
            finality_verifier_binary=finality,
            finality_chain_spec_path=chain_spec,
        )

    proof.write_bytes(b"proof release")
    chain_spec.write_bytes(b'{"name":"tampered"}')
    with pytest.raises(RuntimeError, match="finality chain spec"):
        validate_live_shadow_runtime(
            policy,
            target_triple=target,
            storage_proof_verifier_binary=proof,
            finality_verifier_binary=finality,
            finality_chain_spec_path=chain_spec,
        )

    chain_spec.write_bytes(b'{"name":"finney"}')
    proof.chmod(0o600)
    with pytest.raises(RuntimeError, match="not executable by its owner"):
        validate_live_shadow_runtime(
            policy,
            target_triple=target,
            storage_proof_verifier_binary=proof,
            finality_verifier_binary=finality,
            finality_chain_spec_path=chain_spec,
        )

    proof.chmod(0o700)
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    with pytest.raises(RuntimeError, match="unsafe ownership"):
        validate_live_shadow_runtime(
            policy,
            target_triple=target,
            storage_proof_verifier_binary=proof,
            finality_verifier_binary=finality,
            finality_chain_spec_path=chain_spec,
        )


def test_local_profile_cannot_pass_live_runtime_validation(tmp_path: Path) -> None:
    binary = (tmp_path / "verifier").resolve()
    binary.write_bytes(b"release")
    binary.chmod(0o700)
    with pytest.raises(RuntimeError, match="not a live shadow"):
        validate_live_shadow_runtime(
            make_policy(),
            target_triple="aarch64-apple-darwin",
            storage_proof_verifier_binary=binary,
            finality_verifier_binary=binary,
            finality_chain_spec_path=binary,
        )
