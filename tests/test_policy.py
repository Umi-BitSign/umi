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
    scoring_policy_hash,
    umi_source_tree_sha256,
    validate_scoring_runtime,
)
from umi.protocol import canonical_json_bytes


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
