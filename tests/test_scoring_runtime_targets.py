from __future__ import annotations

import pytest
from pydantic import ValidationError

from umi.policy import ScoringPolicy, scoring_policy_hash, validate_scoring_runtime
from umi.protocol import canonical_json_bytes
from umi.runtime_targets import scoring_runtime_target

from .test_policy import make_policy

MAC = "aarch64-apple-darwin"
LINUX = "x86_64-unknown-linux-gnu"
ARTIFACT_FIELDS = (
    "regex_distribution_content_sha256",
    "rfc8785_distribution_content_sha256",
    "pydantic_distribution_content_sha256",
    "pydantic_core_distribution_content_sha256",
)


@pytest.fixture
def document():
    return make_policy().model_dump(mode="json", by_alias=True)


def portable(document):
    pins = document["implementation_pins"]
    actual = pins["scoring"].copy()
    other = {**actual, **dict.fromkeys(ARTIFACT_FIELDS, "ab" * 32)}
    pins["scoring"] = other
    pins["scoring_by_target"] = {MAC: other, LINUX: actual}
    return document


def test_legacy_policy_bytes_and_runtime_validation_are_unchanged(document):
    assert "scoring_by_target" not in document["implementation_pins"]
    raw = canonical_json_bytes(document)
    policy = ScoringPolicy.model_validate_json(raw)
    assert canonical_json_bytes(policy) == raw
    validate_scoring_runtime(policy)
    document["implementation_pins"]["scoring_by_target"] = None
    assert canonical_json_bytes(ScoringPolicy.model_validate(document)) == raw


def test_target_variants_are_bound_in_policy_digest(document):
    legacy = ScoringPolicy.model_validate(document)
    policy = ScoringPolicy.model_validate(portable(document))
    assert scoring_policy_hash(policy) != scoring_policy_hash(legacy)
    raw = canonical_json_bytes(policy)
    assert canonical_json_bytes(ScoringPolicy.model_validate_json(raw)) == raw


def test_verification_uses_only_the_host_target_and_keeps_artifact_checks(document, monkeypatch):
    policy = ScoringPolicy.model_validate(portable(document))
    monkeypatch.setattr("umi.policy.scoring_runtime_target", lambda: LINUX)
    validate_scoring_runtime(policy)
    monkeypatch.setattr("umi.policy.scoring_runtime_target", lambda: MAC)
    with pytest.raises(RuntimeError, match="regex_distribution_content_sha256"):
        validate_scoring_runtime(policy)
    monkeypatch.setattr(
        "umi.policy.scoring_runtime_target", lambda: "aarch64-unknown-linux-gnu"
    )
    with pytest.raises(RuntimeError, match="target is not pinned"):
        validate_scoring_runtime(policy)


@pytest.mark.parametrize("field", ARTIFACT_FIELDS)
def test_each_target_specific_artifact_must_match(document, monkeypatch, field):
    raw = portable(document)
    raw["implementation_pins"]["scoring_by_target"][LINUX][field] = "cd" * 32
    policy = ScoringPolicy.model_validate(raw)
    monkeypatch.setattr("umi.policy.scoring_runtime_target", lambda: LINUX)
    with pytest.raises(RuntimeError, match=field):
        validate_scoring_runtime(policy)


@pytest.mark.parametrize(
    "field",
    (
        "python_version", "unicode_data_version", "regex_distribution_version",
        "rfc8785_distribution_version", "pydantic_distribution_version",
        "pydantic_core_distribution_version", "scoring_source_sha256",
        "normalization_fixture_set_sha256",
    ),
)
def test_variants_cannot_change_normalization_or_scoring(document, field):
    raw = portable(document)
    raw["implementation_pins"]["scoring_by_target"][LINUX][field] = (
        "cd" * 32 if field.endswith("sha256") else "other-version"
    )
    with pytest.raises(ValidationError, match="must share versions"):
        ScoringPolicy.model_validate(raw)


def test_variants_require_primary_pin_and_recognized_target(document):
    raw = portable(document)
    targets = raw["implementation_pins"]["scoring_by_target"]
    primary = targets.pop(MAC)
    with pytest.raises(ValidationError, match="include the primary"):
        ScoringPolicy.model_validate(raw)
    targets["miner-selected-platform"] = primary
    with pytest.raises(ValidationError):
        ScoringPolicy.model_validate(raw)
    targets.clear()
    with pytest.raises(ValidationError):
        ScoringPolicy.model_validate(raw)


def test_target_verification_still_checks_import_origins(document, monkeypatch):
    policy = ScoringPolicy.model_validate(portable(document))
    monkeypatch.setattr("umi.policy.scoring_runtime_target", lambda: LINUX)
    checked = []

    def require_origin(module, distribution):
        checked.append((module, distribution))
        if module == "pydantic_core":
            raise RuntimeError("loaded module is outside the pinned distribution")

    monkeypatch.setattr("umi.policy._require_loaded_module_from_distribution", require_origin)
    with pytest.raises(RuntimeError, match="outside the pinned distribution"):
        validate_scoring_runtime(policy)
    assert checked == [
        ("regex", "regex"), ("rfc8785", "rfc8785"),
        ("pydantic", "pydantic"), ("pydantic_core", "pydantic-core"),
    ]


@pytest.mark.parametrize(
    "system,machine,libc,expected",
    [
        ("Darwin", "arm64", "", MAC),
        ("Darwin", "x86_64", "", "x86_64-apple-darwin"),
        ("Linux", "x86_64", "glibc", LINUX),
        ("Linux", "aarch64", "glibc", "aarch64-unknown-linux-gnu"),
        ("Linux", "x86_64", "musl", None),
        ("Linux", "riscv64", "glibc", None),
        ("Windows", "x86_64", "", None),
    ],
)
def test_target_is_detected_from_host(system, machine, libc, expected, monkeypatch):
    monkeypatch.setattr("umi.runtime_targets.platform.system", lambda: system)
    monkeypatch.setattr("umi.runtime_targets.platform.machine", lambda: machine)
    monkeypatch.setattr("umi.runtime_targets.platform.libc_ver", lambda: (libc, "1"))
    if expected is None:
        with pytest.raises(RuntimeError, match="target is unsupported"):
            scoring_runtime_target()
    else:
        assert scoring_runtime_target() == expected
