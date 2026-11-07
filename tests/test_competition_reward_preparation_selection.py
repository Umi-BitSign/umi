"""Preparation reports bind exact native inputs without becoming handoff authority."""

import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as activation
from umi import competition_reward_preparation_selection as selection
from umi.competition_reward_handoff_preparation import LegacyHandoffPreparationResult
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


@pytest.fixture
def selected(tmp_path):
    directory = tmp_path / "providers"
    directory.mkdir(mode=0o700)
    config, boot = {"config": "original"}, {"boot": "original"}
    installation = SimpleNamespace(config=config, receipt_sha256="ab" * 32)
    value = selection.LegacyPreparationSelection(
        schema="umi-legacy-preparation-selection/1",
        transition_id="cd" * 32,
        retained_intent_sha256="ef" * 32,
        source_revision="12" * 20,
        config_sha256=digest(config),
        installation_receipt_sha256=installation.receipt_sha256,
        standing_boot_sha256=digest(boot),
        provider_directory=str(directory),
        maximum_memory_bytes=2 * 1024**3,
        background_cpus=(0, 1, 14, 15),
    )
    result = LegacyHandoffPreparationResult("ef" * 32, "34" * 32, 449, 12345)
    return value, installation, boot, result


def test_scope_binds_installed_inputs_and_native_intent(selected):
    value, installation, boot, _ = selected
    args = (
        value,
        installation,
        boot,
        Path("/opt/umi-validator-supervisor-hosts") / value.source_revision,
        Path(value.provider_directory),
        value.retained_intent_sha256,
    )
    selection.check_legacy_preparation_selection(*args)
    for index, changed in (
        (1, SimpleNamespace(config={}, receipt_sha256="ab" * 32)),
        (1, SimpleNamespace(config=installation.config, receipt_sha256="00" * 32)),
        (2, {}),
        (3, Path("/other/source")),
        (4, Path("/other/providers")),
        (5, "00" * 32),
    ):
        altered = list(args)
        altered[index] = changed
        with pytest.raises(ValueError, match="authenticated inputs"):
            selection.check_legacy_preparation_selection(*altered)


@pytest.mark.parametrize("change", ["digest", "canonical", "mode", "owner", "symlink", "oversized"])
def test_root_selection_refuses_changed_or_unsafe_controls(selected, tmp_path, monkeypatch, change):
    value, *_ = selected
    path = tmp_path / "selection.json"
    raw = canonical_json_bytes(value)
    path.write_bytes(raw)
    path.chmod(0o444)
    # Exercise native ownership/mode/path reads under the test service UID.
    monkeypatch.setattr(activation, "_root_owner_uid", os.getuid)
    assert (
        selection.load_legacy_preparation_selection(
            path, selection.legacy_preparation_selection_sha256(value)
        )
        == value
    )
    expected = selection.legacy_preparation_selection_sha256(value)
    if change == "digest":
        expected = "00" * 32
    elif change == "canonical":
        path.chmod(0o600)
        path.write_bytes(raw + b"\n")
        path.chmod(0o444)
        expected = hashlib.sha256(raw + b"\n").hexdigest()
    elif change == "mode":
        path.chmod(0o644)
    elif change == "owner":
        monkeypatch.setattr(activation, "_root_owner_uid", lambda: os.getuid() + 1)
    elif change == "symlink":
        link = tmp_path / "alias.json"
        link.symlink_to(path)
        path = link
    else:
        path.chmod(0o600)
        path.write_bytes(b" " * (selection.MAX_SELECTION_BYTES + 1))
        path.chmod(0o444)
    with pytest.raises((ValueError, OSError, activation.HostActivationError)):
        selection.load_legacy_preparation_selection(path, expected)


def test_durable_outcome_exact_retry_and_changed_result_refusal(selected):
    value, _, _, result = selected
    outcome = selection.publish_legacy_preparation_outcome(value, result)
    path = selection.legacy_preparation_outcome_path(value)
    before = path.stat()
    assert selection.publish_legacy_preparation_outcome(value, result) == outcome
    assert path.stat().st_ino == before.st_ino
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert selection.read_legacy_preparation_outcome(value) == outcome
    assert outcome.writer_authority is False
    with pytest.raises(ValueError, match="different bytes"):
        selection.publish_legacy_preparation_outcome(value, replace(result, attempts=450))
    with pytest.raises(ValueError, match="retained intent"):
        selection.publish_legacy_preparation_outcome(
            value, replace(result, intent_sha256="00" * 32)
        )
    assert path.read_bytes() == canonical_json_bytes(outcome)


@pytest.mark.parametrize(
    "change", ["selection", "intent", "authority", "canonical", "mode", "symlink", "hardlink"]
)
def test_outcome_rejects_forged_or_unsafe_completion(selected, change):
    value, _, _, result = selected
    outcome = selection.publish_legacy_preparation_outcome(value, result)
    path = selection.legacy_preparation_outcome_path(value)
    if change in {"selection", "intent", "authority"}:
        field, replacement = {
            "selection": ("selection_sha256", "00" * 32),
            "intent": ("intent_sha256", "00" * 32),
            "authority": ("writer_authority", True),
        }[change]
        path.write_bytes(canonical_json_bytes(outcome.model_copy(update={field: replacement})))
    elif change == "canonical":
        path.write_bytes(path.read_bytes() + b"\n")
    elif change == "mode":
        path.chmod(0o644)
    elif change == "symlink":
        renamed = path.with_name("renamed.json")
        path.rename(renamed)
        path.symlink_to(renamed)
    else:
        os.link(path, path.with_name("alias.json"))
    with pytest.raises((ValueError, OSError)):
        selection.read_legacy_preparation_outcome(value)


def test_root_reader_checks_installed_uid_and_mapping_without_current_uid_assumption(
    selected, monkeypatch
):
    value, _, _, result = selected
    outcome = selection.publish_legacy_preparation_outcome(value, result)
    uid = os.getuid()
    assert uid > 0, "run ownership tests under the unprivileged qualification service"
    with pytest.raises(ValueError, match="root controller"):
        selection.read_service_legacy_preparation_outcome(
            value, service_uid=uid, mapped_directory=Path(value.provider_directory)
        )
    monkeypatch.setattr(selection.os, "geteuid", lambda: 0)
    assert (
        selection.read_service_legacy_preparation_outcome(
            value, service_uid=uid, mapped_directory=Path(value.provider_directory)
        )
        == outcome
    )
    with pytest.raises(ValueError, match="service owner"):
        selection.read_service_legacy_preparation_outcome(
            value, service_uid=uid + 1, mapped_directory=Path(value.provider_directory)
        )
    path = selection.legacy_preparation_outcome_path(value)
    path.chmod(0o644)
    with pytest.raises(activation.HostActivationError, match="unsafe"):
        selection.read_service_legacy_preparation_outcome(
            value, service_uid=uid, mapped_directory=Path(value.provider_directory)
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("background_cpus", (1, 0)),
        ("background_cpus", (0, 0)),
        ("background_cpus", ()),
        ("maximum_memory_bytes", 0),
        ("maximum_memory_bytes", True),
        ("source_revision", "branch"),
    ],
)
def test_invalid_resource_or_source_selection_refused(selected, field, value):
    original, *_ = selected
    raw = original.model_dump(by_alias=True)
    raw[field] = value
    with pytest.raises(ValueError):
        selection.LegacyPreparationSelection.model_validate(raw)
