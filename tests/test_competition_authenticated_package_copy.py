from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from umi import competition_materialization as material
from umi import competition_package as package
from umi import competition_package_copy as copier
from umi import competition_package_reuse as reuse_module
from umi.competition_package_reuse import (
    PackageVerificationRepairRequired,
    package_verification_session,
)
from umi.competition_verification_reuse import metadata_completion
from umi.private_files import publish_private_model

from .test_competition_package import _load
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import policy as policy
from .test_competition_package import release_identity as release_identity
from .test_competition_package import replay_limits as replay_limits


@pytest.fixture
def copy_case(package_case, policy, package_limits, release_identity, tmp_path):
    arguments = dict(
        expected_package_sha256=package_case.prepared.package_sha256,
        expected_policy_sha256=package.digest(policy),
        observed_release=release_identity,
        limits=package_limits,
    )
    directory = tmp_path / "verification"
    with package_verification_session(directory=directory):
        verified = _load(package_case, policy, package_limits, release_identity)
    return package_case.path, verified, arguments, directory


def _receipt(directory, path, arguments):
    key, _ = package._package_reuse_key(path, **arguments)
    identity = reuse_module._metadata_digest(reuse_module._sealed_identity(key))
    return directory / (identity + ".json")


def _no_replay(*args, **kwargs):
    pytest.fail("completed source/copy must not repeat semantic verification")


def test_new_copies_and_parent_relocation_share_verified_semantics(
    copy_case, tmp_path, monkeypatch
):
    source, verified, arguments, directory = copy_case
    stage = tmp_path / "stage"
    stage.mkdir()
    destination = stage / "package"
    monkeypatch.setattr(package, "_verify_publications", _no_replay)
    with package_verification_session(directory=directory):
        first = package.load_competition_package(source, **arguments)
        copier.copy_verified_package(source, destination, verified.manifest, **arguments)
        stage.chmod(0o555)
        tree_limits = material.SuccessorCurrentMaterializationLimits(
            maximum_stages=2,
            maximum_cache_bytes=40_000_000,
            maximum_tree_entries=100,
            maximum_tree_depth=3,
        )
        monkeypatch.setattr(material, "_hash_tree_file", _no_replay)
        material._tree(stage, tree_limits, sealed=True)
        # Copying necessarily reads source bytes; consuming the successful copy
        # and relocating its unchanged parent must not read payloads again.
        monkeypatch.setattr(package, "_read_sealed_file", _no_replay)
        assert package.load_competition_package(destination, **arguments) == first
        current = tmp_path / "current"
        stage.rename(current)
        destination = current / "package"
        material._tree(current, tree_limits, sealed=True)
        assert package.load_competition_package(destination, **arguments) == first
        assert package.load_competition_package(source, **arguments) == first
    monkeypatch.undo()
    monkeypatch.setattr(package, "_verify_publications", _no_replay)
    monkeypatch.setattr(material, "_hash_tree_file", _no_replay)
    with package_verification_session(directory=directory):
        material._tree(current, tree_limits, sealed=True)
        restored = package.load_competition_package(destination, **arguments)
        assert restored == verified
        assert not restored.chain_submission_authorized


@pytest.mark.parametrize(
    "change", ["source", "destination", "source_replace", "destination_replace"]
)
def test_copy_races_publish_no_destination_verdict(copy_case, tmp_path, monkeypatch, change):
    source, verified, arguments, directory = copy_case
    destination = tmp_path / "copy"
    original = copier._copy_file
    changed = False

    def raced(source_fd, destination_fd, name, *args):
        nonlocal changed
        result = original(source_fd, destination_fd, name, *args)
        if not changed:
            changed = True
            parent = source if change.startswith("source") else destination
            path = parent / name
            if change.endswith("replace"):
                mode = parent.stat().st_mode & 0o777
                parent.chmod(0o700)
                raw = path.read_bytes()
                path.unlink()
                path.write_bytes(raw)
                path.chmod(0o400)
                parent.chmod(mode)
            else:
                path.chmod(0o600)
                path.chmod(0o400)
        return result

    monkeypatch.setattr(copier, "_copy_file", raced)
    with (
        package_verification_session(directory=directory),
        pytest.raises(ValueError, match="changed"),
    ):
        copier.copy_verified_package(source, destination, verified.manifest, **arguments)
    if destination.stat().st_mode & 0o777 == 0o500:
        assert not _receipt(directory, destination, arguments).exists()


@pytest.mark.parametrize("change", ["policy", "release", "limits", "manifest", "missing_source"])
def test_copy_requires_exact_prior_source_verdict(copy_case, tmp_path, change):
    source, verified, arguments, directory = copy_case
    arguments = dict(arguments)
    manifest = verified.manifest
    if change == "policy":
        arguments["expected_policy_sha256"] = "f" * 64
    elif change == "release":
        arguments["observed_release"] = arguments["observed_release"].model_copy(
            update={"umi_revision": "1" * 40}
        )
    elif change == "limits":
        arguments["limits"] = arguments["limits"].model_copy(
            update={"maximum_manifest_bytes": arguments["limits"].maximum_manifest_bytes + 1}
        )
    elif change == "manifest":
        manifest = manifest.model_copy(update={"policy_sha256": "f" * 64})
    else:
        _receipt(directory, source, arguments).unlink()
    destination = tmp_path / "copy"
    with package_verification_session(directory=directory), pytest.raises(ValueError):
        copier.copy_verified_package(source, destination, manifest, **arguments)
    assert not destination.exists()


def test_interrupted_copy_keeps_private_input_and_retry_verifies_only_new_copy(
    copy_case, tmp_path, monkeypatch
):
    source, verified, arguments, directory = copy_case
    destination = tmp_path / "interrupted"
    original = copier._copy_file
    count = 0

    def interrupted(*args):
        nonlocal count
        count += 1
        if count == 3:
            raise OSError("injected interrupted write")
        return original(*args)

    with package_verification_session(directory=directory):
        monkeypatch.setattr(copier, "_copy_file", interrupted)
        with pytest.raises(OSError, match="interrupted"):
            copier.copy_verified_package(source, destination, verified.manifest, **arguments)
        assert destination.stat().st_mode & 0o777 == 0o700
        retained = {path.name: path.read_bytes() for path in destination.iterdir()}
        monkeypatch.setattr(copier, "_copy_file", original)
        with pytest.raises(FileExistsError):
            copier.copy_verified_package(source, destination, verified.manifest, **arguments)
        assert retained == {path.name: path.read_bytes() for path in destination.iterdir()}
        retry = tmp_path / "retry"
        copier.copy_verified_package(source, retry, verified.manifest, **arguments)
    monkeypatch.setattr(package, "_verify_publications", _no_replay)
    with package_verification_session(directory=directory):
        assert package.load_competition_package(retry, **arguments) == verified


@pytest.mark.parametrize("damage", ["missing", "invalid"])
def test_completed_record_requires_explicit_repair_and_recovers(copy_case, damage, monkeypatch):
    source, verified, arguments, directory = copy_case
    receipt = _receipt(directory, source, arguments)
    assert metadata_completion(receipt).exists()
    if damage == "missing":
        receipt.unlink()
    else:
        receipt.write_bytes(b"{}")
    with (
        package_verification_session(directory=directory),
        pytest.raises(PackageVerificationRepairRequired),
    ):
        package.load_competition_package(source, **arguments)
    calls = []
    original = package._verify_publications

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(package, "_verify_publications", counted)
    with package_verification_session(
        directory=directory, repair_reason="recover damaged metadata"
    ):
        assert package.load_competition_package(source, **arguments) == verified
    assert calls == [1]
    monkeypatch.setattr(package, "_verify_publications", _no_replay)
    with package_verification_session(directory=directory):
        assert package.load_competition_package(source, **arguments) == verified


def test_failed_native_repair_does_not_replace_record(copy_case, monkeypatch):
    source, _, arguments, directory = copy_case
    receipt = _receipt(directory, source, arguments)
    receipt.write_bytes(b"{}")

    def refuse(*args, **kwargs):
        raise ValueError("native refusal")

    monkeypatch.setattr(package, "_verify_publications", refuse)
    with (
        package_verification_session(directory=directory, repair_reason="explicit repair"),
        pytest.raises(ValueError, match="native refusal"),
    ):
        package.load_competition_package(source, **arguments)
    assert receipt.read_bytes() == b"{}"


@pytest.mark.parametrize("changed_abi", [False, True])
def test_legacy_path_receipt_migrates_only_under_original_abi(copy_case, monkeypatch, changed_abi):
    source, verified, arguments, directory = copy_case
    new = _receipt(directory, source, arguments)
    new.unlink()
    metadata_completion(new).unlink()
    key, _ = package._package_reuse_key(source, **arguments)
    legacy = reuse_module._metadata_digest(key)
    publish_private_model(
        directory / (legacy + ".json"),
        reuse_module.PackageVerificationReceipt(
            schema="umi-private-package-verification/1",
            metadata_sha256=legacy,
            manifest_sha256=verified.manifest_sha256,
        ),
        maximum_bytes=1024,
    )
    calls = []
    original = package._verify_publications

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    if changed_abi:
        monkeypatch.setattr(reuse_module, "runtime_identity", lambda: "f" * 64)
        new = _receipt(directory, source, arguments)
        monkeypatch.setattr(package, "_verify_publications", counted)
    else:
        monkeypatch.setattr(package, "_verify_publications", _no_replay)
    with package_verification_session(directory=directory):
        assert package.load_competition_package(source, **arguments) == verified
    assert calls == ([1] if changed_abi else [])
    assert new.exists() and metadata_completion(new).exists()


@pytest.mark.parametrize("path_kind", ["relative", "parent_traversal", "symlink_parent"])
def test_invalid_destination_refused_before_mutation(copy_case, tmp_path, path_kind, monkeypatch):
    source, verified, arguments, directory = copy_case
    if path_kind == "relative":
        monkeypatch.chdir(tmp_path)
        destination = Path("copy")
    elif path_kind == "parent_traversal":
        destination = tmp_path / ".." / tmp_path.name / "copy"
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        destination = alias / "copy"
    with package_verification_session(directory=directory), pytest.raises((OSError, ValueError)):
        copier.copy_verified_package(source, destination, verified.manifest, **arguments)
    assert not (tmp_path / "copy").exists()


def test_short_reads_and_writes_preserve_exact_copy(copy_case, tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    source, verified, arguments, directory = copy_case
    destination = tmp_path / "short-copy"
    read, write = os.read, os.write
    monkeypatch.setattr(copier.os, "read", lambda fd, count: read(fd, min(count, 97)))
    monkeypatch.setattr(copier.os, "write", lambda fd, value: write(fd, value[:71]))
    with package_verification_session(directory=directory):
        copier.copy_verified_package(source, destination, verified.manifest, **arguments)
        assert package.load_competition_package(destination, **arguments) == verified
    assert all(
        (source / path.name).read_bytes() == path.read_bytes() for path in destination.iterdir()
    )
    events = [json.loads(record.message) for record in caplog.records]
    assert not any(event.get("state") == "accounting_mismatch" for event in events)
    assert any(
        event.get("stage") == "package_authenticated_copy" and event.get("state") == "completed"
        for event in events
    )


def test_repair_command_uses_selected_bounds_and_retains_signed_payload(
    copy_case, tmp_path, capsys
):
    from umi.competition_package_reuse_cli import PackageVerificationRepairRequest, main

    source, verified, arguments, directory = copy_case
    _receipt(directory, source, arguments).unlink()
    before = {path.name: path.read_bytes() for path in source.iterdir()}
    request = tmp_path / "repair.json"
    publish_private_model(
        request,
        PackageVerificationRepairRequest(
            schema="umi-package-verification-repair/1",
            directory=str(directory),
            package_path=str(source),
            **arguments,
        ),
    )
    assert main(["repair", "--request", str(request), "--reason", "restore missing metadata"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["manifest_sha256"] == verified.manifest_sha256
    assert result["chain_submission_authorized"] is False
    assert before == {path.name: path.read_bytes() for path in source.iterdir()}
