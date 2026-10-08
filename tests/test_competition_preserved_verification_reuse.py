"""Verification survives retries and restarts without rereading model weights."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_open_competition import bundle_at
from tests.test_open_competition import policy as policy_fixture
from umi import competition_artifacts as artifacts
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


@pytest.fixture
def policy():
    return policy_fixture.__wrapped__()


def fixture_archive(tmp_path, policy):
    source = tmp_path / "source"
    bundle = bundle_at(source)
    archive = tmp_path / "archive"
    artifacts.preserve_bundle(bundle, source, archive, policy)
    return bundle, source, archive


def forbid_hashing(*args, **kwargs):
    raise AssertionError("verified content was hashed again")


def test_verified_copy_is_not_rehashed_on_preservation_or_execution(tmp_path, policy, monkeypatch):
    calls = []
    copy = artifacts._copy_verified

    def counting_copy(stream, record, target):
        calls.append(record.path)
        return copy(stream, record, target)

    monkeypatch.setattr(artifacts, "_copy_verified", counting_copy)
    bundle, source, archive = fixture_archive(tmp_path, policy)
    assert calls == [record.path for record in bundle.files]
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    assert artifacts.verify_preserved_bundle(bundle, archive, policy) == digest(bundle)
    assert artifacts.preserve_bundle(bundle, source, archive, policy) == archive / digest(bundle)
    assert set(path.name for path in (archive / digest(bundle)).iterdir()) == {
        "model",
        "manifest.json",
    }


def test_verification_survives_new_python_process(tmp_path, policy):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    inputs = tmp_path / "inputs.json"
    inputs.write_bytes(
        canonical_json_bytes(
            {
                "bundle": canonical_json_bytes(bundle).decode(),
                "policy": canonical_json_bytes(policy).decode(),
            }
        )
    )
    source = Path(artifacts.__file__).resolve().parents[1]
    code = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from umi import competition_artifacts as a
from umi.open_competition import CompetitionPolicy, ModelBundle, digest
assert Path(a.__file__).is_relative_to(Path(sys.argv[1]))
data = json.loads(Path(sys.argv[2]).read_bytes())
bundle = ModelBundle.model_validate_json(data['bundle'])
policy = CompetitionPolicy.model_validate_json(data['policy'])
def forbidden(*args, **kwargs):
    raise AssertionError('content rehashed after restart')
a._copy_verified = forbidden
assert a.verify_preserved_bundle(bundle, Path(sys.argv[3]), policy) == digest(bundle)
"""
    subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(source), str(inputs), str(archive)],
        check=True,
        timeout=120,
    )


def test_legacy_materialization_is_verified_once(tmp_path, policy, monkeypatch):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    (archive / (".verified-" + digest(bundle) + ".json")).unlink()
    calls = []
    copy = artifacts._copy_verified

    def counting_copy(stream, record, target):
        calls.append(record.path)
        return copy(stream, record, target)

    monkeypatch.setattr(artifacts, "_copy_verified", counting_copy)
    artifacts.verify_preserved_bundle(bundle, archive, policy)
    assert calls == [record.path for record in bundle.files]
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    artifacts.verify_preserved_bundle(bundle, archive, policy)


def test_verified_readers_do_not_require_the_preservation_lock(tmp_path, policy, monkeypatch):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    monkeypatch.setattr(artifacts, "lock_private_file", forbid_hashing)
    artifacts.verify_preserved_bundle(bundle, archive, policy)


@pytest.mark.parametrize("mutation", ["content", "symlink", "hardlink", "receipt", "permissions"])
def test_changed_materialization_cannot_borrow_verification(
    tmp_path, policy, monkeypatch, mutation
):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    target = archive / digest(bundle) / "model" / bundle.files[0].path
    receipt = archive / (".verified-" + digest(bundle) + ".json")
    if mutation == "content":
        target.chmod(0o600)
        target.write_bytes(b"x" * target.stat().st_size)
    elif mutation == "symlink":
        target.unlink()
        target.symlink_to(tmp_path / "source" / bundle.files[0].path)
    elif mutation == "hardlink":
        os.link(target, tmp_path / "another-link")
    elif mutation == "receipt":
        receipt.chmod(0o600)
        receipt.write_bytes(b"invalid receipt")
        receipt.chmod(0o400)
    else:
        receipt.chmod(0o600)
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    with pytest.raises((ValueError, OSError)):
        artifacts.verify_preserved_bundle(bundle, archive, policy)


def test_failed_first_verification_is_never_cached(tmp_path, policy):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    receipt = archive / (".verified-" + digest(bundle) + ".json")
    receipt.unlink()
    target = archive / digest(bundle) / "model" / bundle.files[0].path
    target.chmod(0o600)
    target.write_bytes(b"x" * target.stat().st_size)
    target.chmod(0o400)
    with pytest.raises(ValueError, match="immutable manifest"):
        artifacts.verify_preserved_bundle(bundle, archive, policy)
    assert not receipt.exists()


def test_new_policy_constraints_still_apply(tmp_path, policy, monkeypatch):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    restrictive = policy.model_copy(update={"accepted_model_licenses": ("MIT",)})
    with pytest.raises(ValueError):
        artifacts.verify_preserved_bundle(bundle, archive, restrictive)


def test_copied_archive_gets_its_own_receipt_once(tmp_path, policy, monkeypatch):
    import shutil

    bundle, _, archive = fixture_archive(tmp_path, policy)
    restored = tmp_path / "restored"
    shutil.copytree(archive, restored)
    calls = []
    original = artifacts._copy_verified

    def counted(stream, record, target):
        calls.append(record.path)
        return original(stream, record, target)

    monkeypatch.setattr(artifacts, "_copy_verified", counted)
    assert artifacts.verify_preserved_bundle(bundle, restored, policy) == digest(bundle)
    assert calls == [record.path for record in bundle.files]
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    assert artifacts.verify_preserved_bundle(bundle, restored, policy) == digest(bundle)
    assert artifacts.verify_preserved_bundle(bundle, archive, policy) == digest(bundle)


def test_copied_receipt_never_authorizes_changed_destination(tmp_path, policy):
    import shutil

    bundle, _, archive = fixture_archive(tmp_path, policy)
    restored = tmp_path / "restored"
    shutil.copytree(archive, restored)
    target = restored / digest(bundle) / "model" / bundle.files[0].path
    target.chmod(0o600)
    target.write_bytes(b"x" * target.stat().st_size)
    target.chmod(0o400)
    with pytest.raises(ValueError, match="immutable manifest"):
        artifacts.verify_preserved_bundle(bundle, restored, policy)


def test_legacy_receipt_reuses_only_unchanged_materialization(tmp_path, policy, monkeypatch):
    import json
    import shutil

    bundle, _, archive = fixture_archive(tmp_path, policy)
    receipt = archive / (".verified-" + digest(bundle) + ".json")
    legacy = json.loads(receipt.read_bytes())
    legacy.pop("archive_identity")
    legacy["schema"] = "umi-preserved-content-verification/1"
    receipt.chmod(0o600)
    receipt.write_bytes(canonical_json_bytes(legacy))
    receipt.chmod(0o400)
    restored = tmp_path / "legacy-copy"
    shutil.copytree(archive, restored)
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    assert artifacts.verify_preserved_bundle(bundle, archive, policy) == digest(bundle)
    with pytest.raises(ValueError, match="changed after verification"):
        artifacts.verify_preserved_bundle(bundle, restored, policy)


def test_other_archive_entries_do_not_expire_verified_content(tmp_path, policy, monkeypatch):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    (archive / "other-unrelated-entry").mkdir(mode=0o700)
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    assert artifacts.verify_preserved_bundle(bundle, archive, policy) == digest(bundle)


def test_atomically_restored_file_gets_one_new_verification(tmp_path, policy, monkeypatch):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    target = archive / digest(bundle) / "model" / bundle.files[0].path
    replacement = target.with_name(target.name + ".restoring")
    replacement.write_bytes(target.read_bytes())
    replacement.chmod(0o400)
    os.replace(replacement, target)
    calls = []
    original = artifacts._copy_verified

    def counted(stream, record, output):
        calls.append(record.path)
        return original(stream, record, output)

    monkeypatch.setattr(artifacts, "_copy_verified", counted)
    assert artifacts.verify_preserved_bundle(bundle, archive, policy) == digest(bundle)
    assert calls == [record.path for record in bundle.files]
    monkeypatch.setattr(artifacts, "_copy_verified", forbid_hashing)
    assert artifacts.verify_preserved_bundle(bundle, archive, policy) == digest(bundle)


def test_replaced_file_cannot_inherit_trust_for_wrong_bytes(tmp_path, policy):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    receipt = archive / (".verified-" + digest(bundle) + ".json")
    old_receipt = receipt.read_bytes()
    target = archive / digest(bundle) / "model" / bundle.files[0].path
    replacement = target.with_name(target.name + ".restoring")
    replacement.write_bytes(b"x" * target.stat().st_size)
    replacement.chmod(0o400)
    os.replace(replacement, target)
    with pytest.raises(ValueError, match="immutable manifest"):
        artifacts.verify_preserved_bundle(bundle, archive, policy)
    assert receipt.read_bytes() == old_receipt


def test_directory_change_cannot_hide_in_place_corruption(tmp_path, policy):
    bundle, _, archive = fixture_archive(tmp_path, policy)
    target = archive / digest(bundle) / "model" / bundle.files[0].path
    target.chmod(0o600)
    target.write_bytes(b"x" * target.stat().st_size)
    target.chmod(0o400)
    scratch = target.parent / ".discarded-restore"
    scratch.write_bytes(b"temporary")
    scratch.unlink()
    with pytest.raises(ValueError, match="immutable manifest"):
        artifacts.verify_preserved_bundle(bundle, archive, policy)
