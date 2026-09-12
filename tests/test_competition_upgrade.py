from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.factories import dev_wallet
from tests.test_validator_supervisor import _config, _directive, _release, _signed, _wallets
from tests.test_validator_supervisor_adapters import _bootstrap_bundle
from umi.competition_upgrade import inspect_successor_upgrade
from umi.crypto import sign_response_digest
from umi.protocol import canonical_json_bytes
from umi.registration_bridge import registration_bridge_policy_sha256
from umi.validator_supervisor import advance_supervisor_directive_state
from umi.validator_supervisor_adapters import (
    SUPERVISOR_RELEASE_BUNDLE_MAGIC,
    SUPERVISOR_RELEASE_MANIFEST_SCHEMA,
    SUPERVISOR_RELEASE_SIGNATURE_DOMAIN,
    SupervisorRegistrationBridgeInputBundle,
    SupervisorReleaseManifest,
)


def write(path: Path, body: bytes, mode=0o400):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(body)
    path.chmod(mode)


@pytest.fixture(scope="module")
def inputs():
    return _bootstrap_bundle()


def release(root, config, inputs, *, sequence=1, previous=None, **changes):
    # Deliberately inert bytes: integrity checking must not imply runnable OCI.
    archive = b"inert archive; never execute this fixture"
    values = _release(target_platform=config.target_platform)
    if isinstance(inputs, SupervisorRegistrationBridgeInputBundle):
        changes.setdefault("validator_scope", "any_permitted_sn78")
        values.update(
            entrypoint_profile="umi-registration-bridge-validator/1",
            umi_git_revision=inputs.signed_policy.body.umi_git_revision,
        )
        policy_sha = registration_bridge_policy_sha256(inputs.signed_policy)
        content_name = "registration-bridge"
        input_files = {"registration-bridge-policy.json": inputs.signed_policy}
    else:
        policy_sha = inputs.signed_manifest.manifest.policy_sha256
        content_name = "bootstrap"
        input_files = {
            "signed-manifest.json": inputs.signed_manifest,
            "direct-transition-authorization.json": inputs.transition_authorization,
            "drain-checkpoint.json": inputs.drain_checkpoint,
            "owner-fence-receipt.json": inputs.owner_fence_receipt,
        }
    values["umi_git_revision"] = changes.pop("release_revision", values["umi_git_revision"])
    manifest = SupervisorReleaseManifest(
        schema=SUPERVISOR_RELEASE_MANIFEST_SCHEMA,
        **{
            key: values[key]
            for key in (
                "oci_repository",
                "oci_manifest_sha256",
                "target_platform",
                "umi_git_revision",
                "umi_source_tree_sha256",
                "entrypoint_profile",
                "state_schema_minimum",
                "state_schema_maximum",
            )
        },
        oci_archive_sha256=hashlib.sha256(archive).hexdigest(),
        oci_archive_size_bytes=len(archive),
    )
    raw_manifest = canonical_json_bytes(manifest)
    _, signature = sign_response_digest(
        _wallets()[0], hashlib.sha256(SUPERVISOR_RELEASE_SIGNATURE_DOMAIN + raw_manifest).digest()
    )
    frame = (
        SUPERVISOR_RELEASE_BUNDLE_MAGIC
        + struct.pack(">I", len(raw_manifest))
        + raw_manifest
        + bytes.fromhex(signature[2:])
        + archive
    )
    values.update(
        release_bundle_sha256=hashlib.sha256(frame).hexdigest(),
        release_bundle_size_bytes=len(frame),
        release_manifest_sha256=hashlib.sha256(raw_manifest).hexdigest(),
    )
    raw_inputs = canonical_json_bytes(inputs)
    directive = _directive(
        sequence=sequence,
        previous_directive_sha256=previous,
        validator_hotkeys=[]
        if changes.get("validator_scope") == "any_permitted_sn78"
        else [config.validator_hotkey],
        release=values,
        policy_sha256=changes.pop("policy_sha256", policy_sha),
        operator_inputs={
            "artifact_type": "canonical_json",
            "profile": inputs.profile,
            "bundle_url": "https://releases.umi.vision/bootstrap.json",
            "bundle_sha256": hashlib.sha256(raw_inputs).hexdigest(),
            "bundle_size_bytes": len(raw_inputs),
        },
        **changes,
    )
    signed = _signed(directive)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, content in {
        "signed-directive.json": canonical_json_bytes(signed),
        "release-bundle.bin": frame,
        "release-manifest.json": raw_manifest,
        "image.oci.tar": archive,
        "operator-input-bundle.json": raw_inputs,
    }.items():
        write(root / name, content)
    bootstrap = root / "operator-inputs" / content_name
    for name, item in input_files.items():
        write(bootstrap / name, canonical_json_bytes(item))
    bootstrap.chmod(0o500)
    bootstrap.parent.chmod(0o500)
    return signed


def installation(root, inputs, platform, hotkey=None):
    root.mkdir(mode=0o700, parents=True)
    config = _config(
        target_platform=platform,
        validator_hotkey=hotkey or _config().validator_hotkey,
        state_root=str(root / "state"),
        worker_state_root=str(root / "worker"),
        release_root=str(root / "releases"),
        operator_input_root=str(root / "inputs"),
        wallet={
            "path": str(root / "wallets-must-not-be-opened"),
            "name": "validator",
            "hotkey": "sn78",
        },
    )
    for name in ("state", "worker", "releases", "inputs"):
        (root / name).mkdir(mode=0o700)
    config_path = root / "config.json"
    write(config_path, canonical_json_bytes(config), 0o600)
    temporary = root / "stage-installed"
    signed = release(temporary, config, inputs)
    current = root / "releases" / signed.directive_sha256
    temporary.rename(current)
    state = advance_supervisor_directive_state(
        signed,
        config=config,
        finalized_block=120,
        prior_state=None,
    )
    state_path = root / "state" / "directive-state.json"
    write(state_path, canonical_json_bytes(state), 0o600)
    staged_root = root / "staged-next"
    staged = release(staged_root, config, inputs, sequence=2, previous=signed.directive_sha256)
    return SimpleNamespace(
        root=root,
        config=config,
        config_path=config_path,
        current=current,
        signed=signed,
        state=state,
        state_path=state_path,
        staged=staged,
        staged_root=staged_root,
    )


@pytest.fixture(params=["linux/amd64", "linux/arm64"])
def installed(tmp_path, inputs, request):
    return installation(tmp_path / "installed", inputs, request.param)


def inspect(s, **changes):
    kwargs = dict(
        config_path=s.config_path,
        accepted_directive_bytes=canonical_json_bytes(s.signed),
        expected_hotkey=s.config.validator_hotkey,
        expected_platform=s.config.target_platform,
        service_uid=os.geteuid(),
        staged_directory=s.staged_root,
    )
    kwargs.update(changes)
    return inspect_successor_upgrade(**kwargs)


def tree(root):
    return {
        str(path.relative_to(root)): (
            path.stat().st_mode,
            path.stat().st_mtime_ns,
            path.read_bytes(),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def test_exact_read_only_checkpoint_preserves_raw_history_and_never_authorizes_upgrade(installed):
    s = installed
    before = tree(s.root)
    result = inspect(s)
    assert result.verified_checks == (
        "installed_config_and_expected_public_hotkey",
        "installed_non_wallet_root_permissions",
        "accepted_signature_and_highwater_execution_binding",
        "installed_release_and_input_bytes",
        "staged_signed_worker_release_under_installed_consent",
    ), result.holds
    assert result.accepted_sequence == s.state.accepted_sequence
    assert result.accepted_directive_sha256 == s.signed.directive_sha256
    assert result.accepted_at_finalized_block == 120
    assert result.staged_directive_sha256 == s.staged.directive_sha256
    assert result.observed_files_unchanged
    assert result.readiness == "hold"
    assert not result.may_stop_service and not result.host_upgrade_authorized
    assert not result.chain_submission_authorized and not result.consistent_stopped_checkpoint
    assert "worker_journals_not_reconciled" in result.holds
    assert "replacement_host_source_not_authenticated" in result.holds
    assert "production_sandbox_not_rehearsed" in result.holds
    observations = {item.label: item for item in result.files}
    assert (
        observations["highwater"].sha256
        == hashlib.sha256(before["state/directive-state.json"][2]).hexdigest()
    )
    assert (
        observations["accepted_signed_directive"].sha256
        == hashlib.sha256(canonical_json_bytes(s.signed)).hexdigest()
    )
    assert "wallets-must-not-be-opened" not in str(asdict(result))
    assert not Path(s.config.wallet.path).exists()
    assert tree(s.root) == before


@pytest.mark.parametrize("field", ["expected_hotkey", "expected_platform"])
def test_wrong_installation_identity_fails_before_state_or_stage(installed, field):
    value = (
        dev_wallet("//AnotherValidator").hotkey.ss58_address
        if field == "expected_hotkey"
        else "unknown"
    )
    result = inspect(installed, **{field: value})
    assert result.verified_checks == ()
    assert result.accepted_sequence is None
    assert any("binding_mismatch" in hold for hold in result.holds)


@pytest.mark.parametrize(
    "field,value",
    [
        ("accepted_sequence", 2),
        ("accepted_directive_sha256", "99" * 32),
        ("accepted_oci_manifest_sha256", "99" * 32),
        ("accepted_operator_input_sha256", "99" * 32),
    ],
)
def test_highwater_must_match_the_exact_signed_execution_identity(installed, field, value):
    state = installed.state.model_copy(update={field: value})
    write(installed.state_path, canonical_json_bytes(state), 0o600)
    result = inspect(installed)
    assert "accepted_signature_and_highwater_execution_binding" not in result.verified_checks
    assert result.staged_directive_sha256 is None


def test_invalid_accepted_signature_cannot_be_a_checkpoint(installed):
    value = installed.signed.model_dump(mode="json", by_alias=True)
    value["signatures"][0]["signature"] = "0x" + "00" * 64
    result = inspect(installed, accepted_directive_bytes=canonical_json_bytes(value))
    assert "directive_signature_invalid" in result.holds
    assert result.accepted_sequence is None


def test_release_signature_is_checked_even_when_outer_directive_hash_matches(installed):
    path = installed.staged_root / "release-bundle.bin"
    frame = bytearray(path.read_bytes())
    size_offset = len(SUPERVISOR_RELEASE_BUNDLE_MAGIC)
    manifest_size = struct.unpack(">I", frame[size_offset : size_offset + 4])[0]
    signature_offset = size_offset + 4 + manifest_size
    frame[signature_offset : signature_offset + 64] = b"\0" * 64
    write(path, bytes(frame))
    directive = installed.staged.directive
    signed = _signed(
        directive.model_copy(
            update={
                "release": directive.release.model_copy(
                    update={"release_bundle_sha256": hashlib.sha256(frame).hexdigest()}
                )
            }
        )
    )
    write(installed.staged_root / "signed-directive.json", canonical_json_bytes(signed))
    result = inspect(installed)
    assert "staged_release_signature_invalid" in result.holds
    assert result.staged_directive_sha256 is None


@pytest.mark.parametrize("target", ["config_path", "state_path"])
def test_noncanonical_history_is_rejected_without_rewriting_it(installed, target):
    path = getattr(installed, target)
    malformed = path.read_bytes() + b"\n"
    write(path, malformed, 0o600)
    result = inspect(installed)
    assert result.accepted_sequence is None
    assert path.read_bytes() == malformed


@pytest.mark.parametrize(
    "name",
    [
        "release-bundle.bin",
        "release-manifest.json",
        "image.oci.tar",
        "operator-input-bundle.json",
        "operator-inputs/bootstrap/signed-manifest.json",
    ],
)
def test_corrupt_staged_bytes_hold_without_changing_installed_state(installed, name):
    before = tree(installed.current)
    write(installed.staged_root / name, b"corrupt")
    result = inspect(installed)
    assert "installed_release_and_input_bytes" in result.verified_checks
    assert "staged_signed_worker_release_under_installed_consent" not in result.verified_checks
    assert tree(installed.current) == before


@pytest.mark.parametrize("mutation", ["sequence", "predecessor", "platform", "schema"])
def test_staged_directive_cannot_change_history_platform_or_state_contract(installed, mutation):
    directive = installed.staged.directive
    changes = {
        "sequence": {"sequence": 3},
        "predecessor": {"previous_directive_sha256": "99" * 32},
        "platform": {
            "release": directive.release.model_copy(
                update={
                    "target_platform": "linux/amd64"
                    if installed.config.target_platform == "linux/arm64"
                    else "linux/arm64"
                }
            )
        },
        "schema": {
            "release": directive.release.model_copy(
                update={"state_schema_minimum": 2, "state_schema_maximum": 2}
            )
        },
    }[mutation]
    signed = _signed(directive.model_copy(update=changes))
    write(installed.staged_root / "signed-directive.json", canonical_json_bytes(signed))
    result = inspect(installed)
    assert result.staged_directive_sha256 is None
    assert "staged_signed_worker_release_under_installed_consent" not in result.verified_checks


def test_stage_may_not_overlay_any_existing_installation_root(installed):
    for root in (
        installed.config.release_root,
        installed.config.worker_state_root,
        installed.config.wallet.path,
    ):
        result = inspect(installed, staged_directory=Path(root))
        assert "stage_overlaps_installed_roots" in result.holds


@pytest.mark.parametrize("kind", ["link", "fifo", "hardlink", "writable"])
def test_unsafe_files_fail_without_blocking_or_following_links(installed, kind):
    path = installed.staged_root / "signed-directive.json"
    if kind == "writable":
        path.chmod(0o666)
    else:
        path.unlink()
        if kind == "link":
            path.symlink_to(installed.config_path)
        elif kind == "fifo":
            os.mkfifo(path, 0o600)
        else:
            os.link(installed.config_path, path)
    result = inspect(installed)
    assert "staged_signed_worker_release_under_installed_consent" not in result.verified_checks
    assert result.staged_directive_sha256 is None


def test_intermediate_directory_symlink_is_not_followed(installed):
    link = installed.root / "linked-stage"
    link.symlink_to(installed.staged_root, target_is_directory=True)
    result = inspect(installed, staged_directory=link)
    assert result.staged_directive_sha256 is None


def test_concurrent_state_change_invalidates_read_only_observation(installed, monkeypatch):
    from umi import competition_upgrade

    original = competition_upgrade._verify_release

    def change(*args, **kwargs):
        original(*args, **kwargs)
        write(
            installed.state_path,
            canonical_json_bytes(
                installed.state.model_copy(update={"accepted_at_finalized_block": 121})
            ),
            0o600,
        )

    monkeypatch.setattr(competition_upgrade, "_verify_release", change)
    result = inspect(installed)
    assert not result.observed_files_unchanged
    assert "inspection_files_changed" in result.holds


def test_absent_state_is_not_treated_as_new_installation(installed):
    installed.state_path.unlink()
    result = inspect(installed)
    assert result.accepted_sequence is None
    assert result.staged_directive_sha256 is None


def test_two_installations_remain_isolated(tmp_path, inputs):
    first = installation(tmp_path / "uid0", inputs, "linux/arm64")
    second = installation(
        tmp_path / "uid54",
        inputs,
        "linux/arm64",
        dev_wallet("//Uid54Validator").hotkey.ss58_address,
    )
    before = tree(second.root)
    result = inspect(first)
    assert result.observed_files_unchanged
    assert tree(second.root) == before
    assert inspect(first, expected_hotkey=second.config.validator_hotkey).accepted_sequence is None


def test_missing_stage_and_expired_historical_directive_do_not_authorize_restart(installed):
    # No claim about today's finalized head or the old directive's remaining lease.
    result = inspect(installed, staged_directory=None)
    assert "staged_release_not_supplied" in result.holds
    assert "fresh_finality_and_policy_validity_not_checked" in result.holds
    assert not result.may_stop_service
