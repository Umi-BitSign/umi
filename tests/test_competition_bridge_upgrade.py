from __future__ import annotations

import hashlib
import os
from dataclasses import replace

import pytest

from tests.test_competition_upgrade import inspect, installation, release, tree, write
from tests.test_registration_bridge import signed_policy
from umi import competition_host_upgrade as host
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor_adapters import (
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
    SupervisorRegistrationBridgeInputBundle,
)

__all__ = ["signed_policy"]


@pytest.fixture
def inputs(signed_policy):
    return SupervisorRegistrationBridgeInputBundle(
        schema=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
        profile=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
        signed_policy=signed_policy,
    )


@pytest.fixture(params=["linux/amd64", "linux/arm64"])
def installed(tmp_path, inputs, request):
    return installation(tmp_path / "bridge", inputs, request.param)


def test_bridge_policy_is_verified_without_a_frozen_manifest(installed):
    before = tree(installed.root)
    result = inspect(installed)
    assert "installed_release_and_input_bytes" in result.verified_checks, result.holds
    assert "staged_signed_worker_release_under_installed_consent" in result.verified_checks
    assert result.observed_files_unchanged
    assert result.readiness == "hold"
    assert not result.chain_submission_authorized
    assert not result.may_stop_service
    assert tree(installed.root) == before


def test_bridge_policy_digest_is_bound_to_accepted_directive(installed, inputs):
    # A threshold-signed directive cannot substitute another policy digest.
    stage = installed.root / "wrong-policy"
    release(
        stage,
        installed.config,
        inputs,
        sequence=2,
        previous=installed.signed.directive_sha256,
        policy_sha256="ff" * 32,
    )
    result = inspect(installed, staged_directory=stage)
    assert "staged_input_policy_binding_mismatch" in result.holds
    assert "staged_signed_worker_release_under_installed_consent" not in result.verified_checks


def test_bridge_extracted_policy_must_match_the_signed_bundle(installed):
    path = installed.current / "operator-inputs/registration-bridge/registration-bridge-policy.json"
    write(path, b"{}")
    result = inspect(installed)
    assert "installed_extracted_input_mismatch" in result.holds


@pytest.mark.parametrize("location", ["operator-inputs", "operator-inputs/registration-bridge"])
def test_bridge_rejects_extra_extracted_input_names(installed, location):
    parent = installed.current / location
    parent.chmod(0o700)
    write(parent / "unexpected.json", b"{}")
    parent.chmod(0o500)
    assert "installed_input_file_set_mismatch" in inspect(installed).holds


def test_bridge_policy_signature_is_checked_even_when_directive_is_signed(installed, inputs):
    policy = inputs.signed_policy.model_copy(update={"signature": "0x" + "00" * 64})
    forged = inputs.model_copy(update={"signed_policy": policy})
    stage = installed.root / "wrong-signature"
    release(stage, installed.config, forged, sequence=2, previous=installed.signed.directive_sha256)
    result = inspect(installed, staged_directory=stage)
    assert "staged_signed_worker_release_under_installed_consent" not in result.verified_checks
    assert any("invalid" in item for item in result.holds)


def test_bundle_readback_records_policy_bytes(installed, inputs):
    result = inspect(installed)
    observed = {item.label: item for item in result.files}
    assert (
        observed["installed_registration-bridge-policy.json"].sha256
        == hashlib.sha256(canonical_json_bytes(inputs.signed_policy)).hexdigest()
    )


def test_stopped_bridge_lease_keeps_policy_distinct_from_frozen_manifest(
    installed, monkeypatch, inputs
):
    write(installed.root / "state/supervisor-process.lock", b"", 0o600)
    monkeypatch.setattr(host, "_require_root_linux", lambda: None)
    monkeypatch.setattr(host, "_root_file", lambda _: None)
    monkeypatch.setattr(
        host, "_check_unit", lambda *args: {"FragmentPath": str(installed.config_path)}
    )
    with host.hold_stopped_supervisor(
        config_path=installed.config_path,
        accepted_directive_bytes=canonical_json_bytes(installed.signed),
        expected_hotkey=installed.config.validator_hotkey,
        service_uid=os.geteuid(),
    ) as stopped:
        assert stopped.expected_manifest_sha256 is None
        assert (
            stopped.expected_registration_bridge_policy_sha256
            == hashlib.sha256(canonical_json_bytes(inputs.signed_policy)).hexdigest()
        )
        stopped.recheck_stopped()
        with pytest.raises(host.HostUpgradeError, match="altered"):
            replace(stopped, expected_registration_bridge_policy_sha256="ff" * 32).recheck_stopped()


def test_signed_policy_revision_must_match_signed_release(installed, inputs):
    # All signatures are valid but the policy names a different revision.
    stage = installed.root / "wrong-revision"
    release(
        stage,
        installed.config,
        inputs,
        sequence=2,
        previous=installed.signed.directive_sha256,
        release_revision="cd" * 20,
    )
    result = inspect(installed, staged_directory=stage)
    assert "staged_input_release_binding_mismatch" in result.holds
    assert "staged_signed_worker_release_under_installed_consent" not in result.verified_checks
