"""Build contracts; actual native image execution is a separate release gate."""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def test_bridge_image_supplies_the_fixed_native_manifest_and_binaries():
    dockerfile = (DEPLOY / "linux-registration-bridge/Dockerfile").read_text()
    assert "rust:1.98.0-bookworm@sha256:" in dockerfile
    assert "COPY rust /build/rust" in dockerfile
    assert (
        "sh /build/build-native-verifiers.sh substrate-proof-verifier runtime-metadata"
        in dockerfile
    )
    assert "COPY deploy/native-verifiers/build.sh /build/build-native-verifiers.sh" in dockerfile
    for name in ("umi-substrate-proof-verifier", "umi-runtime-metadata"):
        assert f"COPY --from=native-builder /build/bin/{name} /opt/umi/bin/{name}" in dockerfile
    assert "python /build/seal-native.py" in dockerfile
    assert "UMI_PINNED_ARTIFACT_STAGE=/run/umi-finality/stage" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/usr/local/bin/umi-registration-bridge"]' in dockerfile


def test_bridge_downloads_are_verified_before_execution():
    dockerfile = (DEPLOY / "linux-registration-bridge/Dockerfile").read_text()
    assert "ADD --checksum=" not in dockerfile
    verification = dockerfile.index('"$finality_sha256" /opt/umi/bin/')
    execution = dockerfile.index(
        "&& /opt/umi/bin/umi-grandpa-finality-observer --conformance-self-test"
    )
    assert verification < execution
    for digest in (
        "cd696ea86acd691112413a7909b6bf469f90042747c87b9350f01dacfe4ae8c3",
        "b263758fb273aed83868e986f4738ff14008996b200226e34c14633a863e5587",
        "f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105",
    ):
        assert digest in dockerfile[:verification]
    assert dockerfile.count("sha256sum --check") == 2


def test_shared_native_build_requires_locked_tests_and_explicit_targets():
    builder = (DEPLOY / "native-verifiers/build.sh").read_text()
    assert "cargo +1.98.0 test --locked --release" in builder
    assert "cargo +1.98.0 build --locked --release" in builder
    assert "export CARGO_TARGET_DIR=/build/target" in builder
    assert "--conformance-self-test" in builder
    patterns = (ROOT / ".dockerignore").read_text().splitlines()
    for path in (
        "deploy/native-verifiers/build.sh",
        "deploy/linux-registration-bridge/Dockerfile",
        "deploy/linux-registration-bridge/seal-native.py",
    ):
        assert "!" + path in patterns


def test_release_checks_native_readers_inside_the_read_only_networkless_image():
    workflow = (ROOT / ".github/workflows/registration-bridge-worker-release.yml").read_text()
    assert "--network none --read-only --cap-drop ALL" in workflow
    assert "read_image_artifacts()" in workflow
    assert 'tools["verifier"].verify_extrinsics_root' in workflow
    assert 'tools["verifier"].verify_many' in workflow
    assert 'error.reason_code == "invalid_proof"' in workflow
    assert "< rust/substrate-proof-verifier/fixtures/finney-state-v1.json" in workflow
    assert 'tools["runtime_executor"]._invoke' in workflow
    assert 'error.reason_code == "runtime_execution_failed"' in workflow
    assert "/tmp:rw,noexec" in workflow


@pytest.mark.parametrize("arguments", [[], ["arbitrary"], ["runtime-metadata", "../elsewhere"]])
def test_invalid_native_build_targets_fail_before_invoking_cargo(arguments):
    result = subprocess.run(
        ["/bin/sh", str(DEPLOY / "native-verifiers/build.sh"), *arguments],
        env={"PATH": "/nonexistent"},
        capture_output=True,
        timeout=5,
    )
    assert result.returncode in {1, 2}
    assert b"cargo" not in result.stderr
