from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import validator_supervisor_cli as supervisor_cli
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor_adapters import (
    ValidatorSupervisorAdapterError,
    _parse_bootstrap_input_bundle,
    parse_canonical_signed_supervisor_host_artifact_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deploy" / "linux-validator-supervisor"
MANIFESTS = DEPLOYMENT / "host-artifacts"
PLATFORMS = ("linux-amd64", "linux-arm64")


def test_first_install_pin_matches_published_runtime_independent_operator_bundle() -> None:
    # Captured from the sequence-14 release. Verify the real signature,
    # without a wallet or any permit lookup. Keep first-install artifacts and
    # this release compatibility fixture in sync when publishing a new host.
    payload = (
        (ROOT / "tests/fixtures/validator-supervisor/runtime458-registration-bridge.json")
        .read_bytes()
        .removesuffix(b"\n")
    )
    assert hashlib.sha256(payload).hexdigest() == (
        "9ad7f434fde7a406725f93db6c09bfec0f049f49b4552197e036986051d316fe"
    )
    bundle = _parse_bootstrap_input_bundle(payload)
    # The legacy signed annotation is retained, but no longer gates operation.
    assert bundle.signed_policy.body.required_runtime_spec_version == 458
    assert (DEPLOYMENT / "CURRENT_RELEASE_REVISION").read_text().strip() == (
        bundle.signed_policy.body.umi_git_revision
    )


@pytest.mark.parametrize("platform", PLATFORMS)
def test_committed_host_manifest_signature_and_release_pin(platform: str) -> None:
    payload = (MANIFESTS / f"{platform}.json").read_bytes()
    # One repository newline is removed by the installer's command substitution.
    signed = parse_canonical_signed_supervisor_host_artifact_manifest(payload.removesuffix(b"\n"))
    assert payload == canonical_json_bytes(signed) + b"\n"
    assert signed.manifest.target_platform == platform.replace("-", "/")
    assert (
        signed.manifest.umi_git_revision
        == (DEPLOYMENT / "CURRENT_RELEASE_REVISION").read_text().strip()
    )
    for artifact in (
        signed.manifest.uv,
        signed.manifest.finality_verifier,
        signed.manifest.finney_chain_spec,
    ):
        assert f"/host-artifacts/{artifact.sha256}/" in artifact.url


@pytest.mark.parametrize("platform", PLATFORMS)
async def test_committed_manifest_rejects_wrong_pin_before_downloading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    def unexpected_client():
        pytest.fail("a mismatched pin must fail before downloading or installing artifacts")

    monkeypatch.setattr(supervisor_cli, "PinnedHTTPSClient", unexpected_client)
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes((MANIFESTS / f"{platform}.json").read_bytes().removesuffix(b"\n"))
    destination = tmp_path / "artifacts"
    destination.mkdir()
    with pytest.raises(
        ValidatorSupervisorAdapterError, match="common_host_artifact_binding_mismatch"
    ):
        await supervisor_cli._install_common_host_artifacts(
            SimpleNamespace(
                manifest=manifest,
                target_platform=platform.replace("-", "/"),
                # The old main installer pin which caused the reported failure.
                expected_revision="023ab99869ede537e3f590e5b2fddcc03dbf4554",
                destination=destination,
            )
        )
    assert list(destination.iterdir()) == []


@pytest.mark.parametrize("platform", PLATFORMS)
def test_committed_signature_cannot_be_reused_for_an_altered_revision(platform: str) -> None:
    value = json.loads((MANIFESTS / f"{platform}.json").read_bytes())
    value["manifest"]["umi_git_revision"] = "00" * 20
    with pytest.raises(ValidatorSupervisorAdapterError, match="host_artifact_manifest_invalid"):
        parse_canonical_signed_supervisor_host_artifact_manifest(canonical_json_bytes(value))


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        [
            "git",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Release test",
            "-c",
            "user.email=release-test@example.invalid",
            "-C",
            str(root),
            *args,
        ],
        text=True,
    ).strip()


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(
    "replacement",
    (b"changed channel and checkout", b"x" * 1_048_577),
    ids=("later-manifest", "oversized-blob"),
)
def test_installer_reads_bounded_manifest_from_its_commit(
    tmp_path: Path, platform: str, replacement: bytes
) -> None:
    # Exercise the actual shell block without root, wallets, network or services.
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    relative = Path("deploy/linux-validator-supervisor/host-artifacts") / f"{platform}.json"
    manifest = repo / relative
    manifest.parent.mkdir(parents=True)
    expected = (MANIFESTS / f"{platform}.json").read_bytes()
    manifest.write_bytes(expected)
    _git(repo, "add", str(relative))
    _git(repo, "commit", "--quiet", "-m", "Original signed release")
    original = _git(repo, "rev-parse", "HEAD")

    manifest.write_bytes(replacement)
    _git(repo, "add", str(relative))
    _git(repo, "commit", "--quiet", "-m", "Later publication")
    later = _git(repo, "rev-parse", "HEAD")

    source = (DEPLOYMENT / "install.sh").read_text()
    start = source.index('host_manifest_object="$installer_revision:')
    end = source.index('"$supervisor_executable" install-common-host-artifacts', start)
    block = source[start:end]
    assert "curl" not in block
    assert "host_manifest_url=" not in source
    assert end < source.index('systemctl disable --now "$legacy_unit"')
    output = tmp_path / "selected.json"
    env = {
        **os.environ,
        "source_root": str(repo),
        "installer_revision": original,
        "platform_suffix": platform,
        "host_manifest": str(output),
    }
    script = 'fail() { printf "%s\\n" "$*" >&2; exit 2; }\n' + block
    subprocess.run(["sh", "-eu", "-c", script], env=env, check=True, capture_output=True)
    assert output.read_bytes() == expected.removesuffix(b"\n")
    parse_canonical_signed_supervisor_host_artifact_manifest(output.read_bytes())

    # Selecting an oversized Git blob fails before materializing the manifest.
    if len(replacement) > 1_048_576:
        output.unlink()
        result = subprocess.run(
            ["sh", "-eu", "-c", script],
            env={**env, "installer_revision": later},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2
        assert "invalid size" in result.stderr
        assert not output.exists()

    result = subprocess.run(
        ["sh", "-eu", "-c", script],
        env={**env, "platform_suffix": "missing"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "committed host artifact manifest is missing" in result.stderr
