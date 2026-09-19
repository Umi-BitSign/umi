"""Opt-in real Podman rehearsal with a locally built, synthetic-key release.

Run only in the disposable Linux rehearsal VM. This stages a supplied OCI
archive and runs the inert sandbox probe; it never activates a worker, reads
a wallet, or submits weights. Normal regression runs skip this test.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_validator_supervisor import _config, _wallets
from umi import competition_release as releases
from umi.competition_container import PodmanSuccessorContainer, SuccessorContainerLimits
from umi.competition_package import CompetitionReleaseIdentity
from umi.competition_supervisor import SuccessorSupervisorReleaseTarget
from umi.crypto import sign_response_digest
from umi.policy import umi_source_tree_sha256
from umi.protocol import canonical_json_bytes

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_PODMAN_REHEARSAL") != "1",
    reason="requires explicit opt-in inside the wallet-free Linux rehearsal VM",
)


@pytest.mark.asyncio
async def test_real_signed_oci_load_and_inert_sandbox(tmp_path):
    archive_path = Path(os.environ["UMI_REHEARSAL_OCI_ARCHIVE"])
    assert archive_path.is_absolute() and not archive_path.is_symlink()
    assert 0 < archive_path.stat().st_size <= releases.MAX_SUPERVISOR_RELEASE_BUNDLE_BYTES
    reference = "ghcr.io/umi-bitsign/umi-validator:synthetic-successor-rehearsal"
    inspected = subprocess.run(
        ["/usr/bin/podman", "image", "inspect", "--format=json", reference],
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
    )
    assert len(inspected.stdout) <= 1024 * 1024
    (record,) = json.loads(inspected.stdout)
    labels = record["Config"]["Labels"]
    assert labels.get("vision.umi.source-tree-sha256") == umi_source_tree_sha256(), (
        "rebuild the rehearsal image from this checkout; its Python source digest differs"
    )
    archive = archive_path.read_bytes()
    manifest = releases.SuccessorOCIReleaseManifest(
        schema=releases.SUCCESSOR_RELEASE_SCHEMA,
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256=record["Digest"].removeprefix("sha256:"),
        oci_archive_sha256=hashlib.sha256(archive).hexdigest(),
        oci_archive_size_bytes=len(archive),
        target_platform="linux/" + record["Architecture"],
        umi_git_revision=labels["org.opencontainers.image.revision"],
        umi_source_tree_sha256=labels["vision.umi.source-tree-sha256"],
        entrypoint_profile=labels["vision.umi.entrypoint-profile"],
        state_schema_minimum=4,
        state_schema_maximum=4,
    )
    assert manifest.entrypoint_profile == "umi-competition-replay-worker/1"
    payload = canonical_json_bytes(manifest)
    # Well-known development key, never an installed authority or wallet.
    authority = _wallets()[0]
    signature = bytes.fromhex(
        sign_response_digest(authority, releases.successor_release_signature_digest(manifest))[1][
            2:
        ]
    )
    bundle = releases._header(payload, signature) + archive
    bundle_hash = hashlib.sha256(bundle).hexdigest()
    manifest_hash = hashlib.sha256(payload).hexdigest()
    identity = CompetitionReleaseIdentity(
        schema="umi-competition-replay-release-identity/1",
        umi_revision=manifest.umi_git_revision,
        release_manifest_sha256=manifest_hash,
        release_bundle_sha256=bundle_hash,
        target_triple=("aarch64" if record["Architecture"] == "arm64" else "x86_64")
        + "-unknown-linux-gnu",
    )
    target = SuccessorSupervisorReleaseTarget(
        schema="umi-successor-supervisor-release-target/1",
        release_bundle_url="https://releases.umi.vision/rehearsal/release.bundle",
        release_bundle_sha256=bundle_hash,
        release_bundle_size_bytes=len(bundle),
        release_manifest_sha256=manifest_hash,
        release_authority_hotkey=authority.hotkey.ss58_address,
        release_authority_signature_scheme="sr25519",
        replay_release_identity=identity,
        **{name: getattr(manifest, name) for name in releases._BOUND_FIELDS},
    )
    root = tmp_path / "release-cache"
    root.mkdir(mode=0o700)
    source = tmp_path / "synthetic-release.bundle"
    source.write_bytes(bundle)
    source.chmod(0o600)
    config = _config(
        target_platform=manifest.target_platform,
        release_root=str(root),
        state_root=str(tmp_path / "unused-state"),
        worker_state_root=str(tmp_path / "unused-worker-state"),
        container_runtime="/usr/bin/podman",
    )
    port = PodmanSuccessorContainer(
        config,
        limits=SuccessorContainerLimits(
            maximum_cache_entries=2,
            maximum_cache_bytes=2 * len(bundle),
            maximum_input_entries=100,
            maximum_input_bytes=1024 * 1024,
            maximum_state_entries=100,
            maximum_state_bytes=1024 * 1024,
        ),
    )
    staged = port.stage_release(source, target)
    try:
        await port.prepare_image(staged)
        assert (await port.status()).phase == "absent"
        assert not Path(config.wallet.path).exists()
        assert not Path(config.worker_state_root).exists()
    finally:
        # Only unseal this test's generated cache directory for pytest cleanup.
        staged.path.chmod(0o700)
