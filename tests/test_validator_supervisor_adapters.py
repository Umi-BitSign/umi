from __future__ import annotations

import asyncio
import hashlib
import json
import os
import queue
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest
from bittensor.keyfiles import serialized_keypair_to_keyfile_data

import umi.validator_supervisor_adapters as supervisor_adapters
import umi.validator_supervisor_cli as supervisor_cli
from tests.factories import dev_wallet
from tests.test_bootstrap_direct_weights import (
    NOW,
    _operational,
    _owner_fence_preflight,
    _preflight,
)
from umi.bootstrap_direct_weights import (
    OWNER_FENCE_RECEIPT_SCHEMA,
    OwnerFenceReceipt,
    build_owner_fence_call,
)
from umi.bootstrap_weights import SignedBootstrapEligibilityManifest
from umi.grandpa_finality import FINNEY_BOOTSTRAP_BLOCK_NUMBER
from umi.protocol import canonical_json_bytes
from umi.simple_bootstrap_validator import (
    SIMPLE_BOOTSTRAP_LEASE_SCHEMA,
    SignedSimpleBootstrapLease,
    build_simple_bootstrap_lease_body,
)
from umi.validator_supervisor import (
    COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
    COMMON_SUPERVISOR_CHANNELS,
    COMMON_SUPERVISOR_RELEASE_ORIGIN,
    SUPERVISOR_CONFIG_SCHEMA,
    SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
    SupervisorDirectiveState,
    SupervisorOperatorInputTarget,
    SupervisorReleaseTarget,
    ValidatorSupervisorConfig,
    store_supervisor_directive_state,
)
from umi.validator_supervisor_adapters import (
    BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL,
    MAX_FINALIZED_HEAD_AGE_SECONDS,
    SIMPLE_BOOTSTRAP_WORKER_ENTRYPOINT,
    SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
    SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE,
    WORKER_BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL_PATH,
    WORKER_CONTAINER_NAME,
    WORKER_ENTRYPOINT,
    FinneyFinalizedBlockReader,
    HTTPSDirectiveFetcher,
    PinnedHTTPSClient,
    RootlessPodmanWorkerAdapter,
    StagedSupervisorRelease,
    SupervisorBootstrapInputBundle,
    SupervisorReleaseManifest,
    SupervisorSimpleBootstrapInputBundle,
    ValidatorSupervisorAdapterError,
    _parse_bootstrap_input_bundle,
    _require_bootstrap_result_upload_credential,
    _require_wallet_tree,
    _run_bounded_command,
)
from umi.validator_supervisor_cli import (
    SupervisorProcessLock,
    _status,
    _store_reconcile_receipt,
    _write_new_canonical,
)
from umi.validator_supervisor_runtime import SupervisorWorkerActivation


class _AsyncBytes(httpx.AsyncByteStream):
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    async def __aiter__(self):
        yield self.payload


def _config(tmp_path: Path) -> ValidatorSupervisorConfig:
    authority = dev_wallet("//SupervisorAdapterAuthority").hotkey.ss58_address
    validator = dev_wallet("//SupervisorAdapterValidator").hotkey.ss58_address
    return ValidatorSupervisorConfig.model_validate(
        {
            "schema": SUPERVISOR_CONFIG_SCHEMA,
            "network": "finney",
            "netuid": 78,
            "mechanism_id": 0,
            "validator_hotkey": validator,
            "channel_id": "11" * 32,
            "signature_threshold": 1,
            "trusted_authorities": [{"hotkey": authority, "signature_scheme": "sr25519"}],
            "allowed_oci_repositories": ["ghcr.io/umi-bitsign/umi-validator"],
            "release_origins": ["https://api.umi.vision"],
            "target_platform": "linux/amd64",
            "state_schema_version": 1,
            "directive_url": "https://api.umi.vision/api/v1/validator-directives/validator",
            "poll_seconds": 30,
            "container_runtime": "/usr/bin/podman",
            "state_root": str(tmp_path / "state"),
            "worker_state_root": str(tmp_path / "worker-state"),
            "release_root": str(tmp_path / "releases"),
            "operator_input_root": str(tmp_path / "operator-inputs"),
            "finality_verifier_binary": str(tmp_path / "observer"),
            "finality_verifier_sha256": "22" * 32,
            "finality_chain_spec_path": str(tmp_path / "finney.json"),
            "worker_cpu_millis": 8_000,
            "worker_memory_bytes": 12 * 1024**3,
            "worker_pids_limit": 512,
            "worker_uid": 65_532,
            "worker_gid": 65_532,
            "wallet": {
                "path": str(tmp_path / "wallets"),
                "name": "validator",
                "hotkey": "default",
            },
            "allowed_modes": [
                "hold",
                "inactive_shadow",
                "bootstrap_service_weights",
                "translation_weights",
            ],
        }
    )


def _release(config: ValidatorSupervisorConfig) -> SupervisorReleaseTarget:
    return SupervisorReleaseTarget(
        artifact_type="oci",
        release_bundle_url="https://api.umi.vision/releases/validator.bin",
        release_bundle_sha256="33" * 32,
        release_bundle_size_bytes=1_000,
        release_manifest_sha256="44" * 32,
        release_authority_hotkey=config.trusted_authorities[0].hotkey,
        release_authority_signature_scheme="sr25519",
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256="55" * 32,
        target_platform="linux/amd64",
        umi_git_revision="66" * 20,
        umi_source_tree_sha256="77" * 32,
        entrypoint_profile="umi-bootstrap-weight-validator/2",
        state_schema_minimum=1,
        state_schema_maximum=1,
    )


def _bootstrap_bundle() -> SupervisorBootstrapInputBundle:
    signed, authorization, owner, _participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    fence_preflight = _owner_fence_preflight(owner, applied=True)
    material, _call = build_owner_fence_call(fence_preflight)
    receipt = OwnerFenceReceipt(
        schema=OWNER_FENCE_RECEIPT_SCHEMA,
        classification="already_applied",
        call_material_sha256=hashlib.sha256(canonical_json_bytes(material)).hexdigest(),
        call_material=material,
        extrinsic=None,
        observation_block=fence_preflight.block_number,
        observation_block_hash=fence_preflight.block_hash,
        observed_weights_version_key=fence_preflight.current_weights_version_key,
        observed_min_allowed_weights=fence_preflight.current_min_allowed_weights,
        observed_commit_reveal_enabled=fence_preflight.current_commit_reveal_enabled,
        source_snapshot_pending_commit_count=fence_preflight.pending_commit_count,
        observed_pending_commit_count=fence_preflight.pending_commit_count,
        batch_all_finalized_success=False,
        all_storage_targets_verified=True,
        sdk_finalized_reads_verified=True,
        storage_proofs_verified=False,
        created_at=NOW,
    )
    return SupervisorBootstrapInputBundle(
        schema=SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
        profile=SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
        signed_manifest=signed,
        transition_authorization=authorization,
        drain_checkpoint=drain,
        owner_fence_receipt=receipt,
    )


@pytest.mark.asyncio
async def test_directive_fetcher_uses_only_the_canonical_cursor_path(tmp_path: Path) -> None:
    config = _config(tmp_path)
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, stream=_AsyncBytes(b"page"))

    client = PinnedHTTPSClient(transport=httpx.MockTransport(handler))
    fetcher = HTTPSDirectiveFetcher(config, client=client)
    digest = "ab" * 32

    assert (
        await fetcher.fetch_directive_page(
            after_sequence=7,
            after_directive_sha256=digest,
        )
        == b"page"
    )
    assert requests[0].url == httpx.URL(f"{config.directive_url}/after/7/{digest}.json")
    with pytest.raises(ValidatorSupervisorAdapterError, match="directive_cursor_invalid"):
        await fetcher.fetch_directive_page(
            after_sequence=0,
            after_directive_sha256=digest,
        )


@pytest.mark.asyncio
async def test_https_client_rejects_redirect_and_oversize_body() -> None:
    async def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/elsewhere"})

    client = PinnedHTTPSClient(transport=httpx.MockTransport(redirect))
    with pytest.raises(ValidatorSupervisorAdapterError, match="https_status_invalid"):
        await client.fetch_bytes("https://api.umi.vision/object", maximum_bytes=32)

    async def oversized(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_AsyncBytes(b"x" * 33))

    client = PinnedHTTPSClient(transport=httpx.MockTransport(oversized))
    with pytest.raises(ValidatorSupervisorAdapterError, match="https_body_limit"):
        await client.fetch_bytes("https://api.umi.vision/object", maximum_bytes=32)


def test_bootstrap_input_bundle_is_canonical_and_cross_bound() -> None:
    bundle = _bootstrap_bundle()
    payload = canonical_json_bytes(bundle)

    assert _parse_bootstrap_input_bundle(payload) == bundle
    changed = bundle.model_dump(mode="json", by_alias=True)
    changed["transition_authorization"]["manifest_sha256"] = "99" * 32
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_bundle_invalid",
    ):
        _parse_bootstrap_input_bundle(canonical_json_bytes(changed))


def test_common_bootstrap_input_bundle_contains_no_validator_specific_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = Path(__file__).resolve().parents[1] / "deploy" / "linux-validator-supervisor"
    manifest_path /= "bootstrap-manifest.json"
    if not manifest_path.exists():
        manifest_path = (
            Path(__file__).resolve().parents[1]
            / "deploy"
            / "simple-bootstrap-validator"
            / "bootstrap-manifest.json"
        )
    signed_manifest = SignedBootstrapEligibilityManifest.model_validate_json(
        manifest_path.read_bytes()
    )
    body = build_simple_bootstrap_lease_body(
        signed_manifest,
        umi_git_revision="ab" * 20,
        valid_from_block=9_040_000,
    )
    signed_lease = SignedSimpleBootstrapLease(
        schema=SIMPLE_BOOTSTRAP_LEASE_SCHEMA,
        body=body,
        signature_scheme="sr25519",
        signature="0x" + "00" * 64,
    )
    monkeypatch.setattr(
        "umi.validator_supervisor_adapters.verify_simple_bootstrap_lease",
        lambda value, **_kwargs: value,
    )
    bundle = SupervisorSimpleBootstrapInputBundle(
        schema="umi-validator-supervisor-simple-bootstrap-input-bundle/1",
        profile=SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE,
        signed_manifest=signed_manifest,
        signed_lease=signed_lease,
    )

    parsed = _parse_bootstrap_input_bundle(canonical_json_bytes(bundle))

    assert parsed == bundle
    assert set(bundle.model_dump(mode="json", by_alias=True)) == {
        "schema",
        "profile",
        "signed_manifest",
        "signed_lease",
    }


def test_cli_builds_bootstrap_input_bundle_and_hash_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _bootstrap_bundle()
    paths: dict[str, Path] = {}
    for name, value in (
        ("signed-manifest", bundle.signed_manifest),
        ("authorization", bundle.transition_authorization),
        ("drain-checkpoint", bundle.drain_checkpoint),
        ("owner-fence-receipt", bundle.owner_fence_receipt),
    ):
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_json_bytes(value))
        paths[name] = path
    output = tmp_path / "bootstrap-inputs.json"
    target_output = tmp_path / "bootstrap-input-target.json"

    assert (
        supervisor_cli.run_cli(
            [
                "build-bootstrap-input-bundle",
                "--signed-manifest",
                str(paths["signed-manifest"]),
                "--authorization",
                str(paths["authorization"]),
                "--drain-checkpoint",
                str(paths["drain-checkpoint"]),
                "--owner-fence-receipt",
                str(paths["owner-fence-receipt"]),
                "--bundle-url",
                "https://api.umi.vision/releases/bootstrap-inputs.json",
                "--output",
                str(output),
                "--target-output",
                str(target_output),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    target = SupervisorOperatorInputTarget.model_validate_json(target_output.read_bytes())
    assert output.read_bytes() == canonical_json_bytes(bundle)
    assert result["bundle_sha256"] == target.bundle_sha256
    assert target.bundle_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert target.bundle_size_bytes == output.stat().st_size


def test_common_config_is_generated_from_platform_and_local_hotkey_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wallet = dev_wallet("//GeneratedCommonSupervisorConfig")
    monkeypatch.setattr(bt, "Wallet", lambda **_kwargs: wallet)
    monkeypatch.setattr(bt, "resolve_signer", lambda _wallet, role: wallet.hotkey)
    output = tmp_path / "validator-supervisor.json"
    args = SimpleNamespace(
        wallet_name="validator",
        wallet_hotkey="default",
        target_platform="linux/amd64",
        finality_verifier_sha256="12" * 32,
        output=output,
    )

    result = supervisor_cli._build_common_config(args)
    config = ValidatorSupervisorConfig.model_validate_json(output.read_bytes())

    assert result["validator_hotkey"] == wallet.hotkey.ss58_address
    assert config.channel_id == COMMON_SUPERVISOR_CHANNELS["linux/amd64"]
    assert config.validator_hotkey == wallet.hotkey.ss58_address
    assert config.trusted_authorities[0].hotkey == COMMON_SUPERVISOR_AUTHORITY_HOTKEY
    assert config.release_origins == [COMMON_SUPERVISOR_RELEASE_ORIGIN]
    assert config.directive_url.endswith("/linux-amd64")
    assert config.wallet.name == "validator"
    assert config.wallet.hotkey == "default"
    assert config.worker_cpu_millis == 8_000
    assert config.worker_memory_bytes == 12 * 1024**3
    assert config.worker_pids_limit == 512
    assert config.allowed_modes == [
        "hold",
        "inactive_shadow",
        "bootstrap_service_weights",
        "translation_weights",
    ]
    supervisor_cli._validate_linux_systemd_profile(config)
    for field, value, reason in (
        ("worker_cpu_millis", 7_999, "linux_systemd_profile_cpu_limit"),
        ("worker_memory_bytes", 12 * 1024**3 - 1, "linux_systemd_profile_memory_limit"),
        ("worker_pids_limit", 511, "linux_systemd_profile_pids_limit"),
    ):
        with pytest.raises(ValidatorSupervisorAdapterError, match=reason):
            supervisor_cli._validate_linux_systemd_profile(config.model_copy(update={field: value}))


@pytest.mark.asyncio
async def test_host_artifact_install_uses_signed_release_not_installer_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = dev_wallet("//CommonHostArtifactTest").hotkey
    monkeypatch.setattr(
        supervisor_cli,
        "COMMON_SUPERVISOR_AUTHORITY_HOTKEY",
        authority.ss58_address,
    )
    monkeypatch.setattr(
        supervisor_adapters,
        "COMMON_SUPERVISOR_AUTHORITY_HOTKEY",
        authority.ss58_address,
    )
    monkeypatch.setattr(
        supervisor_cli,
        "_load_signer",
        lambda _args: (authority, "sr25519"),
    )
    release_revision = "12" * 20
    installer_revision = "34" * 20
    assert release_revision != installer_revision
    artifacts: dict[str, bytes] = {
        f"{COMMON_SUPERVISOR_RELEASE_ORIGIN}/immutable/uv": b"uv",
        f"{COMMON_SUPERVISOR_RELEASE_ORIGIN}/immutable/finality": b"finality",
        f"{COMMON_SUPERVISOR_RELEASE_ORIGIN}/immutable/spec": b"spec",
    }
    paths: dict[str, Path] = {}
    for name, payload in zip(("uv", "finality", "spec"), artifacts.values(), strict=True):
        path = tmp_path / name
        path.write_bytes(payload)
        paths[name] = path
    signed_manifest = tmp_path / "host-artifacts.json"
    supervisor_cli._build_common_host_artifacts(
        SimpleNamespace(
            target_platform="linux/amd64",
            umi_git_revision=release_revision,
            uv=paths["uv"],
            uv_url=f"{COMMON_SUPERVISOR_RELEASE_ORIGIN}/immutable/uv",
            finality_verifier=paths["finality"],
            finality_verifier_url=(f"{COMMON_SUPERVISOR_RELEASE_ORIGIN}/immutable/finality"),
            finney_chain_spec=paths["spec"],
            finney_chain_spec_url=f"{COMMON_SUPERVISOR_RELEASE_ORIGIN}/immutable/spec",
            output=signed_manifest,
        )
    )

    downloads: list[str] = []

    class FakePinnedHTTPSClient:
        async def download_file(
            self,
            url: str,
            *,
            destination: Path,
            maximum_bytes: int,
            expected_size_bytes: int,
            expected_sha256: str,
        ) -> None:
            payload = artifacts[url]
            assert maximum_bytes == expected_size_bytes == len(payload)
            assert hashlib.sha256(payload).hexdigest() == expected_sha256
            destination.write_bytes(payload)
            downloads.append(url)

    monkeypatch.setattr(supervisor_cli, "PinnedHTTPSClient", FakePinnedHTTPSClient)
    destination = tmp_path / "installed"
    destination.mkdir()
    result = await supervisor_cli._install_common_host_artifacts(
        SimpleNamespace(
            manifest=signed_manifest,
            target_platform="linux/amd64",
            expected_revision=release_revision,
            destination=destination,
        )
    )

    assert result["status"] == "common_host_artifacts_installed"
    assert downloads == list(artifacts)
    assert (destination / "uv").read_bytes() == b"uv"
    assert (destination / "umi-grandpa-finality-observer").read_bytes() == b"finality"
    assert (destination / "raw_spec_finney.json").read_bytes() == b"spec"

    rollback_destination = tmp_path / "rollback"
    rollback_destination.mkdir()
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="common_host_artifact_binding_mismatch",
    ):
        await supervisor_cli._install_common_host_artifacts(
            SimpleNamespace(
                manifest=signed_manifest,
                target_platform="linux/amd64",
                expected_revision="56" * 20,
                destination=rollback_destination,
            )
        )
    assert list(rollback_destination.iterdir()) == []

    altered_payload = json.loads(signed_manifest.read_bytes())
    altered_payload["manifest"]["umi_git_revision"] = "78" * 20
    altered_manifest = tmp_path / "altered-host-artifacts.json"
    altered_manifest.write_bytes(canonical_json_bytes(altered_payload))
    altered_destination = tmp_path / "altered"
    altered_destination.mkdir()
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="host_artifact_manifest_invalid",
    ):
        await supervisor_cli._install_common_host_artifacts(
            SimpleNamespace(
                manifest=altered_manifest,
                target_platform="linux/amd64",
                expected_revision=release_revision,
                destination=altered_destination,
            )
        )
    assert list(altered_destination.iterdir()) == []


def test_linux_systemd_runtime_cgroup_must_match_fixed_profile(tmp_path: Path) -> None:
    cgroup_root = tmp_path / "cgroup"
    service = cgroup_root / "system.slice" / "umi-validator-supervisor.service"
    service.mkdir(parents=True)
    proc_self_cgroup = tmp_path / "proc-self-cgroup"
    proc_self_cgroup.write_text("0::/system.slice/umi-validator-supervisor.service\n")
    (service / "memory.high").write_text(f"{11 * 1024**3}\n")
    (service / "memory.max").write_text(f"{12 * 1024**3}\n")
    (service / "pids.max").write_text("512\n")
    (service / "cpu.max").write_text("800000 100000\n")

    supervisor_cli._validate_linux_systemd_runtime_cgroup(
        proc_self_cgroup=proc_self_cgroup,
        cgroup_root=cgroup_root,
    )

    for filename, value, reason in (
        ("memory.high", str(11 * 1024**3 - 1), "linux_systemd_cgroup_memory_high_invalid"),
        ("memory.max", str(12 * 1024**3 + 1), "linux_systemd_cgroup_memory_max_invalid"),
        ("pids.max", "513", "linux_systemd_cgroup_pids_max_invalid"),
        ("cpu.max", "max 100000", "linux_systemd_cgroup_cpu_max_invalid"),
    ):
        original = (service / filename).read_text()
        (service / filename).write_text(f"{value}\n")
        with pytest.raises(ValidatorSupervisorAdapterError, match=reason):
            supervisor_cli._validate_linux_systemd_runtime_cgroup(
                proc_self_cgroup=proc_self_cgroup,
                cgroup_root=cgroup_root,
            )
        (service / filename).write_text(original)


@pytest.mark.asyncio
async def test_adapter_stages_and_reverifies_directive_bound_bootstrap_inputs(
    tmp_path: Path,
) -> None:
    bundle = _bootstrap_bundle()
    payload = canonical_json_bytes(bundle)
    target = SupervisorOperatorInputTarget(
        artifact_type="canonical_json",
        profile=SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
        bundle_url="https://api.umi.vision/releases/bootstrap-inputs.json",
        bundle_sha256=hashlib.sha256(payload).hexdigest(),
        bundle_size_bytes=len(payload),
    )

    class HTTPS:
        async def download_file(self, _url, *, destination, **_kwargs):
            destination.write_bytes(payload)

    release_root = tmp_path / "release"
    release_root.mkdir(mode=0o700)
    config = _config(tmp_path)
    adapter = RootlessPodmanWorkerAdapter(config, https=HTTPS())
    await adapter._stage_operator_inputs(release_root, target)
    release = _release(config)
    manifest = SupervisorReleaseManifest(
        schema="umi-validator-supervisor-release-manifest/1",
        oci_repository=release.oci_repository,
        oci_manifest_sha256=release.oci_manifest_sha256,
        oci_archive_sha256="88" * 32,
        oci_archive_size_bytes=100,
        target_platform=release.target_platform,
        umi_git_revision=release.umi_git_revision,
        umi_source_tree_sha256=release.umi_source_tree_sha256,
        entrypoint_profile=release.entrypoint_profile,
        state_schema_minimum=1,
        state_schema_maximum=1,
    )
    staged = StagedSupervisorRelease(
        root=release_root,
        manifest_path=release_root / "release-manifest.json",
        archive_path=release_root / "image.oci.tar",
        image_reference=f"{release.oci_repository}@sha256:{release.oci_manifest_sha256}",
        manifest=manifest,
        operator_input_root=release_root / "operator-inputs",
    )
    await adapter._verify_staged_operator_inputs(staged, target)
    extracted = staged.operator_input_root / "bootstrap"
    assert (extracted / "signed-manifest.json").read_bytes() == canonical_json_bytes(
        bundle.signed_manifest
    )
    assert (extracted / "owner-fence-receipt.json").read_bytes() == canonical_json_bytes(
        bundle.owner_fence_receipt
    )

    manifest_path = extracted / "signed-manifest.json"
    manifest_path.chmod(0o600)
    manifest_path.write_bytes(b"{}")
    manifest_path.chmod(0o400)
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_file_binding_mismatch",
    ):
        await adapter._verify_staged_operator_inputs(staged, target)


@pytest.mark.asyncio
async def test_bounded_command_drains_chunked_stdout_and_enforces_the_total_limit() -> None:
    chunked = (
        "import sys,time;sys.stdout.buffer.write(b'a');sys.stdout.flush();"
        "time.sleep(0.05);sys.stdout.buffer.write(b'b');sys.stdout.flush()"
    )
    assert (
        await _run_bounded_command(
            (sys.executable, "-c", chunked),
            timeout_seconds=1,
            maximum_output_bytes=2,
        )
        == b"ab"
    )

    oversized = (
        "import sys,time;sys.stdout.buffer.write(b'a');sys.stdout.flush();"
        "time.sleep(0.05);sys.stdout.buffer.write(b'bc');sys.stdout.flush()"
    )
    with pytest.raises(ValidatorSupervisorAdapterError, match="podman_output_limit"):
        await _run_bounded_command(
            (sys.executable, "-c", oversized),
            timeout_seconds=1,
            maximum_output_bytes=2,
        )


class _QueueObserver:
    def __init__(self) -> None:
        self.records: queue.Queue[object] = queue.Queue()

    def attestations(self, *, stop_requested, **_kwargs):
        while not stop_requested():
            try:
                yield self.records.get(timeout=0.01)
            except queue.Empty:
                continue


def _attestation(number: int, observed: datetime) -> object:
    return SimpleNamespace(
        block=SimpleNamespace(
            number=number,
            hash="0x" + f"{number:064x}",
            timestamp_ms=int(observed.timestamp() * 1_000),
        )
    )


@pytest.mark.asyncio
async def test_finality_reader_requires_a_strictly_new_fresh_owned_head() -> None:
    observed = datetime.now(timezone.utc)
    observer = _QueueObserver()
    reader = FinneyFinalizedBlockReader(
        SimpleNamespace(),
        observer=observer,
        timeout_seconds=0.2,
        clock=lambda: observed,
    )
    first = FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1
    observer.records.put(_attestation(first, observed))
    identity = await reader.read_finalized_identity()
    assert identity.number == first
    assert identity.block_hash == "0x" + f"{first:064x}"

    pending = asyncio.create_task(reader.read_finalized_block())
    await asyncio.sleep(0.03)
    assert not pending.done()
    observer.records.put(_attestation(first + 1, observed))
    assert await pending == first + 1
    await reader.stop()


@pytest.mark.asyncio
async def test_finality_reader_accepts_normal_public_finality_lag() -> None:
    observed = datetime.now(timezone.utc)
    observer = _QueueObserver()
    reader = FinneyFinalizedBlockReader(
        SimpleNamespace(),
        observer=observer,
        timeout_seconds=0.2,
        clock=lambda: observed,
    )
    head = FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1
    observer.records.put(_attestation(head, observed - timedelta(seconds=39)))
    try:
        assert await reader.read_finalized_block() == head
    finally:
        await reader.stop()


@pytest.mark.asyncio
async def test_finality_reader_rejects_stale_head_and_times_out_without_a_new_one() -> None:
    observed = datetime.now(timezone.utc)
    stale_observer = _QueueObserver()
    stale_reader = FinneyFinalizedBlockReader(
        SimpleNamespace(),
        observer=stale_observer,
        timeout_seconds=0.1,
        clock=lambda: observed,
    )
    stale_observer.records.put(
        _attestation(
            FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1,
            observed - timedelta(seconds=MAX_FINALIZED_HEAD_AGE_SECONDS + 1),
        )
    )
    with pytest.raises(ValidatorSupervisorAdapterError, match="finalized_head_stale"):
        await stale_reader.read_finalized_block()
    await stale_reader.stop()

    observer = _QueueObserver()
    reader = FinneyFinalizedBlockReader(
        SimpleNamespace(), observer=observer, timeout_seconds=0.05, clock=lambda: observed
    )
    observer.records.put(_attestation(FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1, observed))
    try:
        await reader.read_finalized_block()
        with pytest.raises(ValidatorSupervisorAdapterError, match="finalized_block_timeout"):
            await reader.read_finalized_block()
    finally:
        await reader.stop()


@pytest.mark.asyncio
async def test_finality_reader_keeps_a_regression_failure_until_restart() -> None:
    observed = datetime.now(timezone.utc)
    observer = _QueueObserver()
    reader = FinneyFinalizedBlockReader(
        SimpleNamespace(), observer=observer, timeout_seconds=0.2, clock=lambda: observed
    )
    first = FINNEY_BOOTSTRAP_BLOCK_NUMBER + 2
    observer.records.put(_attestation(first, observed))
    assert await reader.read_finalized_block() == first

    observer.records.put(_attestation(first - 1, observed))
    observer.records.put(_attestation(first + 1, observed))
    with pytest.raises(ValidatorSupervisorAdapterError, match="finality_observer_failed"):
        await reader.read_finalized_block()
    await reader.stop()


def test_worker_arguments_are_fixed_digest_platform_and_lease_bound(tmp_path: Path) -> None:
    config = _config(tmp_path)
    release = _release(config)
    manifest = SupervisorReleaseManifest(
        schema="umi-validator-supervisor-release-manifest/1",
        oci_repository=release.oci_repository,
        oci_manifest_sha256=release.oci_manifest_sha256,
        oci_archive_sha256="88" * 32,
        oci_archive_size_bytes=100,
        target_platform=release.target_platform,
        umi_git_revision=release.umi_git_revision,
        umi_source_tree_sha256=release.umi_source_tree_sha256,
        entrypoint_profile=release.entrypoint_profile,
        state_schema_minimum=1,
        state_schema_maximum=1,
    )
    staged = StagedSupervisorRelease(
        root=tmp_path / "staged",
        manifest_path=tmp_path / "staged" / "release-manifest.json",
        archive_path=tmp_path / "staged" / "image.oci.tar",
        image_reference=f"{release.oci_repository}@sha256:{release.oci_manifest_sha256}",
        manifest=manifest,
        operator_input_root=tmp_path / "staged" / "operator-inputs",
    )
    operator_inputs = SupervisorOperatorInputTarget(
        artifact_type="canonical_json",
        profile="umi-bootstrap-direct-inputs/2",
        bundle_url="https://api.umi.vision/releases/bootstrap-inputs.json",
        bundle_sha256="89" * 32,
        bundle_size_bytes=1_024,
    )
    activation = SupervisorWorkerActivation(
        mode="bootstrap_service_weights",
        sequence=2,
        directive_sha256="99" * 32,
        policy_sha256="aa" * 32,
        valid_from_block=1_000,
        valid_through_block=2_000,
        release=release,
        operator_inputs=operator_inputs,
    )
    arguments = RootlessPodmanWorkerAdapter(config)._worker_arguments(staged, activation)

    assert arguments[0:3] == ("/usr/bin/podman", "run", "--rm")
    assert arguments[3:5] == ("--name", WORKER_CONTAINER_NAME)
    assert "--pull=never" in arguments
    assert "--image-volume=ignore" in arguments
    assert "--cap-drop=all" in arguments
    assert "--cgroups=disabled" in arguments
    assert "--cgroupns=private" in arguments
    for unsupported_nested_limit in ("--cpus", "--memory", "--pids-limit"):
        assert unsupported_nested_limit not in arguments
    assert WORKER_ENTRYPOINT in arguments
    assert f"UMI_SUPERVISOR_VALID_FROM_BLOCK={activation.valid_from_block}" in arguments
    assert f"UMI_SUPERVISOR_VALID_THROUGH_BLOCK={activation.valid_through_block}" in arguments
    assert f"UMI_SUPERVISOR_SEQUENCE={activation.sequence}" in arguments
    assert f"UMI_RELEASE_MANIFEST_SHA256={activation.release.release_manifest_sha256}" in arguments
    assert f"UMI_EXPECTED_VALIDATOR_HOTKEY={config.validator_hotkey}" in arguments
    assert str(Path(config.state_root)) not in "\n".join(arguments)
    assert str(Path(config.release_root)) not in "\n".join(arguments)
    assert str(staged.operator_input_root) in "\n".join(arguments)
    assert str(Path(config.operator_input_root)) not in "\n".join(arguments)
    assert str(BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL) in "\n".join(arguments)
    assert WORKER_BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL_PATH in "\n".join(arguments)
    assert arguments[-2:] == (
        staged.image_reference,
        "run-bootstrap-service-weights",
    )


def test_common_bootstrap_dispatch_has_fixed_entrypoint_and_no_upload_key(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    release = _release(config).model_copy(
        update={"entrypoint_profile": "umi-simple-bootstrap-validator/1"}
    )
    manifest = SupervisorReleaseManifest(
        schema="umi-validator-supervisor-release-manifest/1",
        oci_repository=release.oci_repository,
        oci_manifest_sha256=release.oci_manifest_sha256,
        oci_archive_sha256="88" * 32,
        oci_archive_size_bytes=100,
        target_platform=release.target_platform,
        umi_git_revision=release.umi_git_revision,
        umi_source_tree_sha256=release.umi_source_tree_sha256,
        entrypoint_profile=release.entrypoint_profile,
        state_schema_minimum=1,
        state_schema_maximum=1,
    )
    staged = StagedSupervisorRelease(
        root=tmp_path / "staged",
        manifest_path=tmp_path / "staged" / "release-manifest.json",
        archive_path=tmp_path / "staged" / "image.oci.tar",
        image_reference=f"{release.oci_repository}@sha256:{release.oci_manifest_sha256}",
        manifest=manifest,
        operator_input_root=tmp_path / "staged" / "operator-inputs",
    )
    operator_inputs = SupervisorOperatorInputTarget(
        artifact_type="canonical_json",
        profile=SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE,
        bundle_url="https://api.umi.vision/releases/common-bootstrap-inputs.json",
        bundle_sha256="89" * 32,
        bundle_size_bytes=1_024,
    )
    activation = SupervisorWorkerActivation(
        mode="bootstrap_service_weights",
        sequence=2,
        directive_sha256="99" * 32,
        policy_sha256="aa" * 32,
        valid_from_block=1_000,
        valid_through_block=2_000,
        release=release,
        operator_inputs=operator_inputs,
    )

    arguments = RootlessPodmanWorkerAdapter(config)._worker_arguments(staged, activation)
    encoded = "\n".join(arguments)

    assert arguments[arguments.index("--entrypoint") + 1] == SIMPLE_BOOTSTRAP_WORKER_ENTRYPOINT
    assert str(BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL) not in encoded
    assert WORKER_BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL_PATH not in encoded
    assert f"UMI_HOTKEY={config.wallet.hotkey}" in arguments
    assert "UMI_IMAGE_REVISION_PATH=/opt/umi-image-revision" in arguments
    assert f"UMI_IMAGE_SOURCE_TREE_SHA256={release.umi_source_tree_sha256}" in arguments
    assert arguments[-4:] == (
        staged.image_reference,
        "run",
        "--state-dir",
        "/var/lib/umi-worker",
    )


def test_bootstrap_result_upload_credential_is_exact_and_private(tmp_path: Path) -> None:
    credential = tmp_path / "bootstrap-result-upload.key"
    credential.write_text("ab" * 32 + "\n", encoding="ascii")
    credential.chmod(0o400)
    _require_bootstrap_result_upload_credential(credential)

    credential.chmod(0o600)
    credential.write_text("AB" * 32, encoding="ascii")
    credential.chmod(0o400)
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="bootstrap_result_upload_credential_unsafe",
    ):
        _require_bootstrap_result_upload_credential(credential)


def test_wallet_tree_binds_exact_plaintext_hotkey_and_rejects_broken_coldkey_symlink(
    tmp_path: Path,
) -> None:
    wallet = dev_wallet("//SupervisorAdapterWallet")
    directory = tmp_path / "validator"
    hotkeys = directory / "hotkeys"
    hotkeys.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    hotkeys.chmod(0o700)
    hotkey = hotkeys / "default"
    hotkey.write_bytes(bytes(serialized_keypair_to_keyfile_data(wallet.hotkey)))
    hotkey.chmod(0o600)

    _require_wallet_tree(
        directory,
        "default",
        expected_hotkey=wallet.hotkey.ss58_address,
    )
    with pytest.raises(ValidatorSupervisorAdapterError, match="wallet_hotkey_identity_mismatch"):
        _require_wallet_tree(
            directory,
            "default",
            expected_hotkey=dev_wallet("//DifferentValidator").hotkey.ss58_address,
        )

    os.symlink(directory / "missing", directory / "coldkeypub.txt")
    with pytest.raises(ValidatorSupervisorAdapterError, match="wallet_coldkeypub_unsafe"):
        _require_wallet_tree(
            directory,
            "default",
            expected_hotkey=wallet.hotkey.ss58_address,
        )


def test_process_lock_exposes_only_the_current_live_holder_identity(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    assert SupervisorProcessLock(tmp_path).holder_identity() is None
    first = SupervisorProcessLock(tmp_path)
    first.acquire()
    try:
        observed = SupervisorProcessLock(tmp_path).holder_identity()
        assert observed == first.identity
        assert observed is not None
        assert hashlib.sha256(str(observed["nonce"]).encode()).digest()
    finally:
        first.close()
    assert SupervisorProcessLock(tmp_path).holder_identity() is None


@pytest.mark.asyncio
async def test_supervisor_run_survives_a_normal_poll_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path).model_copy(update={"poll_seconds": 0.01})
    Path(config.state_root).mkdir(mode=0o700)
    calls = 0
    stopped: list[str] = []

    class EndTest(RuntimeError):
        pass

    class Adapter:
        def __init__(self, _config: ValidatorSupervisorConfig) -> None:
            pass

        async def check_host(self) -> None:
            pass

        async def stop_worker(self) -> None:
            stopped.append("adapter")

        async def start_hold(self, *, reason_code: str) -> None:
            assert reason_code == "process_start"

    class Finality:
        def __init__(self, _config: ValidatorSupervisorConfig) -> None:
            pass

        async def start(self) -> None:
            pass

        async def stop(self) -> None:
            stopped.append("finality")

    class Runtime:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def reconcile(self) -> SimpleNamespace:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise EndTest
            return SimpleNamespace(
                accepted_directive_sha256=None,
                accepted_sequence=None,
                active_mode="hold",
                finalized_block=None,
                prior_worker_may_have_chain_effects=False,
                reason_code="waiting",
                status=SimpleNamespace(value="waiting_for_activation"),
            )

        async def stop(self) -> None:
            stopped.append("runtime")

    monkeypatch.setattr(supervisor_cli, "load_validator_supervisor_config", lambda _path: config)
    monkeypatch.setattr(supervisor_cli, "_validate_linux_systemd_profile", lambda _config: None)
    monkeypatch.setattr(supervisor_cli, "_validate_linux_systemd_runtime_cgroup", lambda: None)
    monkeypatch.setattr(supervisor_cli, "RootlessPodmanWorkerAdapter", Adapter)
    monkeypatch.setattr(supervisor_cli, "FinneyFinalizedBlockReader", Finality)
    monkeypatch.setattr(supervisor_cli, "ValidatorSupervisorRuntime", Runtime)
    loop = asyncio.get_running_loop()

    def reject_signal_handler(*_args: object) -> None:
        raise NotImplementedError

    monkeypatch.setattr(loop, "add_signal_handler", reject_signal_handler)

    with pytest.raises(EndTest):
        await supervisor_cli._run(tmp_path / "ignored.json")
    assert calls == 2
    assert stopped == ["adapter", "runtime", "finality"]


def test_authoring_rejects_an_output_larger_than_the_consumer_limit(tmp_path: Path) -> None:
    output = tmp_path / "oversized.json"
    with pytest.raises(ValidatorSupervisorAdapterError, match="authoring_output_size_limit"):
        _write_new_canonical(output, {"value": "x" * (1024 * 1024)})
    assert not output.exists()


@pytest.mark.asyncio
async def test_status_rejects_stale_hold_state_and_receipt_without_a_live_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    for path in (
        config.state_root,
        config.worker_state_root,
        config.release_root,
        config.operator_input_root,
    ):
        Path(path).mkdir(mode=0o700)
    config_path = tmp_path / "supervisor.json"
    config_path.write_bytes(canonical_json_bytes(config))
    config_path.chmod(0o600)
    state = SupervisorDirectiveState(
        schema=SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
        channel_id=config.channel_id,
        accepted_sequence=1,
        accepted_directive_sha256="bb" * 32,
        accepted_at_finalized_block=100,
        accepted_mode="hold",
        accepted_oci_manifest_sha256=None,
    )
    store_supervisor_directive_state(
        Path(config.state_root) / "directive-state.json",
        state,
        trust_policy=config.trust_policy(),
        expected_prior=None,
    )
    _store_reconcile_receipt(
        Path(config.state_root),
        process_identity={"nonce": "cc" * 32},
        result=SimpleNamespace(
            accepted_directive_sha256=state.accepted_directive_sha256,
            accepted_sequence=state.accepted_sequence,
            finalized_block=100,
        ),
    )

    async def no_container(_self):
        return {
            "container_name": WORKER_CONTAINER_NAME,
            "managed_container_present": False,
            "runtime": "rootless_podman",
            "target_platform": config.target_platform,
        }

    monkeypatch.setattr(RootlessPodmanWorkerAdapter, "public_status", no_container)
    output, code = await _status(config_path, require_hold=True)
    assert code == 2
    assert output["daemon_running"] is False
    assert output["durable_hold"] is False
