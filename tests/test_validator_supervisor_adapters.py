from __future__ import annotations

import asyncio
import hashlib
import os
import queue
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from bittensor.keyfiles import serialized_keypair_to_keyfile_data

from tests.factories import dev_wallet
from umi.grandpa_finality import FINNEY_BOOTSTRAP_BLOCK_NUMBER
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    SUPERVISOR_CONFIG_SCHEMA,
    SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
    SupervisorDirectiveState,
    SupervisorReleaseTarget,
    ValidatorSupervisorConfig,
    store_supervisor_directive_state,
)
from umi.validator_supervisor_adapters import (
    WORKER_CONTAINER_NAME,
    WORKER_ENTRYPOINT,
    FinneyFinalizedBlockReader,
    HTTPSDirectiveFetcher,
    PinnedHTTPSClient,
    RootlessPodmanWorkerAdapter,
    StagedSupervisorRelease,
    SupervisorReleaseManifest,
    ValidatorSupervisorAdapterError,
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
        entrypoint_profile="umi-bootstrap-weight-validator/1",
        state_schema_minimum=1,
        state_schema_maximum=1,
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
    assert await reader.read_finalized_block() == first

    pending = asyncio.create_task(reader.read_finalized_block())
    await asyncio.sleep(0.03)
    assert not pending.done()
    observer.records.put(_attestation(first + 1, observed))
    assert await pending == first + 1
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
        _attestation(FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1, observed - timedelta(seconds=31))
    )
    with pytest.raises(ValidatorSupervisorAdapterError, match="finalized_head_stale"):
        await stale_reader.read_finalized_block()
    await stale_reader.stop()

    observer = _QueueObserver()
    reader = FinneyFinalizedBlockReader(
        SimpleNamespace(), observer=observer, timeout_seconds=0.05, clock=lambda: observed
    )
    observer.records.put(_attestation(FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1, observed))
    await reader.read_finalized_block()
    with pytest.raises(ValidatorSupervisorAdapterError, match="finalized_block_timeout"):
        await reader.read_finalized_block()
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
    )
    activation = SupervisorWorkerActivation(
        mode="bootstrap_service_weights",
        sequence=2,
        directive_sha256="99" * 32,
        policy_sha256="aa" * 32,
        valid_from_block=1_000,
        valid_through_block=2_000,
        release=release,
    )
    arguments = RootlessPodmanWorkerAdapter(config)._worker_arguments(staged, activation)

    assert arguments[0:3] == ("/usr/bin/podman", "run", "--rm")
    assert arguments[3:5] == ("--name", WORKER_CONTAINER_NAME)
    assert "--pull=never" in arguments
    assert "--image-volume=ignore" in arguments
    assert "--cap-drop=all" in arguments
    assert WORKER_ENTRYPOINT in arguments
    assert f"UMI_SUPERVISOR_VALID_FROM_BLOCK={activation.valid_from_block}" in arguments
    assert f"UMI_SUPERVISOR_VALID_THROUGH_BLOCK={activation.valid_through_block}" in arguments
    assert f"UMI_EXPECTED_VALIDATOR_HOTKEY={config.validator_hotkey}" in arguments
    assert str(Path(config.state_root)) not in "\n".join(arguments)
    assert str(Path(config.release_root)) not in "\n".join(arguments)
    assert arguments[-2:] == (
        staged.image_reference,
        "run-bootstrap-service-weights",
    )


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
