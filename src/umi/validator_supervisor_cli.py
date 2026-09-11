"""Installed CLI and offline authoring tools for the validator supervisor."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import json
import os
import secrets
import signal
import stat
import struct
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .protocol import canonical_json_bytes
from .validator_supervisor import (
    COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
    COMMON_SUPERVISOR_CHANNELS,
    COMMON_SUPERVISOR_RELEASE_ORIGIN,
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
    SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SUPERVISOR_DIRECTIVE_SCHEMA,
    SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
    SignedSupervisorDirective,
    SupervisorAuthority,
    SupervisorDirective,
    SupervisorDirectivePage,
    SupervisorDirectiveSignature,
    SupervisorOperatorInputTarget,
    SupervisorReleaseTarget,
    SupervisorWalletBinding,
    ValidatorSupervisorConfig,
    ValidatorSupervisorError,
    advance_supervisor_directive_history_state,
    advance_supervisor_directive_state,
    load_supervisor_directive_state,
    load_validator_supervisor_config,
    parse_canonical_supervisor_directive_page,
    parse_canonical_validator_supervisor_config,
    supervisor_directive_digest,
    supervisor_directive_sha256,
    verify_signed_supervisor_directive_history,
)
from .validator_supervisor_adapters import (
    SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
    SUPERVISOR_RELEASE_BUNDLE_MAGIC,
    SUPERVISOR_RELEASE_SIGNATURE_DOMAIN,
    SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE,
    FinneyFinalizedBlockReader,
    HTTPSDirectiveFetcher,
    PinnedHTTPSClient,
    RootlessPodmanWorkerAdapter,
    SignedSupervisorHostArtifactManifest,
    SupervisorBootstrapInputBundle,
    SupervisorHostArtifact,
    SupervisorHostArtifactManifest,
    SupervisorReleaseManifest,
    SupervisorSimpleBootstrapInputBundle,
    ValidatorSupervisorAdapterError,
    parse_canonical_signed_supervisor_host_artifact_manifest,
)
from .validator_supervisor_runtime import (
    DIRECTIVE_STATE_FILENAME,
    SupervisorWorkerActivation,
    ValidatorSupervisorRuntime,
    ValidatorSupervisorRuntimeError,
)

SUPERVISOR_PROCESS_LOCK_FILENAME = "supervisor-process.lock"
SUPERVISOR_RECONCILE_RECEIPT_FILENAME = "supervisor-reconcile-receipt.json"
SUPERVISOR_PROCESS_IDENTITY_SCHEMA = "umi-validator-supervisor-process-identity/1"
SUPERVISOR_RECONCILE_RECEIPT_SCHEMA = "umi-validator-supervisor-reconcile-receipt/1"
LINUX_SYSTEMD_V1 = {
    "state_root": "/var/lib/umi-validator-supervisor/state",
    "worker_state_root": "/var/lib/umi-validator-worker-state",
    "release_root": "/var/lib/umi-validator-supervisor/releases",
    "operator_input_root": "/var/lib/umi-validator-operator-inputs",
    "wallet_path": "/var/lib/umi-validator-runtime-wallets",
    "finality_verifier_binary": (
        "/opt/umi-validator-supervisor/artifacts/umi-grandpa-finality-observer"
    ),
    "finality_chain_spec_path": ("/opt/umi-validator-supervisor/artifacts/raw_spec_finney.json"),
    "worker_cpu_millis": 8_000,
    "worker_memory_bytes": 12 * 1024**3,
    "worker_pids_limit": 512,
    "service_memory_high_bytes": 11 * 1024**3,
}


class SupervisorProcessLock:
    """One nonblocking process-wide singleton lock under the private state root."""

    def __init__(self, state_root: str | Path) -> None:
        self.path = Path(state_root) / SUPERVISOR_PROCESS_LOCK_FILENAME
        self._descriptor = -1
        self.identity: dict[str, object] | None = None

    def acquire(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise ValidatorSupervisorAdapterError("supervisor_process_lock_failed") from error
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
                or stat.S_IMODE(details.st_mode) != 0o600
            ):
                raise ValidatorSupervisorAdapterError("supervisor_process_lock_unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise ValidatorSupervisorAdapterError("supervisor_already_running") from error
        except Exception:
            os.close(descriptor)
            raise
        identity: dict[str, object] = {
            "nonce": secrets.token_hex(32),
            "pid": os.getpid(),
            "schema": SUPERVISOR_PROCESS_IDENTITY_SCHEMA,
        }
        try:
            payload = canonical_json_bytes(identity)
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short process-identity write")
                view = view[written:]
            os.fsync(descriptor)
        except OSError as error:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
            raise ValidatorSupervisorAdapterError("supervisor_process_lock_failed") from error
        self._descriptor = descriptor
        self.identity = identity

    def held_by_another_process(self) -> bool:
        return self.holder_identity() is not None

    def holder_identity(self) -> dict[str, object] | None:
        """Return the identity written by the live lock holder, if one exists."""

        flags = os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise ValidatorSupervisorAdapterError("supervisor_process_lock_failed") from error
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
                or stat.S_IMODE(details.st_mode) != 0o600
            ):
                raise ValidatorSupervisorAdapterError("supervisor_process_lock_unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.lseek(descriptor, 0, os.SEEK_SET)
                payload = os.read(descriptor, MAX_SUPERVISOR_DOCUMENT_BYTES + 1)
                return _parse_process_identity(payload)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return None
        finally:
            os.close(descriptor)

    def close(self) -> None:
        if self._descriptor >= 0:
            with contextlib.suppress(OSError):
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            os.close(self._descriptor)
            self._descriptor = -1
            self.identity = None

    def __enter__(self) -> SupervisorProcessLock:
        self.acquire()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run or inspect the UMI validator supervisor")
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check-config", help="validate the complete Linux host profile")
    check.add_argument("--config", type=Path, required=True)
    check.add_argument("--profile", choices=["linux-systemd-v1"], default="linux-systemd-v1")

    common_config = commands.add_parser(
        "build-common-config",
        help="build one local config for the shared signed UMI release channel",
    )
    common_config.add_argument("--wallet-name", required=True)
    common_config.add_argument("--wallet-hotkey", required=True)
    common_config.add_argument(
        "--target-platform",
        choices=sorted(COMMON_SUPERVISOR_CHANNELS),
        required=True,
    )
    common_config.add_argument("--finality-verifier-sha256", required=True)
    common_config.add_argument("--output", type=Path, required=True)

    host_manifest = commands.add_parser(
        "build-common-host-artifacts",
        help="sign the immutable platform artifacts used to start the shared supervisor",
    )
    host_manifest.add_argument(
        "--target-platform",
        choices=sorted(COMMON_SUPERVISOR_CHANNELS),
        required=True,
    )
    host_manifest.add_argument("--umi-git-revision", required=True)
    host_manifest.add_argument("--uv", type=Path, required=True)
    host_manifest.add_argument("--uv-url", required=True)
    host_manifest.add_argument("--finality-verifier", type=Path, required=True)
    host_manifest.add_argument("--finality-verifier-url", required=True)
    host_manifest.add_argument("--finney-chain-spec", type=Path, required=True)
    host_manifest.add_argument("--finney-chain-spec-url", required=True)
    _wallet_arguments(host_manifest)
    host_manifest.add_argument("--output", type=Path, required=True)

    install_host = commands.add_parser(
        "install-common-host-artifacts",
        help="verify and install the signed common supervisor host artifacts",
    )
    install_host.add_argument("--manifest", type=Path, required=True)
    install_host.add_argument(
        "--target-platform",
        choices=sorted(COMMON_SUPERVISOR_CHANNELS),
        required=True,
    )
    install_host.add_argument("--expected-revision", required=True)
    install_host.add_argument("--destination", type=Path, required=True)

    initial = commands.add_parser(
        "preflight-initial-hold",
        help="verify the current signed sequence-1 hold before legacy retirement",
    )
    initial.add_argument("--config", type=Path, required=True)

    common_switch = commands.add_parser(
        "preflight-common-switch",
        help="verify the shared hold, current worker release, wallet, and host before cutover",
    )
    common_switch.add_argument("--config", type=Path, required=True)

    run = commands.add_parser("run", help="run the permanent fail-closed supervisor")
    run.add_argument("--config", type=Path, required=True)

    status = commands.add_parser("status", help="print bounded local supervisor status")
    status.add_argument("--config", type=Path, required=True)
    status.add_argument("--require-hold", action="store_true")

    bundle = commands.add_parser(
        "build-release-bundle", help="sign and frame one immutable OCI release bundle"
    )
    bundle.add_argument("--manifest", type=Path, required=True)
    bundle.add_argument("--oci-archive", type=Path, required=True)
    bundle.add_argument("--release-bundle-url", required=True)
    _wallet_arguments(bundle)
    bundle.add_argument("--output", type=Path, required=True)
    bundle.add_argument("--target-output", type=Path, required=True)

    inputs = commands.add_parser(
        "build-bootstrap-input-bundle",
        help="bind canonical bootstrap inputs into one immutable directive artifact",
    )
    inputs.add_argument("--signed-manifest", type=Path, required=True)
    inputs.add_argument("--authorization", type=Path, required=True)
    inputs.add_argument("--drain-checkpoint", type=Path, required=True)
    inputs.add_argument("--owner-fence-receipt", type=Path, required=True)
    inputs.add_argument("--bundle-url", required=True)
    inputs.add_argument("--output", type=Path, required=True)
    inputs.add_argument("--target-output", type=Path, required=True)

    common_inputs = commands.add_parser(
        "build-common-bootstrap-input-bundle",
        help="bind the common signed bootstrap manifest and lease",
    )
    common_inputs.add_argument("--signed-manifest", type=Path, required=True)
    common_inputs.add_argument("--signed-lease", type=Path, required=True)
    common_inputs.add_argument("--bundle-url", required=True)
    common_inputs.add_argument("--output", type=Path, required=True)
    common_inputs.add_argument("--target-output", type=Path, required=True)

    sign = commands.add_parser("sign-directive", help="sign one canonical typed directive")
    sign.add_argument("--directive", type=Path, required=True)
    _wallet_arguments(sign)
    sign.add_argument("--output", type=Path, required=True)

    assemble = commands.add_parser(
        "assemble-directive", help="assemble ordered detached signatures into one object"
    )
    assemble.add_argument("--directive", type=Path, required=True)
    assemble.add_argument("--signature", type=Path, action="append", required=True)
    assemble.add_argument("--output", type=Path, required=True)

    page = commands.add_parser(
        "assemble-directive-page",
        help="assemble a canonical cursor-bound page of signed directives",
    )
    page.add_argument("--config", type=Path, required=True)
    page.add_argument("--after-sequence", type=int, required=True)
    page.add_argument("--after-directive-sha256")
    page.add_argument("--directive", type=Path, action="append", default=[])
    page.add_argument("--head", type=Path)
    page.add_argument("--more", action="store_true")
    page.add_argument("--output", type=Path, required=True)
    return parser


def _wallet_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--wallet-path", required=True)
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--wallet-hotkey", required=True)
    parser.add_argument("--expected-hotkey", required=True)


def _build_common_config(args: argparse.Namespace) -> dict[str, object]:
    import bittensor as bt

    try:
        wallet = bt.Wallet(
            name=args.wallet_name,
            hotkey=args.wallet_hotkey,
            path=LINUX_SYSTEMD_V1["wallet_path"],
        )
        signer = bt.resolve_signer(wallet, role="hotkey")
    except Exception as error:
        raise ValidatorSupervisorAdapterError("common_config_wallet_unavailable") from error
    channel_id = COMMON_SUPERVISOR_CHANNELS[args.target_platform]
    config = ValidatorSupervisorConfig(
        schema="umi-validator-supervisor-config/1",
        network="finney",
        netuid=78,
        mechanism_id=0,
        validator_hotkey=signer.ss58_address,
        channel_id=channel_id,
        signature_threshold=1,
        trusted_authorities=[
            SupervisorAuthority(
                hotkey=COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
                signature_scheme="sr25519",
            )
        ],
        allowed_oci_repositories=["ghcr.io/umi-bitsign/umi-validator"],
        release_origins=[COMMON_SUPERVISOR_RELEASE_ORIGIN],
        target_platform=args.target_platform,
        state_schema_version=1,
        directive_url=(
            f"{COMMON_SUPERVISOR_RELEASE_ORIGIN}/validator-supervisor/channels/"
            f"{channel_id}/{args.target_platform.replace('/', '-')}"
        ),
        poll_seconds=30,
        container_runtime="/usr/bin/podman",
        state_root=LINUX_SYSTEMD_V1["state_root"],
        worker_state_root=LINUX_SYSTEMD_V1["worker_state_root"],
        release_root=LINUX_SYSTEMD_V1["release_root"],
        operator_input_root=LINUX_SYSTEMD_V1["operator_input_root"],
        finality_verifier_binary=LINUX_SYSTEMD_V1["finality_verifier_binary"],
        finality_verifier_sha256=args.finality_verifier_sha256,
        finality_chain_spec_path=LINUX_SYSTEMD_V1["finality_chain_spec_path"],
        worker_cpu_millis=8_000,
        worker_memory_bytes=12 * 1024**3,
        worker_pids_limit=512,
        worker_uid=65_532,
        worker_gid=65_532,
        wallet=SupervisorWalletBinding(
            path=LINUX_SYSTEMD_V1["wallet_path"],
            name=args.wallet_name,
            hotkey=args.wallet_hotkey,
        ),
        allowed_modes=[
            "hold",
            "inactive_shadow",
            "bootstrap_service_weights",
            "translation_weights",
        ],
    )
    _write_new_canonical(args.output, config)
    return {
        "channel_id": channel_id,
        "status": "common_config_built",
        "target_platform": args.target_platform,
        "validator_hotkey": config.validator_hotkey,
    }


def _host_artifact(path: Path, url: str) -> SupervisorHostArtifact:
    size, digest = _file_identity(path, 256 * 1024 * 1024)
    return SupervisorHostArtifact(url=url, sha256=digest, size_bytes=size)


def _build_common_host_artifacts(args: argparse.Namespace) -> dict[str, object]:
    signer, scheme = _load_signer(args)
    if signer.ss58_address != COMMON_SUPERVISOR_AUTHORITY_HOTKEY:
        raise ValidatorSupervisorAdapterError("common_host_artifact_authority_mismatch")
    manifest = SupervisorHostArtifactManifest(
        schema="umi-validator-supervisor-host-artifacts/1",
        channel_id=COMMON_SUPERVISOR_CHANNELS[args.target_platform],
        authority_hotkey=signer.ss58_address,
        target_platform=args.target_platform,
        umi_git_revision=args.umi_git_revision,
        uv=_host_artifact(args.uv, args.uv_url),
        finality_verifier=_host_artifact(
            args.finality_verifier,
            args.finality_verifier_url,
        ),
        finney_chain_spec=_host_artifact(
            args.finney_chain_spec,
            args.finney_chain_spec_url,
        ),
    )
    manifest_bytes = canonical_json_bytes(manifest)
    digest = hashlib.sha256(
        b"umi-validator-supervisor-host-artifacts-v1\0" + manifest_bytes
    ).digest()
    signature = bytes(signer.sign(digest))
    if len(signature) != 64:
        raise ValidatorSupervisorAdapterError("common_host_artifact_signature_invalid")
    signed = SignedSupervisorHostArtifactManifest(
        schema="umi-validator-supervisor-signed-host-artifacts/1",
        manifest=manifest,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        manifest_digest=digest.hex(),
        signature_scheme=scheme,
        signature="0x" + signature.hex(),
    )
    _write_new_canonical(args.output, signed)
    return {
        "channel_id": manifest.channel_id,
        "manifest_sha256": signed.manifest_sha256,
        "status": "common_host_artifacts_built",
        "target_platform": manifest.target_platform,
    }


async def _install_common_host_artifacts(args: argparse.Namespace) -> dict[str, object]:
    payload = _read_bounded(args.manifest, MAX_SUPERVISOR_DOCUMENT_BYTES)
    signed = parse_canonical_signed_supervisor_host_artifact_manifest(payload)
    manifest = signed.manifest
    if (
        manifest.target_platform != args.target_platform
        or manifest.channel_id != COMMON_SUPERVISOR_CHANNELS[args.target_platform]
        or manifest.umi_git_revision != args.expected_revision
    ):
        raise ValidatorSupervisorAdapterError("common_host_artifact_binding_mismatch")
    destination = args.destination
    if not destination.is_absolute() or destination != Path(os.path.normpath(destination)):
        raise ValidatorSupervisorAdapterError("common_host_artifact_destination_invalid")
    try:
        metadata = destination.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValidatorSupervisorAdapterError("common_host_artifact_destination_unsafe")
        if any(destination.iterdir()):
            raise ValidatorSupervisorAdapterError("common_host_artifact_destination_not_empty")
    except OSError as error:
        raise ValidatorSupervisorAdapterError("common_host_artifact_destination_unsafe") from error
    client = PinnedHTTPSClient()
    targets = (
        ("uv", manifest.uv, 0o555),
        ("umi-grandpa-finality-observer", manifest.finality_verifier, 0o555),
        ("raw_spec_finney.json", manifest.finney_chain_spec, 0o444),
    )
    installed: list[Path] = []
    try:
        for filename, target, mode in targets:
            destination_path = destination / filename
            await client.download_file(
                target.url,
                destination=destination_path,
                maximum_bytes=target.size_bytes,
                expected_size_bytes=target.size_bytes,
                expected_sha256=target.sha256,
            )
            destination_path.chmod(mode)
            installed.append(destination_path)
    except Exception:
        for path in installed:
            with contextlib.suppress(OSError):
                path.unlink()
        raise
    return {
        "finality_verifier_sha256": manifest.finality_verifier.sha256,
        "status": "common_host_artifacts_installed",
        "target_platform": manifest.target_platform,
        "uv_sha256": manifest.uv.sha256,
    }


async def _check_config(config_path: Path) -> dict[str, object]:
    config = load_validator_supervisor_config(config_path)
    _validate_linux_systemd_profile(config)
    adapter = RootlessPodmanWorkerAdapter(config)
    await adapter.check_host()
    return {
        "network": "finney",
        "netuid": 78,
        "profile": "linux-systemd-v1",
        "status": "config_ok",
        "validator_hotkey": config.validator_hotkey,
    }


async def _preflight_initial_hold(config_path: Path) -> dict[str, object]:
    """Prove a fresh, validator-bound initial hold without changing local state."""

    config = load_validator_supervisor_config(config_path)
    _validate_linux_systemd_profile(config)
    adapter = RootlessPodmanWorkerAdapter(config)
    await adapter.check_host()
    local_status = await adapter.public_status()
    if local_status["managed_container_present"] is not False:
        raise ValidatorSupervisorAdapterError("initial_hold_managed_container_present")
    payload = await HTTPSDirectiveFetcher(config).fetch_directive_page(
        after_sequence=0,
        after_directive_sha256=None,
    )
    if payload is None:
        raise ValidatorSupervisorAdapterError("initial_hold_directive_missing")
    try:
        page = parse_canonical_supervisor_directive_page(payload)
    except Exception as error:
        raise ValidatorSupervisorAdapterError("initial_hold_directive_invalid") from error
    if (
        page.after_sequence != 0
        or page.after_directive_sha256 is not None
        or page.more
        or len(page.directives) != 1
    ):
        raise ValidatorSupervisorAdapterError("initial_hold_directive_required")
    signed = page.directives[0]
    directive = signed.directive
    if (
        directive.sequence != 1
        or directive.previous_directive_sha256 is not None
        or directive.mode != "hold"
    ):
        raise ValidatorSupervisorAdapterError("initial_hold_directive_required")
    finality = FinneyFinalizedBlockReader(config)
    try:
        finalized_block = await finality.read_finalized_block()
        if not directive.valid_from_block <= finalized_block <= directive.valid_through_block:
            raise ValidatorSupervisorAdapterError("initial_hold_directive_not_current")
        try:
            state = advance_supervisor_directive_state(
                signed,
                config=config,
                finalized_block=finalized_block,
                prior_state=None,
            )
        except Exception as error:
            raise ValidatorSupervisorAdapterError("initial_hold_directive_rejected") from error
    finally:
        await finality.stop()
    return {
        "directive_sha256": state.accepted_directive_sha256,
        "finalized_block": finalized_block,
        "sequence": state.accepted_sequence,
        "status": "initial_hold_preflight_ok",
        "validator_hotkey": config.validator_hotkey,
    }


async def _preflight_common_switch(config_path: Path) -> dict[str, object]:
    """Verify the complete common chain and stage its current worker without executing it."""

    config = load_validator_supervisor_config(config_path)
    _validate_linux_systemd_profile(config)
    adapter = RootlessPodmanWorkerAdapter(config)
    await adapter.check_host()
    local_status = await adapter.public_status()
    if local_status["managed_container_present"] is not False:
        raise ValidatorSupervisorAdapterError("common_switch_managed_container_present")

    fetcher = HTTPSDirectiveFetcher(config)
    finality = FinneyFinalizedBlockReader(config)
    cursor_sequence = 0
    cursor_digest: str | None = None
    state = None
    first_seen = False
    current_signed: SignedSupervisorDirective | None = None
    directive_count = 0
    try:
        finalized_block = await finality.read_finalized_block()
        while True:
            payload = await fetcher.fetch_directive_page(
                after_sequence=cursor_sequence,
                after_directive_sha256=cursor_digest,
            )
            if payload is None:
                raise ValidatorSupervisorAdapterError("common_switch_directive_missing")
            try:
                page = parse_canonical_supervisor_directive_page(payload)
            except Exception as error:
                raise ValidatorSupervisorAdapterError("common_switch_directive_invalid") from error
            if (
                page.after_sequence != cursor_sequence
                or page.after_directive_sha256 != cursor_digest
            ):
                raise ValidatorSupervisorAdapterError("common_switch_cursor_mismatch")
            if not page.directives:
                raise ValidatorSupervisorAdapterError("common_switch_directive_missing")

            history = page.directives if page.more else page.directives[:-1]
            for signed in history:
                directive_count += 1
                if directive_count > 4_096:
                    raise ValidatorSupervisorAdapterError("common_switch_history_limit")
                directive = signed.directive
                if directive.validator_scope != "any_permitted_sn78" or directive.validator_hotkeys:
                    raise ValidatorSupervisorAdapterError("common_switch_scope_invalid")
                if not first_seen:
                    if (
                        directive.sequence != 1
                        or directive.previous_directive_sha256 is not None
                        or directive.mode != "hold"
                    ):
                        raise ValidatorSupervisorAdapterError("common_switch_initial_hold_required")
                    first_seen = True
                try:
                    state = advance_supervisor_directive_history_state(
                        signed,
                        config=config,
                        finalized_block=finalized_block,
                        prior_state=state,
                    )
                except Exception as error:
                    raise ValidatorSupervisorAdapterError(
                        "common_switch_directive_rejected"
                    ) from error

            if page.more:
                cursor_sequence = page.directives[-1].directive.sequence
                cursor_digest = page.directives[-1].directive_sha256
                continue

            current_signed = page.head
            directive_count += 1
            if directive_count > 4_096:
                raise ValidatorSupervisorAdapterError("common_switch_history_limit")
            directive = current_signed.directive
            if directive.validator_scope != "any_permitted_sn78" or directive.validator_hotkeys:
                raise ValidatorSupervisorAdapterError("common_switch_scope_invalid")
            if not first_seen:
                if (
                    directive.sequence != 1
                    or directive.previous_directive_sha256 is not None
                    or directive.mode != "hold"
                ):
                    raise ValidatorSupervisorAdapterError("common_switch_initial_hold_required")
                first_seen = True
            try:
                state = advance_supervisor_directive_state(
                    current_signed,
                    config=config,
                    finalized_block=finalized_block,
                    prior_state=state,
                )
            except Exception as error:
                raise ValidatorSupervisorAdapterError("common_switch_directive_rejected") from error
            break

        directive = current_signed.directive
        release = directive.release
        operator_inputs = directive.operator_inputs
        if (
            directive.mode != "bootstrap_service_weights"
            or release is None
            or release.entrypoint_profile != "umi-simple-bootstrap-validator/1"
            or operator_inputs is None
            or operator_inputs.profile != SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE
            or directive.policy_sha256 is None
        ):
            raise ValidatorSupervisorAdapterError("common_switch_release_required")
        activation = SupervisorWorkerActivation(
            mode=directive.mode,
            sequence=directive.sequence,
            directive_sha256=current_signed.directive_sha256,
            policy_sha256=directive.policy_sha256,
            valid_from_block=directive.valid_from_block,
            valid_through_block=directive.valid_through_block,
            release=release,
            operator_inputs=operator_inputs,
        )
        await adapter.preflight_activation(activation=activation)
        refreshed_finalized_block = await finality.read_finalized_block()
        if (
            refreshed_finalized_block <= finalized_block
            or refreshed_finalized_block > directive.valid_through_block
            or directive.valid_through_block - refreshed_finalized_block < 2
        ):
            raise ValidatorSupervisorAdapterError("common_switch_release_headroom_invalid")
    finally:
        await finality.stop()

    return {
        "directive_sha256": state.accepted_directive_sha256,
        "finalized_block": refreshed_finalized_block,
        "initial_hold_verified": True,
        "sequence": state.accepted_sequence,
        "status": "common_switch_preflight_ok",
        "target_platform": config.target_platform,
        "validator_hotkey": config.validator_hotkey,
    }


async def _status(config_path: Path, *, require_hold: bool) -> tuple[dict[str, object], int]:
    config = load_validator_supervisor_config(config_path)
    adapter = RootlessPodmanWorkerAdapter(config)
    local = await adapter.public_status()
    state = load_supervisor_directive_state(
        Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
        trust_policy=config.trust_policy(),
    )
    holder_identity = SupervisorProcessLock(config.state_root).holder_identity()
    daemon_running = holder_identity is not None
    container_present = bool(local["managed_container_present"])
    accepted_mode = None if state is None else state.accepted_mode
    receipt = _load_reconcile_receipt(Path(config.state_root))
    holding = bool(
        holder_identity is not None
        and not container_present
        and state is not None
        and accepted_mode == "hold"
        and receipt is not None
        and receipt.get("process_nonce") == holder_identity.get("nonce")
        and receipt.get("accepted_directive_sha256") == state.accepted_directive_sha256
        and receipt.get("accepted_sequence") == state.accepted_sequence
    )
    output = {
        **local,
        "accepted_directive_sha256": (None if state is None else state.accepted_directive_sha256),
        "accepted_mode": accepted_mode,
        "accepted_sequence": None if state is None else state.accepted_sequence,
        "daemon_running": daemon_running,
        "durable_hold": holding,
        "status": "holding" if holding else "observed",
        "validator_hotkey": config.validator_hotkey,
    }
    return output, 0 if not require_hold or holding else 2


async def _run(config_path: Path) -> int:
    config = load_validator_supervisor_config(config_path)
    _validate_linux_systemd_profile(config)
    _validate_linux_systemd_runtime_cgroup()
    lock = SupervisorProcessLock(config.state_root)
    lock.acquire()
    finality: FinneyFinalizedBlockReader | None = None
    runtime: ValidatorSupervisorRuntime | None = None
    adapter: RootlessPodmanWorkerAdapter | None = None
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    try:
        if lock.identity is None:
            raise ValidatorSupervisorAdapterError("supervisor_process_lock_failed")
        _clear_reconcile_receipt(Path(config.state_root))
        adapter = RootlessPodmanWorkerAdapter(config)
        await adapter.check_host()
        await adapter.stop_worker()
        await adapter.start_hold(reason_code="process_start")
        finality = FinneyFinalizedBlockReader(config)
        await finality.start()
        runtime = ValidatorSupervisorRuntime(
            config=config,
            directive_fetcher=HTTPSDirectiveFetcher(config),
            finalized_block_reader=finality,
            worker_adapter=adapter,
        )
        for item in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(item, stop_event.set)
                installed.append(item)
            except (NotImplementedError, RuntimeError):
                pass
        while not stop_event.is_set():
            _clear_reconcile_receipt(Path(config.state_root))
            result = await runtime.reconcile()
            if result.reason_code == "directive_hold" and result.status.value == "holding":
                _store_reconcile_receipt(
                    Path(config.state_root),
                    process_identity=lock.identity,
                    result=result,
                )
            print(canonical_json_bytes(_result_json(result)).decode("utf-8"), flush=True)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop_event.wait(), timeout=config.poll_seconds)
        return 0
    finally:
        stop_event.set()
        for item in installed:
            loop.remove_signal_handler(item)
        if runtime is not None:
            with contextlib.suppress(Exception):
                await runtime.stop()
        elif adapter is not None:
            with contextlib.suppress(Exception):
                await adapter.stop_worker()
        if finality is not None:
            with contextlib.suppress(Exception):
                await finality.stop()
        lock.close()


def _parse_process_identity(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValidatorSupervisorAdapterError("supervisor_process_identity_invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("schema") != SUPERVISOR_PROCESS_IDENTITY_SCHEMA
        or not isinstance(value.get("pid"), int)
        or isinstance(value.get("pid"), bool)
        or not 1 <= int(value["pid"]) <= 2_147_483_647
        or not isinstance(value.get("nonce"), str)
        or len(str(value["nonce"])) != 64
        or any(character not in "0123456789abcdef" for character in str(value["nonce"]))
        or canonical_json_bytes(value) != payload
    ):
        raise ValidatorSupervisorAdapterError("supervisor_process_identity_invalid")
    return value


def _receipt_path(state_root: Path) -> Path:
    return state_root / SUPERVISOR_RECONCILE_RECEIPT_FILENAME


def _clear_reconcile_receipt(state_root: Path) -> None:
    target = _receipt_path(state_root)
    try:
        target.unlink(missing_ok=True)
        _fsync_directory(state_root)
    except OSError as error:
        raise ValidatorSupervisorAdapterError(
            "supervisor_reconcile_receipt_clear_failed"
        ) from error


def _store_reconcile_receipt(
    state_root: Path,
    *,
    process_identity: dict[str, object],
    result: Any,
) -> None:
    value = {
        "accepted_directive_sha256": result.accepted_directive_sha256,
        "accepted_sequence": result.accepted_sequence,
        "finalized_block": result.finalized_block,
        "process_nonce": process_identity["nonce"],
        "schema": SUPERVISOR_RECONCILE_RECEIPT_SCHEMA,
    }
    payload = canonical_json_bytes(value)
    target = _receipt_path(state_root)
    temporary = state_root / f".{SUPERVISOR_RECONCILE_RECEIPT_FILENAME}.{os.getpid()}.tmp"
    handle = _new_private_file(temporary)
    try:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(temporary, target)
        _fsync_directory(state_root)
    except Exception:
        if not handle.closed:
            handle.close()
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def _load_reconcile_receipt(state_root: Path) -> dict[str, object] | None:
    target = _receipt_path(state_root)
    try:
        payload = _read_private_state_file(target)
    except FileNotFoundError:
        return None
    try:
        value = json.loads(payload)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValidatorSupervisorAdapterError("supervisor_reconcile_receipt_invalid") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "accepted_directive_sha256",
            "accepted_sequence",
            "finalized_block",
            "process_nonce",
            "schema",
        }
        or value.get("schema") != SUPERVISOR_RECONCILE_RECEIPT_SCHEMA
        or not isinstance(value.get("accepted_directive_sha256"), str)
        or len(str(value["accepted_directive_sha256"])) != 64
        or not isinstance(value.get("accepted_sequence"), int)
        or isinstance(value.get("accepted_sequence"), bool)
        or int(value["accepted_sequence"]) < 1
        or not isinstance(value.get("finalized_block"), int)
        or isinstance(value.get("finalized_block"), bool)
        or int(value["finalized_block"]) < 1
        or not isinstance(value.get("process_nonce"), str)
        or len(str(value["process_nonce"])) != 64
        or canonical_json_bytes(value) != payload
    ):
        raise ValidatorSupervisorAdapterError("supervisor_reconcile_receipt_invalid")
    return value


def _read_private_state_file(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ValidatorSupervisorAdapterError("supervisor_reconcile_receipt_read_failed") from error
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size <= 0
            or details.st_size > MAX_SUPERVISOR_DOCUMENT_BYTES
        ):
            raise ValidatorSupervisorAdapterError("supervisor_reconcile_receipt_unsafe")
        payload = os.read(descriptor, MAX_SUPERVISOR_DOCUMENT_BYTES + 1)
        if len(payload) != details.st_size:
            raise ValidatorSupervisorAdapterError("supervisor_reconcile_receipt_changed")
        return payload
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _result_json(result: Any) -> dict[str, object]:
    return {
        "accepted_directive_sha256": result.accepted_directive_sha256,
        "accepted_sequence": result.accepted_sequence,
        "active_mode": result.active_mode,
        "finalized_block": result.finalized_block,
        "prior_worker_may_have_chain_effects": result.prior_worker_may_have_chain_effects,
        "reason_code": result.reason_code,
        "status": result.status.value,
    }


def _validate_linux_systemd_profile(config: Any) -> None:
    expected = {
        "state_root": config.state_root,
        "worker_state_root": config.worker_state_root,
        "release_root": config.release_root,
        "operator_input_root": config.operator_input_root,
        "wallet_path": config.wallet.path,
        "finality_verifier_binary": config.finality_verifier_binary,
        "finality_chain_spec_path": config.finality_chain_spec_path,
    }
    if any(expected[key] != LINUX_SYSTEMD_V1[key] for key in expected):
        raise ValidatorSupervisorAdapterError("linux_systemd_profile_path_mismatch")
    if config.worker_cpu_millis != LINUX_SYSTEMD_V1["worker_cpu_millis"]:
        raise ValidatorSupervisorAdapterError("linux_systemd_profile_cpu_limit")
    if config.worker_memory_bytes != LINUX_SYSTEMD_V1["worker_memory_bytes"]:
        raise ValidatorSupervisorAdapterError("linux_systemd_profile_memory_limit")
    if config.worker_pids_limit != LINUX_SYSTEMD_V1["worker_pids_limit"]:
        raise ValidatorSupervisorAdapterError("linux_systemd_profile_pids_limit")


def _read_cgroup_value(path: Path, reason: str) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            payload = os.read(descriptor, 129)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ValidatorSupervisorAdapterError(reason) from error
    if not payload or len(payload) > 128:
        raise ValidatorSupervisorAdapterError(reason)
    try:
        value = payload.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValidatorSupervisorAdapterError(reason) from error
    if not value or "\x00" in value:
        raise ValidatorSupervisorAdapterError(reason)
    return value


def _validate_linux_systemd_runtime_cgroup(
    *,
    proc_self_cgroup: Path = Path("/proc/self/cgroup"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> None:
    identity = _read_cgroup_value(proc_self_cgroup, "linux_systemd_cgroup_identity_invalid")
    lines = identity.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise ValidatorSupervisorAdapterError("linux_systemd_cgroup_identity_invalid")
    relative = lines[0][3:]
    parts = Path(relative).parts
    if not relative or relative == "/" or any(part in {"", ".", ".."} for part in parts):
        raise ValidatorSupervisorAdapterError("linux_systemd_cgroup_identity_invalid")
    control_root = cgroup_root.joinpath(*parts[1:])
    expected = {
        "memory.high": str(LINUX_SYSTEMD_V1["service_memory_high_bytes"]),
        "memory.max": str(LINUX_SYSTEMD_V1["worker_memory_bytes"]),
        "pids.max": str(LINUX_SYSTEMD_V1["worker_pids_limit"]),
    }
    for filename, value in expected.items():
        actual = _read_cgroup_value(
            control_root / filename, f"linux_systemd_cgroup_{filename.replace('.', '_')}_invalid"
        )
        if actual != value:
            raise ValidatorSupervisorAdapterError(
                f"linux_systemd_cgroup_{filename.replace('.', '_')}_invalid"
            )
    cpu = _read_cgroup_value(control_root / "cpu.max", "linux_systemd_cgroup_cpu_max_invalid")
    fields = cpu.split()
    try:
        quota, period = (int(field, 10) for field in fields)
    except (TypeError, ValueError) as error:
        raise ValidatorSupervisorAdapterError("linux_systemd_cgroup_cpu_max_invalid") from error
    if len(fields) != 2 or quota <= 0 or period <= 0 or quota != 8 * period:
        raise ValidatorSupervisorAdapterError("linux_systemd_cgroup_cpu_max_invalid")


def _build_release_bundle(args: argparse.Namespace) -> dict[str, object]:
    manifest_bytes = _read_bounded(args.manifest, MAX_SUPERVISOR_DOCUMENT_BYTES)
    manifest = SupervisorReleaseManifest.model_validate_json(manifest_bytes)
    if canonical_json_bytes(manifest) != manifest_bytes:
        raise ValidatorSupervisorAdapterError("release_manifest_noncanonical")
    signer, scheme = _load_signer(args)
    digest = hashlib.sha256(SUPERVISOR_RELEASE_SIGNATURE_DOMAIN + manifest_bytes).digest()
    signature = bytes(signer.sign(digest))
    if len(signature) != 64:
        raise ValidatorSupervisorAdapterError("release_signature_invalid")
    output = _new_private_file(args.output)
    try:
        output.write(SUPERVISOR_RELEASE_BUNDLE_MAGIC)
        output.write(struct.pack(">I", len(manifest_bytes)))
        output.write(manifest_bytes)
        output.write(signature)
        archive_size, archive_sha256 = _copy_verified_input(
            args.oci_archive,
            output,
            1024 * 1024 * 1024,
        )
        if (
            archive_size != manifest.oci_archive_size_bytes
            or archive_sha256 != manifest.oci_archive_sha256
        ):
            raise ValidatorSupervisorAdapterError("oci_archive_manifest_mismatch")
        output.flush()
        os.fsync(output.fileno())
    except Exception:
        output.close()
        with contextlib.suppress(OSError):
            args.output.unlink()
        raise
    finally:
        if not output.closed:
            output.close()
    bundle_size, bundle_sha256 = _file_identity(args.output, 1024 * 1024 * 1024 + 2**20)
    target = SupervisorReleaseTarget(
        artifact_type="oci",
        release_bundle_url=args.release_bundle_url,
        release_bundle_sha256=bundle_sha256,
        release_bundle_size_bytes=bundle_size,
        release_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        release_authority_hotkey=signer.ss58_address,
        release_authority_signature_scheme=scheme,
        **manifest.model_dump(
            mode="python",
            exclude={"schema_", "oci_archive_sha256", "oci_archive_size_bytes"},
        ),
    )
    _write_new_canonical(args.target_output, target)
    return {
        "release_bundle_sha256": bundle_sha256,
        "release_bundle_size_bytes": bundle_size,
        "release_manifest_sha256": target.release_manifest_sha256,
        "status": "release_bundle_built",
    }


def _build_bootstrap_input_bundle(args: argparse.Namespace) -> dict[str, object]:
    values: dict[str, object] = {}
    for field, path in (
        ("signed_manifest", args.signed_manifest),
        ("transition_authorization", args.authorization),
        ("drain_checkpoint", args.drain_checkpoint),
        ("owner_fence_receipt", args.owner_fence_receipt),
    ):
        payload = _read_bounded(path, MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES)
        try:
            value = json.loads(payload)
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValidatorSupervisorAdapterError("operator_input_document_invalid") from error
        if canonical_json_bytes(value) != payload:
            raise ValidatorSupervisorAdapterError("operator_input_document_noncanonical")
        values[field] = value
    try:
        bundle = SupervisorBootstrapInputBundle.model_validate_json(
            canonical_json_bytes(
                {
                    "schema": SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
                    "profile": SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
                    **values,
                }
            )
        )
    except Exception as error:
        raise ValidatorSupervisorAdapterError("operator_input_bundle_invalid") from error
    bundle_bytes = canonical_json_bytes(bundle)
    if len(bundle_bytes) > MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES:
        raise ValidatorSupervisorAdapterError("operator_input_bundle_size_invalid")
    _write_new_bytes(args.output, bundle_bytes, MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES)
    target = SupervisorOperatorInputTarget(
        artifact_type="canonical_json",
        profile=SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
        bundle_url=args.bundle_url,
        bundle_sha256=hashlib.sha256(bundle_bytes).hexdigest(),
        bundle_size_bytes=len(bundle_bytes),
    )
    _write_new_canonical(args.target_output, target)
    return {
        "bundle_sha256": target.bundle_sha256,
        "bundle_size_bytes": target.bundle_size_bytes,
        "profile": target.profile,
        "status": "bootstrap_input_bundle_built",
    }


def _build_common_bootstrap_input_bundle(args: argparse.Namespace) -> dict[str, object]:
    values: dict[str, object] = {}
    for field, path in (
        ("signed_manifest", args.signed_manifest),
        ("signed_lease", args.signed_lease),
    ):
        payload = _read_bounded(path, MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES)
        try:
            value = json.loads(payload)
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValidatorSupervisorAdapterError("operator_input_document_invalid") from error
        if canonical_json_bytes(value) != payload:
            raise ValidatorSupervisorAdapterError("operator_input_document_noncanonical")
        values[field] = value
    try:
        bundle = SupervisorSimpleBootstrapInputBundle.model_validate(
            {
                "schema": SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
                "profile": SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE,
                **values,
            }
        )
    except Exception as error:
        raise ValidatorSupervisorAdapterError("operator_input_bundle_invalid") from error
    bundle_bytes = canonical_json_bytes(bundle)
    _write_new_bytes(args.output, bundle_bytes, MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES)
    target = SupervisorOperatorInputTarget(
        artifact_type="canonical_json",
        profile=SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE,
        bundle_url=args.bundle_url,
        bundle_sha256=hashlib.sha256(bundle_bytes).hexdigest(),
        bundle_size_bytes=len(bundle_bytes),
    )
    _write_new_canonical(args.target_output, target)
    return {
        "bundle_sha256": target.bundle_sha256,
        "bundle_size_bytes": target.bundle_size_bytes,
        "profile": target.profile,
        "status": "common_bootstrap_input_bundle_built",
    }


def _sign_directive(args: argparse.Namespace) -> dict[str, object]:
    directive = _load_directive(args.directive)
    signer, scheme = _load_signer(args)
    signature = bytes(signer.sign(supervisor_directive_digest(directive)))
    record = SupervisorDirectiveSignature(
        hotkey=signer.ss58_address,
        signature_scheme=scheme,
        signature="0x" + signature.hex(),
    )
    _write_new_canonical(args.output, record)
    return {"hotkey": record.hotkey, "status": "directive_signed"}


def _assemble_directive(args: argparse.Namespace) -> dict[str, object]:
    directive = _load_directive(args.directive)
    signatures = [
        SupervisorDirectiveSignature.model_validate_json(
            _read_bounded(path, MAX_SUPERVISOR_DOCUMENT_BYTES)
        )
        for path in args.signature
    ]
    signatures.sort(key=lambda item: _account(item.hotkey))
    signed = SignedSupervisorDirective(
        schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=directive,
        directive_sha256=supervisor_directive_sha256(directive),
        directive_digest=supervisor_directive_digest(directive).hex(),
        signatures=signatures,
    )
    _write_new_canonical(args.output, signed)
    return {
        "directive_sha256": signed.directive_sha256,
        "signature_count": len(signed.signatures),
        "status": "directive_assembled",
    }


def _assemble_directive_page(args: argparse.Namespace) -> dict[str, object]:
    directives = [_load_signed_directive(path) for path in args.directive]
    if directives:
        if args.head is not None:
            raise ValidatorSupervisorAdapterError("directive_page_head_ambiguous")
        head = directives[-1]
    else:
        if args.head is None:
            raise ValidatorSupervisorAdapterError("directive_page_head_required")
        head = _load_signed_directive(args.head)
    try:
        config = parse_canonical_validator_supervisor_config(
            _read_bounded(args.config, MAX_SUPERVISOR_DOCUMENT_BYTES)
        )
        verification_height = max(
            signed.directive.issued_at_block for signed in [*directives, head]
        )
        for signed in [*directives, head]:
            verify_signed_supervisor_directive_history(
                signed,
                config=config,
                finalized_block=verification_height,
            )
    except Exception as error:
        raise ValidatorSupervisorAdapterError("directive_page_signature_invalid") from error
    try:
        page = SupervisorDirectivePage(
            schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
            after_sequence=args.after_sequence,
            after_directive_sha256=args.after_directive_sha256,
            directives=directives,
            more=args.more,
            head=head,
        )
    except Exception as error:
        raise ValidatorSupervisorAdapterError("directive_page_invalid") from error
    _write_new_canonical(args.output, page)
    return {
        "after_sequence": page.after_sequence,
        "directive_count": len(page.directives),
        "head_directive_sha256": page.head.directive_sha256,
        "more": page.more,
        "status": "directive_page_assembled",
    }


def _load_directive(path: Path) -> SupervisorDirective:
    payload = _read_bounded(path, MAX_SUPERVISOR_DOCUMENT_BYTES)
    directive = SupervisorDirective.model_validate_json(payload)
    if (
        directive.schema_ != SUPERVISOR_DIRECTIVE_SCHEMA
        or canonical_json_bytes(directive) != payload
    ):
        raise ValidatorSupervisorAdapterError("directive_noncanonical")
    return directive


def _load_signed_directive(path: Path) -> SignedSupervisorDirective:
    payload = _read_bounded(path, MAX_SUPERVISOR_DOCUMENT_BYTES)
    try:
        signed = SignedSupervisorDirective.model_validate_json(payload)
    except Exception as error:
        raise ValidatorSupervisorAdapterError("signed_directive_invalid") from error
    if canonical_json_bytes(signed) != payload:
        raise ValidatorSupervisorAdapterError("signed_directive_noncanonical")
    return signed


def _load_signer(args: argparse.Namespace) -> tuple[Any, str]:
    import bittensor as bt

    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.wallet_hotkey, path=args.wallet_path)
    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme = bt.wallets.format_crypto_type(signer.crypto_type)
    if signer.ss58_address != args.expected_hotkey or scheme not in {"sr25519", "ed25519"}:
        raise ValidatorSupervisorAdapterError("signer_identity_mismatch")
    return signer, scheme


def _account(value: str) -> bytes:
    from .encoding import account_id32

    return account_id32(value)


def _read_bounded(path: Path, maximum_bytes: int) -> bytes:
    descriptor, before = _open_authoring_input(path, maximum_bytes)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ValidatorSupervisorAdapterError("authoring_input_size_limit")
            chunks.append(chunk)
        _require_unchanged_input(descriptor, before, total)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _file_identity(path: Path, maximum_bytes: int) -> tuple[int, str]:
    descriptor, before = _open_authoring_input(path, maximum_bytes)
    try:
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > maximum_bytes:
                raise ValidatorSupervisorAdapterError("authoring_input_size_limit")
            digest.update(chunk)
        _require_unchanged_input(descriptor, before, total)
        return total, digest.hexdigest()
    except ValidatorSupervisorAdapterError:
        raise
    except OSError as error:
        raise ValidatorSupervisorAdapterError("authoring_input_unavailable") from error
    finally:
        os.close(descriptor)


def _copy_verified_input(path: Path, output: Any, maximum_bytes: int) -> tuple[int, str]:
    descriptor, before = _open_authoring_input(path, maximum_bytes)
    digest = hashlib.sha256()
    total = 0
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > maximum_bytes:
                raise ValidatorSupervisorAdapterError("authoring_input_size_limit")
            digest.update(chunk)
            output.write(chunk)
        _require_unchanged_input(descriptor, before, total)
        return total, digest.hexdigest()
    except ValidatorSupervisorAdapterError:
        raise
    except OSError as error:
        raise ValidatorSupervisorAdapterError("authoring_input_unavailable") from error
    finally:
        os.close(descriptor)


def _open_authoring_input(path: Path, maximum_bytes: int) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise ValidatorSupervisorAdapterError("authoring_input_unavailable") from error
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        os.close(descriptor)
        raise ValidatorSupervisorAdapterError("authoring_input_unsafe")
    if details.st_size <= 0 or details.st_size > maximum_bytes:
        os.close(descriptor)
        raise ValidatorSupervisorAdapterError("authoring_input_size_limit")
    return descriptor, details


def _require_unchanged_input(
    descriptor: int,
    before: os.stat_result,
    total: int,
) -> None:
    try:
        after = os.fstat(descriptor)
    except OSError as error:
        raise ValidatorSupervisorAdapterError("authoring_input_unavailable") from error
    if total != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValidatorSupervisorAdapterError("authoring_input_changed")


def _new_private_file(path: Path) -> Any:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    return os.fdopen(descriptor, "wb", buffering=0)


def _write_new_canonical(path: Path, value: Any) -> None:
    payload = canonical_json_bytes(value)
    _write_new_bytes(path, payload, MAX_SUPERVISOR_DOCUMENT_BYTES)


def _write_new_bytes(path: Path, payload: bytes, maximum_bytes: int) -> None:
    if not payload or len(payload) > maximum_bytes:
        raise ValidatorSupervisorAdapterError("authoring_output_size_limit")
    handle = _new_private_file(path)
    try:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()


def run_cli(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check-config":
            result = asyncio.run(_check_config(args.config))
            code = 0
        elif args.command == "build-common-config":
            result, code = _build_common_config(args), 0
        elif args.command == "build-common-host-artifacts":
            result, code = _build_common_host_artifacts(args), 0
        elif args.command == "install-common-host-artifacts":
            result, code = asyncio.run(_install_common_host_artifacts(args)), 0
        elif args.command == "preflight-initial-hold":
            result = asyncio.run(_preflight_initial_hold(args.config))
            code = 0
        elif args.command == "preflight-common-switch":
            result = asyncio.run(_preflight_common_switch(args.config))
            code = 0
        elif args.command == "status":
            result, code = asyncio.run(_status(args.config, require_hold=args.require_hold))
        elif args.command == "run":
            return asyncio.run(_run(args.config))
        elif args.command == "build-release-bundle":
            result, code = _build_release_bundle(args), 0
        elif args.command == "build-bootstrap-input-bundle":
            result, code = _build_bootstrap_input_bundle(args), 0
        elif args.command == "build-common-bootstrap-input-bundle":
            result, code = _build_common_bootstrap_input_bundle(args), 0
        elif args.command == "sign-directive":
            result, code = _sign_directive(args), 0
        elif args.command == "assemble-directive":
            result, code = _assemble_directive(args), 0
        elif args.command == "assemble-directive-page":
            result, code = _assemble_directive_page(args), 0
        else:  # pragma: no cover
            raise ValidatorSupervisorAdapterError("command_invalid")
        print(canonical_json_bytes(result).decode("utf-8"))
        return code
    except (
        ValidatorSupervisorAdapterError,
        ValidatorSupervisorError,
        ValidatorSupervisorRuntimeError,
    ) as error:
        print(
            canonical_json_bytes(
                {
                    "reason_code": getattr(error, "reason_code", "supervisor_failed"),
                    "status": "blocked",
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 2
    except Exception:
        print(
            canonical_json_bytes({"reason_code": "supervisor_failed", "status": "blocked"}).decode(
                "utf-8"
            ),
            file=sys.stderr,
        )
        return 2


def main() -> None:
    raise SystemExit(run_cli())


__all__ = ["SupervisorProcessLock", "main", "run_cli"]
