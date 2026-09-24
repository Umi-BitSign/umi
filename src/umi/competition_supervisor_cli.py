"""Fixed installed successor supervisor; no fresh-install or wallet interface.

Startup requires a real root-owned activation seal, the exact signed host tree,
and the original supervisor lock/history. This command does not perform the
privileged service migration or create missing activation authority.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import signal
import stat
import sys
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import asdict
from pathlib import Path

from .competition_host_activation import (
    ACTIVATION_MOUNT_ROOT,
    ANCHOR_DIRECTORY_NAME,
    SIGNED_HOST_ARTIFACT_FILENAME,
    load_successor_worker_inputs,
    validate_authenticated_successor_installation,
)
from .competition_host_anchor import load_materialized_successor_anchor_for_repair
from .competition_host_artifacts import (
    MAX_HOST_MANIFEST_BYTES,
    _ancestor_identity,
    _ancestor_paths,
    _read_tree,
    parse_signed_host_artifact,
    verify_host_artifact_authority,
)
from .competition_host_maintenance import verify_host_maintenance
from .competition_materialization import (
    SuccessorCurrentMaterializationLimits,
    repair_successor_source_permissions,
)
from .competition_package_reuse import package_verification_session
from .competition_progress import configure_progress_logging, log_phase, progress_phase
from .competition_supervisor_runtime import (
    SuccessorStartupLease,
    SuccessorSupervisorRuntime,
    hold_successor_startup_lease,
)
from .competition_upgrade import _fingerprint, _open_without_links
from .protocol import canonical_json_bytes
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    parse_canonical_validator_supervisor_config,
)

_HOST_PARENT = Path("/opt/umi-validator-supervisor-hosts")
_PROC_SELF_EXE = Path("/proc/self/exe")


def _root_control(path: Path, maximum: int) -> bytes:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ValueError("installed control path is not canonical and absolute")
    fd = _open_without_links(path)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o440, 0o444, 0o600, 0o640}
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError("installed control is not a bounded root-owned file")
        body = bytearray()
        while len(body) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if len(body) != before.st_size or _fingerprint(before) != _fingerprint(os.fstat(fd)):
            raise ValueError("installed control changed during reading")
        return bytes(body)
    finally:
        os.close(fd)


def _stable_file_identity(path: Path) -> tuple[int, ...]:
    descriptor = _open_without_links(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("running host path is not an unlinked regular file")
        identity = _fingerprint(before)
        if _fingerprint(os.fstat(descriptor)) != identity:
            raise ValueError("running host path changed while inspecting it")
        return identity
    finally:
        os.close(descriptor)


def _running_executable_identity(expected: Path) -> tuple[int, ...]:
    identity = _stable_file_identity(expected)
    running = os.stat(_PROC_SELF_EXE)
    if not stat.S_ISREG(running.st_mode) or (running.st_dev, running.st_ino) != identity[:2]:
        raise ValueError("running interpreter differs from the signed host interpreter")
    return identity


def _verify_running_host_values(config, receipt, host_manifest_sha256):
    root = _HOST_PARENT / receipt.host_umi_git_revision
    maintenance = Path(__file__).parent.parent.parent != root
    if maintenance:
        signed = verify_host_maintenance(
            _root_control(
                Path("/etc/umi/validator-supervisor-maintenance.json"),
                MAX_HOST_MANIFEST_BYTES,
            ),
            config=config,
            receipt=receipt,
        )
        root = _HOST_PARENT / signed.manifest.umi_git_revision
    source = root / "src/umi/competition_supervisor_cli.py"
    interpreter = root / ".venv/bin/python"
    if (
        sys.platform != "linux"
        or os.geteuid() == 0
        or Path(__file__) != source
        or Path(sys.executable) != interpreter
        or Path(sys.prefix) != root / ".venv"
    ):
        raise ValueError("supervisor is not the fixed installed non-root host")
    expected_platform = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}.get(platform.machine())
    if expected_platform != config.target_platform:
        raise ValueError("running supervisor platform differs from installed release")
    payload = _root_control(
        ACTIVATION_MOUNT_ROOT / ANCHOR_DIRECTORY_NAME / SIGNED_HOST_ARTIFACT_FILENAME,
        MAX_HOST_MANIFEST_BYTES,
    )
    if hashlib.sha256(payload).hexdigest() != receipt.signed_host_artifact_sha256:
        raise ValueError("running host manifest differs from root receipt")
    original_signed = parse_signed_host_artifact(payload)
    verify_host_artifact_authority(
        original_signed,
        config=config,
        expected_manifest_sha256=host_manifest_sha256,
    )
    if (
        original_signed.manifest.umi_git_revision != receipt.host_umi_git_revision
        or original_signed.manifest.target_platform != expected_platform
    ):
        raise ValueError("running host manifest identity differs")
    if not maintenance:
        signed = original_signed
    source_identity = _stable_file_identity(source)
    interpreter_identity = _running_executable_identity(interpreter)
    ancestors = {path: _ancestor_identity(path) for path in _ancestor_paths(root)}
    fingerprints, _ = _read_tree(root, signed.manifest)
    if (
        fingerprints.get(source) != source_identity
        or fingerprints.get(interpreter) != interpreter_identity
    ):
        raise ValueError("running source or interpreter is absent from the signed host tree")
    if any(_ancestor_identity(path) != identity for path, identity in ancestors.items()):
        raise ValueError("running host parent changed while verifying")
    if maintenance:
        print(
            json.dumps(
                {
                    "schema": "umi-supervisor-host-maintenance-status/1",
                    "status": "verified",
                    "host_manifest_sha256": signed.manifest_sha256,
                    "host_revision": signed.manifest.umi_git_revision,
                    "original_host_manifest_sha256": receipt.host_manifest_sha256,
                }
            ),
            flush=True,
        )


def _verify_running_host(installation):
    """Recheck the exact signed host through a full installed capability."""
    validate_authenticated_successor_installation(installation)
    _verify_running_host_values(
        installation.config, installation._receipt, installation.host_manifest_sha256
    )
    validate_authenticated_successor_installation(installation)


def _verify_running_host_anchor(anchor):
    """Recheck immutable host authority before touching crash-repair state."""
    anchor.recheck_for_parent_repair()
    _verify_running_host_values(anchor.config, anchor.receipt, anchor.receipt.host_manifest_sha256)
    anchor.recheck_for_parent_repair()


class _DeferredAdapter:
    """Do not create adapter journals before the runtime owns its old lock."""

    def __init__(self, factory):
        self._factory, self._adapter = factory, None

    def _get(self):
        if self._adapter is None:
            self._adapter = self._factory()
        return self._adapter

    async def stage(self, selection):
        return await self._get().stage(selection)

    async def preflight(self, selection, observation):
        return await self._get().preflight(selection, observation)

    async def stop_worker(self):
        return await self._get().stop_worker()

    async def recover_stopped_transactions(self, observation):
        return await self._get().recover_stopped_transactions(observation)

    async def worker_is_healthy(self, selection):
        return await self._get().worker_is_healthy(selection)

    async def start_replay(self, selection):
        return await self._get().start_replay(selection)

    async def start_weights(self, selection):
        return await self._get().start_weights(selection)


def _container_limits():
    from .competition_container import SuccessorContainerLimits

    return SuccessorContainerLimits(
        maximum_cache_entries=16384,
        maximum_cache_bytes=8 * 1024**3,
        maximum_input_entries=65536,
        maximum_input_bytes=4 * 1024**3,
        maximum_state_entries=131072,
        maximum_state_bytes=32 * 1024**3,
        maximum_tree_depth=32,
    )


def _materialization_limits():
    return SuccessorCurrentMaterializationLimits(
        maximum_stages=1024,
        maximum_cache_bytes=16 * 1024**3,
        maximum_tree_entries=65536,
        maximum_tree_depth=16,
    )


def _new_container(config):
    from .competition_container import PodmanSuccessorContainer

    return PodmanSuccessorContainer(config, limits=_container_limits())


async def _stop_startup_worker(config, lease: SuccessorStartupLease) -> None:
    """Confirm exact managed-process absence before repairing writable leaves."""
    container = _new_container(config)
    try:
        await container.check_host()
        status = await container.stop()
        if status.phase not in {"absent", "created", "completed", "held", "failed"}:
            raise ValueError("successor worker absence is not confirmed")
    except BaseException:
        lease.preserve_on_failure()
        raise


def _delivery_client(installation):
    from .competition_delivery_config import successor_delivery_client

    host_payload = _root_control(
        ACTIVATION_MOUNT_ROOT / ANCHOR_DIRECTORY_NAME / SIGNED_HOST_ARTIFACT_FILENAME,
        MAX_HOST_MANIFEST_BYTES,
    )
    if (
        hashlib.sha256(host_payload).hexdigest()
        != installation._receipt.signed_host_artifact_sha256
    ):
        raise ValueError("delivery host manifest differs from installed receipt")
    return successor_delivery_client(
        installation.config,
        parse_signed_host_artifact(host_payload),
        expected_manifest_sha256=installation.host_manifest_sha256,
    )


def _build_runtime(installation, config_path, *, startup_lease):
    # These are fixed host-code imports, not operator-selectable plugins.
    from .competition_delivery import (
        HTTPSSuccessorArtifactDelivery,
        HTTPSSuccessorDirectiveFetcher,
        SuccessorDeliveryLimits,
    )
    from .competition_materializer import AuthenticatedSuccessorArtifactMaterializer
    from .competition_supervisor_adapters import (
        ProductionSuccessorRuntimeAdapter,
        SuccessorAdapterLimits,
    )
    from .competition_supervisor_observer import OwnedSuccessorHostObserver
    from .competition_supervisor_runtime import SuccessorRuntimeLimits

    config = installation.config
    observer = OwnedSuccessorHostObserver(installation=installation)
    client = _delivery_client(installation)

    def adapter():
        # Operational ceilings are fixed in the signed host source; directives
        # may narrow them, not enlarge them. No completed history is evicted.
        delivery = HTTPSSuccessorArtifactDelivery(
            config=config,
            operator_consent=installation.operator_consent,
            worker_limits=installation.worker_execution_limits,
            limits=SuccessorDeliveryLimits(
                maximum_cached_objects=2048,
                maximum_cache_bytes=16 * 1024**3,
                total_fetch_timeout_seconds=1800,
            ),
            client=client,
        )
        materializer = AuthenticatedSuccessorArtifactMaterializer(
            installation=installation,
            delivery=delivery,
            observer=observer,
            config_path=config_path,
            limits=_materialization_limits(),
        )
        container = _new_container(config)
        maintenance_path = Path("/etc/umi/validator-supervisor-maintenance.json")
        if maintenance_path.exists():
            from .competition_worker_maintenance import approved_worker_source_overlay

            container.source_overlay = approved_worker_source_overlay(
                _root_control(maintenance_path, MAX_HOST_MANIFEST_BYTES),
                installation=installation,
                running_root=Path(__file__).parent.parent.parent,
            )
        return ProductionSuccessorRuntimeAdapter(
            installation=installation,
            materializer=materializer,
            observer=observer,
            container=container,
            limits=SuccessorAdapterLimits(
                maximum_retained_runs=65536,
                maximum_registry_bytes=64 * 1024**2,
                maximum_staged_selections=4,
            ),
        )

    runtime = SuccessorSupervisorRuntime(
        installation=installation,
        worker_adapter=_DeferredAdapter(adapter),
        directive_fetcher=HTTPSSuccessorDirectiveFetcher(config, client=client),
        observation_reader=observer,
        limits=SuccessorRuntimeLimits(
            maximum_history_records=65536, maximum_history_bytes=64 * 1024**2
        ),
        startup_lease=startup_lease,
    )
    return runtime, observer


def _emit(result):
    # Only bounded status identifiers; no exception strings, paths or wallet data.
    print(
        canonical_json_bytes({"schema": "umi-successor-host-status/1", **asdict(result)}).decode(),
        flush=True,
    )


@log_phase("host_service")
async def run_supervisor(config_path: Path, *, stop_event=None):
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("successor supervisor requires the installed non-root Linux service")
    config_bytes = _root_control(config_path, MAX_SUPERVISOR_DOCUMENT_BYTES)
    config = parse_canonical_validator_supervisor_config(config_bytes)
    with progress_phase("host_anchor"):
        anchor = load_materialized_successor_anchor_for_repair(config_path)
    if config_bytes != canonical_json_bytes(anchor.config):
        raise ValueError("supervisor config differs from the root-sealed anchor")
    _verify_running_host_anchor(anchor)
    with hold_successor_startup_lease(anchor) as startup_lease:
        await _stop_startup_worker(config, startup_lease)
        repair_successor_source_permissions(anchor=anchor, limits=_materialization_limits())
        anchor.recheck()
        with progress_phase("worker_inputs"):
            installation = load_successor_worker_inputs()
        if config_bytes != canonical_json_bytes(installation.config):
            raise ValueError("supervisor config differs from sealed installation")
        _verify_running_host(installation)
        runtime, observer = _build_runtime(installation, config_path, startup_lease=startup_lease)
        stop = stop_event if stop_event is not None else asyncio.Event()
        loop, handlers = asyncio.get_running_loop(), []
        try:
            if stop_event is None:
                for signum in (signal.SIGTERM, signal.SIGINT):
                    loop.add_signal_handler(signum, stop.set)
                    handlers.append(signum)
            async with runtime:
                while not stop.is_set():
                    result = await runtime.reconcile()
                    _emit(result)
                    with suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(
                            stop.wait(), timeout=float(installation.config.poll_seconds)
                        )
        finally:
            for signum in handlers:
                loop.remove_signal_handler(signum)
            await observer.aclose()


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "--config", type=Path, required=True, help="existing root-owned supervisor config"
    )
    args = parser.parse_args(argv)
    configure_progress_logging()
    try:
        with package_verification_session():
            asyncio.run(run_supervisor(args.config))
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(
            '{"schema":"umi-successor-host-status/1","status":"holding","reason":"successor_host_failed"}',
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
