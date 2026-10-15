"""Native history-only child for the root-owned preparation broker.

The broker authenticates the root selection and owns the process lifetime.
Serialized controls select scope, never supply native proof capabilities. Only
the ordinary owned-finality provider and history verifier can issue success.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import resource
import signal
import sys
import time
from contextlib import AsyncExitStack, suppress
from pathlib import Path

from .competition_chain_resource_preflight import preflight_chain_resources
from .competition_proof_archive_selection import selected_proof_archive
from .competition_remote_proof_store import RemoteProofStore
from .competition_reward_boot import StandingRewardBootConfig
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_history_preparation import StandingHistoryPreparationApproval
from .competition_reward_history_preparation_runtime import WORK, HistoryPreparationLaunch
from .competition_reward_proof_archive import RewardProofArchive
from .competition_reward_service import _close_provider
from .competition_verification_rules import runtime_identity
from .concurrency import run_owned_thread
from .historical_header_recovery import HistoricalHeaderRecoveryProgress
from .host_memory_runtime import memory_runtime
from .open_competition import digest
from .protocol import canonical_json_bytes
from .rpc_transport import load_routes, transport_config_path
from .validator_chain import ValidatorChainError


async def run(
    logical: Path,
    service_uid: int,
    expected_directory: tuple[int, ...],
    *,
    action: str,
    parent_mount_namespace: str,
    parent_pid_namespace: str,
):
    started = time.monotonic()
    boot_raw = Path("/boot.json").read_bytes()
    config = StandingRewardBootConfig.model_validate_json(boot_raw)
    approval = StandingHistoryPreparationApproval.model_validate_json(
        Path("/approval.json").read_bytes()
    )
    launch = HistoryPreparationLaunch.model_validate_json(Path("/launch.json").read_bytes())
    if action not in {"readiness", "replay"}:
        raise ValueError("unsupported native preparation action")
    selected = config.series if approval.history == "current" else config.predecessor_series
    target = approval.through_block if launch.through_block is None else launch.through_block
    if (
        (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        != (service_uid, service_uid, approval.service_gid, approval.service_gid)
        or os.getgroups()
        or launch.preparation_approval_sha256 != digest(approval)
        or approval.standing_boot_raw_sha256 != hashlib.sha256(boot_raw).hexdigest()
        or approval.series_sha256 != digest(selected)
        or approval.chain_config_sha256 != digest(config.chain)
        or approval.verifier_semantics != runtime_identity()
        or not selected.recovery.authority.issued_at_block <= target <= approval.through_block
        or any(Path(path).exists() for path in ("/root", "/home", "/var/lib/umi-validator-hosts"))
        or (logical.parent.parent.parent / "supervisor-process.lock").exists()
    ):
        raise ValueError("native preparation scope or namespace differs")
    info = logical.stat()
    if (info.st_dev, info.st_ino, info.st_uid, info.st_gid) != expected_directory:
        raise ValueError("native preparation history directory differs")
    status = Path("/proc/self/status").read_text()
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if int(
            next(line.split()[1] for line in status.splitlines() if line.startswith(name + ":")), 16
        ):
            raise ValueError("native preparation retained capabilities")
    if "NoNewPrivs:\t1" not in status:
        raise ValueError("native preparation privileges are not locked")
    if (
        os.readlink("/proc/self/ns/mnt") == parent_mount_namespace
        or os.readlink("/proc/self/ns/pid") == parent_pid_namespace
    ):
        raise ValueError("native preparation namespaces are not isolated")
    transport = transport_config_path()
    if (None if transport is None else str(transport)) != launch.rpc_transport:
        raise ValueError("native preparation lost selected RPC transport")
    routes = {} if transport is None else load_routes(transport)
    if (
        transport is not None
        and hashlib.sha256(transport.read_bytes()).hexdigest() != launch.rpc_transport_sha256
    ):
        raise ValueError("native preparation RPC control changed")
    # Check the real signed-policy build and selected native artifact bytes
    # before opening any journal. Construction does not spawn an observer or
    # initialize finality state; replay later uses the ordinary owned provider.
    preflight = await preflight_chain_resources(config.chain, launch.resources)
    if action == "readiness":
        print(
            json.dumps(
                {
                    "stage": "history_preparation_namespace",
                    "status": "ready",
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "supplementary_groups": [],
                    "capabilities": 0,
                    "private_mount_and_pid_namespaces": True,
                    "staged_directory_identity_preserved": True,
                    "rpc_routes": len(routes),
                    "through_block": target,
                    "approved_through_block": approval.through_block,
                    "native_history_opened": False,
                    "provider_constructed": False,
                    "finality_policy_and_artifacts_checked": True,
                    **preflight,
                    "elapsed_seconds": time.monotonic() - started,
                    "percent": 100,
                    "eta_seconds": 0,
                    "eta_basis": "namespace_readiness_completed",
                    "weight_authority": False,
                },
                separators=(",", ":"),
            ),
            flush=True,
        )
        return None
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    reader = None

    def report(state, **fields):
        value = {
            "stage": "history_preparation_native",
            "state": state,
            "first_block": selected.recovery.authority.issued_at_block,
            "target_block": target,
            "approved_target_block": approval.through_block,
            "elapsed_seconds": time.monotonic() - started,
            "maxrss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "eta_scope": "bounded_staged_history_only",
            "weight_authority": False,
            **fields,
        }
        print(json.dumps(value, separators=(",", ":")), flush=True)
        return value

    report(
        "starting",
        percent=0,
        eta_seconds=None,
        planning_eta_seconds=[5, 1800],
        eta_basis="planning_native_finality_bootstrap_only_excludes_history_verification",
    )
    try:
        async with AsyncExitStack() as resources:
            resources.enter_context(
                memory_runtime(
                    config.host_memory_admission,
                    maximum_aggregate_bytes=config.maximum_package_bytes,
                    role="reward_writer",
                )
            )
            stores = launch.proof_stores
            remote = (
                None
                if stores is None or stores.imported is None
                else RemoteProofStore(WORK / "proof-import-receipts", stores.imported)
            )
            imported = RewardProofArchive(Path("/proof-input"), remote=remote)
            exported = await run_owned_thread(
                selected_proof_archive,
                WORK / "proof-exports",
                None if stores is None else stores.exported,
            )
            reader = await run_owned_thread(
                lambda: RewardControlHistoryReader(
                    logical,
                    control_hotkey=selected.control_hotkey,
                    chain_config_sha256=digest(config.chain),
                    first_block=selected.recovery.authority.issued_at_block,
                    maximum_bytes=config.maximum_history_bytes,
                    archive=imported,
                    export_archive=exported,
                    verification_profile=launch.verification_profile,
                )
            )
            provider = HistoricalRewardControlProvider(
                config.chain,
                config.policy,
                runtime_proof_reads=config.runtime_proof_reads,
                resources=launch.resources,
                historical_header_directory=WORK / "headers",
                historical_header_maximum_bytes=config.maximum_header_bytes,
                historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
            )
            resources.push_async_callback(_close_provider, provider)
            await provider.start()
            while not stop.is_set():
                provider.ensure_observer_running()
                try:
                    result = await reader.advance(
                        provider,
                        through_block=target,
                        maximum_blocks=min(256, config.service.maximum_history_blocks),
                    )
                except HistoricalHeaderRecoveryProgress:
                    await asyncio.sleep(0)
                    continue
                except (OSError, ValidatorChainError) as error:
                    # A dead native observer is not a retriable missing head.
                    # Surface its real failure instead of waiting indefinitely.
                    provider.ensure_observer_running()
                    report(
                        "retrying",
                        error_type=type(error).__name__,
                        eta_seconds=None,
                        eta_basis="withdrawn_operational_retry",
                        progress=reader.progress.latest,
                    )
                    with suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(stop.wait(), timeout=config.service.poll_seconds)
                    continue
                if result.history is not None:
                    final = report(
                        "completed",
                        percent=100,
                        eta_seconds=0,
                        eta_basis="native_owned_history",
                        progress=reader.progress.latest,
                        checkpoint_owner=reader.checkpoints.owner,
                        verifier_semantics=reader.checkpoints.semantics,
                        verified_history_tip=result.history.tip.block_number,
                    )
                    result_path = WORK / "result.json"
                    pending = WORK / "result.pending"
                    with pending.open("wb") as stream:
                        stream.write(canonical_json_bytes(final))
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(pending, result_path)
                    directory = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                    return final
                await asyncio.sleep(0)
            return report(
                "interrupted",
                eta_seconds=None,
                eta_basis="withdrawn_interrupted",
                progress={} if reader is None else reader.progress.latest,
            )
    except BaseException as error:
        report(
            "failed",
            error_type=type(error).__name__,
            eta_seconds=None,
            eta_basis="withdrawn_failure",
        )
        raise
    finally:
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(signum)


def main():
    logging.basicConfig(level=logging.INFO)
    result = asyncio.run(
        run(
            Path(sys.argv[3]),
            int(sys.argv[4]),
            tuple(json.loads(sys.argv[5])),
            action=sys.argv[6],
            parent_mount_namespace=sys.argv[7],
            parent_pid_namespace=sys.argv[8],
        )
    )
    if result is not None and result.get("state") == "interrupted":
        raise SystemExit(130)


if __name__ == "__main__":
    main()
