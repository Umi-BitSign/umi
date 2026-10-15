"""Check every native input before opening long-running recovery journals.

These local startup checks supply no chain-verification capability. Ordinary
native consumers still stage their pinned inputs at the point of execution.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import suppress
from functools import partial
from pathlib import Path

from .concurrency import run_owned_thread
from .grandpa_finality import GrandpaFinalityObserver
from .pinned_artifact import PinnedArtifact, staged_pinned_artifacts
from .runtime_metadata import RuntimeMetadataExecutor
from .substrate_proof import SubprocessStorageProofVerifier

_LOG = logging.getLogger("umi.competition.progress")


def _metadata(config, resources):
    path = Path(resources.storage_codec_metadata_path)
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("storage codec metadata must not traverse symlinks")
    with staged_pinned_artifacts(
        (
            PinnedArtifact(
                "storage-codec-metadata",
                path,
                config.chain_pin.metadata_sha256,
                maximum_bytes=4 * 1024**2,
            ),
        )
    ):
        pass


async def preflight_chain_resources(config, resources):
    """Run in the actual consuming UID/GID/mount view, before providers or journals."""
    resources.check(config)
    total = (
        3
        + int(resources.runtime_metadata_binary is not None)
        + int(resources.storage_codec_metadata_path is not None)
    )
    started, completed, last_progress = time.monotonic(), 0, time.monotonic()
    timer = None
    loop = asyncio.get_running_loop()

    def report(state):
        now = time.monotonic()
        elapsed = now - started
        stalled = state == "running" and now - last_progress > 60
        if stalled:
            state = "stalled"
        with suppress(Exception):
            _LOG.info(
                json.dumps(
                    {
                        "stage": "native_resource_preflight",
                        "state": state,
                        "completed": completed,
                        "total": total,
                        "percent": 100
                        if state == "completed"
                        else min(99.9, completed * 100 / total),
                        "elapsed_seconds": elapsed,
                        "eta_seconds": 0 if state == "completed" else None,
                        "planning_eta_seconds": [1, 60]
                        if state == "running" and elapsed <= 60
                        else None,
                        "eta_basis": "completed"
                        if state == "completed"
                        else (
                            "planning_local_pinned_artifact_reads_and_runtime_execution_probe"
                            if state == "running" and elapsed <= 60
                            else "withdrawn"
                        ),
                        "eta_scope": "native_resource_preflight_only",
                        "stalled": stalled,
                        "retrying": False,
                        "chain_submission_authorized": False,
                    },
                    separators=(",", ":"),
                )
            )

    def heartbeat():
        nonlocal timer
        report("running")
        timer = loop.call_later(30, heartbeat)

    async def check(function, count=1, **kwargs):
        nonlocal completed, last_progress
        await run_owned_thread(partial(function, **kwargs))
        completed += count
        last_progress = time.monotonic()
        report("running")

    report("running")
    timer = loop.call_later(30, heartbeat)
    try:
        await check(
            lambda: GrandpaFinalityObserver.from_policy_pin(
                config.finality_pin,
                target_triple=config.target_triple,
                binary_path=resources.finality_binary,
                chain_spec_path=resources.chain_spec,
            ),
            count=2,
        )
        await check(
            SubprocessStorageProofVerifier,
            binary_path=resources.proof_binary,
            expected_sha256=config.proof_binary_sha256,
        )
        if resources.runtime_metadata_binary is not None:
            await check(
                RuntimeMetadataExecutor(
                    binary_path=Path(resources.runtime_metadata_binary),
                    expected_sha256=config.runtime_metadata_binary_sha256,
                ).preflight,
            )
        if resources.storage_codec_metadata_path is not None:
            await check(lambda: _metadata(config, resources))
        report("completed")
        return {"native_artifacts_checked": total, "chain_submission_authorized": False}
    except BaseException:
        report("interrupted")
        raise
    finally:
        if timer is not None:
            timer.cancel()
