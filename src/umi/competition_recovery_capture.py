"""Capture fresh owned proofs after locked historical parsing, before acceptance.

These entrypoints preserve the synchronous recovery schemas and checks. The
callback supplies no authority by itself: stopped-host and owned-observation
validation still guard archive creation and checkpoint capability issuance.
"""

from __future__ import annotations

from .competition_recovery import (
    _check_stopped,
    _checkpoint_context,
    _load_archive,
    _prepare_recovery_snapshot,
    _snapshot_kwargs,
    _unchanged,
    _verify_recovery_snapshot,
    snapshot_legacy_bootstrap,
)


async def prepare_recovery_checkpoint(
    stopped,
    *,
    observe,
    destination_root,
    limits,
    historical_manifests=(),
    historical_leases=(),
):
    _check_stopped(stopped)
    with snapshot_legacy_bootstrap(
        stopped.worker_state_root,
        **_snapshot_kwargs(stopped, limits, historical_manifests, historical_leases),
    ) as snapshot:
        _check_stopped(stopped)
        observation, bridge_observation = await observe(snapshot)
        _check_stopped(stopped)
        _unchanged(snapshot)
        return _prepare_recovery_snapshot(
            stopped,
            observation,
            snapshot=snapshot,
            destination_root=destination_root,
            limits=limits,
            historical_manifests=historical_manifests,
            historical_leases=historical_leases,
            bridge_observation=bridge_observation,
        )


async def verify_recovery_checkpoint(
    checkpoint_path,
    *,
    expected_checkpoint_sha256,
    stopped,
    observe,
    limits,
):
    _check_stopped(stopped)
    body, objects = _load_archive(
        checkpoint_path,
        expected_sha256=expected_checkpoint_sha256,
        owner=stopped.service_uid,
        limits=limits,
    )
    manifests, leases = _checkpoint_context(body, objects)
    with snapshot_legacy_bootstrap(
        stopped.worker_state_root, **_snapshot_kwargs(stopped, limits, manifests, leases)
    ) as snapshot:
        _check_stopped(stopped)
        observation, bridge_observation = await observe(snapshot)
        _check_stopped(stopped)
        _unchanged(snapshot)
        return _verify_recovery_snapshot(
            stopped,
            observation,
            snapshot=snapshot,
            body=body,
            objects=objects,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
            manifests=manifests,
            bridge_observation=bridge_observation,
        )
