"""Capture fresh owned proofs after locked historical parsing, before acceptance.

These entrypoints preserve the synchronous recovery schemas and checks. The
callback supplies no authority by itself: stopped-host and owned-observation
validation still guard archive creation and checkpoint capability issuance.
"""

from __future__ import annotations

from contextlib import contextmanager

from .competition_recovery import (
    CompetitionRecoveryError,
    _check_stopped,
    _checkpoint_context,
    _load_archive,
    _prepare_recovery_snapshot,
    _snapshot_kwargs,
    _unchanged,
    _verify_recovery_snapshot,
    snapshot_legacy_bootstrap,
)
from .competition_recovery_observation import StoppedLegacyDrainProof


@contextmanager
def _capture_snapshot(stopped, limits, manifests, leases, legacy_drain):
    if legacy_drain is None:
        with snapshot_legacy_bootstrap(
            stopped.worker_state_root, **_snapshot_kwargs(stopped, limits, manifests, leases)
        ) as snapshot:
            yield snapshot
        return
    if type(legacy_drain) is not StoppedLegacyDrainProof:
        raise CompetitionRecoveryError("legacy retirement requires the live stopped drain proof")
    legacy_drain.recheck()
    if legacy_drain.session.stopped is not stopped:
        raise CompetitionRecoveryError("legacy drain belongs to another stopped host")
    # The session already holds these exact lock inodes. Both acceptance helpers
    # validate this proof against the fresh observation collected below.
    yield legacy_drain.session.snapshot
    legacy_drain.recheck()


async def prepare_recovery_checkpoint(
    stopped,
    *,
    observe,
    destination_root,
    limits,
    historical_manifests=(),
    historical_leases=(),
    legacy_drain=None,
):
    _check_stopped(stopped)
    with _capture_snapshot(
        stopped, limits, historical_manifests, historical_leases, legacy_drain
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
            legacy_drain=legacy_drain,
        )


async def verify_recovery_checkpoint(
    checkpoint_path,
    *,
    expected_checkpoint_sha256,
    stopped,
    observe,
    limits,
    legacy_drain=None,
):
    _check_stopped(stopped)
    body, objects = _load_archive(
        checkpoint_path,
        expected_sha256=expected_checkpoint_sha256,
        owner=stopped.service_uid,
        limits=limits,
    )
    manifests, leases = _checkpoint_context(body, objects)
    with _capture_snapshot(stopped, limits, manifests, leases, legacy_drain) as snapshot:
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
            legacy_drain=legacy_drain,
        )
