"""Consented v1 drain and archival checkpoint inside a stopped host upgrade."""

from __future__ import annotations

import asyncio
import logging
import os
import stat
from contextlib import contextmanager
from pathlib import Path

from bittensor.keyfiles import deserialize_keypair_from_keyfile_data, keyfile_data_is_encrypted

from .competition_host_anchor import _read_source, _recheck_source, _require_private_control_parent
from .competition_host_upgrade import HostUpgradeError
from .competition_legacy_drain import hold_legacy_drain
from .competition_legacy_marker import (
    LegacyMarkerConsent,
    PriorMarkerPending,
    hold_marker_publisher,
)
from .competition_recovery import manifest_anchor_for_snapshot
from .competition_recovery_capture import prepare_recovery_checkpoint, verify_recovery_checkpoint
from .competition_upgrade import _fingerprint, _open_without_links
from .competition_weights import BittensorCompetitionWeightTransport
from .concurrency import wait_for_owned
from .encoding import account_id32
from .protocol import canonical_json_bytes

_LOG = logging.getLogger(__name__)


@contextmanager
def _progress_output():
    # Enable only the two selected recovery loggers. Do not enable SDK/HTTP
    # request logging or exception text while the configured signer is open.
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    saved = []
    for name in (__name__, "umi.competition_legacy_marker"):
        logger = logging.getLogger(name)
        saved.append((logger, logger.level, logger.propagate))
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.addHandler(handler)
    try:
        yield
    finally:
        for logger, level, propagate in saved:
            logger.removeHandler(handler)
            logger.setLevel(level)
            logger.propagate = propagate
        handler.close()


def load_marker_consent(path: Path, config, directive_sha256: str):
    _require_private_control_parent(path.parent)
    source = _read_source(path, maximum_bytes=16384, modes=frozenset({0o400, 0o440, 0o444}))
    consent = LegacyMarkerConsent.model_validate_json(source.payload)
    if canonical_json_bytes(consent) != source.payload:
        raise HostUpgradeError("marker consent must be canonical")
    if (
        consent.validator_hotkey != config.validator_hotkey
        or consent.accepted_directive_sha256 != directive_sha256
    ):
        raise HostUpgradeError("marker consent describes another validator or release")
    return source, consent


def _load_marker_signer(config, service_uid):
    """Read only the configured plaintext hotkey after fee consent and stop."""
    path = Path(config.wallet.path) / config.wallet.name / "hotkeys" / config.wallet.hotkey
    descriptor = _open_without_links(path)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, service_uid}
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            or not 0 < before.st_size <= 65536
        ):
            raise HostUpgradeError("marker hotkey file is not private and bounded")
        payload = os.read(descriptor, 65537)
        if len(payload) != before.st_size or _fingerprint(os.fstat(descriptor)) != _fingerprint(
            before
        ):
            raise HostUpgradeError("marker hotkey changed while reading")
        named = _open_without_links(path)
        try:
            if _fingerprint(os.fstat(named)) != _fingerprint(before):
                raise HostUpgradeError("marker hotkey path changed while reading")
        finally:
            os.close(named)
    finally:
        os.close(descriptor)
    if keyfile_data_is_encrypted(payload):
        raise HostUpgradeError("marker hotkey requires an unsupported interactive unlock")
    signer = deserialize_keypair_from_keyfile_data(payload)
    if account_id32(signer.ss58_address) != account_id32(config.validator_hotkey):
        raise HostUpgradeError("marker hotkey does not match the stopped validator")
    return signer


async def recover_legacy_checkpoint(
    *,
    stopped,
    observer,
    config,
    consent_source,
    consent,
    outbox,
    recovery_root,
    limits,
    historical_manifests=(),
    historical_leases=(),
    retained_checkpoint=None,
):
    """No reset or re-sign on failure; all original state stays in place.

    The marker's 64-block signing era bounds each fee attempt. The command's
    30-minute wait is operational only: reaching it leaves recovery unresolved
    and the service stopped. It does not manufacture a transaction outcome.
    """

    async def run():
        _recheck_source(consent_source)
        with (
            hold_legacy_drain(
                stopped,
                limits=limits,
                historical_manifests=historical_manifests,
                historical_leases=historical_leases,
            ) as session,
            hold_marker_publisher(session, consent, outbox) as publisher,
        ):
            async with observer.owned_provider() as provider:
                observation = await provider.wait_weights_ready(stopped.validator_hotkey, ())
                _recheck_source(consent_source)
                session.recheck()
                signer = _load_marker_signer(config, stopped.service_uid)
                while True:
                    try:
                        publisher.prepare(observation, signer)
                        break
                    except PriorMarkerPending:
                        _LOG.info("legacy_marker_waiting_for_prior_era block=%s", observation.block)
                        await asyncio.sleep(10)
                        _recheck_source(consent_source)
                        observation = await provider.wait_weights_ready(
                            stopped.validator_hotkey, ()
                        )
                transport = BittensorCompetitionWeightTransport(
                    endpoint=provider.config.rpc_url,
                    fallback_endpoints=provider.config.proof_rpc_fallback_urls,
                )
                try:
                    await wait_for_owned(publisher.submit(transport, signer), timeout=120)
                except Exception as exc:
                    _LOG.warning(
                        "legacy_marker_collect_after_send error_type=%s", type(exc).__name__
                    )
                while True:
                    _recheck_source(consent_source)
                    proof = await publisher.collect(provider)
                    if proof is not None:
                        break
                    _LOG.info("legacy_marker_waiting_for_finalized_drain")
                    await asyncio.sleep(10)

                async def observe(snapshot):
                    observation = await provider.wait_weights_ready(
                        stopped.validator_hotkey,
                        (),
                        manifest_anchor_sha256=manifest_anchor_for_snapshot(snapshot),
                    )
                    return observation, None

                if retained_checkpoint is None:
                    prepared = await prepare_recovery_checkpoint(
                        stopped,
                        observe=observe,
                        destination_root=recovery_root,
                        limits=limits,
                        historical_manifests=historical_manifests,
                        historical_leases=historical_leases,
                        legacy_drain=proof,
                    )
                    path, sha = Path(prepared.checkpoint_path), prepared.checkpoint_sha256
                else:
                    path, sha = retained_checkpoint
                verified = await verify_recovery_checkpoint(
                    path,
                    expected_checkpoint_sha256=sha,
                    stopped=stopped,
                    observe=observe,
                    limits=limits,
                    legacy_drain=proof,
                )
                _recheck_source(consent_source)
                return path, sha, verified

    with _progress_output():
        return await wait_for_owned(run(), timeout=1800)
