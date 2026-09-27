"""One consented marker transaction under the original stopped-writer locks.

The caller owns the provider and signer. This module never opens a wallet or
changes a legacy journal. Persisted records account for fee attempts and unknown
sends; they cannot authorize recovery after losing the live drain session.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_chain_state import (
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_host_upgrade import HostUpgradeError
from .competition_legacy_drain import StoppedLegacyDrain
from .competition_weights import BittensorCompetitionWeightTransport
from .encoding import account_id32
from .private_files import (
    ensure_private_directory,
    lock_private_file,
    publish_private_model,
    read_private_model,
)
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .signed_extrinsic import encode_mortal_call, exact_signed_extrinsic

_LOG = logging.getLogger(__name__)
MARKER_PERIOD = 64
_PUBLISHER_OWNER = object()


class PriorMarkerPending(HostUpgradeError):
    """The controller may wait for fresh owned finality, without signing again."""


class LegacyMarkerConsent(StrictProtocolModel):
    """Local operator consent, separate from permission to upgrade the host."""

    schema_: Literal["umi-legacy-marker-consent/1"] = Field(alias="schema")
    validator_hotkey: str
    source_config_sha256: Hex32
    accepted_directive_sha256: Hex32
    accept_marker_transaction_fees: Literal[True]
    all_other_hotkey_writers_stopped: Literal[True]
    maximum_marker_transactions: Annotated[int, Field(ge=1, le=4)]


class MarkerAttempt(StrictProtocolModel):
    schema_: Literal["umi-legacy-marker-attempt/1"] = Field(alias="schema")
    consent_sha256: Hex32
    legacy_snapshot_sha256: Hex32
    marker_sha256: Hex32
    validator_hotkey: str
    birth_block: Annotated[int, Field(gt=0, le=2**53 - 73)]
    birth_hash: BlockHash
    period: Literal[64]
    nonce: Annotated[int, Field(ge=0, le=2**32 - 1)]
    chain_config_sha256: Hex32
    owned_observation_sha256: Hex32
    signed_extrinsic: Annotated[str, Field(pattern=r"^[0-9a-f]+$", max_length=131072)]
    signed_extrinsic_hash: BlockHash


class MarkerSendIntent(StrictProtocolModel):
    schema_: Literal["umi-legacy-marker-send-intent/1"] = Field(alias="schema")
    attempt_sha256: Hex32


@dataclass(frozen=True)
class _Remark:
    params: dict
    module: str = "System"
    function: str = "remark"


@contextmanager
def hold_marker_publisher(session: StoppedLegacyDrain, consent: LegacyMarkerConsent, root: Path):
    """Serialize the bounded fee budget while the genuine stopped lease is held."""
    if type(session) is not StoppedLegacyDrain or type(consent) is not LegacyMarkerConsent:
        raise HostUpgradeError("marker publication requires a live session and explicit consent")
    session.recheck()
    # Reparse strict fields: model_copy/construct must not bypass fee consent.
    consent = LegacyMarkerConsent.model_validate_json(canonical_json_bytes(consent))
    stopped = session.stopped
    if (
        account_id32(consent.validator_hotkey) != account_id32(stopped.validator_hotkey)
        or consent.source_config_sha256 != stopped.config_sha256
        or consent.accepted_directive_sha256 != stopped.accepted_directive_sha256
    ):
        raise HostUpgradeError("marker consent describes another stopped installation")
    for protected in (stopped.worker_state_root, stopped.state_root):
        if root == protected or root in protected.parents or protected in root.parents:
            raise HostUpgradeError("marker outbox overlaps legacy state")
    ensure_private_directory(root)
    descriptor = lock_private_file(root / "marker.lock")
    publisher = None
    try:
        publish_private_model(root / "consent.json", consent)
        publisher = LegacyMarkerPublisher(session, consent, root, _owner=_PUBLISHER_OWNER)
        yield publisher
    finally:
        if publisher is not None:
            publisher._closed = True
        os.close(descriptor)


class LegacyMarkerPublisher:
    """Persist before send; retry proof collection without signing again."""

    def __init__(self, session, consent, root, *, _owner=None):
        if _owner is not _PUBLISHER_OWNER:
            raise HostUpgradeError("marker publisher requires its owned outbox lock")
        self.session, self.consent, self.root = session, consent, root
        self._closed = False
        self._attempt: MarkerAttempt | None = None
        self._path: Path | None = None
        self._sent = False
        self._lock = asyncio.Lock()
        self._consent_sha = hashlib.sha256(canonical_json_bytes(consent)).hexdigest()

    def _recheck(self):
        if self._closed:
            raise HostUpgradeError("marker publisher is closed")
        self.session.recheck()
        if read_private_model(self.root / "consent.json", LegacyMarkerConsent) != self.consent:
            raise HostUpgradeError("marker fee consent changed")

    def prepare(self, observation: OwnedCompetitionChainObservation, signer) -> MarkerAttempt:
        self._recheck()
        validate_owned_weight_observation(observation)
        if account_id32(observation.validator_hotkey) != account_id32(
            self.consent.validator_hotkey
        ):
            raise HostUpgradeError("marker observation describes another hotkey")
        if observation.block < self.session.stopped.accepted_at_finalized_block:
            raise HostUpgradeError("marker observation predates the stopped installation")
        if self._attempt is not None:
            self._retained()
            return self._attempt
        slot = None
        for number in range(1, self.consent.maximum_marker_transactions + 1):
            path = self.root / f"attempt-{number}.json"
            try:
                previous = read_private_model(path, MarkerAttempt)
            except FileNotFoundError:
                slot = path
                break
            if (
                previous.consent_sha256 != self._consent_sha
                or previous.validator_hotkey != observation.validator_hotkey
                or previous.legacy_snapshot_sha256 != self.session.snapshot.sha256
                or previous.chain_config_sha256 != observation.chain_config_sha256
            ):
                raise HostUpgradeError("retained marker attempt belongs to another recovery")
            # A restarted process cannot reuse the old challenge's causal
            # authority. Wait out its exact era before spending another nonce.
            if observation.block < previous.birth_block + previous.period:
                raise PriorMarkerPending("prior marker transaction mortality has not elapsed")
        if slot is None:
            raise HostUpgradeError("consented marker transaction budget is exhausted")
        encoded = encode_mortal_call(
            _Remark({"remark": "0x" + self.session.marker.hex()}),
            runtime=observation.runtime,
            signer=signer,
            validator_hotkey=observation.validator_hotkey,
            nonce=observation.validator_nonce,
            mortality_period=MARKER_PERIOD,
            genesis_hash=observation.genesis_hash,
        )
        if self.session.marker not in encoded:
            raise HostUpgradeError("signed remark does not contain the complete drain marker")
        attempt = MarkerAttempt(
            schema="umi-legacy-marker-attempt/1",
            consent_sha256=self._consent_sha,
            legacy_snapshot_sha256=self.session.snapshot.sha256,
            marker_sha256=hashlib.sha256(self.session.marker).hexdigest(),
            validator_hotkey=observation.validator_hotkey,
            birth_block=observation.block,
            birth_hash=observation.block_hash,
            period=MARKER_PERIOD,
            nonce=observation.validator_nonce,
            chain_config_sha256=observation.chain_config_sha256,
            owned_observation_sha256=observation.evidence_sha256,
            signed_extrinsic=encoded.hex(),
            signed_extrinsic_hash=exact_signed_extrinsic(encoded).extrinsic_hash,
        )
        self._recheck()
        validate_owned_weight_observation(observation)
        publish_private_model(slot, attempt)
        self._attempt, self._path = attempt, slot
        _LOG.info(
            "legacy_marker_prepared block=%s extrinsic_hash=%s",
            attempt.birth_block,
            attempt.signed_extrinsic_hash,
        )
        return attempt

    def _retained(self) -> MarkerAttempt:
        self._recheck()
        if self._attempt is None or self._path is None:
            raise HostUpgradeError("marker must be prepared in this live session")
        if read_private_model(self._path, MarkerAttempt) != self._attempt:
            raise HostUpgradeError("retained marker transaction changed")
        return self._attempt

    async def submit(self, transport: BittensorCompetitionWeightTransport, signer) -> None:
        """Send at most once, preserving uncertainty if cancellation or disconnect occurs."""
        if type(transport) is not BittensorCompetitionWeightTransport:
            raise HostUpgradeError("marker requires the exact-byte transaction transport")
        async with self._lock:
            attempt = self._retained()
            if account_id32(signer.ss58_address) != account_id32(attempt.validator_hotkey):
                raise HostUpgradeError("marker signer differs from the prepared hotkey")
            intent_path = self._path.with_suffix(".send.json")
            if self._sent or intent_path.exists() or intent_path.is_symlink():
                raise HostUpgradeError("marker send already attempted; collect its proof")
            publish_private_model(
                intent_path,
                MarkerSendIntent(
                    schema="umi-legacy-marker-send-intent/1",
                    attempt_sha256=hashlib.sha256(canonical_json_bytes(attempt)).hexdigest(),
                ),
            )
            self._sent = True
            self._retained()
            _LOG.info("legacy_marker_submitting extrinsic_hash=%s", attempt.signed_extrinsic_hash)
            try:
                # Neither the receipt nor an RPC error can clear the legacy hold.
                await transport.submit(bytes.fromhex(attempt.signed_extrinsic), signer)
            except BaseException as exc:
                _LOG.warning("legacy_marker_send_unresolved error_type=%s", type(exc).__name__)
                raise

    async def collect(self, provider):
        attempt = self._retained()
        proof = await self.session.find(
            provider,
            birth_block=attempt.birth_block,
            birth_hash=attempt.birth_hash,
            period=attempt.period,
        )
        self._retained()
        if proof is not None:
            _LOG.info(
                "legacy_marker_drain_verified included_block=%s owned_head=%s",
                proof.result.included.block_number,
                proof.result.owned_head.block_number,
            )
        return proof
