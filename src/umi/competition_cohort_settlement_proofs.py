"""Durable original registration proofs for independent settlement reviewers.

Delivery never establishes finality. SettlementPeerReviewer replays these bytes
against its own provider before any new signature. Exported files contain no
keys or live databases and can be replicated while either service is offline.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path

from .competition_execution import ExecutionBoundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_registration_archive import MAX_ARCHIVE_BYTES, MAX_METADATA_BYTES
from .competition_reward_proof_archive import RewardProofArchive
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes


class SettlementRegistrationFiles:
    def __init__(self, provider: HistoricalRegistrationProvider, *, inbox: Path, outbox: Path):
        self.provider = provider
        self.inbox, self.outbox = RewardProofArchive(inbox), RewardProofArchive(outbox)
        if inbox.is_relative_to(outbox) or outbox.is_relative_to(inbox):
            raise ValueError("settlement proof inbox and outbox must be disjoint")

    @staticmethod
    def _read(archive: RewardProofArchive, observation: ExecutionBoundary) -> tuple[bytes, bytes]:
        context, fields = archive.read(
            "registration",
            digest(observation),
            bounds={"proof": MAX_ARCHIVE_BYTES, "metadata": MAX_METADATA_BYTES},
        )
        if context != observation.model_dump(mode="json", by_alias=True):
            raise ValueError("settlement proof changes its original observation")
        return fields["proof"], fields["metadata"]

    async def publish(self, observation: ExecutionBoundary) -> None:
        observation = ExecutionBoundary.model_validate_json(canonical_json_bytes(observation))
        try:
            raw, metadata = await run_owned_thread(self._read, self.outbox, observation)
        except FileNotFoundError:
            raw, metadata = await self.provider.retained_archive(observation)
        if not 0 < len(raw) <= MAX_ARCHIVE_BYTES or not 0 < len(metadata) <= MAX_METADATA_BYTES:
            raise ValueError("settlement original proof exceeds its delivery bounds")
        # Exact retries also retry the directory sync after a lost write ack.
        await run_owned_thread(
            partial(
                self.outbox.write,
                "registration",
                digest(observation),
                context=observation.model_dump(mode="json", by_alias=True),
                fields={"proof": raw, "metadata": metadata},
            )
        )

    async def read(self, observation: ExecutionBoundary) -> tuple[bytes, bytes]:
        observation = ExecutionBoundary.model_validate_json(canonical_json_bytes(observation))
        return await run_owned_thread(self._read, self.inbox, observation)
