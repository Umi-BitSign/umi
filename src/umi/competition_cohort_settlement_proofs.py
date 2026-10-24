"""Durable original registration proofs for independent settlement reviewers.

Delivery never establishes finality. SettlementPeerReviewer replays these bytes
against its own provider before any new signature. Exported files contain no
keys or live databases and can be replicated while either service is offline.
"""

from __future__ import annotations

import os
import stat
from functools import partial
from pathlib import Path

from .competition_execution import ExecutionBoundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_proof_archive_selection import selected_proof_archives
from .competition_registration_archive import MAX_ARCHIVE_BYTES, MAX_METADATA_BYTES
from .competition_remote_proof_store import ProofArchiveStores
from .competition_reward_proof_archive import RewardProofArchive
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import private_path
from .protocol import canonical_json_bytes


class SettlementRegistrationFiles:
    def __init__(
        self,
        provider: HistoricalRegistrationProvider,
        *,
        inbox: Path,
        outbox: Path,
        proof_stores: ProofArchiveStores | None = None,
        shared_archives: tuple[Path, ...] = (),
    ):
        self.provider = provider
        if inbox.is_relative_to(outbox) or outbox.is_relative_to(inbox):
            raise ValueError("settlement proof inbox and outbox must be disjoint")
        self.inbox, self.outbox = selected_proof_archives(inbox, outbox, proof_stores)
        self.shared = tuple(RewardProofArchive(path) for path in shared_archives)
        paths = (inbox, outbox, *(archive.root for archive in self.shared))
        if len(paths) != len(set(paths)) or any(
            a.is_relative_to(b) or b.is_relative_to(a)
            for index, a in enumerate(paths)
            for b in paths[index + 1 :]
        ):
            raise ValueError("settlement shared proof sources must be distinct and disjoint")
        for archive in self.shared:
            self._check_shared(archive)

    @staticmethod
    def _check_shared(archive):
        private_path(str(archive.root))
        info = archive.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("shared proof archive must be owned and private")

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
        return await run_owned_thread(self._read_selected, observation)

    def _read_selected(self, observation):
        for archive in (self.inbox, self.outbox, *self.shared):
            if archive in self.shared:
                self._check_shared(archive)
            result = archive.read_if_present(
                "registration",
                digest(observation),
                bounds={"proof": MAX_ARCHIVE_BYTES, "metadata": MAX_METADATA_BYTES},
            )
            if result is None:
                continue
            context, fields = result
            if context != observation.model_dump(mode="json", by_alias=True):
                raise ValueError("settlement proof changes its original observation")
            return fields["proof"], fields["metadata"]
        raise FileNotFoundError("selected settlement registration proof is unavailable")
