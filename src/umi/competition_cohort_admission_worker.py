"""Coordinator-hosted admission reviewer with owned finality and restartable votes."""

from __future__ import annotations

import asyncio
import os
import signal
import sqlite3
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_cohort_admission_journal import (
    CohortAdmissionJournal,
    CohortAdmissionSignerConfig,
    admission_slot,
)
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_admission_signer import CohortAdmissionSigner
from .competition_cohort_intake import CohortIntake, CohortIntakeConfig
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_store import AdmissionCapacity
from .concurrency import run_owned_thread
from .open_competition import CompetitionPolicy, digest, identity, sign_object
from .private_files import Directory, ensure_private_directory, lock_private_file
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CohortAdmissionWorkerConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-admission-worker-config/1"] = Field(alias="schema")
    policy_sha256: Hex32
    intake: CohortIntakeConfig
    signing: CohortAdmissionSignerConfig
    chain: CompetitionChainConfig
    admission_capacity: AdmissionCapacity = Field(default_factory=AdmissionCapacity)
    eligible_tracks: tuple[Literal["endpoint", "model"], ...] = ("endpoint",)
    wallet_name: Annotated[str, Field(min_length=1, max_length=128)]
    hotkey_name: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_path: Directory
    hotkey_password_file: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    batch_size: Annotated[int, Field(ge=1, le=256)] = 16
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5

    @model_validator(mode="after")
    def bindings(self):
        if (
            self.signing.policy_sha256 != self.policy_sha256
            or self.chain.policy_sha256 != self.policy_sha256
        ):
            raise ValueError("cohort admission worker policies differ")
        if self.signing.cohorts != self.intake.cohorts:
            raise ValueError("cohort admission worker authorities differ")
        if not self.eligible_tracks or len(set(self.eligible_tracks)) != len(self.eligible_tracks):
            raise ValueError("cohort admission worker tracks must be nonempty and unique")
        roots = [
            Path(p).resolve()
            for p in (self.intake.directory, self.signing.directory, self.chain.state_directory)
        ]
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(roots)
            for b in roots[i + 1 :]
        ):
            raise ValueError("admission intake, signer and finality state must not overlap")
        return self


class CohortAdmissionWorker:
    def __init__(
        self, queue: CohortAdmissionQueue, signer: CohortAdmissionSigner, *, batch_size=16
    ):
        if (
            queue.policy != signer.journal.policy
            or queue.intake.config.cohorts != signer.journal.config.cohorts
        ):
            raise ValueError("admission queue and signer use different policies or authorities")
        if type(batch_size) is not int or not 1 <= batch_size <= 256:
            raise ValueError("admission worker batch is outside bounds")
        self.queue, self.signer, self.batch_size = queue, signer, batch_size
        self.cursors = {}

    async def poll_once(self):
        published = certified = retried = 0
        for cohort in self.signer.journal.cohorts:
            after = self.cursors.get(cohort, "")
            try:
                pending = await run_owned_thread(
                    lambda cohort=cohort, after=after: self.queue.pending(
                        cohort,
                        self.signer.journal.config.signer,
                        after=after,
                        limit=self.batch_size,
                    )
                )
            except (OSError, ValueError, sqlite3.Error):
                retried += 1
                continue
            for consent in pending:
                try:
                    raw = await run_owned_thread(self.queue.record, cohort, consent)
                    try:
                        _, evidence, metadata = await run_owned_thread(
                            self.queue.evidence, cohort, consent
                        )
                    except FileNotFoundError:
                        # A reviewer that already retained an intent can restore
                        # missing relay bytes without asking a miner to resubmit.
                        saved = await run_owned_thread(
                            self.signer.journal.load, admission_slot(raw)
                        )
                        if saved is None or saved[1] != raw:
                            raise
                        evidence, metadata = saved[2:4]
                        await run_owned_thread(
                            self.queue.attach_evidence, cohort, consent, evidence, metadata
                        )
                    vote = await self.signer.attest(raw, registration_archive=(evidence, metadata))
                    capture = await self.signer.provider.collect()
                    certificate = await run_owned_thread(self.queue.publish_vote, vote, capture)
                    published += 1
                    certified += certificate is not None
                except (OSError, ValueError, RuntimeError, sqlite3.Error):
                    # One unavailable proof or participant cannot starve later
                    # records. The next scan retries every still-pending entry.
                    retried += 1
            self.cursors[cohort] = pending[-1] if len(pending) == self.batch_size else ""
        return {
            "status": "admission_review_retry" if retried else "admission_review_current",
            "votes_published": published,
            "certificates_published": certified,
            "retry_count": retried,
            "chain_submission_authorized": False,
        }


async def run_admission_worker(
    config,
    policy,
    *,
    once=False,
    stop=None,
    report=None,
    wallet=None,
    provider_factory=HistoricalRegistrationProvider,
):
    """Own boot/process exclusion, noninteractive hotkey access and all async work."""
    import bittensor as bt

    config = CohortAdmissionWorkerConfig.model_validate_json(canonical_json_bytes(config))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if config.policy_sha256 != digest(policy):
        raise ValueError("admission worker selects another policy")
    root = Path(config.signing.directory)
    ensure_private_directory(root)
    lease = lock_private_file(root / "admission-service.lock")
    provider = None
    handlers = []
    own_stop = stop is None
    stop = asyncio.Event() if stop is None else stop
    loop = asyncio.get_running_loop()
    try:
        wallet = (
            wallet
            if wallet is not None
            else bt.Wallet(
                name=config.wallet_name, hotkey=config.hotkey_name, path=config.wallet_path
            )
        )
        key = bt.resolve_signer(
            wallet,
            role="hotkey",
            password_file=config.hotkey_password_file,
            macos_prompt=False,
            keychain=False,
        )
        if identity(key.ss58_address) != identity(config.signing.signer):
            raise ValueError("admission worker does not hold its configured hotkey")
        intake = CohortIntake(
            config.intake,
            policy,
            eligible_tracks=config.eligible_tracks,
            capacity=config.admission_capacity,
        )
        queue = CohortAdmissionQueue(intake)
        journal = CohortAdmissionJournal(config.signing, policy)
        provider = provider_factory(
            config.chain, policy, retained_capture_blocks=intake.retained_registration_blocks
        )

        async def history(cohort):
            return await run_owned_thread(queue.history, cohort)

        async def sign(body):
            return await run_owned_thread(sign_object, body, key)

        worker = CohortAdmissionWorker(
            queue,
            CohortAdmissionSigner(journal, provider, history, sign),
            batch_size=config.batch_size,
        )
        if own_stop:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop.set)
                handlers.append(sig)
        await provider.start()

        async def cycle():
            provider.ensure_observer_running()
            return await worker.poll_once()

        while not stop.is_set():
            task, stopping = asyncio.create_task(cycle()), asyncio.create_task(stop.wait())
            try:
                done, _ = await asyncio.wait((task, stopping), return_when=asyncio.FIRST_COMPLETED)
                if stopping in done:
                    break
                try:
                    result = task.result()
                except (OSError, ValueError, RuntimeError, sqlite3.Error):
                    result = {
                        "status": "admission_review_retry",
                        "chain_submission_authorized": False,
                    }
                if report is not None:
                    report(result)
                if once:
                    return result
            finally:
                task.cancel()
                stopping.cancel()
                await asyncio.gather(task, stopping, return_exceptions=True)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=config.poll_seconds)
        return {"status": "stopped", "chain_submission_authorized": False}
    finally:
        try:
            if provider is not None:
                await provider.aclose()
        finally:
            for sig in handlers:
                loop.remove_signal_handler(sig)
            os.close(lease)
