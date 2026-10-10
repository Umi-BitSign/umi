"""Prepare immutable model evidence while requests and settlement run independently.

This worker has no signer, finality provider, scoring or phase-transition port.
The ordinary artifact verifiers retain their own successful receipts, including
across restart. Final settlement still verifies its complete selected roster.
"""

from __future__ import annotations

import asyncio
import logging
import math
from bisect import bisect_right
from collections.abc import Mapping
from contextlib import suppress
from functools import partial
from pathlib import Path

from .competition_artifacts import verify_preserved_bundle
from .competition_cohort_direct_model_review import DirectModelSettlementVerifier
from .competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelReviewRequest,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_roster import RecoverableRosterParticipant
from .competition_cohort_settlement_config import SettlementServiceConfig
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .open_competition import ModelBundle, digest, identity, model_content_digest, verify_signature
from .private_files import ensure_private_directory, private_path, read_private_model

logger = logging.getLogger(__name__)
MAX_PREPARATION_BYTES = 16 * 1024**2
MAX_ENTRIES = 65536


def _identity(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class SettlementArtifactPreparation:
    """One bounded, fair preparation lane per settlement service account."""

    def __init__(
        self,
        config: SettlementServiceConfig,
        promotion: CompetitionStore,
        direct_by_cohort: Mapping[str, DirectModelSettlementVerifier],
        *,
        batch_size: int = 2,
    ) -> None:
        if type(batch_size) is not int or not 1 <= batch_size <= 16:
            raise ValueError("settlement preparation batch size is outside bounds")
        self.policy = config.policy
        self.authority = digest(config.series.recovery.authority)
        self.cohorts = {digest(plan) for plan in config.series.cohorts}
        self.root = promotion.directory
        self.archive = self.root / "model-reward-artifacts"
        ensure_private_directory(self.archive)
        self.direct = dict(direct_by_cohort)
        if not set(self.direct) <= self.cohorts:
            raise ValueError("artifact preparation changes selected cohorts")
        self.batch_size, self.after = batch_size, ""
        self.serial = asyncio.Lock()

    def _page(self) -> tuple[tuple[str, Path], ...]:
        private_path(str(self.archive))
        entries = {}
        # Existing installations need no new publication to prepare local
        # bundles and the frozen baseline. Native verification authenticates
        # each manifest and all file identities before reusing a receipt.
        for path in self.archive.iterdir():
            if _identity(path.name):
                entries["local/" + path.name] = path
            if len(entries) > MAX_ENTRIES:
                raise OSError("settlement preparation inventory exceeds its bound")
        for cohort in sorted(self.cohorts):
            root = self.root / "model-reward-preparation" / cohort
            private_path(str(root))
            if not root.exists():
                continue
            for path in root.iterdir():
                if path.suffix == ".json" and _identity(path.stem):
                    entries["accepted/" + cohort + "/" + path.stem] = path
                if len(entries) > MAX_ENTRIES:
                    raise OSError("settlement preparation inventory exceeds its bound")
        keys = sorted(entries)
        start = bisect_right(keys, self.after)
        if start == len(keys):
            start = 0
        selected = keys[start : start + self.batch_size]
        return tuple((key, entries[key]) for key in selected)

    def _accepted(
        self, key: str, path: Path
    ) -> tuple[RecoverableRosterParticipant, CertifiedModelArtifactAcceptance]:
        _, cohort, submission = key.split("/")
        request = read_private_model(path, ModelReviewRequest, maximum_bytes=MAX_PREPARATION_BYTES)
        certificate = read_private_model(
            self.root / "model-reward-acceptances" / cohort / (submission + ".json"),
            CertifiedModelArtifactAcceptance,
            maximum_bytes=256 * 1024,
        )
        a, record = certificate.acceptance, request.record
        signed = record.request.signed_submission
        sub, consent = signed.submission, record.request.consent.consent
        admission = request.admission.admission
        if (
            a != request.acceptance
            or a.cohort_sha256 != cohort
            or a.policy_sha256 != digest(self.policy)
            or a.authority_sha256 != self.authority
            or a.submission_sha256 != submission
            or digest(sub) != submission
            or sub.policy_sha256 != digest(self.policy)
            or sub.track != "model"
            or sub.model_bundle is None
            or a.model_sha256 != digest(sub.model_bundle)
            or a.content_sha256 != model_content_digest(sub.model_bundle)
            or identity(a.recipient_hotkey) != identity(sub.hotkey)
            or consent.cohort_sha256 != cohort
            or consent.authority_sha256 != self.authority
            or admission != record.proposed_admission
            or admission.cohort_sha256 != cohort
            or admission.submission_sha256 != submission
            or admission.consent_sha256 != digest(consent)
            or admission.snapshot_sha256 != digest(record.snapshot)
            or admission.admitted_at_block > a.accepted_at_block
            or any(identity(s.hotkey) == identity(sub.hotkey) for s in certificate.signatures)
        ):
            raise ValueError("settlement preparation differs from its certified model")
        verify_signature(sub, signed.signature)
        verify_recovery_quorum(a, certificate.signatures, self.policy)
        verify_recovery_quorum(admission, request.admission.signatures, self.policy)
        return RecoverableRosterParticipant(record=record, admission=request.admission), certificate

    async def _prepare(self, key: str, path: Path) -> None:
        if key.startswith("local/"):
            bundle = await run_owned_thread(
                partial(
                    read_private_model,
                    path / "manifest.json",
                    ModelBundle,
                    maximum_bytes=MAX_PREPARATION_BYTES,
                )
            )
            if digest(bundle) != path.name:
                raise ValueError("settlement preparation manifest changed its identity")
            await run_owned_thread(verify_preserved_bundle, bundle, self.archive, self.policy)
            return
        participant, certificate = await run_owned_thread(self._accepted, key, path)
        a = certificate.acceptance
        if a.direct_artifact is not None:
            verifier = self.direct.get(a.cohort_sha256)
            if verifier is None:
                raise OSError("direct model preparation requires the selected R2 verifier")
            await verifier.ensure(participant, certificate)
        else:
            await run_owned_thread(
                verify_preserved_bundle,
                participant.record.request.signed_submission.submission.model_bundle,
                self.archive,
                self.policy,
            )

    async def poll_once(self, stop: asyncio.Event) -> dict:
        async with self.serial:
            checked = ready = pending = 0
            failures = []
            for key, path in await run_owned_thread(self._page):
                if stop.is_set():
                    break
                # A missing/corrupt entry gets another turn after its siblings.
                self.after = key
                checked += 1
                try:
                    await self._prepare(key, path)
                    ready += 1
                except (OSError, ValueError, RuntimeError) as error:
                    pending += 1
                    failures.append({"entry": key, "error_type": type(error).__name__})
            return {
                "status": "settlement_artifacts_prepared"
                if not pending
                else "settlement_artifacts_pending",
                "entries_checked": checked,
                "entries_ready": ready,
                "entries_pending": pending,
                "failures": failures,
                "request_closure_authorized": False,
                "scoring_authorized": False,
                "chain_submission_authorized": False,
            }

    async def run(self, stop: asyncio.Event, *, poll_seconds: float = 30) -> None:
        if not math.isfinite(poll_seconds) or poll_seconds <= 0:
            raise ValueError("settlement preparation poll interval must be positive and finite")
        while not stop.is_set():
            try:
                result = await self.poll_once(stop)
            except (OSError, ValueError, RuntimeError) as error:
                result = {
                    "status": "settlement_artifacts_retry",
                    "error_type": type(error).__name__,
                }
            logger.info("cohort_settlement_preparation %s", result)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
