"""Manifest-selected service review in the existing private reviewer host."""

import asyncio
from pathlib import Path

import bittensor as bt

from .competition_cohort_history_http import CohortHistoryHTTPClient, CohortHistoryReader
from .competition_cohort_review_config import PhaseReviewServiceConfig
from .competition_cohort_service_export import ServiceWorkHTTPClient, ServiceWorkReader
from .competition_cohort_service_quality import ServiceTerms
from .competition_cohort_service_review import (
    ServiceRequestReview,
    ServiceRetryReview,
    ServiceWorkReviewer,
)
from .competition_progress import log_phase
from .competition_round_journal import RoundJournal
from .competition_transport_finality import CompetitionTransportFinality
from .concurrency import run_owned_thread
from .open_competition import digest
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes


class ServiceReviewInputs(StrictProtocolModel):
    terms: ServiceTerms
    transport: ScoringPolicy


class SelectedServiceReviewer:
    def __init__(self, config: PhaseReviewServiceConfig, provider, client, token, archive, sign):
        if config.service_signing is None:
            raise ValueError("service review is not configured")
        self.config, self.provider, self.archive, self.sign = config, provider, archive, sign
        limits = dict(token=token, timeout_seconds=config.service_signing.read_timeout_seconds)
        self.history = CohortHistoryReader(
            config.owner_hotkey,
            CohortHistoryHTTPClient(client, config.owner_origin, **limits),
            timeout_seconds=config.service_signing.read_timeout_seconds,
        )
        self.owner = ServiceWorkReader(
            config.policy,
            config.owner_hotkey,
            ServiceWorkHTTPClient(client, config.owner_origin, **limits),
            timeout_seconds=config.service_signing.read_timeout_seconds,
        )
        self.root = Path(config.service_signing.directory)
        self.journal = RoundJournal(
            self.root / "selection",
            {
                "series": digest(config.series),
                "manifest": digest(config.manifest),
                "signing": config.service_signing.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude={
                        "maximum_votes",
                        "maximum_bytes",
                        "signing_timeout_seconds",
                        "read_timeout_seconds",
                    },
                ),
            },
            maximum_rounds=512,
            maximum_bytes=config.service_signing.maximum_bytes,
            maximum_record_bytes=config.maximum_export_bytes,
        )
        self.reviewers = {}
        self.selection_lock = asyncio.Lock()

    def _inputs(self, cohort):
        requirement = self.config.manifest.requirement(cohort)
        with self.journal.locked():
            raw = self.journal.get("service_review_inputs", cohort)
            if raw is not None:
                value = ServiceReviewInputs.model_validate_json(canonical_json_bytes(raw))
            else:
                root = Path(self.config.inputs_directory)
                terms = read_private_model(
                    root / "terms" / (requirement.terms_sha256 + ".json"),
                    ServiceTerms,
                    maximum_bytes=self.config.maximum_export_bytes,
                )
                transport = read_private_model(
                    root / "transport" / (terms.transport_policy_sha256 + ".json"),
                    ScoringPolicy,
                    maximum_bytes=self.config.maximum_export_bytes,
                )
                value = ServiceReviewInputs(terms=terms, transport=transport)
            if (
                digest(value.terms) != requirement.terms_sha256
                or value.terms.policy_sha256 != digest(self.config.policy)
                or scoring_policy_hash(value.transport) != value.terms.transport_policy_sha256
            ):
                raise ValueError("service review inputs differ from selected manifest")
            self.journal.put("service_review_inputs", cohort, value)
            return value

    def _select(self, review):
        body = review.grant.body if isinstance(review, ServiceRetryReview) else review.body
        catalog = body.assignment.catalog.catalog
        cohort = catalog.cohort_sha256
        requirement = self.config.manifest.requirement(cohort)
        if (
            digest(catalog) not in requirement.catalog_sha256s
            or catalog.service_terms_sha256 != requirement.terms_sha256
        ):
            raise ValueError("service review catalog is outside selected manifest")
        selected = self._inputs(cohort)
        key = scoring_policy_hash(selected.transport)
        if key not in self.reviewers:
            cfg = self.config.service_signing.model_copy(
                update={"directory": str(self.root / "votes" / key)}
            )
            self.reviewers[key] = ServiceWorkReviewer(
                cfg,
                self.config.policy,
                selected.transport,
                self.provider,
                CompetitionTransportFinality(self.provider, selected.transport),
                self.history,
                self.owner,
                self.archive,
                self._round,
                self.sign,
            )
        return self.reviewers[key]

    @staticmethod
    async def _round():
        return await run_owned_thread(bt.timelock.current_round)

    @log_phase("cohort_service_vote")
    async def attest(self, review: ServiceRequestReview | ServiceRetryReview):
        # Selection is serialized before a reviewer is shared by both routes.
        # The native signer owns vote concurrency and drains signing on cancel.
        async with self.selection_lock:
            reviewer = await run_owned_thread(self._select, review)
        return await reviewer.attest(review)
