"""Select native reviewers lazily from the host's immutable series manifest."""

from functools import partial
from pathlib import Path

from .competition_cohort_intake_export import RemoteIntakeProgressReviewer
from .competition_cohort_intake_review_http import IntakeReviewHTTPClient
from .competition_cohort_preparation_export import RemotePreparationProgressReviewer
from .competition_cohort_preparation_review_http import PreparationReviewHTTPClient
from .competition_cohort_request_remote_review import RemoteRequestProgressReviewer
from .competition_cohort_request_review_http import RequestReviewHTTPClient
from .competition_cohort_review_config import PhaseReviewServiceConfig
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_quality import ServiceTerms
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .open_competition import digest
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import read_private_model
from .protocol import canonical_json_bytes


class SelectedPhaseReviewer:
    """Missing future inputs hold only that vote; committed votes need no reread.

    Replicated files supply bytes, never selection authority. Catalog and terms
    hashes come from the host manifest. Native remote replay checks the roster
    round against the certified preparation in the original history.
    """

    def __init__(
        self,
        config: PhaseReviewServiceConfig,
        provider: HistoricalRegistrationProvider,
        client,
        token: str,
        archive,
        promotion: CompetitionStore,
    ):
        self.config, self.provider = config, provider
        self.policy, self.cohorts = config.policy, config.signing.cohorts
        common = dict(
            maximum_bytes=config.maximum_export_bytes, timeout_seconds=config.review_timeout_seconds
        )
        args = (provider, self.cohorts, config.owner_hotkey)
        self.intake = RemoteIntakeProgressReviewer(
            *args,
            IntakeReviewHTTPClient(client, config.owner_origin, token=token, **common),
            archive,
            maximum_sample_gap_blocks=config.maximum_sample_gap_blocks,
            **common,
        )
        self.preparation = RemotePreparationProgressReviewer(
            *args,
            PreparationReviewHTTPClient(client, config.owner_origin, token=token, **common),
            archive,
            promotion,
            eligible_tracks=config.eligible_tracks,
            maximum_promotion_bytes=config.maximum_promotion_bytes,
            **common,
        )
        self.request_fetch = RequestReviewHTTPClient(
            client, config.owner_origin, token=token, **common
        )
        self.archive = archive

    def _requests(self, cohort: str) -> RemoteRequestProgressReviewer:
        c = self.config
        requirement = c.manifest.requirement(cohort)
        root = Path(c.inputs_directory)
        total = 0

        def read(folder, key, model):
            nonlocal total
            value = read_private_model(
                root / folder / (key + ".json"), model, maximum_bytes=c.maximum_export_bytes
            )
            total += len(canonical_json_bytes(value))
            if total > c.maximum_export_bytes:
                raise ValueError("phase review selections exceed aggregate capacity")
            return value

        roster = read("rosters", cohort, RecoverableRosterEvidence)
        terms = read("terms", requirement.terms_sha256, ServiceTerms)
        catalogs = tuple(
            read("catalogs", key, SignedServiceWorkCatalog) for key in requirement.catalog_sha256s
        )
        transport = read("transport", terms.transport_policy_sha256, ScoringPolicy)
        if (
            roster.round.cohort_sha256 != cohort
            or roster.round.policy_sha256 != digest(self.policy)
            or roster.round.eligible_tracks != c.eligible_tracks
            or digest(terms) != requirement.terms_sha256
            or terms.policy_sha256 != digest(self.policy)
            or tuple(digest(v.catalog) for v in catalogs) != requirement.catalog_sha256s
            or any(v.catalog.service_terms_sha256 != requirement.terms_sha256 for v in catalogs)
            or scoring_policy_hash(transport) != terms.transport_policy_sha256
        ):
            raise ValueError("phase review inputs differ from selected manifest")
        return RemoteRequestProgressReviewer(
            self.provider,
            self.cohorts,
            c.owner_hotkey,
            self.request_fetch,
            self.archive,
            roster=roster,
            catalogs=catalogs,
            transport=transport,
            maximum_sample_gap_blocks=c.maximum_sample_gap_blocks,
            maximum_bytes=c.maximum_export_bytes,
            timeout_seconds=c.review_timeout_seconds,
        )

    async def _select(self, progress):
        if progress.cohort_sha256 not in {b.cohort_sha256 for b in self.cohorts}:
            raise ValueError("phase vote is outside selected cohorts")
        if progress.phase == "intake":
            return self.intake
        if progress.phase == "preparation":
            return self.preparation
        if progress.phase == "requests":
            return await run_owned_thread(partial(self._requests, progress.cohort_sha256))
        raise ValueError("phase vote is outside configured phases")

    async def review(self, progress):
        return await (await self._select(progress)).review(progress)

    async def decision(self, transition, evidence):
        return await (await self._select(evidence.progress.progress)).decision(transition, evidence)
