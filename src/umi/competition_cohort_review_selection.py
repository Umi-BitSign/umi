"""Select native reviewers lazily from the host's immutable series manifest."""

from contextlib import nullcontext
from functools import partial
from pathlib import Path

from .competition_cohort_admission_journal import CohortAdmissionJournal
from .competition_cohort_history_http import CohortHistoryHTTPClient, CohortHistoryReader
from .competition_cohort_intake_export import RemoteIntakeProgressReviewer
from .competition_cohort_intake_review_http import IntakeReviewHTTPClient
from .competition_cohort_model_delivery_api import ModelDeliveryAdoptionReviewer
from .competition_cohort_model_delivery_candidate import ModelDeliveryAdoptionCandidate
from .competition_cohort_model_delivery_reservation import ModelDeliveryReservationReader
from .competition_cohort_model_transport_selection import selected_cohort_profile
from .competition_cohort_preparation_export import RemotePreparationProgressReviewer
from .competition_cohort_preparation_review_http import PreparationReviewHTTPClient
from .competition_cohort_recovery import cohort_tracks, verify_cohort_service_pool
from .competition_cohort_request_remote_review import RemoteRequestProgressReviewer
from .competition_cohort_request_review_http import RequestReviewHTTPClient
from .competition_cohort_request_rule_api import RequestTailAdoptionReviewer
from .competition_cohort_request_rule_reservation import RequestTailReservationReader
from .competition_cohort_review_config import PhaseReviewServiceConfig
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_quality import ServiceTerms
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .competition_cohort_suite_adoption_api import EvaluationSuiteAdoptionReviewer
from .competition_cohort_suite_adoption_candidate import EvaluationSuiteAdoptionCandidate
from .competition_cohort_suite_adoption_reservation import EvaluationSuiteReservationReader
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_store import CompetitionStore
from .competition_verification_reuse import VerificationReuse
from .competition_work_progress import work_heartbeats
from .concurrency import run_owned_thread
from .host_memory_request_bounds import bounded_stage_declarations, stage_count
from .host_memory_runtime import memory_operation, requests_stage_policy
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
        admission: CohortAdmissionJournal | None = None,
    ):
        self.config, self.provider = config, provider
        self.policy, self.cohorts = config.policy, config.signing.cohorts
        self.request_verification = VerificationReuse(
            Path(config.signing.directory) / "request-verification",
            owner={
                "kind": "selected_request_review",
                "signer": config.signing.signer,
                "source_owner": config.owner_hotkey,
                "policy": digest(config.policy),
            },
        )
        phase_export_timeout = (
            config.phase_review_budget.export_exchange_seconds
            if config.phase_review_budget is not None
            else config.review_timeout_seconds
        )
        common = dict(
            maximum_bytes=config.maximum_export_bytes, timeout_seconds=phase_export_timeout
        )
        args = (provider, self.cohorts, config.owner_hotkey)
        self.intake = RemoteIntakeProgressReviewer(
            *args,
            IntakeReviewHTTPClient(client, config.owner_origin, token=token, **common),
            archive,
            maximum_sample_gap_blocks=config.maximum_sample_gap_blocks,
            reviewed_participation=(
                None
                if admission is None
                else partial(run_owned_thread, admission.reviewed_participation)
            ),
            remember_participation_review=(
                None
                if admission is None
                else partial(run_owned_thread, admission.remember_participation_review)
            ),
            **common,
        )
        self.preparation = RemotePreparationProgressReviewer(
            *args,
            PreparationReviewHTTPClient(client, config.owner_origin, token=token, **common),
            archive,
            promotion,
            eligible_tracks=config.eligible_tracks,
            maximum_promotion_bytes=config.maximum_promotion_bytes,
            reviewed_participation=self.intake.reviewed_participation,
            remember_participation_review=self.intake.remember_participation_review,
            **common,
        )
        self.request_fetch = RequestReviewHTTPClient(
            client,
            config.owner_origin,
            token=token,
            maximum_bytes=config.request_evidence_bytes,
            timeout_seconds=phase_export_timeout,
        )
        self.archive = archive
        adoption_export_timeout = (
            config.phase_review_budget.export_exchange_seconds
            if config.phase_review_budget is not None
            else 2400
        )
        self.adoption = RequestTailAdoptionReviewer(
            config.series,
            self.policy,
            provider,
            CohortHistoryReader(
                config.owner_hotkey,
                CohortHistoryHTTPClient(
                    client,
                    config.owner_origin,
                    token=token,
                    timeout_seconds=adoption_export_timeout,
                ),
                timeout_seconds=adoption_export_timeout,
            ),
            RequestTailReservationReader(
                client,
                config.owner_origin,
                token=token,
                owner=config.owner_hotkey,
                timeout_seconds=adoption_export_timeout,
                complete_exchange=config.phase_review_budget is not None,
            ),
            budget=config.phase_review_budget,
        )

        self.model_delivery_adoption = ModelDeliveryAdoptionReviewer(
            config.series,
            self.policy,
            provider,
            self.adoption.history,
            ModelDeliveryReservationReader(
                client,
                config.owner_origin,
                token=token,
                owner=config.owner_hotkey,
                timeout_seconds=adoption_export_timeout,
                complete_exchange=config.phase_review_budget is not None,
            ),
            candidates={
                value.source.cohort_sha256: ModelDeliveryAdoptionCandidate(value, self.policy)
                for value in config.model_delivery_adoption_candidates
            },
            budget=config.phase_review_budget,
        )

        self.evaluation_suite_adoption = EvaluationSuiteAdoptionReviewer(
            config.series,
            self.policy,
            provider,
            self.adoption.history,
            EvaluationSuiteReservationReader(
                client,
                config.owner_origin,
                token=token,
                owner=config.owner_hotkey,
                timeout_seconds=adoption_export_timeout,
                complete_exchange=config.phase_review_budget is not None,
            ),
            candidates={
                c.cohort_sha256: EvaluationSuiteAdoptionCandidate(c, self.policy)
                for c in config.evaluation_suite_adoption_candidates
            },
            budget=config.phase_review_budget,
        )

    @bounded_stage_declarations
    def _requests(self, cohort: str) -> RemoteRequestProgressReviewer:
        c = self.config
        plan = next((plan for plan in c.series.cohorts if digest(plan) == cohort), None)
        if plan is None:
            raise ValueError("phase review cohort is absent from its standing series")
        selected_tracks = cohort_tracks(
            plan, c.eligible_tracks, adoption=selected_cohort_profile(c, cohort)
        )
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
        stage_count("maximum_participants", len(roster.round.participants))
        stage = requests_stage_policy()
        if stage is not None and digest(roster.round) != stage.preparation_result_sha256:
            raise ValueError("review roster differs from qualified preparation")
        stage_count("maximum_catalogs", len(requirement.catalog_sha256s))
        terms = read("terms", requirement.terms_sha256, ServiceTerms)
        catalogs = tuple(
            read("catalogs", key, SignedServiceWorkCatalog) for key in requirement.catalog_sha256s
        )
        transport = read("transport", terms.transport_policy_sha256, ScoringPolicy)
        verify_cohort_service_pool(plan, terms.service_pool_bps)
        if (
            roster.round.cohort_sha256 != cohort
            or roster.round.policy_sha256 != digest(self.policy)
            or roster.round.eligible_tracks != selected_tracks
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
            maximum_bytes=c.request_evidence_bytes,
            timeout_seconds=(
                c.phase_review_budget.export_exchange_seconds
                if c.phase_review_budget is not None
                else c.review_timeout_seconds
            ),
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

    @memory_operation(
        operation="requests_review",
        scope=lambda self, progress: (progress.cohort_sha256, progress.phase),
    )
    async def review(self, progress):
        scope = (
            self.request_verification.selected() if progress.phase == "requests" else nullcontext()
        )
        with scope, work_heartbeats():
            return await (await self._select(progress)).review(progress)

    @memory_operation(
        operation="requests_decision",
        scope=lambda self, transition, evidence: (transition.cohort_sha256, transition.phase),
    )
    async def decision(self, transition, evidence):
        progress = evidence.progress.progress
        if (transition.cohort_sha256, transition.phase) != (progress.cohort_sha256, progress.phase):
            raise ValueError("decision scope differs from its reserved progress")
        scope = (
            self.request_verification.selected() if progress.phase == "requests" else nullcontext()
        )
        with scope, work_heartbeats():
            return await (await self._select(progress)).decision(transition, evidence)
