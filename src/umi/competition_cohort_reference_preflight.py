"""Check eventual private reference inputs before new paid requests can open.

Read the actual settlement source under the running owner's account each time.
No receipt or cached success stands in for retained evidence. Existing request
and settlement recovery does not acquire a new startup prerequisite here.
"""

from pathlib import Path

from .competition_cohort_endpoint_archive import read_endpoint_object
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_model_transport_selection import retained_model_delivery_adoption
from .competition_cohort_recovery import (
    cohort_tracks,
    verify_cohort_service_pool,
    verify_recovery_quorum,
)
from .competition_cohort_service_quality import ServiceTerms
from .competition_cohort_service_reference import ServiceReference
from .competition_cohort_service_work import MAX_CATALOG_BYTES, SignedServiceWorkCatalog
from .competition_cohort_settlement_config import SettlementOriginalSources
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_reward_manifest import RewardReplayRequirement
from .open_competition import CompetitionPolicy, digest
from .private_files import read_private_model


def preflight_service_references(
    sources: SettlementOriginalSources,
    history: CohortRecoveryHistory,
    requirement: RewardReplayRequirement,
    policy: CompetitionPolicy,
    *,
    phase: str,
) -> int:
    """Return checked reference count; caller supplies verified current history."""
    if phase not in {"intake", "preparation"}:
        return 0
    plan = history.plan
    if "endpoint" not in cohort_tracks(
        plan, sources.eligible_tracks, adoption=retained_model_delivery_adoption(history)
    ):
        return 0
    cohort = digest(plan)
    if plan.policy_sha256 != digest(policy) or requirement.cohort_sha256 != cohort:
        raise ValueError("service reference preflight differs from selected cohort")
    root = Path(sources.objects_directory)
    catalogs = Path(sources.catalogs_directory)
    if not root.is_dir() or not catalogs.is_dir():
        raise FileNotFoundError("service reference preflight lacks its private sources")
    objects = SettlementEvidenceFiles(root)
    terms = ServiceTerms.model_validate_json(
        read_endpoint_object(objects, requirement.terms_sha256)
    )
    if terms.policy_sha256 != digest(policy):
        raise ValueError("service reference preflight terms belong to another policy")
    verify_cohort_service_pool(plan, terms.service_pool_bps)
    if terms.service_pool_bps == 0:
        return 0
    seen = set()
    for key in requirement.catalog_sha256s:
        catalog = read_private_model(
            catalogs / (key + ".json"),
            SignedServiceWorkCatalog,
            maximum_bytes=MAX_CATALOG_BYTES,
        )
        body = catalog.catalog
        if (
            digest(body) != key
            or body.cohort_sha256 != cohort
            or body.policy_sha256 != digest(policy)
            or body.authority_sha256 != digest(history.authority.authority)
            or body.service_terms_sha256 != requirement.terms_sha256
        ):
            raise ValueError("service reference preflight catalog selection changed")
        verify_recovery_quorum(body, catalog.signatures, policy)
        for item in body.work:
            try:
                ref = ServiceReference.model_validate_json(
                    read_endpoint_object(objects, item.reference_sha256)
                )
            except ValueError:
                # Validation details may include the private reference and salt.
                raise ValueError("service reference preflight input is invalid") from None
            if (ref.case_id, ref.video_sha256, ref.stratum) != (
                item.case_id,
                item.video_sha256,
                item.stratum,
            ):
                raise ValueError("service reference preflight catalog binding changed")
            seen.add(item.reference_sha256)
    return len(seen)
