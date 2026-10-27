"""Unsigned baseline review from exact completed coverage under its existing owner."""

from functools import partial
from typing import Annotated

from pydantic import Field

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_reward_decisions import RewardActivation
from .competition_settlement import PromotionHeadBinding
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .protocol import Hex32, StrictProtocolModel


class CompletedCoverageBaselineRequest(StrictProtocolModel):
    endpoint_key: Hex32
    activation: RewardActivation
    target_cohort_sha256: Hex32
    previous: PromotionHeadBinding
    not_before_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    valid_through_block: Annotated[int, Field(ge=1, le=2**53 - 1)]


async def prepare_completed_coverage_baseline(coverage, request):
    """Reuse the selected owners; never recapture absent coverage or import a package.

    The caller holds the configured coordinator state lease with its ordinary
    service stopped. No signer or publisher is constructed for this operation.
    The returned review remains unsigned and cannot append promotion history.
    """
    request = CompletedCoverageBaselineRequest.model_validate(request)
    preparation, files = coverage.preparation, coverage.files
    with TransferProgress(
        "cohort_baseline_completed_coverage_review",
        4,
        unit="steps",
        planning_unit_seconds=(0.1, 30),
    ) as progress:
        # Fresh proof of the control slot prevents promoting a superseded
        # activation. Historical endpoint restoration supplies complete native
        # history and original package semantics separately.
        control = await coverage.provider.collect_control(preparation.reader.series.control_hotkey)
        selected = await run_owned_thread(preparation.reader.select, control, files.decision)
        if selected.state != "selected" or selected.activation != request.activation:
            raise ValueError("baseline source differs from current authenticated reward activation")
        progress.advance(1)
        source = await coverage._source(request.activation)
        endpoint = await coverage.journal.restore_endpoint(
            request.endpoint_key,
            provider=coverage.provider,
            preparation=preparation,
            expected_package_sha256=request.activation.package_sha256,
            history=None,
            history_source=source._history,
            profile=coverage.profile,
            completed_model_groups=source._completed_model_groups,
        )
        if endpoint is None:
            raise ValueError(
                "baseline requires restoration of existing completed coverage metadata"
            )
        progress.advance(1)
        package = await run_owned_thread(
            partial(
                files.package_store.load_existing,
                files.root / "packages" / (request.activation.package_sha256 + ".json"),
                CohortRewardPackage,
                maximum_bytes=files.maximum_package_bytes,
                expected_sha256=request.activation.package_sha256,
            )
        )
        allocation = await run_owned_thread(
            files.allocation,
            request.activation.effective_allocation_sha256 or request.activation.allocation_sha256,
        )
        prepared = await preparation.prepare_from_completed_coverage(
            endpoint, activation=request.activation, allocation=allocation, package=package
        )
        progress.advance(1)
        review = preparation.baseline_review(
            prepared,
            target_cohort_sha256=request.target_cohort_sha256,
            previous=request.previous,
            not_before_block=request.not_before_block,
            valid_through_block=request.valid_through_block,
        )
        progress.advance(1)
        return review
