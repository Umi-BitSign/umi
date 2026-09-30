"""Raised journal capacity also applies to inventory and timing qualification."""

import os
from pathlib import Path

import pytest

from umi.competition_dispatch import EndpointDispatcher
from umi.competition_dispatch_capacity import DispatchTimingBudget, DispatchTimingLimits
from umi.competition_dispatch_inbox import publication_names
from umi.competition_scheduling import AssignmentPublicationJournal
from umi.competition_work_plans import endpoint_proposals
from umi.open_competition import digest

from .test_competition_dispatch import authorization as authorization
from .test_competition_dispatch import dispatch as dispatch
from .test_competition_dispatch import feed as feed
from .test_competition_dispatch import inbox_file
from .test_competition_dispatch import policy as policy
from .test_competition_dispatch_capacity import budget as budget
from .test_competition_dispatch_capacity import limits as limits
from .test_competition_dispatch_capacity import plan
from .test_competition_scheduling_timing import qualification, snapshot
from .test_competition_work_admission_full_cohort import build_work_fixture
from .test_competition_work_plans import runtime as runtime


def retained_entries(directory, count=1025):
    for index in range(count):
        (directory / f"pending-{index}.tmp").touch(mode=0o600)


@pytest.mark.asyncio
async def test_dispatcher_reads_native_publication_beyond_legacy_file_cap(dispatch):
    directory = Path(dispatch.config.publication_directory)
    retained_entries(directory)
    inbox_file(dispatch)
    with pytest.raises(ValueError, match="file capacity"):
        await dispatch.driver.ingest_once()
    capacity = dispatch.config.scheduling_capacity.model_copy(update={"maximum_publications": 4096})
    config = dispatch.config.model_copy(update={"scheduling_capacity": capacity})
    journal = AssignmentPublicationJournal(
        dispatch.feed.journal.path.parent,
        dispatch.feed.item.policy,
        dispatch.feed.item.legacy_policy,
        **capacity.model_dump(),
    )
    driver = EndpointDispatcher(
        config, journal, dispatch.provider, dispatch.feed.item.validator_wallet
    )
    assert await driver.ingest_once() == "retained"
    assert (
        journal.publication(digest(dispatch.feed.item.publication.publication))
        == dispatch.feed.item.publication
    )
    await driver.aclose()


def test_native_qualification_counts_large_inbox_without_changing_timing_receipt_schema(
    policy, runtime, tmp_path, monkeypatch
):
    work = build_work_fixture(
        policy.model_copy(update={"maximum_inference_ms": 600000}),
        runtime,
        tmp_path,
        count=1,
        profile="v2",
        issue_allowance_seconds=86400,
        response_window_seconds=900,
        window_stride_blocks=14400,
        policy_valid_through_block=20000,
        submission_valid_through_block=19900,
    )
    observed = work.options["issuance"]
    monkeypatch.setattr(
        "umi.competition_scheduling.time.time_ns", lambda: observed.timestamp_ms * 1_000_000
    )
    inbox = tmp_path / "inbox"
    inbox.mkdir(mode=0o700)
    retained_entries(inbox)
    directory = tmp_path / "scheduling"

    def reopen(count):
        return AssignmentPublicationJournal(
            directory,
            work.policy,
            work.item.legacy_policy,
            maximum_publications=count,
            maximum_bytes=48 * 1024**3,
        )

    journal = reopen(1024)
    evaluator = work.signers[0].hotkey.ss58_address
    journal.configure_dispatch(
        evaluator_hotkey=evaluator,
        limits=DispatchTimingLimits(
            maximum_concurrency=128,
            page_size=100,
            poll_seconds=1,
            discovery_grace_seconds=5,
            request_timeout_seconds=615,
        ),
        budget=DispatchTimingBudget(
            proof_collection_ms=750,
            origin_collection_ms=3900,
            publication_ingestion_ms=5600,
            local_cycle_ms=250,
            publication_delay_ms=10800000,
            block_advance_numerator=1,
            block_advance_denominator_ms=10000,
            finality_headroom_blocks=12,
            measurement_sha256="ab" * 32,
        ),
        publication_directory=inbox,
    )
    arguments = dict(
        batch_id=digest(work.plan),
        publications=endpoint_proposals(**work.options),
        observed=observed,
        announcements=(work.options["announcement"],),
        evaluator_hotkey=evaluator,
    )
    before = snapshot(journal)
    with pytest.raises(ValueError, match="file capacity"):
        journal.reserve_batch(**arguments)
    assert snapshot(journal) == before
    expanded = reopen(4096)
    receipt = expanded.reserve_batch(**arguments)
    assert qualification(expanded, digest(work.plan))["plan"]["publication_count"] == 1026
    after = snapshot(expanded)
    assert reopen(4096).reserve_batch(**arguments) == receipt
    assert snapshot(expanded) == after


@pytest.mark.parametrize("value", [0, True, 1.5, "4096", 65537])
def test_inbox_and_planner_reject_invalid_capacity(tmp_path, limits, budget, value):
    tmp_path.chmod(0o700)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="inbox capacity"):
            publication_names(fd, maximum_files=value)
        with pytest.raises(ValueError, match="inbox capacity"):
            plan((), limits, budget, maximum_inbox_files=value)
    finally:
        os.close(fd)


def test_expanded_inventory_still_counts_temporary_entries_and_checks_permissions(tmp_path):
    tmp_path.chmod(0o700)
    retained_entries(tmp_path, 4)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert len(publication_names(fd, maximum_files=4)) == 4
        with pytest.raises(ValueError, match="file capacity"):
            publication_names(fd, maximum_files=3)
        tmp_path.chmod(0o755)
        with pytest.raises(ValueError, match="owned and private"):
            publication_names(fd, maximum_files=4096)
    finally:
        os.close(fd)
