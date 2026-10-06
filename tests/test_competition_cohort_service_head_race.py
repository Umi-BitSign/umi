"""An owned finality advance during preparation must not lose a signed claim."""

import pytest

from umi.competition_round_journal import FinalizedHeadRegression

from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_service_api import assert_no_admission_or_archive, native_intake, post
from .test_competition_cohort_service_contention import api_case as api_case
from .test_competition_cohort_service_contention import base_policy as base_policy
from .test_competition_cohort_service_contention import chain as chain
from .test_competition_cohort_service_contention import chain_config as chain_config
from .test_competition_cohort_service_contention import finality_padding as finality_padding
from .test_competition_cohort_service_contention import harness as harness
from .test_competition_cohort_service_contention import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_contention import policy as policy
from .test_competition_cohort_service_contention import queue_case as queue_case
from .test_competition_cohort_service_contention import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_contention import recovery as recovery
from .test_competition_cohort_service_contention import runtime as runtime
from .test_competition_cohort_service_contention import scenario as scenario
from .test_competition_cohort_service_queue import inputs
from .test_competition_historical_registration import change_block


@pytest.mark.parametrize("outcome", ["fresh", "lagging", "closed"])
async def test_shared_head_advance_recollects_once_and_preserves_authority(
    api_case, chain, outcome, monkeypatch
):
    s = api_case
    archive = s.api.archive
    captures = 0
    archives = 0
    capture = s.api.capture
    advanced = s.observed.snapshot.block + 1

    async def counted_capture():
        nonlocal captures
        captures += 1
        return await capture()

    async def advancing_archive(observation):
        nonlocal archives
        raw = await archive(observation)
        archives += 1
        if archives == 1:
            # A different owned operation advances the native shared watermark
            # after this request captured its valid original proof.
            with s.c.queue.journal.locked():
                s.c.queue.journal.observe(advanced)
            if outcome != "lagging":
                change_block(chain, advanced)
        return raw

    original_commit = s.api._commit

    def commit(*args):
        try:
            return original_commit(*args)
        except FinalizedHeadRegression:
            if outcome == "closed":
                s.source = source_for(s.c.h.batch, s.c.h.batch["history"])
            raise

    monkeypatch.setattr(s.api, "_commit", commit)
    s.api.capture = counted_capture
    s.api.archive = advancing_archive
    response = await post(s)
    assert captures == 2, "shared-head race needs one new owned collection"
    if outcome == "fresh":
        assert response.status_code == 200, response.text
        admission = s.c.queue.lookup(inputs(s.c)[0])
        assert admission.registration.block == advanced
        assert len(s.c.queue.entries()) == 1
        assert s.api.archives[s.c.cfg.catalog_sha256].read(admission)
        # Duplicate recovery uses exactly the first admitted claim and no ports.
        s.offline = {"history", "capture", "roster", "archive"}
        s.calls.clear()
        assert (await post(s)).json() == response.json()
        assert s.calls == []
    else:
        assert response.status_code == 503
        assert s.c.queue.entries() == ()
        assert archives == 1, "lagging or closed inputs cannot reach another commit"


@pytest.mark.parametrize("fault", ["publication", "metadata", "head"])
async def test_recollected_commit_still_refuses_changed_authority_or_proof(
    api_case, chain, tmp_path, fault
):
    s = api_case
    _, publish = native_intake(s, tmp_path)
    archive = s.api.archive
    count = 0
    advanced = s.observed.snapshot.block + 1

    async def race(observation):
        nonlocal count
        count += 1
        raw, metadata = await archive(observation)
        if count == 1:
            with s.c.queue.journal.locked():
                s.c.queue.journal.observe(advanced)
            change_block(chain, advanced)
        elif fault == "publication":
            # A certified close after the refreshed proof still cannot slip
            # through the native publication lock at the final commit.
            publish(source_for(s.c.h.batch, s.c.h.batch["history"]))
        elif fault == "metadata":
            metadata += b"changed"
        else:
            with s.c.queue.journal.locked():
                s.c.queue.journal.observe(advanced + 1)
            change_block(chain, advanced + 1)
        return raw, metadata

    s.api.archive = race
    result = await post(s)
    assert result.status_code == 503
    assert count == 2, "recollection must be bounded even during repeated shared advances"
    assert_no_admission_or_archive(s)
