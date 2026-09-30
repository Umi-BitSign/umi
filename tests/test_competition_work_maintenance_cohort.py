"""Bound periodic repair independently of the number of retained miners."""

import pytest

from umi.competition_work_plans import endpoint_proposals
from umi.competition_work_signing import WorkEndorsement, WorkStatement
from umi.open_competition import digest, sign_object

from .test_competition_work_admission_full_cohort import chain_config as chain_config
from .test_competition_work_admission_full_cohort import cohort as cohort
from .test_competition_work_admission_full_cohort import policy as policy
from .test_competition_work_admission_full_cohort import runtime as runtime
from .test_competition_work_admission_full_cohort import signing_setup as signing_setup
from .test_competition_work_admission_full_cohort import work as work


@pytest.mark.asyncio
@pytest.mark.parametrize("work", [(6, "v2-successor")], indirect=True)
async def test_recovery_pages_release_between_miners_and_eventually_wrap(cohort, monkeypatch):
    queue, work = cohort.queue, cohort.work
    await queue.maintain(work.plan, videos=work.options["videos"])
    for body in endpoint_proposals(**work.options):
        statement = WorkStatement(schema="umi-work-statement/1", plan=work.plan, body=body)
        for wallet in work.signers:
            vote = WorkEndorsement(
                statement_sha256=digest(statement), signature=sign_object(body, wallet)
            )
            value, checked, key = queue._verified_vote(vote)
            queue._retain_vote(value, checked, key, work.options["issuance"].height)

    async def no_full_prepare(*args, **kwargs):
        pytest.fail("periodic repair repeated the full batch")

    monkeypatch.setattr(queue, "prepare", no_full_prepare)
    for page in range(3):
        await queue.maintain(work.plan, videos=work.options["videos"])
        assert not queue.serial.locked()
        assert len(list(queue.publication_directory.glob("*.json"))) == (page + 1) * 2
        # An ordinary discovery request can run between bounded repair pages.
        await queue.pending(work.signers[0].hotkey.ss58_address)
    before = {p.name: p.read_bytes() for p in queue.publication_directory.glob("*.json")}
    await queue.maintain(work.plan, videos=work.options["videos"])
    assert before == {p.name: p.read_bytes() for p in queue.publication_directory.glob("*.json")}
