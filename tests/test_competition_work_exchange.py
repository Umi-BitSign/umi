"""Round work -> independent signatures -> exchange -> execution -> agreement."""

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_evaluator import SignedEvaluationOrder, _read
from umi.competition_publication import (
    PublicationReplayLimits,
    SignedCutoffPublication,
    build_cutoff_publication,
    sign_cutoff_publication,
)
from umi.competition_rounds import CutoffEndorsement, RoundJournal, RoundProposal
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_work_plans import prepare_work_plan
from umi.competition_work_queue import WorkQueue
from umi.competition_work_transport import WorkSigningClient, attach_work_route
from umi.open_competition import digest

from .test_competition_evaluator import completed
from .test_competition_exchange import chain_config as chain_config
from .test_competition_exchange import finish
from .test_competition_exchange import model_setup as model_setup
from .test_competition_exchange import policy as policy
from .test_competition_exchange import relay as relay
from .test_competition_exchange import runtime as runtime
from .test_open_competition import snapshot


@pytest.mark.asyncio
async def test_automatically_signed_work_reaches_independent_execution_evidence(relay, tmp_path):
    # Remove only the fixture's manually preassembled order. The rest of the
    # round must discover and deliver the queue's independently signed bytes.
    path = Path(relay.config.order_directory) / (digest(relay.order.order) + ".json")
    path.unlink()
    order = relay.order.order
    cutoff = build_cutoff_publication(
        round_=order.round,
        cutoff_schedule=EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(relay.policy),
            round_sha256=digest(order.round),
            evidence_cutoff_block=order.round.public_schedule.evidence_cutoff_block,
        ),
        registration_snapshot=snapshot(order.round.submission_close_block),
        submissions=(order.submission,),
        policy=relay.policy,
        limits=PublicationReplayLimits(
            maximum_roster_bytes=4 * 1024**2,
            maximum_certificate_bytes=4 * 1024**2,
            maximum_evidence_bytes=16 * 1024**2,
        ),
    )
    signatures = tuple(sign_cutoff_publication(cutoff, w) for w in relay.wallets)
    plan = prepare_work_plan(
        cutoff=SignedCutoffPublication(publication=cutoff, signatures=signatures),
        submissions=(order.submission,),
        suite=relay.suite,
        incumbent=order.incumbent,
        runtime=order.runtime,
        policy=relay.policy,
    )
    queue = WorkQueue(
        tmp_path / "work-state",
        relay.policy,
        relay.provider,
        order_directory=relay.config.order_directory,
        publication_directory=tmp_path / "work-publications",
        minimum_issue_ms=1000,
    )
    await queue.prepare(plan)
    app = FastAPI()
    attach_work_route(app, queue)
    proposal = RoundProposal(
        schema="umi-round-proposal/1",
        cutoff=cutoff,
        submissions=(order.submission,),
        signing_close_block=order.round.submission_close_block + 1,
    )
    for index, (driver, signature) in enumerate(zip(relay.drivers, signatures, strict=True)):
        cutoffs = RoundJournal(tmp_path / f"cutoff-{index}", {"test": index})
        cutoffs.put("intent", str(order.round.sequence), proposal)
        cutoffs.put("suite", order.round.suite_sha256, {"proposal": digest(proposal)})
        cutoffs.put(
            "vote",
            str(order.round.sequence),
            CutoffEndorsement(proposal_sha256=digest(proposal), signature=signature),
        )
        client = WorkSigningClient(
            driver,
            "https://rounds.example",
            cutoffs,
            transport_provider=None,
            minimum_issue_ms=1000,
            legacy=None,
            transport=httpx.ASGITransport(app=app),
        )
        assert await client.sync_once() == {"endorsed": 1, "held": 0}
        if index == 0:
            assert not path.exists()
    generated = _read(path, SignedEvaluationOrder)
    assert generated.order == order and len(generated.signatures) == 2
    await finish(relay)
    assert completed(relay.drivers[0])[0] == completed(relay.drivers[1])[0]
    assert sum(isinstance(call, dict) for call in relay.calls) == 12
    for driver in relay.drivers:
        await driver.aclose()
