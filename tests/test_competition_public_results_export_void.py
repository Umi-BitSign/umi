from umi.competition_public_results_export import export_round
from umi.open_competition import digest

from .test_competition_execution import policy as policy
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_void_settlement import mixed as mixed
from .test_open_competition import snapshot
from .test_policy import make_policy


async def test_recurring_export_replays_native_scored_and_void_evidence(mixed):
    store, round_, suite, _, pairs, void, _ = mixed
    store.record_void_evaluation(evidence=void, suite=suite, observed_block=150)
    store.settle(
        round_=round_, suite=suite, evidence=pairs, snapshot=snapshot(160), current_block=160
    )
    scores = export_round(
        store.path, digest(round_), policy=store.policy, scoring_policy=make_policy()
    )
    assert len(scores.items) == 3
    discarded = [item for item in scores.items if item.status == "void"]
    assert len(discarded) == 1
    assert discarded[0].candidate is discarded[0].incumbent is discarded[0].score_rank is None
    assert {item.track for item in scores.items if item.status == "scored"} == {"endpoint", "model"}
    assert all(item.score_rank == 1 for item in scores.items if item.status == "scored")
    assert scores.certification == scores.rewards == "not_checked"
