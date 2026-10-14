"""Native admission/history with synthetic linked header, trie and SCALE ports."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_cohort_recovery import SignedCohortRecoveryAuthority
from umi.competition_reward_cutover import NativeRewardCutoverReview
from umi.competition_reward_decision_review import review_reward_decision
from umi.competition_reward_decisions import StandingRewardControlReader
from umi.competition_reward_manifest import (
    RewardOpportunityTerms,
    RewardReplayRequirement,
    StandingRewardOpportunityManifest,
)
from umi.open_competition import digest

from . import test_competition_reward_history as history_fixtures
from .test_competition_reward_bootstrap import bootstrap_case
from .test_competition_reward_control import commitment
from .test_competition_reward_decisions import signatures, signed
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import make_history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
original_chain = history_fixtures.chain
original_chain_config = history_fixtures.chain_config


@pytest.fixture
def chain_config(original_chain_config):
    return original_chain_config.model_copy(
        update={
            "minimum_finalized_block": 150,
            "finality_pin": original_chain_config.finality_pin.model_copy(
                update={"bootstrap_block_number": 149}
            ),
        }
    )


@pytest.fixture
def chain(original_chain):
    original_chain.finality.ref = replace(original_chain.finality.ref, block_number=200)
    return original_chain


@pytest.fixture
async def bootstrap_native(historical, monkeypatch, tmp_path, request):
    c = historical.c
    first = historical.old.height
    manifest = StandingRewardOpportunityManifest(
        schema="umi-standing-reward-manifest/2",
        policy_sha256=c.series.policy_sha256,
        cohorts=tuple(
            RewardReplayRequirement(
                cohort_sha256=digest(p), terms_sha256="aa" * 32, catalog_sha256s=("bb" * 32,)
            )
            for p in c.series.cohorts
        ),
        opportunity=RewardOpportunityTerms(
            runtime_profile_sha256="cc" * 32, maximum_interval_ms=12000, minimum_validator_ms=12000
        ),
    )
    authority = c.series.recovery.authority.model_copy(update={"issued_at_block": first})
    c.series = c.series.model_copy(
        update={
            "manifest_sha256": digest(manifest),
            "recovery": SignedCohortRecoveryAuthority(
                authority=authority, signatures=signatures(authority)
            ),
        }
    )
    b = bootstrap_case(c)
    c.initial_commitment = commitment(b.anchor.control_sha256, b.anchor.committed_at_block)
    c.control_writes = {height: () for height in range(first, first + 5)}
    variant = getattr(request, "param", "clean")
    if variant == "write":
        c.control_writes[first + 2] = (b.anchor.control_sha256,)
    elif variant == "unresolved":
        c.cleared_blocks = {first + 2}
    h = await make_history_case(historical, monkeypatch, tmp_path)
    b.genesis = signed(b.genesis.decision.model_copy(update={"observed_at_block": h.end}))

    def reader(selection=b.selection):
        return StandingRewardControlReader(
            tmp_path / "bootstrap-reader",
            c.series,
            c.control.policy,
            expected_series_sha256=digest(c.series),
            expected_chain_config_sha256=digest(c.control.config),
            reward_adoptions=selection,
            maximum_bytes=8 * 1024**2,
        )

    c.reader = reader()
    result = await h.reader.advance(h.item.provider, through_block=h.end)
    control = await h.reader.review_control(h.item.provider, h.end)
    yield SimpleNamespace(
        c=c, b=b, h=h, manifest=manifest, history=result.history, control=control, reader=reader
    )


async def test_native_bootstrap_admission_replays_after_restart(bootstrap_native):
    f = bootstrap_native
    assert not f.history.writes and not f.history.unresolved_blocks

    def review():
        return review_reward_decision(
            f.c.reader,
            f.manifest,
            (),
            f.b.genesis.decision,
            control=f.control,
            history=f.history,
            maximum_promotion_bytes=1000000,
        )

    before = review()
    assert not before.chain_submission_authorized
    f.h.reader = await f.h.restart()
    f.h.offline_through = f.h.end
    f.history = (await f.h.reader.advance(f.h.item.provider, through_block=f.h.end)).history
    f.control = await f.h.reader.review_control(f.h.item.provider, f.h.end)
    f.c.reader = f.reader()
    assert review().intent == before.intent


@pytest.mark.parametrize("bootstrap_native", ["write", "unresolved"], indirect=True)
async def test_native_bootstrap_never_suppresses_writes_or_unresolved_effects(bootstrap_native):
    f = bootstrap_native
    assert f.history.writes or f.history.unresolved_blocks
    with pytest.raises(ValueError, match="exact predecessor"):
        review_reward_decision(
            f.c.reader,
            f.manifest,
            (),
            f.b.genesis.decision,
            control=f.control,
            history=f.history,
            maximum_promotion_bytes=1000000,
        )


async def test_unsigned_cutover_diagnostic_requires_exact_empty_effects_and_no_retained_work(
    bootstrap_native,
):
    f = bootstrap_native
    owner = object.__new__(NativeRewardCutoverReview)
    owner.config = SimpleNamespace(series=f.c.series, reward_adoptions=None)
    owner.bootstrap_manifest = f.b.anchor.signed_manifest
    owner.reader = f.reader(None)
    state = SimpleNamespace(control=f.control)
    assert owner._select_history(state, f.history, ()) == (None, ())
    assert owner._bootstrap_candidate(f.control) == f.b.anchor
    with pytest.raises(ValueError, match="retained or ordered"):
        owner._select_history(state, f.history, (f.b.genesis,))
    owner.reader.journal.put("reward_control_decision", "0000", f.b.genesis)
    with pytest.raises(ValueError, match="retained or ordered"):
        owner._select_history(state, f.history, ())
