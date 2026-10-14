"""Revision-aware discovery preserves old journals without starving current work."""

from types import SimpleNamespace

from umi import competition_reward_coverage_service as module
from umi.competition_reward_coverage_journal import RewardCoverageJournal
from umi.competition_reward_coverage_service import (
    CoverageWork,
    StandingRewardCoverageService,
    coverage_work_key,
)
from umi.open_competition import digest

from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case


async def test_current_revision_gets_independent_work_and_preserves_old_progress(
    opportunity_case, tmp_path, monkeypatch
):
    c = opportunity_case
    rule = module.opportunity_rule(c.manifest, c.series, c.policy)
    journal = RewardCoverageJournal(
        tmp_path / "revision-coverage", rule, expected_rule_sha256=digest(rule)
    )
    old = CoverageWork(
        schema="umi-reward-coverage-work/1",
        activation=c.activation,
        observed_block=100,
        first_block=99,
    )
    journal.journal.put("coverage_work", c.activation.cohort_sha256, old)
    revised = c.activation.model_copy(
        update={"reward_adoption_sha256": "a1" * 32, "effective_allocation_sha256": "a2" * 32}
    )
    selected = SimpleNamespace(activation=revised, effective_at_block=199)
    owner = object.__new__(StandingRewardCoverageService)
    owner.preparation = SimpleNamespace(reader=c.reader, manifest=c.manifest)
    owner.journal = journal
    owner.files = SimpleNamespace(maximum_witness_bytes=1024**2)
    owner._target = 200
    owner.history = SimpleNamespace(first_block=1)
    owner._completed = {c.activation.cohort_sha256: object()}
    owner._active, owner._collector = None, None

    async def selection(height):
        assert height in {200, 202}
        return (
            selected
            if height == 200
            else SimpleNamespace(activation=revised, effective_at_block=201)
        )

    async def source(activation):
        assert activation == revised
        return object()

    class Collector:
        def __init__(self, actual_journal, actual_source, **kwargs):
            assert actual_journal is journal and actual_source is not None
            assert kwargs["activation"] == revised and kwargs["first_block"] == 199

        async def step(self):
            return SimpleNamespace(credited_ms=(), errors=(), certificate=None)

    owner._selection, owner._source = selection, source
    monkeypatch.setattr(module, "RewardCoverageCollector", Collector)
    await owner._discover()
    key = coverage_work_key(revised)
    assert key != coverage_work_key(c.activation)
    retained = journal.journal.get("coverage_work", key)
    assert retained["activation"] == revised.model_dump(mode="json", by_alias=True)
    await owner._collect()
    assert owner._active == key
    assert journal.journal.get("coverage_work", c.activation.cohort_sha256) == (
        old.model_dump(mode="json", by_alias=True)
    )
    # Resuming the exact same allocation must preserve its existing coverage
    # start and journal slot; a fresh control decision is not fresh economics.
    owner._target = 202
    await owner._discover()
    assert journal.journal.get("coverage_work", key) == retained
