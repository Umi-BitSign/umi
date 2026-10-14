"""Selected original migration must be complete before native cutover starts."""

from types import SimpleNamespace

import pytest

from umi import competition_reward_cutover_runtime as runtime
from umi import competition_reward_history_origin as origin
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired

from . import test_competition_reward_history_origin_migration as fixtures

chain = fixtures.chain
chain_config = fixtures.chain_config
control = fixtures.control
historical = fixtures.historical
original = fixtures.original
policy = fixtures.policy
series_case = fixtures.series_case
selected = fixtures.selected

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


def preflight(c):
    _, owner = origin.load_original_export_origin(c.path)
    return runtime._original_export_migration_selection(
        c.h.new_reader(), SimpleNamespace(provenance=owner), c.path
    )


async def test_completed_original_export_preflight_preserves_native_results(selected):
    c = selected
    c.running[0] = False
    fixtures.run(c)
    before = list(c.h.body_requests)
    for _ in range(2):
        result = preflight(c)
        assert result["checkpoint_blocks"] == 5
        assert result["first_block"] == c.h.old.height
        assert result["through_block"] == c.h.end
        assert result["aggregate_completion_claimed"] is False
    assert c.h.body_requests == before


async def test_incomplete_original_export_refuses_instead_of_replaying(selected):
    c = selected
    c.running[0] = False
    fixtures.run(c, maximum_blocks=2)
    with pytest.raises(HistoryCheckpointRepairRequired, match="complete original export"):
        preflight(c)


async def test_missing_middle_checkpoint_refuses_before_provider(selected):
    c = selected
    c.running[0] = False
    fixtures.run(c)
    with c.h.reader.journal.transaction() as db:
        db.execute("DELETE FROM history_checkpoint_index WHERE height=?", (c.h.old.height + 2,))
    with pytest.raises(HistoryCheckpointRepairRequired, match="complete original export"):
        preflight(c)


async def test_original_export_cannot_replace_selected_owner(selected):
    c = selected
    c.running[0] = False
    fixtures.run(c)
    _, owner = origin.load_original_export_origin(c.path)
    owner = {**owner, "first_block": owner["first_block"] + 1}
    with pytest.raises(HistoryCheckpointRepairRequired, match="owner differs"):
        runtime._original_export_migration_selection(
            c.h.new_reader(), SimpleNamespace(provenance=owner), c.path
        )
