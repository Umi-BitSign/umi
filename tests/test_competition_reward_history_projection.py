"""Projection preserves native semantics; fixtures never assert real origin."""

import copy
import json

import pytest

from umi.competition_reward_history_projection import OriginalHistoryProjection
from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key
from umi.open_competition import digest

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import make_history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


@pytest.fixture
async def original(historical, monkeypatch, tmp_path):
    h = await make_history_case(historical, monkeypatch, tmp_path)
    h.exports = RewardProofArchive(tmp_path / "original-exports")
    h.reader.export_archive = h.exports
    h.expected = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    h.native = {n: h.reader.checkpoints.load(n) for n in range(h.old.height, h.end + 1)}
    return h


def exported(h, height):
    key = history_archive_key(digest(h.item.config), h.item.hotkey, height)
    return json.loads((h.exports.root / "history" / (key + ".json")).read_bytes())


def derive(projection, h, height, frame=None):
    return projection.derive(
        height,
        frame or exported(h, height),
        hotkey=h.item.hotkey,
        chain_sha256=digest(h.item.config),
        finality_sha256="ab" * 32,
    )


async def test_every_write_unresolved_clear_and_native_digest_preserved(original):
    h = original
    p = OriginalHistoryProjection(lambda kind, key: h.reader.journal.get(kind, key))
    effects = []
    for height in range(h.old.height, h.end + 1):
        facts = derive(p, h, height)
        assert facts == {key: h.native[height][key] for key in facts}
        assert sorted(p.keys) == [tuple(token[:2]) for token in h.native[height]["sources"]]
        effects.extend(facts["writes"])
    assert len(effects) == 5
    assert h.expected.unresolved_blocks == (h.old.height + 3,)


@pytest.mark.parametrize("damage", ["frame", "recipe", "object"])
async def test_projection_rejects_source_change(original, damage):
    h = original
    frame = exported(h, h.old.height)
    original_get = h.reader.journal.get

    def record(kind, key):
        value = copy.deepcopy(original_get(kind, key))
        if damage == "frame" and kind == "control_history_block":
            value["evidence"] = ["00" * 32]
        if damage == "recipe" and kind == "control_history_chunk":
            value["length"] += 1
        if damage == "object" and kind == "control_history_object":
            value["hex"] = "00" * (len(value["hex"]) // 2)
        return value

    with pytest.raises(ValueError):
        derive(OriginalHistoryProjection(record), h, h.old.height, frame)


async def test_cached_decoding_does_not_reuse_changed_source_revision(original):
    h = original
    revision = [0]
    damaged = [False]

    def record(kind, key):
        value = copy.deepcopy(h.reader.journal.get(kind, key))
        if damaged[0] and kind == "control_history_object":
            value["hex"] = "00" * (len(value["hex"]) // 2)
        return value

    p = OriginalHistoryProjection(record, identity=lambda kind, key: revision[0])
    derive(p, h, h.old.height)
    revision[0], damaged[0] = 1, True
    with pytest.raises(ValueError, match="identity changed"):
        derive(p, h, h.old.height)
