"""Native checkpoint export survives cold R2 sources, interrupted copy and restart."""

import pytest

from umi.competition_reward_history import _FIELDS
from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key

from .test_competition_history_source_externalization import originals, reopen
from .test_competition_remote_proof_store import EvidenceServer, store
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


@pytest.mark.parametrize("parallel", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
async def test_completed_cold_remote_checkpoint_copies_to_new_remote_destination_once(
    history_case, tmp_path, monkeypatch, parallel, interrupted
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    heights = range(h.reader.first_block, h.end + 1)
    fields = {height: h.reader._load(height) for height in heights}
    original = {height: h.reader.checkpoints.load(height) for height in heights}
    source, destination = EvidenceServer(), EvidenceServer()
    h.reader = reopen(h.reader, store(tmp_path / "source", source))
    result = await h.reader.externalize_history_sources(maximum_records=4096)
    assert result["remaining_local_records"] == 0
    assert not originals(h.reader.journal)

    def restart():
        remote = store(tmp_path / "source", source)
        output = store(tmp_path / "destination", destination, prefix="export")
        archive = RewardProofArchive(tmp_path / "archive", remote=output)
        h.reader = reopen(h.reader, remote, parallel=parallel, export_archive=archive)
        prohibit_proof_replay(monkeypatch, h.reader)
        return archive

    archive = restart()
    if interrupted:
        destination.fail_put_suffix = history_archive_key(
            h.reader.config_sha256, h.reader.hotkey, h.reader.first_block
        )
        with pytest.raises(OSError, match="HTTP 503"):
            await h.reader.advance(h.item.provider, through_block=h.end)
        assert h.reader.checkpoints.load(h.reader.first_block) == original[h.reader.first_block]
        assert h.reader._next == h.reader.first_block
        assert not originals(h.reader.journal)
        destination.fail_put_suffix = None
        archive = restart()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert h.reader.progress.native_completed == 0
    assert not originals(h.reader.journal)
    assert any(method == "GET" for method, _ in source.calls)
    for height in heights:
        checkpoint = h.reader.checkpoints.load(height)
        assert checkpoint == {**original[height], "exports": [h.reader._export_identity()]}
        key = history_archive_key(h.reader.config_sha256, h.reader.hotkey, height)
        assert archive.read("history", key, bounds=_FIELDS)[1] == fields[height]
    source.calls.clear()
    destination.calls.clear()
    restart()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == expected
    assert source.calls == destination.calls == []
    assert not originals(h.reader.journal)
