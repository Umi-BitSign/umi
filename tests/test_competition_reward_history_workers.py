"""Spawned offline kernel parity for distinct parent/child runtimes and faults."""

import json
from dataclasses import replace

import pytest

from umi.competition_reward_control_evidence import _Archive
from umi.competition_reward_history_workers import HistoryWorkerError, HistoryWorkers
from umi.protocol import canonical_json_bytes

from .history_worker_fixtures import fixture_data
from .test_competition_reward_history_parallel import inject_spawn_fixture, profile, selection
from .test_competition_reward_write_archive import archived as archived
from .test_competition_reward_write_archive import block_case as block_case
from .test_competition_reward_write_archive import chain as chain
from .test_competition_reward_write_archive import chain_config as chain_config
from .test_competition_reward_write_archive import control as control
from .test_competition_reward_write_archive import historical as historical
from .test_competition_reward_write_archive import policy as policy
from .test_competition_reward_write_archive import series_case as series_case
from .test_validator_chain_scan import extrinsic

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


@pytest.mark.parametrize("fault", [None, "event_proof", "parent", "slot_hash", "semantics"])
async def test_spawned_exact_and_executed_runtime_kernel_matches_native_serial(
    archived, monkeypatch, fault
):
    h = archived
    captured = h.captured
    fields = {
        "slot_evidence": captured.slot.evidence,
        "slot_metadata": captured.slot.metadata,
        "evidence": captured.evidence,
    }
    fixture = fixture_data(
        [(captured.slot.evidence, captured.slot.metadata, captured.evidence)],
        {
            raw: extrinsic(raw, c, signer)
            for raw, c, signer in zip(h.raw, h.body_calls, h.signers, strict=True)
        },
        {h.event_bytes: h.events},
    )
    selected = selection(h.item.provider, h.item.hotkey)
    if fault == "semantics":
        selected = replace(selected, semantics="ab" * 32)
    inject_spawn_fixture(monkeypatch, selected, fixture)
    slot = _Archive(captured.slot.evidence, captured.slot.metadata)
    if fault is not None:
        body = json.loads(captured.evidence)
        if fault == "event_proof":
            body["events"]["proof"] = [b"corrupt-native-event-proof".hex()]
        if fault == "parent":
            body["parent_header"] = body["header"]
        if fault == "slot_hash":
            body["slot_evidence_sha256"] = "00" * 32
        fields["evidence"] = canonical_json_bytes(body)
    pool = HistoryWorkers(profile(), selected)
    try:
        future = pool.submit(
            snapshot=slot.snapshot,
            header=slot.encoded,
            timestamp=None,
            ceiling=h.source.w.head.timestamp_ms,
            fields=fields,
        )
        if fault:
            with pytest.raises(HistoryWorkerError):
                await future
                pool.result(future)
        else:
            await future
            result = pool.result(future)
            assert result.snapshot == captured.slot.snapshot
            assert result.control_sha256 == captured.slot.control_sha256
            assert result.slot_evidence_sha256 == captured.slot.evidence_sha256
            assert result.slot_metadata_sha256 == captured.slot.metadata_sha256
            assert result.writes == tuple(
                (w.extrinsic_index, w.decision_sha256) for w in captured.writes
            )
            assert result.unresolved_extrinsics == captured.unresolved_extrinsics
            assert not hasattr(result, "_issuer")
        pool.release(future)
    finally:
        await pool.close()
