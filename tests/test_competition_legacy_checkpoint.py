"""Retire a v1 uncertainty using live drain evidence, retaining the original bytes."""

from dataclasses import replace
from pathlib import Path

import pytest

from tests.test_bridge_drain import drain as drain
from tests.test_bridge_drain import install_body
from tests.test_bridge_receipt_provider import provider as provider
from tests.test_bridge_receipts import history as history
from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import tx as tx
from tests.test_competition_chain import chain as chain
from tests.test_competition_chain import chain_config as chain_config
from tests.test_competition_host_upgrade import hold
from tests.test_competition_legacy_drain import installed as installed
from tests.test_competition_legacy_drain import limits as limits
from tests.test_competition_legacy_marker import marker_case as marker_case
from tests.test_open_competition import policy as policy
from tests.test_registration_bridge import signed_policy as signed_policy
from umi.competition_legacy_drain import hold_legacy_drain
from umi.competition_recovery import (
    load_retained_checkpoint_archive,
    prepare_recovery_checkpoint,
    verify_recovery_checkpoint,
)
from umi.competition_recovery_models import LegacyDrainRecoveryCheckpointBody
from umi.protocol import canonical_json_bytes


@pytest.fixture(autouse=True)
def archive_root(tmp_path):
    (tmp_path / "archive").mkdir(mode=0o700)


async def proof_for(session, provider, drain):
    number = drain.birth + 2
    install_body(drain, number, (b"inherent", b"remark:" + session.marker))
    return await session.collect(provider, block_number=number, block_hash=drain.hashes[number])


async def observe(item, installed, *, applied=False, unexpected=False):
    attempt = installed.current_journal.attempt
    updates = [0] * 256
    updates[54] = attempt.preflight_block + 1 if applied else attempt.prior_last_update
    item.rpc.values[("SubtensorModule", "LastUpdate", (78,))] = updates
    item.rpc.values[("SubtensorModule", "Weights", (78, 54))] = (
        [[1, 1]] if unexpected else attempt.expected_row if applied else []
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            "umi.validator_chain.bittensor_core.Runtime", type(item.observation.runtime._runtime)
        )
        return await item.provider.collect_weights(item.hotkey, ())


@pytest.mark.parametrize("applied", [False, True])
async def test_live_drain_allows_checkpoint_without_claiming_a_historical_outcome(
    installed, limits, marker_case, provider, drain, tmp_path, applied
):
    item = marker_case
    observation = await observe(item, installed, applied=applied)
    before = {p: p.read_bytes() for p in (installed.root / "worker").rglob("*") if p.is_file()}
    with hold(installed) as stopped, hold_legacy_drain(stopped, limits=limits) as session:
        proof = await proof_for(session, provider, drain)
        prepared = prepare_recovery_checkpoint(
            stopped,
            observation,
            destination_root=tmp_path / "archive",
            limits=limits,
            legacy_drain=proof,
        )
        assert prepared.prior_effects_reconciled and not prepared.holds
        body, objects = load_retained_checkpoint_archive(
            Path(prepared.checkpoint_path),
            expected_sha256=prepared.checkpoint_sha256,
            owner=stopped.service_uid,
            limits=limits,
        )
        assert type(body) is LegacyDrainRecoveryCheckpointBody
        assert body.legacy_drain.historical_submission_outcome_known is False
        assert (
            body.reconciled_effects[-1].classification == "retired_legacy_attempt_outcome_unknown"
        )
        assert canonical_json_bytes(installed.current_journal) in objects.values()
        verified = verify_recovery_checkpoint(
            Path(prepared.checkpoint_path),
            expected_checkpoint_sha256=prepared.checkpoint_sha256,
            stopped=stopped,
            observation=observation,
            limits=limits,
            legacy_drain=proof,
        )
        assert verified.checkpoint_sha256 == prepared.checkpoint_sha256
        with pytest.raises(ValueError, match="absent or altered"):
            verify_recovery_checkpoint(
                Path(prepared.checkpoint_path),
                expected_checkpoint_sha256=prepared.checkpoint_sha256,
                stopped=stopped,
                observation=observation,
                limits=limits,
                legacy_drain=replace(proof),
            )
    assert all(p.read_bytes() == raw for p, raw in before.items())


async def test_drain_cannot_clear_an_unrelated_current_row(
    installed, limits, marker_case, provider, drain, tmp_path
):
    observation = await observe(marker_case, installed, applied=True, unexpected=True)
    with hold(installed) as stopped, hold_legacy_drain(stopped, limits=limits) as session:
        proof = await proof_for(session, provider, drain)
        prepared = prepare_recovery_checkpoint(
            stopped,
            observation,
            destination_root=tmp_path / "archive",
            limits=limits,
            legacy_drain=proof,
        )
        assert not prepared.prior_effects_reconciled
        assert "registration_bridge_latest_effect_not_proven" in prepared.holds


async def test_serialized_drain_cannot_authorize_retirement(
    installed, limits, marker_case, tmp_path
):
    observation = await observe(marker_case, installed)
    with hold(installed) as stopped, pytest.raises(ValueError, match="live stopped drain proof"):
        prepare_recovery_checkpoint(
            stopped,
            observation,
            destination_root=tmp_path / "archive",
            limits=limits,
            legacy_drain={"retired": True},
        )
