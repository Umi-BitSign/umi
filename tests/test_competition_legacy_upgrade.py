"""Stopped upgrade rehearsal with synthetic chain/SDK ports and real private files."""

import logging
import os
from contextlib import asynccontextmanager
from types import SimpleNamespace

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
from tests.test_open_competition import wallet
from tests.test_registration_bridge import signed_policy as signed_policy
from umi import competition_host_anchor as anchor
from umi import competition_legacy_upgrade as upgrade
from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_recovery import load_retained_checkpoint_archive
from umi.protocol import canonical_json_bytes


@pytest.mark.parametrize("reply", ["success", "disconnect"])
async def test_controller_retires_unknown_attempt_even_if_marker_reply_is_lost(
    installed, limits, marker_case, provider, drain, monkeypatch, tmp_path, reply
):
    item = marker_case
    item.behavior = reply
    birth = drain.birth + 10
    raw = drain.headers[drain.hashes[birth]]
    item.finality.ref = FinalizedSnapshotRef(
        birth, drain.hashes[birth], raw["parentHash"], raw["stateRoot"]
    )
    updates = [0] * 256
    updates[54] = installed.current_journal.attempt.prior_last_update
    item.rpc.values[("SubtensorModule", "LastUpdate", (78,))] = updates
    monkeypatch.setattr(
        "umi.validator_chain.bittensor_core.Runtime", type(item.observation.runtime._runtime)
    )
    collected = []

    async def wait(hotkey, recipients):
        result = await item.provider.collect_weights(hotkey, recipients)
        collected.append(result)
        return result

    monkeypatch.setattr(item.provider, "wait_weights_ready", wait)
    monkeypatch.setattr(item.provider, "find_legacy_drain", provider.find_legacy_drain)

    def include(encoded):
        install_body(drain, birth + 1, (encoded,))
        drain.head = birth + 9
        raw = drain.headers[drain.hashes[drain.head]]
        item.finality.ref = FinalizedSnapshotRef(
            drain.head, drain.hashes[drain.head], raw["parentHash"], raw["stateRoot"]
        )

    item.on_send = include
    monkeypatch.setattr(upgrade, "_load_marker_signer", lambda config, uid: item.signer)
    monkeypatch.setattr(
        upgrade, "BittensorCompetitionWeightTransport", lambda **kwargs: item.transport
    )
    root = tmp_path / "root-controls"
    root.mkdir(mode=0o700)
    path = root / "legacy-marker-consent.json"
    path.write_bytes(canonical_json_bytes(item.consent))
    path.chmod(0o400)
    monkeypatch.setattr(anchor, "_root_owner_uid", lambda: path.stat().st_uid)
    source, consent = upgrade.load_marker_consent(
        path, installed.config, installed.signed.directive_sha256
    )
    archive = tmp_path / "archive"
    archive.mkdir(mode=0o700)
    closed = []

    class Observer:
        @asynccontextmanager
        async def owned_provider(self):
            try:
                yield item.provider
            finally:
                closed.append(True)

    before = {p: p.read_bytes() for p in (installed.root / "worker").rglob("*") if p.is_file()}
    with hold(installed) as stopped:
        checkpoint, sha, verified = await upgrade.recover_legacy_checkpoint(
            stopped=stopped,
            observer=Observer(),
            config=installed.config,
            consent_source=source,
            consent=consent,
            outbox=item.root,
            recovery_root=archive,
            limits=limits,
        )
        body, _ = load_retained_checkpoint_archive(
            checkpoint,
            expected_sha256=sha,
            owner=stopped.service_uid,
            limits=limits,
        )
        assert body.prior_effects_reconciled and not body.holds
        assert verified.checkpoint_sha256 == sha
        assert body.legacy_drain.historical_submission_outcome_known is False
    assert len(collected) == 3 and len(item.sends) == len(item.signatures) == 1
    assert closed == [True]
    assert all(p.read_bytes() == raw for p, raw in before.items())


def test_marker_consent_cannot_enable_fees_for_another_hotkey(
    installed, marker_case, tmp_path, monkeypatch
):
    root = tmp_path / "controls"
    root.mkdir(mode=0o700)
    path = root / "consent.json"
    path.write_bytes(
        canonical_json_bytes(marker_case.consent.model_copy(update={"validator_hotkey": "other"}))
    )
    path.chmod(0o400)
    monkeypatch.setattr(anchor, "_root_owner_uid", lambda: path.stat().st_uid)
    with pytest.raises(ValueError, match="another validator"):
        upgrade.load_marker_consent(path, installed.config, installed.signed.directive_sha256)


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_marker_signer_reads_only_the_named_hotkey(tmp_path, mode):
    from bittensor.keyfiles import serialized_keypair_to_keyfile_data

    config = SimpleNamespace(
        wallet=SimpleNamespace(path=str(tmp_path), name="fixture", hotkey="worker"),
        validator_hotkey=wallet("Eve").hotkey.ss58_address,
    )
    root = tmp_path / "fixture"
    (root / "hotkeys").mkdir(parents=True, mode=0o700)
    key = root / "hotkeys/worker"
    key.write_bytes(bytes(serialized_keypair_to_keyfile_data(wallet("Eve").hotkey)))
    key.chmod(mode)
    # This cannot be opened as a regular private key and must never be touched.
    os.mkfifo(root / "coldkey", mode=0o600)
    signer = upgrade._load_marker_signer(config, os.getuid())
    assert signer.ss58_address == config.validator_hotkey
    key.chmod(0o644)
    with pytest.raises(ValueError, match="not private"):
        upgrade._load_marker_signer(config, os.getuid())
    key.chmod(mode)
    config.validator_hotkey = wallet("Alice").hotkey.ss58_address
    with pytest.raises(ValueError, match="does not match"):
        upgrade._load_marker_signer(config, os.getuid())


def test_progress_output_is_visible_without_enabling_sdk_logs(capsys):
    logger = logging.getLogger("umi.competition_legacy_marker")
    sdk = logging.getLogger("httpx")
    before = logger.level, logger.propagate, tuple(logger.handlers), sdk.level
    with upgrade._progress_output():
        logger.info("legacy_marker_prepared block=123")
        assert sdk.level == before[-1]
    assert "legacy_marker_prepared block=123" in capsys.readouterr().err
    assert (logger.level, logger.propagate, tuple(logger.handlers), sdk.level) == before
