"""Synthetic signing/transport ports; real owned capture, locks and durable outbox."""

import asyncio
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_competition_chain import _Runtime
from tests.test_competition_chain import chain as chain
from tests.test_competition_chain import chain_config as chain_config
from tests.test_competition_host_upgrade import hold
from tests.test_competition_legacy_drain import installed as installed
from tests.test_competition_legacy_drain import limits as limits
from tests.test_open_competition import policy as policy
from tests.test_registration_bridge import BLOCK
from tests.test_registration_bridge import signed_policy as signed_policy
from umi.competition_chain_state import FinalizedCompetitionWeightProvider
from umi.competition_host_upgrade import HostUpgradeError
from umi.competition_legacy_drain import hold_legacy_drain
from umi.competition_legacy_marker import (
    LegacyMarkerConsent,
    MarkerAttempt,
    hold_marker_publisher,
)
from umi.competition_weights import BittensorCompetitionWeightTransport
from umi.private_files import read_private_model
from umi.protocol import canonical_json_bytes


@pytest.fixture
async def marker_case(chain, installed, monkeypatch, tmp_path):
    item = chain
    item.hotkey = installed.config.validator_hotkey
    item.signatures, item.encodings, item.sends = [], [], []

    class Runtime(_Runtime):
        def compose_call(self, module, function, params):
            assert (module, function) == ("System", "remark")
            assert set(params) == {"remark"}
            return b"remark:" + bytes.fromhex(params["remark"][2:])

        def signature_payload(self, call, **options):
            assert options["era"] == {"period": 64, "current": item.finality.ref.block_number}
            assert options["nonce"] == 4 and options["tip"] == 0
            assert options["era_block_hash"].hex() == item.finality.ref.block_hash[2:]
            return hashlib.blake2b(call, digest_size=32).digest()

        def encode_signed_extrinsic(self, call, **options):
            item.encodings.append(call)
            encoded = b"fixture:" + call + options["signature"]
            return encoded, hashlib.blake2b(encoded, digest_size=32).digest()

    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", Runtime)
    item.finality.ref = replace(item.finality.ref, block_number=BLOCK + 100)
    values = {
        "ValidatorPermit": [False] * 54 + [True] + [False] * 201,
        "LastUpdate": [0] * 256,
        "MechanismCountCurrent": 1,
        "CommitRevealWeightsEnabled": False,
        "WeightsVersionKey": 2**32,
        "MinAllowedWeights": 256,
        "MaxAllowedUids": 256,
        "MaxWeightsLimit": 65535,
        "WeightsSetRateLimit": 10,
        "SubnetworkN": 256,
    }
    item.rpc.values.update(
        {("SubtensorModule", key, (78,)): value for key, value in values.items()}
    )
    item.rpc.values.update(
        {
            ("SubtensorModule", "Uids", (78, item.hotkey)): 54,
            ("SubtensorModule", "Keys", (78, 54)): item.hotkey,
            ("SubtensorModule", "Weights", (78, 54)): [],
            ("System", "Account", (item.hotkey,)): {"nonce": 4, "providers": 1},
            ("Commitments", "CommitmentOf", (78, item.hotkey)): None,
        }
    )
    item.provider = FinalizedCompetitionWeightProvider(
        item.config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    item.provider.config = item.config.model_copy(update={"minimum_finalized_block": 100})
    item.observation = await item.provider.collect_weights(item.hotkey, ())

    def sign(payload):
        item.signatures.append(payload)
        return b"s" * 64

    item.signer = SimpleNamespace(ss58_address=item.hotkey, crypto_type=1, sign=sign)
    item.root = tmp_path / "marker-outbox"
    item.consent = LegacyMarkerConsent(
        schema="umi-legacy-marker-consent/1",
        validator_hotkey=item.hotkey,
        source_config_sha256=hashlib.sha256(installed.config_path.read_bytes()).hexdigest(),
        accepted_directive_sha256=installed.signed.directive_sha256,
        accept_marker_transaction_fees=True,
        all_other_hotkey_writers_stopped=True,
        maximum_marker_transactions=2,
    )
    item.behavior = "success"

    async def send(extrinsic, signer, **kwargs):
        # Both records must already be durably visible before the first send.
        assert (item.root / "attempt-1.send.json").is_file()
        retained = read_private_model(item.root / "attempt-1.json", MarkerAttempt)
        assert extrinsic.data.hex() == retained.signed_extrinsic
        assert kwargs == {"wait_for_inclusion": True, "wait_for_finalization": True}
        item.sends.append(extrinsic.data)
        if getattr(item, "on_send", None) is not None:
            item.on_send(extrinsic.data)
        if item.behavior == "disconnect":
            raise ConnectionError("injected lost reply")
        if item.behavior == "cancel":
            raise asyncio.CancelledError()
        return {"untrusted_receipt": True}

    class Client:
        def __init__(self, endpoint, retry_forever):
            assert retry_forever is False
            self._substrate = SimpleNamespace(submit_signed=send)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    item.transport = BittensorCompetitionWeightTransport(
        endpoint="wss://fixture.invalid", client_factory=Client
    )
    return item


async def test_persists_exact_bytes_before_send_and_never_resigns(installed, limits, marker_case):
    item = marker_case
    before = {p: p.read_bytes() for p in (installed.root / "worker").rglob("*") if p.is_file()}
    with (
        hold(installed) as stopped,
        hold_legacy_drain(stopped, limits=limits) as session,
        hold_marker_publisher(session, item.consent, item.root) as publisher,
    ):
        attempt = publisher.prepare(item.observation, item.signer)
        assert publisher.prepare(item.observation, item.signer) == attempt
        await publisher.submit(item.transport, item.signer)
        with pytest.raises(HostUpgradeError, match="already attempted"):
            await publisher.submit(item.transport, item.signer)
    assert len(item.signatures) == len(item.encodings) == len(item.sends) == 1
    assert all(p.read_bytes() == raw for p, raw in before.items())


@pytest.mark.parametrize("failure", ["disconnect", "cancel"])
async def test_unknown_send_survives_disconnect_and_cancellation(
    installed, limits, marker_case, failure
):
    item = marker_case
    item.behavior = failure
    error = ConnectionError if failure == "disconnect" else asyncio.CancelledError
    with (
        hold(installed) as stopped,
        hold_legacy_drain(stopped, limits=limits) as session,
        hold_marker_publisher(session, item.consent, item.root) as publisher,
    ):
        publisher.prepare(item.observation, item.signer)
        with pytest.raises(error):
            await publisher.submit(item.transport, item.signer)
        with pytest.raises(HostUpgradeError, match="already attempted"):
            await publisher.submit(item.transport, item.signer)
    assert (item.root / "attempt-1.send.json").is_file() and len(item.sends) == 1


@pytest.mark.parametrize("field", ["source_config_sha256", "accepted_directive_sha256"])
async def test_consent_for_another_installation_never_signs(installed, limits, marker_case, field):
    item = marker_case
    bad = item.consent.model_copy(update={field: "ff" * 32})
    with (
        hold(installed) as stopped,
        hold_legacy_drain(stopped, limits=limits) as session,
        pytest.raises(HostUpgradeError, match="another stopped installation"),
        hold_marker_publisher(session, bad, item.root),
    ):
        pytest.fail("bad consent")
    assert not item.signatures and not item.root.exists()


async def test_outbox_write_failure_prevents_any_send(installed, limits, marker_case, monkeypatch):
    from umi import competition_legacy_marker as module

    item = marker_case
    with (
        hold(installed) as stopped,
        hold_legacy_drain(stopped, limits=limits) as session,
        hold_marker_publisher(session, item.consent, item.root) as publisher,
    ):
        publisher.prepare(item.observation, item.signer)

        def failed(*args):
            raise OSError("injected fsync failure")

        monkeypatch.setattr(module, "publish_private_model", failed)
        with pytest.raises(OSError, match="fsync"):
            await publisher.submit(item.transport, item.signer)
    assert not item.sends


async def test_restart_waits_old_marker_era_then_requires_fresh_challenge(
    installed, limits, marker_case
):
    item = marker_case
    with hold(installed) as stopped:
        with (
            hold_legacy_drain(stopped, limits=limits) as session,
            hold_marker_publisher(session, item.consent, item.root) as publisher,
        ):
            first = publisher.prepare(item.observation, item.signer)
        with (
            hold_legacy_drain(stopped, limits=limits) as session,
            hold_marker_publisher(session, item.consent, item.root) as publisher,
        ):
            with pytest.raises(HostUpgradeError, match="mortality has not elapsed"):
                publisher.prepare(item.observation, item.signer)
            item.finality.ref = replace(item.finality.ref, block_number=first.birth_block + 64)
            current = await item.provider.collect_weights(item.hotkey, ())
            second = publisher.prepare(current, item.signer)
            assert first.marker_sha256 != second.marker_sha256
            assert first.signed_extrinsic != second.signed_extrinsic
        with (
            hold_legacy_drain(stopped, limits=limits) as session,
            hold_marker_publisher(session, item.consent, item.root) as publisher,
        ):
            item.finality.ref = replace(item.finality.ref, block_number=second.birth_block + 64)
            current = await item.provider.collect_weights(item.hotkey, ())
            with pytest.raises(HostUpgradeError, match="budget is exhausted"):
                publisher.prepare(current, item.signer)
    assert len(item.signatures) == 2


async def test_changed_retained_bytes_prevent_send(installed, limits, marker_case):
    item = marker_case
    with (
        hold(installed) as stopped,
        hold_legacy_drain(stopped, limits=limits) as session,
        hold_marker_publisher(session, item.consent, item.root) as publisher,
    ):
        attempt = publisher.prepare(item.observation, item.signer)
        (item.root / "attempt-1.json").write_bytes(
            canonical_json_bytes(attempt.model_copy(update={"signed_extrinsic": "ff"}))
        )
        with pytest.raises(HostUpgradeError, match="transaction changed"):
            await publisher.submit(item.transport, item.signer)
    assert not item.sends
