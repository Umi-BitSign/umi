"""A signed dispatch repair must cross the real exchange collector boundary."""

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_exchange as exchange
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import CompetitionStore
from umi.open_competition import Registration, RegistrationSnapshot, digest
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes

from .test_competition_dispatch_repair import authorization as authorization
from .test_competition_dispatch_repair import dispatch as dispatch
from .test_competition_dispatch_repair import feed as feed
from .test_competition_dispatch_repair import lost as lost
from .test_competition_dispatch_repair import paired_setup as paired_setup
from .test_competition_dispatch_repair import policy as policy
from .test_competition_dispatch_repair import release_identity as release_identity
from .test_competition_dispatch_repair import runtime as runtime
from .test_competition_evaluator import Provider, put
from .test_competition_evaluator import chain_config as chain_config
from .test_competition_exchange import request


@pytest.mark.parametrize("crash_after_store", [False, True])
async def test_repaired_void_http_upload_collection_and_restart(
    lost, chain_config, tmp_path, monkeypatch, crash_after_store
):
    item = lost.item
    round_ = item.round
    config = exchange.ExchangeConfig(
        schema="umi-evaluator-exchange-config/1",
        policy_sha256=digest(item.policy),
        legacy_policy_sha256=scoring_policy_hash(item.legacy_policy),
        chain=chain_config.model_copy(
            update={
                "policy_sha256": digest(item.policy),
                "state_directory": str(tmp_path / "chain"),
            }
        ),
        state_directory=str(tmp_path / "exchange"),
        order_directory=str(tmp_path / "orders"),
        reveal_directory=str(tmp_path / "reveals"),
    )
    put(Path(config.order_directory) / (digest(lost.order.order) + ".json"), lost.order)
    put(Path(config.reveal_directory) / (digest(item.suite) + ".json"), item.suite)
    provider = Provider()
    provider.block = round_.reveal_block
    app = exchange.create_exchange_app(
        config, item.policy, legacy=item.legacy_policy, provider_factory=lambda *_: provider
    )
    relay = SimpleNamespace(policy=item.policy, wallets=lost.signers)
    body = request(
        relay,
        operation="put",
        order_sha256=digest(lost.order.order),
        kind="void",
        payload_sha256=digest(lost.certificate),
        payload=lost.certificate.model_dump(mode="json", by_alias=True),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://relay.example"
    ) as client:
        response = await client.post(
            exchange.ROUTE,
            content=canonical_json_bytes(body),
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 200, response.text
    journal = exchange.ExchangeJournal(config, item.policy, item.legacy_policy)
    with journal.transaction() as db:
        assert db.execute("SELECT count(*) FROM collected").fetchone()[0] == 0
        assert db.execute("SELECT body FROM events WHERE kind='void'").fetchone()[0] == (
            canonical_json_bytes(lost.certificate)
        )

    store = CompetitionStore(tmp_path / "intake", item.policy)
    store.initialize_baseline(item.baseline, lost.setup.archive)
    snap = RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=round_.submission_close_block,
        block_hash="0x" + f"{round_.submission_close_block:064x}",
        registrations=tuple(
            Registration(uid=i, hotkey=s.submission.hotkey) for i, s in enumerate(item.submissions)
        ),
    )
    for signed in item.submissions:
        store.admit(signed, snap, round_.submission_close_block)
    store.fix_evidence_cutoff(
        round_,
        EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(item.policy),
            round_sha256=digest(round_),
            evidence_cutoff_block=round_.public_schedule.evidence_cutoff_block,
        ),
        observed_block=round_.submission_close_block,
    )
    store.close_round(round_, current_block=round_.submission_close_block)
    arrival = round_.reveal_block + 1
    if crash_after_store:
        original = store.record_void_evaluation

        def interrupted(**kwargs):
            original(**kwargs)
            raise OSError("interrupted after coordinator receipt before collected marker")

        monkeypatch.setattr(store, "record_void_evaluation", interrupted)
        with pytest.raises(OSError, match="before collected marker"):
            journal.collect(store, observed_block=arrival)
        store = CompetitionStore(store.directory, item.policy)
        journal = exchange.ExchangeJournal(config, item.policy, item.legacy_policy)
        journal.collect(store, observed_block=arrival + 1)
    else:
        journal.collect(store, observed_block=arrival)

    with store._connection() as db:
        rows = db.execute(
            "SELECT body,first_observed_block FROM void_evaluation_evidence"
        ).fetchall()
    assert rows == [(canonical_json_bytes(lost.evidence), arrival)]
    journal = exchange.ExchangeJournal(config, item.policy, item.legacy_policy)
    journal.collect(CompetitionStore(store.directory, item.policy), observed_block=arrival + 2)
    with journal.transaction() as db:
        assert db.execute("SELECT count(*) FROM collected").fetchone()[0] == 1
