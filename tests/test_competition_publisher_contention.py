"""Real mutex contention must preserve publisher objects and signed history."""

import asyncio
import errno
import os
import pickle
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from umi import competition_successor_publication as publication_module
from umi import competition_successor_publisher_cli as cli
from umi import private_files
from umi.competition_launch import PublicLaunchIdentity
from umi.competition_round_journal import RoundJournal
from umi.protocol import canonical_json_bytes

from .test_competition_successor_follow import automatic as automatic
from .test_competition_successor_follow import chain_config as chain_config
from .test_competition_successor_follow import completed
from .test_competition_successor_follow import feed_case as feed_case
from .test_competition_successor_follow import guarded as guarded
from .test_competition_successor_follow import package_case as package_case
from .test_competition_successor_follow import package_limits as package_limits
from .test_competition_successor_follow import policy as policy
from .test_competition_successor_follow import publication_case as publication_case
from .test_competition_successor_follow import release_identity as release_identity
from .test_competition_successor_follow import replay_limits as replay_limits
from .test_competition_successor_follow import successor_case as successor_case
from .test_competition_successor_follow import successor_chain as successor_chain
from .test_competition_successor_follow import successor_release as successor_release
from .test_competition_successor_follow import v3_predecessor as v3_predecessor
from .test_competition_successor_follow import worker_capacity as worker_capacity


@pytest.mark.parametrize("kind", ["private", "round"])
def test_typed_contention_closes_losing_descriptor_and_preserves_identity(
    tmp_path, monkeypatch, kind
):
    root = tmp_path / "private-resource"
    private_files.ensure_private_directory(root)
    journal = RoundJournal(root, {"purpose": "test"})
    path = journal.lock_path if kind == "round" else root / ".publish.lock"
    held = private_files.lock_private_file(path)
    original_open = os.open
    opened = []

    def tracked(candidate, *args, **kwargs):
        fd = original_open(candidate, *args, **kwargs)
        if candidate == path:
            opened.append(fd)
        return fd

    try:
        identities = []
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", tracked)
            for _ in range(3):
                with pytest.raises(private_files.PrivateStateBusyError) as caught:
                    if kind == "round":
                        with journal.locked():
                            pytest.fail("contended lock was acquired")
                    else:
                        private_files.lock_private_file(path)
                error = caught.value
                assert isinstance(error, BlockingIOError)
                assert error.errno in {errno.EAGAIN, errno.EWOULDBLOCK}
                assert error.operation == (
                    "round_journal_lock" if kind == "round" else "private_file_lock"
                )
                assert str(root) not in str(error) and error.filename is None
                restored = pickle.loads(pickle.dumps(error))
                assert (restored.operation, restored.resource_sha256, restored.errno) == (
                    error.operation,
                    error.resource_sha256,
                    error.errno,
                )
                identities.append(error.resource_sha256)
        assert len(set(identities)) == 1 and len(identities[0]) == 64
        for fd in opened:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
    finally:
        os.close(held)
    if kind == "round":
        with journal.locked():
            journal.put("test", "complete", {"value": 1})
    else:
        os.close(private_files.lock_private_file(path))


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["publisher", "feed"])
async def test_busy_state_waits_then_publishes_using_same_objects(automatic, package_case, kind):
    c = automatic
    completed(c, package_case)
    objects = (c.publisher, c.provider, c.guarded.replay, c.feed)
    journal = c.feed.journal if kind == "feed" else c.publisher.builder.journal
    with journal.locked():
        for _ in range(3):
            result = await c.service.tick()
            assert result["status"] == "waiting_for_local_state"
            assert result["reason_code"] == "private_state_busy"
            assert result["lock_operation"] == "round_journal_lock"
            assert result["retry_after_seconds"] == c.config.poll_interval_seconds
            assert str(journal.root) not in str(result)
            assert not c.service._serial.locked()
            assert not c.publisher.builder.journal.keys("authorization")
    assert (await c.service.tick())["status"] == "published"
    assert objects == (c.publisher, c.provider, c.guarded.replay, c.feed)
    assert len(c.feed.history()) == 1
    assert len(c.publisher.builder.journal.keys("authorization")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["before_delivery", "after_delivery"])
async def test_contention_after_signing_recovers_exact_history_without_signing_again(
    automatic, package_case, monkeypatch, stage
):
    c = automatic
    completed(c, package_case)
    original = c.feed.retain_async
    calls = 0

    async def contended(publication, prepared):
        nonlocal calls
        calls += 1
        if stage == "after_delivery":
            await original(publication, prepared)
        with c.feed.journal.locked():
            await original(publication, prepared)

    monkeypatch.setattr(c.feed, "retain_async", contended)
    assert (await c.service.tick())["status"] == "waiting_for_local_state"
    assert calls == 1
    signed = tuple(c.publisher.builder.history())
    assert len(signed) == 1
    raw = canonical_json_bytes(signed[0])
    monkeypatch.setattr(c.feed, "retain_async", original)
    status = (await c.service.tick())["status"]
    assert status == (
        "recovered_signed_history" if stage == "before_delivery" else "waiting_for_completed_round"
    )
    assert len(c.feed.history()) == len(c.publisher.builder.history()) == 1
    assert canonical_json_bytes(c.feed.history()[0]) == raw
    assert len(c.publisher.builder.journal.keys("authorization")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        BlockingIOError(errno.EAGAIN, "unrelated socket"),
        PermissionError("denied"),
        ValueError("bad signature"),
    ],
)
async def test_other_failures_are_not_reclassified_as_contention(automatic, monkeypatch, failure):
    async def failed():
        raise failure

    monkeypatch.setattr(automatic.service, "_tick_once", failed)
    with pytest.raises(type(failure)) as caught:
        await automatic.service.tick()
    assert caught.value is failure


class Finished(Exception):
    pass


@pytest.mark.asyncio
async def test_contention_during_partial_signing_preserves_reserved_authorization(
    automatic, package_case, monkeypatch, tmp_path
):
    c = automatic
    completed(c, package_case)
    path = tmp_path / "signing-gate.lock"
    held = private_files.lock_private_file(path)
    original = publication_module.sign_response_digest

    def sign(*args, **kwargs):
        fd = private_files.lock_private_file(path)
        os.close(fd)
        return original(*args, **kwargs)

    monkeypatch.setattr(publication_module, "sign_response_digest", sign)
    try:
        result = await c.service.tick()
        assert result["status"] == "waiting_for_local_state"
        assert result["lock_operation"] == "private_file_lock"
        authorization = c.publisher.builder.journal.get("authorization", "2:1")
        assert authorization is not None
        assert not c.feed.history()
    finally:
        os.close(held)
    assert (await c.service.tick())["status"] == "published"
    assert c.publisher.builder.journal.get("authorization", "2:1") == authorization
    assert len(c.publisher.builder.journal.keys("authorization")) == len(c.feed.history()) == 1


def publisher_config(c):
    root = Path(c.config.certificate_directory).parent
    wallet = cli.AuthorityWallet(
        wallet_name="release", hotkey_name="authority", wallet_path=str(root / "wallets")
    )
    return cli.SuccessorPublisherConfig(
        schema="umi-successor-publisher-config/2",
        plan=c.publisher.builder.plan,
        public_launch=PublicLaunchIdentity(
            schema="umi-competition-public-launch/1",
            round_schedule=c.guarded.package.scenario.round.public_schedule,
            eligible_tracks=c.guarded.package.scenario.round.eligible_tracks,
        ),
        chain=c.provider.config,
        intake_directory=str(c.guarded.store.directory),
        submission_head_checkpoint_directory=str(root / "intake-checkpoint"),
        publication_directory=str(c.publisher.builder.journal.root),
        replay_directory=str(c.guarded.replay.state_root),
        replay_capacity=c.guarded.replay.capacity,
        authorization_wallet=wallet,
        directive_wallets=(wallet,),
    )


@pytest.mark.asyncio
async def test_native_follow_loop_waits_without_reopening_provider_or_resigning(
    automatic, package_case, monkeypatch
):
    c = automatic
    completed(c, package_case)
    held = private_files.lock_private_file(c.feed.journal.lock_path)
    opens = 0
    reports = []

    @asynccontextmanager
    async def managed(*args, **kwargs):
        nonlocal opens
        opens += 1
        yield c.publisher, c.feed, c.signers

    def report(result):
        nonlocal held
        reports.append(result)
        if result["status"] == "waiting_for_local_state":
            os.close(held)
            held = None
        elif result["status"] == "published":
            raise Finished

    monkeypatch.setattr(cli, "_managed_publisher", managed)
    try:
        with pytest.raises(Finished):
            await cli.follow_rounds(
                publisher_config(c),
                c.guarded.store.policy,
                c.config,
                feed_config=c.feed_config,
                report=report,
            )
    finally:
        if held is not None:
            os.close(held)
    assert opens == 1
    assert [r["status"] for r in reports] == ["waiting_for_local_state", "published"]
    assert len(c.feed.history()) == len(c.publisher.builder.journal.keys("authorization")) == 1


@pytest.mark.asyncio
async def test_cancel_during_contention_backoff_does_not_touch_pending_state(
    automatic, monkeypatch
):
    c = automatic
    seen = asyncio.Event()

    @asynccontextmanager
    async def managed(*args, **kwargs):
        yield c.publisher, c.feed, c.signers

    monkeypatch.setattr(cli, "_managed_publisher", managed)
    with c.feed.journal.locked():
        task = asyncio.create_task(
            cli.follow_rounds(
                publisher_config(c),
                c.guarded.store.policy,
                c.config,
                feed_config=c.feed_config,
                report=lambda _: seen.set(),
            )
        )
        await asyncio.wait_for(seen.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not c.publisher.builder.journal.keys("authorization")
    assert not c.feed.history()
