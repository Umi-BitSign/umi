from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.factories import dev_wallet
from tests.test_observer import SequenceCollector, _cache, _snapshot
from umi.crypto import sign_response_digest
from umi.encoding import account_id32
from umi.observer import _parser, create_observer_app
from umi.observer_directive_feed import (
    OBSERVER_DIRECTIVE_FEED_CONFIG_SCHEMA,
    ObserverDirectiveFeedError,
    build_observer_directive_feed,
)
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SUPERVISOR_DIRECTIVE_SCHEMA,
    SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
    SignedSupervisorDirective,
    SupervisorDirective,
    SupervisorDirectivePage,
    SupervisorDirectiveSignature,
    supervisor_directive_digest,
    supervisor_directive_sha256,
)


def _signed_hold() -> tuple[SignedSupervisorDirective, object, str]:
    authority = dev_wallet("//ObserverDirectiveAuthority")
    validator = dev_wallet("//ObserverDirectiveValidator").hotkey.ss58_address
    directive = SupervisorDirective(
        schema=SUPERVISOR_DIRECTIVE_SCHEMA,
        channel_id="11" * 32,
        sequence=1,
        previous_directive_sha256=None,
        issued_at_block=1,
        valid_from_block=1,
        valid_through_block=(1 << 53) - 1,
        network="finney",
        netuid=78,
        mechanism_id=0,
        mode="hold",
        validator_hotkeys=[validator],
        policy_sha256=None,
        release=None,
    )
    scheme, signature = sign_response_digest(
        authority,
        supervisor_directive_digest(directive),
    )
    signed = SignedSupervisorDirective(
        schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=directive,
        directive_sha256=supervisor_directive_sha256(directive),
        directive_digest=supervisor_directive_digest(directive).hex(),
        signatures=[
            SupervisorDirectiveSignature(
                hotkey=authority.hotkey.ss58_address,
                signature_scheme=scheme,
                signature=signature,
            )
        ],
    )
    return signed, authority, validator


def _write_feed(tmp_path: Path):
    signed, authority, validator = _signed_hold()
    page = SupervisorDirectivePage(
        schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_sequence=0,
        after_directive_sha256=None,
        directives=[signed],
        more=False,
        head=signed,
    )
    page_bytes = canonical_json_bytes(page)
    account = account_id32(validator).hex()
    route_root = tmp_path / "routes"
    initial_directory = route_root / account / "after" / "0"
    initial_directory.mkdir(parents=True)
    initial_path = initial_directory / "initial.json"
    initial_path.write_bytes(page_bytes)
    current_page = SupervisorDirectivePage(
        schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_sequence=1,
        after_directive_sha256=signed.directive_sha256,
        directives=[],
        more=False,
        head=signed,
    )
    current_directory = route_root / account / "after" / "1"
    current_directory.mkdir()
    (current_directory / f"{signed.directive_sha256}.json").write_bytes(
        canonical_json_bytes(current_page)
    )
    config = {
        "schema": OBSERVER_DIRECTIVE_FEED_CONFIG_SCHEMA,
        "route_root": str(route_root),
        "channels": [
            {
                "validator_account_id32": account,
                "validator_hotkey": validator,
                "channel_id": signed.directive.channel_id,
                "signature_threshold": 1,
                "trusted_authorities": [
                    {
                        "hotkey": authority.hotkey.ss58_address,
                        "signature_scheme": "sr25519",
                    }
                ],
                "initial_directive_sha256": signed.directive_sha256,
                "initial_page_sha256": hashlib.sha256(page_bytes).hexdigest(),
                "readiness_head_sequence": 1,
                "readiness_head_directive_sha256": signed.directive_sha256,
            }
        ],
    }
    config_path = tmp_path / "directive-feed.json"
    config_path.write_bytes(canonical_json_bytes(config))
    return config_path, initial_path, account, signed, page_bytes


def _build_test_feed(config_path: Path):
    return build_observer_directive_feed(
        config_path,
        additional_trusted_owner_uid=os.geteuid(),
    )


def _signed_successor(
    previous: SignedSupervisorDirective,
    authority: object,
    validator: str,
    *,
    channel_id: str | None = None,
) -> SignedSupervisorDirective:
    directive = SupervisorDirective(
        schema=SUPERVISOR_DIRECTIVE_SCHEMA,
        channel_id=channel_id or previous.directive.channel_id,
        sequence=previous.directive.sequence + 1,
        previous_directive_sha256=previous.directive_sha256,
        issued_at_block=previous.directive.issued_at_block + 1,
        valid_from_block=previous.directive.valid_from_block + 1,
        valid_through_block=previous.directive.valid_through_block,
        network="finney",
        netuid=78,
        mechanism_id=0,
        mode="hold",
        validator_hotkeys=[validator],
        policy_sha256=None,
        release=None,
    )
    scheme, signature = sign_response_digest(authority, supervisor_directive_digest(directive))
    return SignedSupervisorDirective(
        schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=directive,
        directive_sha256=supervisor_directive_sha256(directive),
        directive_digest=supervisor_directive_digest(directive).hex(),
        signatures=[
            SupervisorDirectiveSignature(
                hotkey=authority.hotkey.ss58_address,
                signature_scheme=scheme,
                signature=signature,
            )
        ],
    )


def _write_cursor_page(
    feed,
    account: str,
    previous: SignedSupervisorDirective,
    directives: list[SignedSupervisorDirective],
) -> Path:
    page = SupervisorDirectivePage(
        schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_sequence=previous.directive.sequence,
        after_directive_sha256=previous.directive_sha256,
        directives=directives,
        more=False,
        head=directives[-1],
    )
    target = feed.route_root / account / "after" / str(previous.directive.sequence)
    target.mkdir(exist_ok=True)
    path = target / f"{previous.directive_sha256}.json"
    path.write_bytes(canonical_json_bytes(page))
    return path


def test_file_backed_directive_route_preserves_verified_canonical_bytes(
    tmp_path: Path,
) -> None:
    config_path, _, account, signed, page_bytes = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        directive_feed=feed,
    )
    path = f"/api/v1/validator-directives/{account}/after/0/initial.json"

    with TestClient(app) as client:
        response = client.get(path, headers={"Accept-Encoding": "identity"})
        head = client.head(path, headers={"Accept-Encoding": "identity"})
        query = client.get(path + "?unexpected=1")
        absent = client.get(
            f"/api/v1/validator-directives/{account}/after/2/{signed.directive_sha256}.json"
        )

    assert response.status_code == 200
    assert response.content == page_bytes
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-encoding"] == "identity"
    assert response.headers["content-length"] == str(len(page_bytes))
    assert response.headers["cache-control"] == (
        "no-cache, no-store, must-revalidate, no-transform"
    )
    assert response.headers["x-umi-directive-page-sha256"] == hashlib.sha256(page_bytes).hexdigest()
    assert response.headers["x-umi-directive-head"] == signed.directive_sha256
    assert response.headers["x-umi-directive-sequence"] == "1"
    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["content-length"] == str(len(page_bytes))
    assert query.status_code == 422
    assert absent.status_code == 404


def test_feed_serves_a_dynamic_caught_up_cursor_page(tmp_path: Path) -> None:
    config_path, _, account, signed, _ = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    page = SupervisorDirectivePage(
        schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_sequence=1,
        after_directive_sha256=signed.directive_sha256,
        directives=[],
        more=False,
        head=signed,
    )
    encoded = canonical_json_bytes(page)
    target = feed.route_root / account / "after" / "1"
    target.mkdir(exist_ok=True)
    (target / f"{signed.directive_sha256}.json").write_bytes(encoded)

    verified = feed.read_page(
        account,
        after_sequence=1,
        cursor=signed.directive_sha256,
    )

    assert verified is not None
    assert verified.data == encoded
    assert verified.head_sequence == 1


def test_feed_verifies_every_directive_in_a_multi_directive_page(tmp_path: Path) -> None:
    config_path, _, account, first, _ = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    authority = dev_wallet("//ObserverDirectiveAuthority")
    validator = first.directive.validator_hotkeys[0]
    second = _signed_successor(first, authority, validator)
    third = _signed_successor(second, authority, validator)
    path = _write_cursor_page(feed, account, first, [second, third])

    verified = feed.read_page(
        account,
        after_sequence=1,
        cursor=first.directive_sha256,
    )

    assert verified is not None
    assert verified.data == path.read_bytes()
    assert verified.head_sequence == 3
    assert verified.head_directive_sha256 == third.directive_sha256


@pytest.mark.parametrize(
    ("failure", "reason_code"),
    [
        ("signature", "directive_feed_signature_invalid"),
        ("channel", "directive_feed_channel_mismatch"),
        ("validator", "directive_feed_validator_mismatch"),
    ],
)
def test_feed_rejects_invalid_signed_page_bindings(
    tmp_path: Path,
    failure: str,
    reason_code: str,
) -> None:
    config_path, _, account, first, _ = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    authority = dev_wallet("//ObserverDirectiveAuthority")
    validator = first.directive.validator_hotkeys[0]
    if failure == "channel":
        successor = _signed_successor(first, authority, validator, channel_id="22" * 32)
    elif failure == "validator":
        other_validator = dev_wallet("//OtherObserverDirectiveValidator").hotkey.ss58_address
        successor = _signed_successor(first, authority, other_validator)
    else:
        valid = _signed_successor(first, authority, validator)
        invalid_signature = valid.signatures[0].model_copy(update={"signature": "0x" + "00" * 64})
        successor = valid.model_copy(update={"signatures": [invalid_signature]})
    _write_cursor_page(feed, account, first, [successor])

    with pytest.raises(ObserverDirectiveFeedError) as rejected:
        feed.read_page(account, after_sequence=1, cursor=first.directive_sha256)

    assert rejected.value.reason_code == reason_code


def test_feed_rejects_runtime_tampering_and_symlink_substitution(tmp_path: Path) -> None:
    config_path, initial_path, account, _, page_bytes = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    initial_path.write_bytes(page_bytes + b"\n")

    with pytest.raises(ObserverDirectiveFeedError) as changed:
        feed.read_page(account, after_sequence=0, cursor="initial")
    assert changed.value.reason_code == "directive_feed_page_invalid"

    initial_path.unlink()
    outside = tmp_path / "outside.json"
    outside.write_bytes(page_bytes)
    initial_path.symlink_to(outside)
    with pytest.raises(ObserverDirectiveFeedError) as linked:
        feed.read_page(account, after_sequence=0, cursor="initial")
    assert linked.value.reason_code == "directive_feed_route_unavailable"


def test_feed_rejects_writable_directories_and_hard_linked_pages(tmp_path: Path) -> None:
    config_path, initial_path, account, _, _ = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    initial_directory = initial_path.parent
    initial_directory.chmod(0o777)

    with pytest.raises(ObserverDirectiveFeedError) as writable:
        feed.read_page(account, after_sequence=0, cursor="initial")
    assert writable.value.reason_code == "directive_feed_path_unsafe"

    initial_directory.chmod(0o755)
    hard_link = tmp_path / "hard-link.json"
    hard_link.hardlink_to(initial_path)
    with pytest.raises(ObserverDirectiveFeedError) as linked:
        feed.read_page(account, after_sequence=0, cursor="initial")
    assert linked.value.reason_code == "directive_feed_path_unsafe"


def test_feed_rejects_a_symlinked_config_file(tmp_path: Path) -> None:
    config_path, _, _, _, _ = _write_feed(tmp_path)
    symlink = tmp_path / "directive-feed-link.json"
    symlink.symlink_to(config_path)

    with pytest.raises(ObserverDirectiveFeedError) as rejected:
        _build_test_feed(symlink)

    assert rejected.value.reason_code == "directive_feed_config_invalid"


def test_production_feed_requires_a_root_owned_tree(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("the test process already creates root-owned fixtures")
    config_path, _, _, _, _ = _write_feed(tmp_path)

    with pytest.raises(ObserverDirectiveFeedError) as rejected:
        build_observer_directive_feed(config_path)

    assert rejected.value.reason_code == "directive_feed_path_unsafe"


def test_feed_startup_requires_the_pinned_initial_page_hash(tmp_path: Path) -> None:
    config_path, initial_path, _, _, page_bytes = _write_feed(tmp_path)
    initial_path.write_bytes(page_bytes.replace(b'"mode":"hold"', b'"mode":"hold" ', 1))

    with pytest.raises(ObserverDirectiveFeedError) as rejected:
        _build_test_feed(config_path)

    assert rejected.value.reason_code == "directive_feed_page_invalid"


def test_readyz_rechecks_initial_pages_after_startup(tmp_path: Path) -> None:
    config_path, initial_path, _, _, page_bytes = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        directive_feed=feed,
    )

    with TestClient(app) as client:
        assert client.get("/readyz").status_code == 200
        initial_path.write_bytes(page_bytes + b"\n")
        unavailable = client.get("/readyz")
        initial_path.write_bytes(page_bytes)
        recovered = client.get("/readyz")

    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["reason_code"] == "validator_directive_feed_unavailable"
    assert recovered.status_code == 200


def test_readyz_rejects_config_drift_and_current_page_failure(tmp_path: Path) -> None:
    config_path, _, account, signed, _ = _write_feed(tmp_path)
    config_bytes = config_path.read_bytes()
    feed = _build_test_feed(config_path)
    current_path = feed.route_root / account / "after" / "1" / f"{signed.directive_sha256}.json"
    current_bytes = current_path.read_bytes()
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        directive_feed=feed,
    )

    with TestClient(app) as client:
        assert client.get("/readyz").status_code == 200
        config_path.write_bytes(config_bytes + b"\n")
        config_drift = client.get("/readyz")
        config_path.write_bytes(config_bytes)
        current_path.write_bytes(b"{}")
        current_failure = client.get("/readyz")
        current_path.write_bytes(current_bytes)
        recovered = client.get("/readyz")

    assert config_drift.status_code == 503
    assert config_drift.json()["error"]["reason_code"] == ("validator_directive_feed_unavailable")
    assert current_failure.status_code == 503
    assert current_failure.json()["error"]["reason_code"] == (
        "validator_directive_feed_unavailable"
    )
    assert recovered.status_code == 200


def test_readiness_walks_cursor_pages_to_the_configured_head(tmp_path: Path) -> None:
    config_path, _, account, first, _ = _write_feed(tmp_path)
    authority = dev_wallet("//ObserverDirectiveAuthority")
    validator = first.directive.validator_hotkeys[0]
    second = _signed_successor(first, authority, validator)
    first_page = SupervisorDirectivePage(
        schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_sequence=1,
        after_directive_sha256=first.directive_sha256,
        directives=[second],
        more=True,
        head=second,
    )
    first_path = tmp_path / "routes" / account / "after" / "1" / f"{first.directive_sha256}.json"
    first_path.write_bytes(canonical_json_bytes(first_page))
    second_directory = tmp_path / "routes" / account / "after" / "2"
    second_directory.mkdir()
    caught_up = SupervisorDirectivePage(
        schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_sequence=2,
        after_directive_sha256=second.directive_sha256,
        directives=[],
        more=False,
        head=second,
    )
    (second_directory / f"{second.directive_sha256}.json").write_bytes(
        canonical_json_bytes(caught_up)
    )
    config = json.loads(config_path.read_bytes())
    config["channels"][0]["readiness_head_sequence"] = 2
    config["channels"][0]["readiness_head_directive_sha256"] = second.directive_sha256
    config_path.write_bytes(canonical_json_bytes(config))

    feed = _build_test_feed(config_path)

    feed.verify_readiness()


@pytest.mark.asyncio
async def test_public_directive_reads_do_not_saturate_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, _, account, _, _ = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    started = threading.Event()
    release = threading.Event()
    original = type(feed).read_page

    def blocking_read(self, *args, **kwargs):
        if not started.is_set():
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test read did not resume")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(feed), "read_page", blocking_read)
    cache = _cache(SequenceCollector([_snapshot()]))
    app = create_observer_app(
        cache,
        directive_feed=feed,
        directive_feed_read_concurrency=1,
    )
    path = f"/api/v1/validator-directives/{account}/after/0/initial.json"
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="https://testserver") as client,
    ):
        first = asyncio.create_task(client.get(path))
        assert await asyncio.to_thread(started.wait, 2)
        saturated = await asyncio.wait_for(client.get(path), timeout=1)
        ready = await asyncio.wait_for(client.get("/readyz"), timeout=2)
        release.set()
        completed = await asyncio.wait_for(first, timeout=2)

    assert saturated.status_code == 503
    assert saturated.json()["error"]["reason_code"] == "validator_directive_page_unavailable"
    assert ready.status_code == 200
    assert completed.status_code == 200


@pytest.mark.asyncio
async def test_timed_out_read_keeps_its_slot_until_the_thread_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, _, account, _, _ = _write_feed(tmp_path)
    feed = _build_test_feed(config_path)
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    original = type(feed).read_page

    def blocking_read(self, *args, **kwargs):
        if not started.is_set():
            started.set()
            try:
                if not release.wait(timeout=5):
                    raise RuntimeError("test read did not resume")
            finally:
                finished.set()
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(feed), "read_page", blocking_read)
    cache = _cache(SequenceCollector([_snapshot()]))
    app = create_observer_app(
        cache,
        directive_feed=feed,
        directive_feed_read_concurrency=1,
        directive_feed_read_timeout_seconds=0.05,
    )
    path = f"/api/v1/validator-directives/{account}/after/0/initial.json"
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="https://testserver") as client,
    ):
        timed_out = await asyncio.wait_for(client.get(path), timeout=1)
        still_charged = await asyncio.wait_for(client.get(path), timeout=1)
        ready = await asyncio.wait_for(client.get("/readyz"), timeout=2)
        release.set()
        assert await asyncio.to_thread(finished.wait, 2)
        for _ in range(100):
            recovered = await client.get(path)
            if recovered.status_code == 200:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("directive read slot was not returned after its thread exited")

    assert timed_out.status_code == 503
    assert still_charged.status_code == 503
    assert ready.status_code == 200


@pytest.mark.parametrize(
    "kwargs",
    [
        {"directive_feed_read_timeout_seconds": 0},
        {"directive_feed_read_timeout_seconds": float("inf")},
        {"directive_feed_readiness_timeout_seconds": True},
    ],
)
def test_directive_read_timeouts_are_bounded(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="timeout"):
        create_observer_app(
            _cache(SequenceCollector([_snapshot()])),
            **kwargs,
        )


def test_observer_cli_reads_the_root_owned_directive_feed_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "/etc/umi/observer-validator-directive-feed.json"
    monkeypatch.setenv("UMI_OBSERVER_DIRECTIVE_FEED_CONFIG", path)

    args = _parser().parse_args([])

    assert args.directive_feed_config == path
