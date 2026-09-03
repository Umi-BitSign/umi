from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import httpx
import pytest

from umi.audit_publication import PublicBundleIndex
from umi.observer_bundle_feed import (
    BoundedHTTPSFetcher,
    ObserverBundleFeed,
    ObserverBundleFeedConfig,
    ObserverBundleFeedError,
    ObserverFeedTarget,
    load_observer_bundle_feed_config,
)
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.validator_readiness import ReplayPublishedBundleVerifier, VerifiedPublishedBundle

from .test_audit_publication import _publisher, _StaticDocroot
from .test_calibration_bundle import VALIDATOR, _policy, _ports


async def _published(tmp_path: Path):
    root = tmp_path / "publisher"
    root.mkdir()
    return await _publisher(root)


def _feed(
    tmp_path: Path,
    docroot: Path,
    server: _StaticDocroot,
    *,
    now: list[float] | None = None,
    verifier=None,
    maximum_new_entries_per_refresh: int = 2,
) -> ObserverBundleFeed:
    clock = now or [100.0]

    def fetcher(origin: str, timeout: float) -> BoundedHTTPSFetcher:
        return BoundedHTTPSFetcher(
            origin,
            timeout_seconds=timeout,
            transport=httpx.MockTransport(server),
        )

    return ObserverBundleFeed(
        targets=(
            ObserverFeedTarget(
                validator_account_id32=VALIDATOR.hex(),
                scoring_policy_hash=scoring_policy_hash(_policy()),
                release_manifest_sha256="ab" * 32,
                public_origin="https://audit.example",
                verifier=verifier or ReplayPublishedBundleVerifier(_ports()),
            ),
        ),
        state_database_path=tmp_path / "observer-state" / "feed.sqlite3",
        temporary_root=tmp_path / "observer-temporary",
        maximum_stale_seconds=10,
        timeout_seconds=2,
        maximum_new_entries_per_refresh=maximum_new_entries_per_refresh,
        fetcher_factory=fetcher,
        clock=lambda: clock[0],
    )


@pytest.mark.asyncio
async def test_index_is_discovery_only_and_full_replay_precedes_durable_promotion(
    tmp_path: Path,
) -> None:
    publisher, server, _source, docroot = await _published(tmp_path)
    assert (await publisher.run_once()).completed == 1
    feed = _feed(tmp_path, docroot, server)

    assert await feed.refresh(finalized_height=10**9) is True
    snapshot = feed.snapshot()

    assert len(snapshot.windows) == 1
    window = snapshot.windows[0]
    assert window.validator_account_id32 == VALIDATOR.hex()
    assert window.window_id == publisher._load_index().entries[0].window_id
    assert window.terminal_classification == "calibration_no_weight"
    assert snapshot.health[0].status == "current"
    assert snapshot.health[0].accepted_entries == 1

    restarted = _feed(tmp_path, docroot, server)
    assert restarted.snapshot().windows == snapshot.windows
    assert await restarted.refresh(finalized_height=10**9) is True
    assert restarted.snapshot().health[0].accepted_entries == 1


@pytest.mark.asyncio
async def test_noncanonical_or_binding_changed_index_preserves_last_good(tmp_path: Path) -> None:
    publisher, server, _source, docroot = await _published(tmp_path)
    assert (await publisher.run_once()).completed == 1
    feed = _feed(tmp_path, docroot, server)
    assert await feed.refresh(10**9)
    good = feed.snapshot().windows

    index_path = publisher.index_path
    original = index_path.read_bytes()
    index_path.chmod(0o644)
    index_path.write_bytes(original + b" ")
    assert await feed.refresh(10**9) is False
    assert feed.snapshot().windows == good
    assert feed.snapshot().health[0].last_error_code == "feed_index_noncanonical"

    index = PublicBundleIndex.model_validate_json(original)
    changed = index.model_copy(update={"release_manifest_sha256": "ff" * 32})
    index_path.write_bytes(canonical_json_bytes(changed))
    assert await feed.refresh(10**9) is False
    assert feed.snapshot().windows == good
    assert feed.snapshot().health[0].last_error_code == "feed_index_binding_mismatch"

    changed = index.model_copy(
        update={"entries": [index.entries[0].model_copy(update={"tree_sha256": "ee" * 32})]}
    )
    index_path.write_bytes(canonical_json_bytes(changed))
    assert await feed.refresh(10**9) is False
    assert feed.snapshot().windows == good
    assert feed.snapshot().health[0].last_error_code == "feed_index_append_only_violation"


@pytest.mark.asyncio
async def test_future_release_and_tree_tampering_never_advance_cursor(tmp_path: Path) -> None:
    publisher, server, _source, _docroot = await _published(tmp_path)
    assert (await publisher.run_once()).completed == 1
    entry = publisher._load_index().entries[0]
    feed = _feed(tmp_path, publisher.public_docroot, server)

    assert await feed.refresh(entry.audit_release_block - 1) is False
    assert feed.snapshot().windows == ()
    assert feed.snapshot().health[0].last_error_code == "feed_release_block_in_future"

    server.corrupt_suffix = "manifest.json"
    assert await feed.refresh(10**9) is False
    assert feed.snapshot().windows == ()
    assert feed.snapshot().health[0].last_error_code in {
        "feed_body_limit",
        "feed_manifest_digest_mismatch",
    }


@pytest.mark.asyncio
async def test_replay_result_must_match_every_index_and_manifest_binding(tmp_path: Path) -> None:
    publisher, server, _source, docroot = await _published(tmp_path)
    assert (await publisher.run_once()).completed == 1
    entry = publisher._load_index().entries[0]

    class WrongReplay:
        async def verify(self, _root: Path) -> VerifiedPublishedBundle:
            return VerifiedPublishedBundle(
                manifest_sha256=entry.manifest_sha256,
                window_id="ff" * 32,
                window_index=entry.window_index,
                scoring_policy_hash=entry.scoring_policy_hash,
                terminal_classification=entry.terminal_classification,
                highest_stage=entry.highest_stage,
                audit_release_block=entry.audit_release_block,
                audit_release_block_hash=entry.audit_release_block_hash,
                reason_codes=tuple(entry.reason_codes),
            )

    feed = _feed(tmp_path, docroot, server, verifier=WrongReplay())
    assert await feed.refresh(10**9) is False
    assert feed.snapshot().windows == ()
    assert feed.snapshot().health[0].last_error_code == "feed_replay_binding_mismatch"


@pytest.mark.asyncio
async def test_feed_staleness_is_explicit_while_last_good_remains_readable(tmp_path: Path) -> None:
    publisher, server, _source, docroot = await _published(tmp_path)
    assert (await publisher.run_once()).completed == 1
    now = [100.0]
    feed = _feed(tmp_path, docroot, server, now=now)
    assert await feed.refresh(10**9)
    server.enabled = False
    now[0] = 111.0

    assert await feed.refresh(10**9) is False
    snapshot = feed.snapshot()
    assert len(snapshot.windows) == 1
    assert snapshot.health[0].status == "stale"
    assert snapshot.health[0].last_error_code == "feed_http_status"


@pytest.mark.asyncio
async def test_bounded_catch_up_is_degraded_until_the_public_index_is_consumed(
    tmp_path: Path,
) -> None:
    publisher, server, _source, docroot = await _published(tmp_path)
    assert (await publisher.run_once()).completed == 1
    index = publisher._load_index()
    first = index.entries[0]
    second_window = "ff" * 32
    second = first.model_copy(
        update={
            "sequence": 1,
            "window_id": second_window,
            "relative_path": first.relative_path.replace(first.window_id, second_window),
        }
    )
    expanded = index.model_copy(update={"entries": [first, second]})
    publisher.index_path.chmod(0o644)
    publisher.index_path.write_bytes(canonical_json_bytes(expanded))
    feed = _feed(
        tmp_path,
        docroot,
        server,
        maximum_new_entries_per_refresh=1,
    )

    assert await feed.refresh(10**9) is False
    pending = feed.snapshot()
    assert len(pending.windows) == 1
    assert pending.health[0].status == "degraded"
    assert pending.health[0].last_error_code == "feed_backlog_pending"
    assert pending.health[0].accepted_entries == 1

    # The unverified second route does not exist. Its failure cannot remove or
    # replace the already replayed prefix.
    assert await feed.refresh(10**9) is False
    failed = feed.snapshot()
    assert failed.windows == pending.windows
    assert failed.health[0].last_error_code == "feed_http_status"


@pytest.mark.asyncio
async def test_redundant_durable_row_mismatch_fails_closed_on_restart(tmp_path: Path) -> None:
    publisher, server, _source, docroot = await _published(tmp_path)
    assert (await publisher.run_once()).completed == 1
    feed = _feed(tmp_path, docroot, server)
    assert await feed.refresh(10**9)
    with sqlite3.connect(feed.state_path) as connection:
        connection.execute("UPDATE bundles SET window_index = window_index + 1")

    with pytest.raises(ObserverBundleFeedError, match="feed_state_row_binding_mismatch"):
        _feed(tmp_path, docroot, server)


@pytest.mark.asyncio
async def test_fetcher_rejects_private_or_mixed_dns_without_http_request() -> None:
    async def resolver(_hostname: str, _port: int):
        return ("93.184.216.34", "127.0.0.1")

    fetcher = BoundedHTTPSFetcher(
        "https://audit.example",
        timeout_seconds=1,
        resolver=resolver,
        transport=httpx.AsyncHTTPTransport(),
    )
    with pytest.raises(ObserverBundleFeedError, match="feed_dns_address_not_global"):
        async with fetcher.session():
            pass


@pytest.mark.asyncio
async def test_fetcher_pins_public_ipv6_and_preserves_bracketed_authority() -> None:
    async def resolver(_hostname: str, _port: int):
        return ("2606:4700:4700::1111",)

    fetcher = BoundedHTTPSFetcher(
        "https://[2606:4700:4700::1111]",
        timeout_seconds=1,
        resolver=resolver,
        transport=httpx.AsyncHTTPTransport(),
    )
    async with fetcher.session() as session:
        assert session.request_origin == "https://[2606:4700:4700::1111]:443"
        assert session.host_header == "[2606:4700:4700::1111]"
        assert session.sni_hostname == "2606:4700:4700::1111"


@pytest.mark.asyncio
async def test_fetcher_rejects_oversized_and_partial_inputs() -> None:
    def oversized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "11"}, content=b"x", request=request)

    fetcher = BoundedHTTPSFetcher(
        "https://audit.example",
        timeout_seconds=1,
        transport=httpx.MockTransport(oversized),
    )
    async with fetcher.session() as session:
        with pytest.raises(ObserverBundleFeedError, match="feed_body_limit"):
            await fetcher.fetch(session, "index.json", 10)

    class ShortStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"short"

    def partial(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "9"},
            stream=ShortStream(),
            request=request,
        )

    fetcher = BoundedHTTPSFetcher(
        "https://audit.example",
        timeout_seconds=1,
        transport=httpx.MockTransport(partial),
    )
    async with fetcher.session() as session:
        with pytest.raises(ObserverBundleFeedError, match="feed_partial_body"):
            await fetcher.fetch(session, "index.json", 10)


@pytest.mark.asyncio
async def test_fetcher_rejects_redirects_and_encoded_responses() -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://other.example"}, request=request)

    fetcher = BoundedHTTPSFetcher(
        "https://audit.example",
        timeout_seconds=1,
        transport=httpx.MockTransport(redirect),
    )
    async with fetcher.session() as session:
        with pytest.raises(ObserverBundleFeedError, match="feed_http_status"):
            await fetcher.fetch(session, "index.json", 10)

    def encoded(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            stream=httpx.ByteStream(b"encoded"),
            request=request,
        )

    fetcher = BoundedHTTPSFetcher(
        "https://audit.example",
        timeout_seconds=1,
        transport=httpx.MockTransport(encoded),
    )
    async with fetcher.session() as session:
        with pytest.raises(ObserverBundleFeedError, match="feed_content_encoding"):
            await fetcher.fetch(session, "index.json", 10)


def test_tree_hash_is_bound_by_index_not_just_manifest_digest(tmp_path: Path) -> None:
    # The tree digest covers every path, digest, and size. This guards against a
    # future refactor accidentally treating the manifest digest as the whole tree.
    files = (
        ("manifest.json", hashlib.sha256(b"manifest").hexdigest(), 8),
        ("objects/" + "ab" * 32, "ab" * 32, 9),
    )
    from umi.audit_publication import PublishedFile, _bundle_tree_sha256

    first = _bundle_tree_sha256(tuple(PublishedFile(*item) for item in files))
    changed = _bundle_tree_sha256(
        tuple(
            PublishedFile(path, digest, size + (path.startswith("objects/") * 1))
            for path, digest, size in files
        )
    )
    assert first != changed


def test_documented_feed_config_has_read_only_production_shape() -> None:
    encoded = Path("docs/examples/observer-bundle-feed-config.json").read_bytes()
    config = ObserverBundleFeedConfig.model_validate_json(encoded)

    assert canonical_json_bytes(config) == encoded.rstrip(b"\n")
    assert config.translation_weights_active is False
    assert config.wallet_loading_capability is False
    assert config.chain_write_capability is False
    assert config.weight_submission_capability is False
    assert (
        load_observer_bundle_feed_config("docs/examples/observer-bundle-feed-config.json") == config
    )
    with pytest.raises(ValueError):
        ObserverBundleFeedConfig.model_validate(
            config.model_dump(by_alias=True) | {"wallet_loading_capability": True}
        )
