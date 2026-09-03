from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import bittensor as bt
import httpx
import pytest

from umi.encoding import account_id32
from umi.mirror_service import (
    MIRROR_SERVICE_CONFIG_SCHEMA,
    MIRROR_SERVICE_MODE,
    MirrorServiceConfig,
    MirrorValidatorCredential,
    create_app,
    load_mirror_service,
    main,
)
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import (
    PROTOCOL_VERSION,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
)
from umi.publisher_availability import (
    CERTIFIED_RELEASE_FILENAME,
    build_certified_release,
    validate_candidate_bundle,
    write_certified_release,
)
from umi.validator_delivery import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    MIRROR_DISCOVERY_SCHEMA,
    MirrorDiscoveryRule,
    VideoDeliveryCommitment,
    VideoDeliveryIssuanceRequest,
    VideoDeliveryIssuanceResponse,
    build_delivery_request,
    validate_delivery_issuance,
    validate_delivery_response,
)
from umi.validator_live_ports import (
    AuthenticatedMirrorDeliveryIssuer,
    DurablePoolMirrorSource,
)
from umi.validator_pool_effect import DeliveryIssuanceContext
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_policy import make_policy
from .test_publisher_availability import (
    _context,
    _fake_inspect_factory,
    _qualify,
    _window,
    _write_bundle,
)
from .test_validator_pool_effect import _work

RETRIEVAL_ORIGIN = "https://mirror.example"
DELIVERY_ORIGIN = "https://delivery.example"


@dataclass(frozen=True)
class _ServiceFixture:
    policy: ScoringPolicy
    discovery: MirrorDiscoveryRule
    discovery_bytes: bytes
    config: MirrorServiceConfig
    config_path: Path
    release_root: Path
    clock: list[int]
    tokens: dict[str, str]

    @property
    def authorization(self) -> str:
        hotkey = sorted(self.tokens, key=account_id32)[0]
        return "Bearer " + self.tokens[hotkey]


def _service_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _ServiceFixture:
    initial = make_policy()
    discovery = MirrorDiscoveryRule(
        schema=MIRROR_DISCOVERY_SCHEMA,
        protocol=PROTOCOL_VERSION,
        authentication_profile=initial.implementation_pins.rules.mirror_authentication_profile,
        index_path_template=DEFAULT_MIRROR_INDEX_PATH,
        delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
        origins=sorted(
            [
                RETRIEVAL_ORIGIN,
                "https://z-mirror-b.example",
                "https://z-mirror-c.example",
            ]
        ),
        delivery_origins=sorted(
            [
                DELIVERY_ORIGIN,
                "https://z-delivery-b.example",
                "https://z-delivery-c.example",
            ]
        ),
    )
    discovery_bytes = canonical_json_bytes(discovery)
    policy_document = initial.model_dump(mode="json", by_alias=True)
    policy_document["implementation_pins"]["rules"]["mirror_discovery_rule_sha256"] = (
        hashlib.sha256(discovery_bytes).hexdigest()
    )
    policy = ScoringPolicy.model_validate(policy_document)
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(
        tmp_path / "candidate",
        policy,
        window,
        publisher_count=3,
    )
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=_context(loaded, policy, 0),
    )
    receipts = [
        _qualify(tmp_path / f"validator-{index}", validated, policy, index)[0] for index in range(3)
    ]
    material = build_certified_release(validated, receipts, policy=policy)
    release_root = write_certified_release(tmp_path / "certified", material).resolve()

    owner_root = (tmp_path / "owner-private").resolve()
    owner_root.mkdir(mode=0o700)
    policy_path = owner_root / "policy.json"
    policy_bytes = canonical_json_bytes(policy)
    policy_path.write_bytes(policy_bytes)
    policy_path.chmod(0o600)
    discovery_path = owner_root / "mirror-discovery.json"
    discovery_path.write_bytes(discovery_bytes)
    discovery_path.chmod(0o600)
    tokens = {
        entry.validator_hotkey: base64url_encode(bytes([index + 1]) * 32)
        for index, entry in enumerate(
            sorted(policy.validator_registry, key=lambda item: account_id32(item.validator_hotkey))
        )
    }
    credentials = [
        MirrorValidatorCredential(validator_hotkey=hotkey, bearer_token=tokens[hotkey])
        for hotkey in sorted(tokens, key=account_id32)
    ]
    config = MirrorServiceConfig(
        schema=MIRROR_SERVICE_CONFIG_SCHEMA,
        protocol=PROTOCOL_VERSION,
        mode=MIRROR_SERVICE_MODE,
        translation_weights_active=False,
        chain_write_capability=False,
        weight_submission_capability=False,
        policy_path=str(policy_path),
        scoring_policy_sha256=scoring_policy_hash(policy),
        discovery_rule_path=str(discovery_path),
        discovery_rule_sha256=hashlib.sha256(discovery_bytes).hexdigest(),
        certified_tree_root=str(release_root),
        certified_release_sha256=hashlib.sha256(
            (release_root / CERTIFIED_RELEASE_FILENAME).read_bytes()
        ).hexdigest(),
        state_database_path=str(owner_root / "state" / "mirror.sqlite3"),
        validator_credentials=credentials,
        retrieval_origin=RETRIEVAL_ORIGIN,
        delivery_origin=DELIVERY_ORIGIN,
        listen_host="127.0.0.1",
        listen_port=8787,
        workers=2,
    )
    config_path = owner_root / "mirror-service.json"
    config_path.write_bytes(canonical_json_bytes(config))
    config_path.chmod(0o600)
    clock = [QUICKNET_GENESIS_MS + (window.issue_close_round - 1) * QUICKNET_PERIOD_MS - 10_000]
    return _ServiceFixture(
        policy=policy,
        discovery=discovery,
        discovery_bytes=discovery_bytes,
        config=config,
        config_path=config_path,
        release_root=release_root,
        clock=clock,
        tokens=tokens,
    )


def _selected_commitments(fixture: _ServiceFixture, *, batch_offset: int = 0):
    runtime = load_mirror_service(fixture.config_path, clock=lambda: fixture.clock[0])
    batch_ids = sorted(runtime.loaded.batch_publishers, key=base64url_decode)
    selected = set(batch_ids[batch_offset : batch_offset + 2])
    commitments = [
        VideoDeliveryCommitment(
            batch_id=batch_id,
            challenge_id=challenge_id,
            sha256=entry.sha256,
            size_bytes=entry.size_bytes,
        )
        for (batch_id, challenge_id), entry in runtime.loaded.videos.items()
        if batch_id in selected
    ]
    commitments.sort(
        key=lambda item: (
            base64url_decode(item.batch_id),
            base64url_decode(item.challenge_id),
        )
    )
    return runtime, tuple(commitments)


def _headers(fixture: _ServiceFixture, *, hotkey: str | None = None) -> dict[str, str]:
    selected = hotkey or sorted(fixture.tokens, key=account_id32)[0]
    return {
        "Authorization": "Bearer " + fixture.tokens[selected],
        "Content-Type": "application/json",
    }


def _request_for(
    fixture: _ServiceFixture,
    *,
    seed: bytes = b"s" * 32,
    batch_offset: int = 0,
) -> tuple[object, tuple[VideoDeliveryCommitment, ...], VideoDeliveryIssuanceRequest, bytes]:
    runtime, commitments = _selected_commitments(fixture, batch_offset=batch_offset)
    request = build_delivery_request(
        runtime.loaded.release.window.to_plan(),
        commitments,
        delivery_token_seed=base64url_encode(seed),
    )
    return runtime, commitments, request, canonical_json_bytes(request)


@pytest.mark.asyncio
async def test_reference_service_serves_exact_tree_issues_and_restarts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    runtime, commitments, request, request_bytes = _request_for(fixture)
    app = create_app(fixture.config_path, clock=lambda: fixture.clock[0])
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as client:
        index = await client.get(
            RETRIEVAL_ORIGIN + DEFAULT_MIRROR_INDEX_PATH.format(window_id=request.window_id),
            headers=_headers(fixture),
        )
        assert index.status_code == 200
        assert index.content == runtime.loaded.index_bytes
        response = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture),
            content=request_bytes,
        )
        assert response.status_code == 200
        parsed = VideoDeliveryIssuanceResponse.model_validate_json(response.content)
        assert canonical_json_bytes(parsed) == response.content
        assert validate_delivery_response(
            policy=fixture.policy,
            window=runtime.loaded.release.window.to_plan(),
            discovery=fixture.discovery,
            request=request,
            response=parsed,
            expected_commitments=commitments,
        ) == tuple(parsed.deliveries)
        first = await client.get(parsed.deliveries[0].url)
        assert first.status_code == 200
        expected = runtime.loaded.videos[
            (parsed.deliveries[0].batch_id, parsed.deliveries[0].challenge_id)
        ]
        assert first.content == runtime.read_entry(expected)
        assert first.headers["content-length"] == str(expected.size_bytes)
        assert first.headers["content-type"] == "video/mp4"

    restarted = create_app(fixture.config_path, clock=lambda: fixture.clock[0])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted)) as client:
        replay = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture),
            content=request_bytes,
        )
        assert replay.status_code == 200
        assert replay.content == response.content

    with sqlite3.connect(fixture.config.state_database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM requests").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM deliveries").fetchone() == (
            len(commitments),
        )


@pytest.mark.asyncio
async def test_reference_service_is_accepted_by_production_validator_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    runtime, commitments, _request, _request_bytes = _request_for(fixture)
    app = create_app(fixture.config_path, clock=lambda: fixture.clock[0])

    async def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    source = DurablePoolMirrorSource(
        policy=fixture.policy,
        discovery_rule_bytes=fixture.discovery_bytes,
        state_path=Path(fixture.config.state_database_path).with_name("validator.sqlite3"),
        request_headers={
            origin: {
                "Authorization": (
                    fixture.authorization
                    if origin == RETRIEVAL_ORIGIN
                    else f"Bearer unused-independent-{index}"
                )
            }
            for index, origin in enumerate(fixture.discovery.origins)
        },
        transport=httpx.ASGITransport(app=app),
        resolver=resolver,
    )
    plan = runtime.loaded.release.window.to_plan()
    work = _work(plan)
    context = DeliveryIssuanceContext(
        window=plan,
        selected_video_commitments=commitments,
    )
    result = await AuthenticatedMirrorDeliveryIssuer(fixture.policy, source)(context, work)
    assert (
        validate_delivery_issuance(
            policy=fixture.policy,
            window=plan,
            expected_commitments=commitments,
            result=result,
        )
        == result.deliveries
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        delivered = await client.get(result.deliveries[0].url)
    assert delivered.status_code == 200
    assert hashlib.sha256(delivered.content).hexdigest() == result.deliveries[0].sha256


@pytest.mark.asyncio
async def test_reference_service_enforces_authentication_and_origin_separation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    runtime, _commitments, request, request_bytes = _request_for(fixture)
    index_path = DEFAULT_MIRROR_INDEX_PATH.format(window_id=request.window_id)
    app = create_app(fixture.config_path, clock=lambda: fixture.clock[0])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        missing = await client.get(RETRIEVAL_ORIGIN + index_path)
        wrong = await client.get(
            RETRIEVAL_ORIGIN + index_path,
            headers={"Authorization": "Bearer " + base64url_encode(b"x" * 32)},
        )
        cross_origin = await client.get(
            DELIVERY_ORIGIN + index_path,
            headers=_headers(fixture),
        )
        static_release = await client.get(
            RETRIEVAL_ORIGIN + "/" + CERTIFIED_RELEASE_FILENAME,
            headers=_headers(fixture),
        )
        issued = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture),
            content=request_bytes,
        )
        parsed = VideoDeliveryIssuanceResponse.model_validate_json(issued.content)
        token_path = httpx.URL(parsed.deliveries[0].url).path
        delivery_on_retrieval = await client.get(RETRIEVAL_ORIGIN + token_path)
    assert missing.status_code == wrong.status_code == 401
    assert cross_origin.status_code == delivery_on_retrieval.status_code == 421
    assert static_release.status_code == 200
    assert static_release.content == runtime.loaded.release_bytes
    all_errors = (
        missing.content + wrong.content + cross_origin.content + delivery_on_retrieval.content
    )
    assert fixture.authorization.encode() not in all_errors
    assert request.delivery_token_seed.encode() not in all_errors
    assert token_path.encode() not in all_errors


@pytest.mark.asyncio
async def test_reference_service_rejects_bad_http_boundaries_without_consuming_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    _runtime, _commitments, request, request_bytes = _request_for(fixture)
    app = create_app(fixture.config_path, clock=lambda: fixture.clock[0])
    endpoint = RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        query = await client.post(
            endpoint + "?prompt=secret",
            headers=_headers(fixture),
            content=request_bytes,
        )
        traversal = await client.get(
            RETRIEVAL_ORIGIN + "/%2e%2e/certified-release.json",
            headers=_headers(fixture),
        )
        compressed = await client.post(
            endpoint,
            headers={**_headers(fixture), "Content-Encoding": "gzip"},
            content=request_bytes,
        )
        declared_large = await client.post(
            endpoint,
            headers={
                **_headers(fixture),
                "Content-Length": str(fixture.policy.limits.maximum_request_body_bytes + 1),
            },
            content=request_bytes,
        )
        noncanonical = await client.post(
            endpoint,
            headers=_headers(fixture),
            content=request_bytes + b"\n",
        )
        streamed_large = await client.post(
            endpoint,
            headers={
                "Authorization": fixture.authorization,
                "Content-Type": "application/json",
            },
            content=b"x" * (fixture.policy.limits.maximum_request_body_bytes + 1),
        )
        wrong_item = request.model_copy(
            update={
                "items": [
                    request.items[0].model_copy(update={"sha256": "00" * 32}),
                    *request.items[1:],
                ]
            }
        )
        wrong_binding = await client.post(
            endpoint,
            headers=_headers(fixture),
            content=canonical_json_bytes(wrong_item),
        )
        unknown_delivery = await client.get(
            DELIVERY_ORIGIN + "/v1/umi/deliveries/" + base64url_encode(b"unknown-delivery-token!!"),
        )
        with sqlite3.connect(fixture.config.state_database_path) as connection:
            assert connection.execute("SELECT COUNT(*) FROM clock_state").fetchone() == (0,)
        valid = await client.post(
            endpoint,
            headers=_headers(fixture),
            content=request_bytes,
        )
    assert query.status_code == 400
    assert traversal.status_code == 400
    assert compressed.status_code == 415
    assert declared_large.status_code == 413
    assert streamed_large.status_code == 413
    assert noncanonical.status_code == wrong_binding.status_code == 400
    assert unknown_delivery.status_code == 404
    assert valid.status_code == 200
    with sqlite3.connect(fixture.config.state_database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM requests").fetchone() == (1,)


@pytest.mark.asyncio
async def test_one_exact_request_per_validator_is_idempotent_and_conflict_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    _runtime, commitments, request, request_bytes = _request_for(fixture)
    app = create_app(fixture.config_path, clock=lambda: fixture.clock[0])
    hotkeys = sorted(fixture.tokens, key=account_id32)
    changed = request.model_copy(update={"delivery_token_seed": base64url_encode(b"t" * 32)})
    changed_bytes = canonical_json_bytes(changed)
    second_validator = build_delivery_request(
        load_mirror_service(fixture.config_path).loaded.release.window.to_plan(),
        commitments,
        delivery_token_seed=base64url_encode(b"u" * 32),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        first = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture, hotkey=hotkeys[0]),
            content=request_bytes,
        )
        replay = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture, hotkey=hotkeys[0]),
            content=request_bytes,
        )
        conflict = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture, hotkey=hotkeys[0]),
            content=changed_bytes,
        )
        independent = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture, hotkey=hotkeys[1]),
            content=canonical_json_bytes(second_validator),
        )
    assert first.status_code == replay.status_code == independent.status_code == 200
    assert replay.content == first.content
    assert conflict.status_code == 409
    assert changed.delivery_token_seed.encode() not in conflict.content
    with sqlite3.connect(fixture.config.state_database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM requests").fetchone() == (2,)
        assert connection.execute("SELECT COUNT(*) FROM deliveries").fetchone() == (
            2 * len(commitments),
        )


@pytest.mark.asyncio
async def test_two_service_instances_serialize_one_durable_mapping_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    _runtime, commitments, _request, request_bytes = _request_for(fixture)
    runtimes = [
        load_mirror_service(fixture.config_path, clock=lambda: fixture.clock[0]) for _ in range(2)
    ]
    hotkey = sorted(fixture.tokens, key=account_id32)[0]
    first, second = await asyncio.gather(
        *(
            asyncio.to_thread(runtime.issue, request_bytes, validator_hotkey=hotkey)
            for runtime in runtimes
        )
    )
    assert first == second
    with sqlite3.connect(fixture.config.state_database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM requests").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM deliveries").fetchone() == (
            len(commitments),
        )


@pytest.mark.asyncio
async def test_delivery_expiry_clock_rollback_and_state_tamper_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    _runtime, _commitments, _request, request_bytes = _request_for(fixture)
    app = create_app(fixture.config_path, clock=lambda: fixture.clock[0])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        issued = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture),
            content=request_bytes,
        )
        delivery = VideoDeliveryIssuanceResponse.model_validate_json(issued.content).deliveries[0]
        fixture.clock[0] = delivery.expires_at_unix_ms - 1
        before = await client.get(delivery.url)
        fixture.clock[0] = delivery.expires_at_unix_ms
        expired = await client.get(delivery.url)
        fixture.clock[0] -= 1
        rollback = await client.get(delivery.url)
    assert before.status_code == 200
    assert expired.status_code == 410
    assert rollback.status_code == 503
    assert json.loads(rollback.content)["reason_code"] == "mirror_clock_rollback"

    with sqlite3.connect(fixture.config.state_database_path) as connection:
        connection.execute("UPDATE deliveries SET object_sha256 = ?", ("00" * 32,))
    fixture.clock[0] = delivery.expires_at_unix_ms
    tampered_app = create_app
    with pytest.raises(Exception, match="mirror_delivery_state"):
        tampered_app(fixture.config_path, clock=lambda: fixture.clock[0])


@pytest.mark.asyncio
async def test_deleted_clock_high_water_cannot_reset_an_issued_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    _runtime, _commitments, _request, request_bytes = _request_for(fixture)
    app = create_app(fixture.config_path, clock=lambda: fixture.clock[0])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        issued = await client.post(
            RETRIEVAL_ORIGIN + DEFAULT_DELIVERY_ISSUANCE_PATH,
            headers=_headers(fixture),
            content=request_bytes,
        )
        delivery = VideoDeliveryIssuanceResponse.model_validate_json(issued.content).deliveries[0]
        with sqlite3.connect(fixture.config.state_database_path) as connection:
            connection.execute("DELETE FROM clock_state")
        reset = await client.get(delivery.url)
    assert reset.status_code == 503
    assert json.loads(reset.content)["reason_code"] == "mirror_clock_state_tampered"


def test_check_is_no_network_no_write_and_reports_no_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    state_path = Path(fixture.config.state_database_path)
    assert not state_path.exists()
    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    assert main(["--config", str(fixture.config_path), "--check"]) == 0
    after = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    assert after == before
    assert not state_path.exists()
    output = capsys.readouterr().out
    assert '"status":"ready"' in output
    assert fixture.authorization not in output
    assert all(token not in output for token in fixture.tokens.values())


@pytest.mark.asyncio
async def test_runtime_detects_config_and_certified_tree_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    runtime, _commitments, request, _request_bytes = _request_for(fixture)
    app = create_app(fixture.config_path, clock=lambda: fixture.clock[0])
    video = next(iter(runtime.loaded.videos.values()))
    video.path.write_bytes(b"z" * video.size_bytes)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        changed = await client.get(
            RETRIEVAL_ORIGIN + DEFAULT_MIRROR_INDEX_PATH.format(window_id=request.window_id),
            headers=_headers(fixture),
        )
    assert changed.status_code == 503
    assert json.loads(changed.content)["reason_code"] == "mirror_certified_tree_changed"
    assert str(video.path).encode() not in changed.content


def test_example_config_is_canonical_and_cli_disables_sensitive_access_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    example = Path("docs/examples/mirror-service-config.json").read_bytes()
    parsed = MirrorServiceConfig.model_validate_json(example)
    assert canonical_json_bytes(parsed) + b"\n" == example

    fixture = _service_fixture(tmp_path, monkeypatch)
    observed: dict[str, object] = {}

    def fake_run(*args, **kwargs) -> None:
        observed.update(kwargs)

    monkeypatch.setattr("umi.mirror_service.uvicorn.run", fake_run)
    assert main(["--config", str(fixture.config_path)]) == 0
    assert observed["access_log"] is False
    assert observed["proxy_headers"] is False
    assert "ssl_certfile" not in observed
