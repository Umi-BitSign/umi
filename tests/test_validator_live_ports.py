from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from umi.crypto import SealedResponse
from umi.drand import DrandPulse, QuicknetClient
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import PROTOCOL_VERSION, base64url_encode, canonical_json_bytes
from umi.validator_delivery import (
    DELIVERY_ISSUANCE_RESPONSE_SCHEMA,
    IssuedVideoDelivery,
    VideoDeliveryCommitment,
    VideoDeliveryIssuanceEvidence,
    VideoDeliveryIssuanceRequest,
    VideoDeliveryIssuanceResponse,
    derive_delivery_token,
    validate_delivery_issuance,
)
from umi.validator_live_ports import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    MIRROR_DISCOVERY_SCHEMA,
    MIRROR_WINDOW_INDEX_SCHEMA,
    REVEAL_RELEASE_BOUNDARY_SCHEMA,
    AuthenticatedMirrorDeliveryIssuer,
    DurablePoolMirrorSource,
    FinalizedRevealAuditReleaseAdapter,
    MirrorBindingError,
    MirrorDiscoveryRule,
    MirrorLimitError,
    MirrorObjectDescriptor,
    MirrorRetrievalError,
    MirrorRetrievalEvidence,
    MirrorWindowIndex,
    ProofBackedRevealAuditReleaseBoundaryPort,
    QuicknetPortError,
    QuicknetRevealPulseAdapter,
    QuicknetSelectionPulseAdapter,
    RevealAuditReleaseBoundary,
    RevealAuditReleasePortError,
    TimelockRevealPortError,
    TLERevealDecryptAdapter,
    VerifiedRevealAuditReleaseBoundary,
    build_live_pool_effect_ports,
    build_live_reveal_effect_ports,
)
from umi.validator_plans import VerifiedFinalizedBlock
from umi.validator_pool_effect import DeliveryIssuanceContext, PoolSourceRequest
from umi.validator_state import StagePending, StageWorkItem, WindowPlan, WindowStage
from umi.validator_weight_build_effect import WeightCommitScheduleEvidence
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_drand import ROUND, SIGNATURE, info_record, pulse_record
from .test_shadow import _fixture as shadow_fixture
from .test_shadow import _schedule
from .test_validator_closing_snapshot import FINALITY_VERIFIER, _live_policy
from .test_validator_pool_effect import _Fixture as PoolFixture
from .test_validator_weight_build_effect import _fixture as weight_fixture

ORIGIN = "https://mirror.example"
PUBLIC_ADDRESS = "93.184.216.34"
DELIVERY_TOKEN = base64url_encode(b"\xaa" * 24)


class _RawAsyncStream(httpx.AsyncByteStream):
    def __init__(self, data: bytes) -> None:
        self.data = data

    async def __aiter__(self):
        yield self.data


def _raw_response(
    data: bytes,
    *,
    media_type: str = "application/json",
) -> httpx.Response:
    return httpx.Response(
        200,
        headers={
            "Content-Length": str(len(data)),
            "Content-Type": media_type,
        },
        stream=_RawAsyncStream(data),
    )


async def _public_resolver(_hostname: str, _port: int) -> tuple[str, ...]:
    return (PUBLIC_ADDRESS,)


def _per_origin_headers(origins: list[str]) -> dict[str, dict[str, str]]:
    return {
        origin: {
            "Authorization": (
                "Bearer test-token"
                if len(origins) == 1
                else f"Bearer independent-test-token-{index}"
            )
        }
        for index, origin in enumerate(origins)
    }


def _mirror_policy_and_work(
    tmp_path: Path,
    *,
    origins: list[str] | None = None,
):
    fixture = PoolFixture(tmp_path / "pool-fixture")
    profile = fixture.policy.implementation_pins.rules.mirror_authentication_profile
    discovery = MirrorDiscoveryRule(
        schema=MIRROR_DISCOVERY_SCHEMA,
        protocol=PROTOCOL_VERSION,
        authentication_profile=profile,
        index_path_template=DEFAULT_MIRROR_INDEX_PATH,
        delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
        origins=origins or [ORIGIN],
        delivery_origins=["https://delivery.example"],
    )
    discovery_bytes = canonical_json_bytes(discovery)
    policy_data = fixture.policy.model_dump(mode="json", by_alias=True)
    policy_data["implementation_pins"]["rules"]["mirror_discovery_rule_sha256"] = hashlib.sha256(
        discovery_bytes
    ).hexdigest()
    policy = ScoringPolicy.model_validate(policy_data)
    _announcement_ms, schedule = _schedule(policy)
    plan = WindowPlan.from_schedule(schedule, scoring_policy_hash=scoring_policy_hash(policy))
    work = replace(
        fixture.work,
        window=replace(fixture.work.window, plan=plan),
    )
    return policy, discovery_bytes, work


def test_mirror_discovery_separates_private_retrieval_and_public_delivery_origins() -> None:
    with pytest.raises(ValueError, match="separate from mirror origins"):
        MirrorDiscoveryRule(
            schema=MIRROR_DISCOVERY_SCHEMA,
            protocol=PROTOCOL_VERSION,
            authentication_profile="umi-authenticated-content-mirror/1",
            index_path_template=DEFAULT_MIRROR_INDEX_PATH,
            delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
            origins=[ORIGIN],
            delivery_origins=[ORIGIN],
        )
    with pytest.raises(ValueError, match="separate hostnames"):
        MirrorDiscoveryRule(
            schema=MIRROR_DISCOVERY_SCHEMA,
            protocol=PROTOCOL_VERSION,
            authentication_profile="umi-authenticated-content-mirror/1",
            index_path_template=DEFAULT_MIRROR_INDEX_PATH,
            delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
            origins=["https://same-host.example"],
            delivery_origins=["https://same-host.example:8443"],
        )


def test_production_mirror_source_requires_verified_readiness(tmp_path: Path) -> None:
    policy, discovery_bytes, _work = _mirror_policy_and_work(tmp_path)
    with pytest.raises(MirrorBindingError, match="mirror_readiness_missing"):
        DurablePoolMirrorSource(
            policy=policy,
            discovery_rule_bytes=discovery_bytes,
            state_path=tmp_path / "missing-readiness.sqlite3",
            request_headers={"Authorization": "Bearer test-token"},
            require_mirror_readiness=True,
        )


def _mirror_index(policy: ScoringPolicy, work: StageWorkItem):
    publisher = policy.publisher_registry[0].publisher_hotkey
    batch_id = base64url_encode(b"\x01" * 16)
    challenge_id = base64url_encode(b"\x02" * 16)
    bodies = {
        "/objects/pool.json": (b'{"pool":"bytes"}', "application/json"),
        "/objects/public.json": (b'{"public":"bytes"}', "application/json"),
        "/objects/ground.tle": (b"portable-ground-truth", "application/octet-stream"),
        "/objects/video.mp4?token=short-lived": (b"video-bytes", "video/mp4"),
    }
    objects = [
        MirrorObjectDescriptor(
            kind="pool_manifest",
            publisher_hotkey=publisher,
            path="/objects/pool.json",
            sha256=hashlib.sha256(bodies["/objects/pool.json"][0]).hexdigest(),
            size_bytes=len(bodies["/objects/pool.json"][0]),
            media_type="application/json",
        ),
        MirrorObjectDescriptor(
            kind="public_manifest",
            batch_id=batch_id,
            path="/objects/public.json",
            sha256=hashlib.sha256(bodies["/objects/public.json"][0]).hexdigest(),
            size_bytes=len(bodies["/objects/public.json"][0]),
            media_type="application/json",
        ),
        MirrorObjectDescriptor(
            kind="ground_truth_envelope",
            batch_id=batch_id,
            path="/objects/ground.tle",
            sha256=hashlib.sha256(bodies["/objects/ground.tle"][0]).hexdigest(),
            size_bytes=len(bodies["/objects/ground.tle"][0]),
            media_type="application/octet-stream",
        ),
        MirrorObjectDescriptor(
            kind="video",
            batch_id=batch_id,
            challenge_id=challenge_id,
            path="/objects/video.mp4?token=short-lived",
            sha256=hashlib.sha256(bodies["/objects/video.mp4?token=short-lived"][0]).hexdigest(),
            size_bytes=len(bodies["/objects/video.mp4?token=short-lived"][0]),
            media_type="video/mp4",
        ),
    ]
    index = MirrorWindowIndex(
        schema=MIRROR_WINDOW_INDEX_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=work.window.plan.window_id,
        window_index=work.window.plan.window_index,
        scoring_policy_hash=scoring_policy_hash(policy),
        objects=objects,
    )
    return canonical_json_bytes(index), bodies


def _mirror_transport(index_bytes: bytes, bodies, calls: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        assert request.url.host == PUBLIC_ADDRESS
        assert request.headers["host"] == "mirror.example"
        assert request.headers["authorization"] == "Bearer test-token"
        assert request.headers["accept-encoding"] == "identity"
        path = request.url.raw_path.decode("ascii")
        if path.startswith("/v1/umi/windows/"):
            return _raw_response(index_bytes)
        body, media_type = bodies[path]
        return _raw_response(body, media_type=media_type)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_pool_mirror_streams_pins_and_replays_identically_after_restart(tmp_path) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    index_bytes, bodies = _mirror_index(policy, work)
    calls: list[str] = []
    state = tmp_path / "mirror.sqlite3"
    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state,
        request_headers=_per_origin_headers([ORIGIN]),
        transport=_mirror_transport(index_bytes, bodies, calls),
        resolver=_public_resolver,
    )

    first = await source(work)
    assert len(calls) == 5
    assert first.final_pool_manifest_bytes == (bodies["/objects/pool.json"][0],)
    assert first.batch_artifacts[0].public_manifest_bytes == bodies["/objects/public.json"][0]
    assert first.video_deliveries[0].url == (ORIGIN + "/objects/video.mp4?token=short-lived")

    def network_must_not_run(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("completed mirror package attempted network retrieval")

    restarted = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state,
        request_headers=_per_origin_headers([ORIGIN]),
        transport=httpx.MockTransport(network_must_not_run),
        resolver=_public_resolver,
    )
    second = await restarted(work)
    assert second == first
    assert second.artifact_retrieval_evidence_bytes == first.artifact_retrieval_evidence_bytes


@pytest.mark.asyncio
async def test_pool_mirror_serializes_independent_process_instances(tmp_path) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    index_bytes, bodies = _mirror_index(policy, work)
    state = tmp_path / "concurrent-mirror.sqlite3"
    entered = asyncio.Event()
    release = asyncio.Event()
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode("ascii")
        calls.append(path)
        entered.set()
        await release.wait()
        if path.startswith("/v1/umi/windows/"):
            return _raw_response(index_bytes)
        body, media_type = bodies[path]
        return _raw_response(body, media_type=media_type)

    sources = [
        DurablePoolMirrorSource(
            policy=policy,
            discovery_rule_bytes=discovery_bytes,
            state_path=state,
            request_headers={"Authorization": "Bearer test-token"},
            transport=httpx.MockTransport(handler),
            resolver=_public_resolver,
        )
        for _index in range(2)
    ]
    first = asyncio.create_task(sources[0](work))
    await entered.wait()
    second = asyncio.create_task(sources[1](work))
    await asyncio.sleep(0.1)
    assert len(calls) == 1
    release.set()

    first_result, second_result = await asyncio.gather(first, second)
    assert first_result == second_result
    assert len(calls) == 5
    evidence = MirrorRetrievalEvidence.model_validate_json(
        first_result.artifact_retrieval_evidence_bytes
    )
    assert all(item.status == "success" for item in evidence.attempts)
    assert len(evidence.attempts) == 5
    with sqlite3.connect(state) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM attempts WHERE status = 'success'"
        ).fetchone() == (5,)


@pytest.mark.asyncio
async def test_anchor_pool_mirror_serializes_independent_process_instances(tmp_path) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    state = tmp_path / "concurrent-anchor-mirror.sqlite3"
    invalid_manifest = b"{}"
    digest = hashlib.sha256(invalid_manifest).hexdigest()
    publisher = policy.publisher_registry[0].publisher_hotkey
    request = PoolSourceRequest(
        work=work,
        eligible_anchor_hashes=((publisher, digest),),
        timely_anchor_hashes=((publisher, digest),),
        active_validator_hotkeys=tuple(
            entry.validator_hotkey for entry in policy.validator_registry
        ),
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return _raw_response(invalid_manifest)

    sources = [
        DurablePoolMirrorSource(
            policy=policy,
            discovery_rule_bytes=discovery_bytes,
            state_path=state,
            request_headers={"Authorization": "Bearer test-token"},
            transport=httpx.MockTransport(handler),
            resolver=_public_resolver,
        )
        for _index in range(2)
    ]
    first = asyncio.create_task(sources[0](request))
    await entered.wait()
    second = asyncio.create_task(sources[1](request))
    await asyncio.sleep(0.1)
    assert calls == 1
    release.set()
    first_result, second_result = await asyncio.gather(first, second)
    assert first_result == second_result
    assert calls == 1


@pytest.mark.asyncio
async def test_pool_mirror_cancellation_after_reservation_skips_interrupted_origin(
    tmp_path,
) -> None:
    origins = ["https://mirror-a.example", "https://mirror-b.example"]
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path, origins=origins)
    index_bytes, bodies = _mirror_index(policy, work)
    state = tmp_path / "cancelled-mirror.sqlite3"
    entered = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode("ascii")
        if request.headers["host"] == "mirror-a.example" and path.startswith("/v1/umi/windows/"):
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("cancelled mirror request resumed unexpectedly")
        if path.startswith("/v1/umi/windows/"):
            return _raw_response(index_bytes)
        body, media_type = bodies[path]
        return _raw_response(body, media_type=media_type)

    first_source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state,
        request_headers=_per_origin_headers(origins),
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    first = asyncio.create_task(first_source(work))
    await entered.wait()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    restarted = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state,
        request_headers=_per_origin_headers(origins),
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    result = await restarted(work)
    evidence = MirrorRetrievalEvidence.model_validate_json(result.artifact_retrieval_evidence_bytes)
    index_attempts = [
        item
        for item in evidence.attempts
        if item.resource_key_sha256 == hashlib.sha256(b"index").hexdigest()
    ]
    assert [item.status for item in index_attempts] == [
        "pending_after_restart",
        "success",
    ]


@pytest.mark.asyncio
async def test_pool_mirror_rejects_private_dns_before_http(tmp_path) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    index_bytes, bodies = _mirror_index(policy, work)
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    async def private_resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        return ("127.0.0.1",)

    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "private-dns.sqlite3",
        request_headers=_per_origin_headers([ORIGIN]),
        transport=httpx.MockTransport(handler),
        resolver=private_resolver,
    )
    del index_bytes, bodies
    with pytest.raises(MirrorRetrievalError, match="mirror_dns_non_public"):
        await source(work)
    assert called is False


@pytest.mark.asyncio
async def test_pool_mirror_rejects_stream_size_and_noncanonical_index(tmp_path) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    oversized = b"x" * (policy.limits.maximum_manifest_bytes + 1)

    def oversized_handler(_request: httpx.Request) -> httpx.Response:
        return _raw_response(oversized)

    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "oversized.sqlite3",
        request_headers=_per_origin_headers([ORIGIN]),
        transport=httpx.MockTransport(oversized_handler),
        resolver=_public_resolver,
    )
    with pytest.raises(MirrorLimitError, match="mirror_declared_body_size_limit"):
        await source(work)

    index_bytes, _bodies = _mirror_index(policy, work)

    def noncanonical_handler(_request: httpx.Request) -> httpx.Response:
        return _raw_response(index_bytes + b"\n")

    noncanonical = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "noncanonical.sqlite3",
        request_headers=_per_origin_headers([ORIGIN]),
        transport=httpx.MockTransport(noncanonical_handler),
        resolver=_public_resolver,
    )
    with pytest.raises(MirrorBindingError, match="mirror_index_not_canonical"):
        await noncanonical(work)


@pytest.mark.asyncio
async def test_pool_mirror_counts_and_hashes_a_full_invalid_first_origin_body(tmp_path) -> None:
    origins = ["https://mirror-a.example", "https://mirror-b.example"]
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path, origins=origins)
    index_bytes, bodies = _mirror_index(policy, work)
    invalid_pool = b"x" * len(bodies["/objects/pool.json"][0])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("pool-source.json"):
            return _raw_response(index_bytes)
        key = request.url.raw_path.decode()
        body, media_type = bodies[key]
        if key == "/objects/pool.json" and request.headers["host"] == "mirror-a.example":
            body = invalid_pool
        return _raw_response(body, media_type=media_type)

    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "wrong-body-retry.sqlite3",
        request_headers=_per_origin_headers(origins),
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    package = await source(work)
    evidence = MirrorRetrievalEvidence.model_validate_json(
        package.artifact_retrieval_evidence_bytes
    )
    failed = [item for item in evidence.attempts if item.status == "failed"]
    assert len(failed) == 1
    assert failed[0].error_code == "mirror_body_digest_mismatch"
    assert failed[0].response_body_sha256 == hashlib.sha256(invalid_pool).hexdigest()
    assert failed[0].response_body_size_bytes == len(invalid_pool)
    assert failed[0].observed_wire_bytes >= len(invalid_pool)
    assert evidence.observed_window_wire_bytes == sum(
        item.observed_wire_bytes for item in evidence.attempts
    )


@pytest.mark.asyncio
async def test_pool_mirror_startup_detects_blob_tampering_and_symlink(tmp_path) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    index_bytes, bodies = _mirror_index(policy, work)
    state = tmp_path / "tamper.sqlite3"
    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state,
        request_headers=_per_origin_headers([ORIGIN]),
        transport=_mirror_transport(index_bytes, bodies, []),
        resolver=_public_resolver,
    )
    await source(work)
    with sqlite3.connect(state) as connection:
        digest, size = connection.execute(
            "SELECT sha256, size_bytes FROM objects WHERE media_type = 'video/mp4'"
        ).fetchone()
        connection.execute("UPDATE objects SET data = ? WHERE sha256 = ?", (b"x" * size, digest))
    with pytest.raises(MirrorBindingError, match="mirror_cached_object_tampered"):
        DurablePoolMirrorSource(
            policy=policy,
            discovery_rule_bytes=discovery_bytes,
            state_path=state,
            request_headers={"Authorization": "Bearer test-token"},
            resolver=_public_resolver,
        )

    target = tmp_path / "real.sqlite3"
    target.touch()
    symlink = tmp_path / "linked.sqlite3"
    symlink.symlink_to(target)
    with pytest.raises(MirrorRetrievalError, match="mirror_database_path_unsafe"):
        DurablePoolMirrorSource(
            policy=policy,
            discovery_rule_bytes=discovery_bytes,
            state_path=symlink,
            request_headers={"Authorization": "Bearer test-token"},
            resolver=_public_resolver,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("restart", [False, True])
async def test_pool_mirror_reconciles_frozen_package_with_attempt_rows(
    tmp_path,
    restart: bool,
) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    index_bytes, bodies = _mirror_index(policy, work)
    state = tmp_path / f"package-attempt-tamper-{restart}.sqlite3"
    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state,
        request_headers={"Authorization": "Bearer test-token"},
        transport=_mirror_transport(index_bytes, bodies, []),
        resolver=_public_resolver,
    )
    await source(work)
    with sqlite3.connect(state) as connection:
        connection.execute(
            "UPDATE attempts SET url_sha256 = ? WHERE resource_key = 'index'",
            ("00" * 32,),
        )

    if restart:
        with pytest.raises(
            MirrorBindingError,
            match="mirror_completed_attempt_evidence_changed",
        ):
            DurablePoolMirrorSource(
                policy=policy,
                discovery_rule_bytes=discovery_bytes,
                state_path=state,
                request_headers={"Authorization": "Bearer test-token"},
                resolver=_public_resolver,
            )
    else:
        with pytest.raises(
            MirrorBindingError,
            match="mirror_completed_attempt_evidence_changed",
        ):
            await source(work)


def _delivery_context(policy: ScoringPolicy, work: StageWorkItem):
    _index_bytes, bodies = _mirror_index(policy, work)
    batch_id = base64url_encode(b"\x01" * 16)
    challenge_id = base64url_encode(b"\x02" * 16)
    video = bodies["/objects/video.mp4?token=short-lived"][0]
    commitment = VideoDeliveryCommitment(
        batch_id=batch_id,
        challenge_id=challenge_id,
        sha256=hashlib.sha256(video).hexdigest(),
        size_bytes=len(video),
    )
    return (
        DeliveryIssuanceContext(
            window=work.window.plan,
            selected_video_commitments=(commitment,),
        ),
        commitment,
    )


def _delivery_response(
    request: VideoDeliveryIssuanceRequest,
    commitment: VideoDeliveryCommitment,
    *,
    delivery_updates: dict | None = None,
) -> bytes:
    close_ms = QUICKNET_GENESIS_MS + (request.response_close_round - 1) * QUICKNET_PERIOD_MS
    delivery = IssuedVideoDelivery(
        batch_id=commitment.batch_id,
        challenge_id=commitment.challenge_id,
        sha256=commitment.sha256,
        size_bytes=commitment.size_bytes,
        url=(
            "https://delivery.example/v1/umi/deliveries/"
            + derive_delivery_token(request, commitment)
        ),
        expires_at_unix_ms=close_ms,
    )
    if delivery_updates:
        delivery = delivery.model_copy(update=delivery_updates)
    return canonical_json_bytes(
        VideoDeliveryIssuanceResponse(
            schema=DELIVERY_ISSUANCE_RESPONSE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=request.window_id,
            window_index=request.window_index,
            scoring_policy_hash=request.scoring_policy_hash,
            response_close_round=request.response_close_round,
            deliveries=[delivery],
        )
    )


@pytest.mark.asyncio
async def test_post_selection_delivery_uses_authenticated_canonical_exchange_without_source_url(
    tmp_path,
) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    context, commitment = _delivery_context(policy, work)
    requests: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.host == PUBLIC_ADDRESS
        assert request.headers["host"] == "mirror.example"
        assert request.headers["authorization"] == "Bearer test-token"
        assert request.headers["accept-encoding"] == "identity"
        request_bytes = request.content
        requests.append(request_bytes)
        parsed = VideoDeliveryIssuanceRequest.model_validate_json(request_bytes)
        assert canonical_json_bytes(parsed) == request_bytes
        return _raw_response(_delivery_response(parsed, commitment))

    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "delivery.sqlite3",
        request_headers={"Authorization": "Bearer test-token"},
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    result = await AuthenticatedMirrorDeliveryIssuer(policy, source)(context, work)

    assert len(requests) == 1
    assert b"/objects/video.mp4" not in requests[0]
    assert b"token=short-lived" not in requests[0]
    assert result.deliveries[0].url == (
        "https://delivery.example/v1/umi/deliveries/"
        + derive_delivery_token(
            VideoDeliveryIssuanceRequest.model_validate_json(result.request_bytes),
            commitment,
        )
    )
    assert "token=" not in result.deliveries[0].url
    validate_delivery_issuance(
        policy=policy,
        window=work.window.plan,
        expected_commitments=context.selected_video_commitments,
        result=result,
        private_source_urls=(ORIGIN + "/objects/video.mp4?token=short-lived",),
    )


@pytest.mark.parametrize(
    "delivery_updates",
    [
        {"batch_id": base64url_encode(b"\x03" * 16)},
        {"challenge_id": base64url_encode(b"\x04" * 16)},
        {"sha256": "00" * 32},
        {"size_bytes": 999},
        {"url": "https://untrusted.example/video"},
        {"url": "https://user@delivery.example/video"},
        {"url": "https://delivery.example/video#fragment"},
        {"url": "https://delivery.example/video?answer=leak"},
        {"url": "https://delivery.example/prompt/the-answer-is-foo.mp4"},
        {"url": ("https://delivery.example/v1/umi/deliveries/dGhlIGFuc3dlciBpcyBoZWxsbyEhISEh")},
        {"url": (f"https://delivery.example/v1/umi/deliveries/{DELIVERY_TOKEN}/extra")},
        {"url": ("https://delivery.example/v1/umi/deliveries/%2fetc%2fpasswd")},
        {"url": "https://delivery.example/v1/umi/deliveries/short"},
        {"expires_at_unix_ms": 1},
        {"expires_at_unix_ms": 9_000_000_000_000_000},
    ],
    ids=[
        "batch",
        "challenge",
        "hash",
        "size",
        "origin",
        "credentials",
        "fragment",
        "answer-query",
        "answer-path",
        "canonical-answer-token",
        "extra-segment",
        "encoded-separator",
        "short-token",
        "early-expiry",
        "late-expiry",
    ],
)
@pytest.mark.asyncio
async def test_post_selection_delivery_rejects_unbound_or_unsafe_result(
    tmp_path,
    delivery_updates,
) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    context, commitment = _delivery_context(policy, work)

    def handler(request: httpx.Request) -> httpx.Response:
        parsed = VideoDeliveryIssuanceRequest.model_validate_json(request.content)
        return _raw_response(
            _delivery_response(
                parsed,
                commitment,
                delivery_updates=delivery_updates,
            )
        )

    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "invalid-delivery.sqlite3",
        request_headers={"Authorization": "Bearer test-token"},
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    with pytest.raises(MirrorBindingError, match="delivery_issuance_response_invalid"):
        await AuthenticatedMirrorDeliveryIssuer(policy, source)(context, work)


@pytest.mark.asyncio
async def test_post_selection_delivery_rejects_noncanonical_response_and_tampered_evidence(
    tmp_path,
) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    context, commitment = _delivery_context(policy, work)

    def noncanonical_handler(request: httpx.Request) -> httpx.Response:
        parsed = VideoDeliveryIssuanceRequest.model_validate_json(request.content)
        return _raw_response(_delivery_response(parsed, commitment) + b"\n")

    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "noncanonical-delivery.sqlite3",
        request_headers={"Authorization": "Bearer test-token"},
        transport=httpx.MockTransport(noncanonical_handler),
        resolver=_public_resolver,
    )
    with pytest.raises(MirrorBindingError, match="delivery_issuance_response_invalid"):
        await AuthenticatedMirrorDeliveryIssuer(policy, source)(context, work)

    def valid_handler(request: httpx.Request) -> httpx.Response:
        parsed = VideoDeliveryIssuanceRequest.model_validate_json(request.content)
        return _raw_response(_delivery_response(parsed, commitment))

    valid_source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "tampered-delivery.sqlite3",
        request_headers={"Authorization": "Bearer test-token"},
        transport=httpx.MockTransport(valid_handler),
        resolver=_public_resolver,
    )
    result = await AuthenticatedMirrorDeliveryIssuer(policy, valid_source)(context, work)
    evidence = VideoDeliveryIssuanceEvidence.model_validate_json(result.evidence_bytes)
    tampered = replace(
        result,
        evidence_bytes=canonical_json_bytes(
            evidence.model_copy(update={"response_sha256": "00" * 32})
        ),
    )
    with pytest.raises(ValueError, match=r"evidence (?:is invalid|does not reproduce)"):
        validate_delivery_issuance(
            policy=policy,
            window=work.window.plan,
            expected_commitments=context.selected_video_commitments,
            result=tampered,
        )


@pytest.mark.asyncio
async def test_post_selection_delivery_retries_invalid_first_origin_without_caching_it(
    tmp_path,
) -> None:
    origins = ["https://mirror-a.example", "https://mirror-b.example"]
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path, origins=origins)
    context, commitment = _delivery_context(policy, work)
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.headers["host"], request.headers["authorization"]))
        parsed = VideoDeliveryIssuanceRequest.model_validate_json(request.content)
        if len(calls) == 1:
            return _raw_response(
                _delivery_response(
                    parsed,
                    commitment,
                    delivery_updates={"sha256": "00" * 32},
                )
            )
        return _raw_response(_delivery_response(parsed, commitment))

    state_path = tmp_path / "retry-invalid-delivery.sqlite3"
    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state_path,
        request_headers=_per_origin_headers(origins),
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    result = await AuthenticatedMirrorDeliveryIssuer(policy, source)(context, work)
    evidence = VideoDeliveryIssuanceEvidence.model_validate_json(result.evidence_bytes)
    assert calls == [
        ("mirror-a.example", "Bearer independent-test-token-0"),
        ("mirror-b.example", "Bearer independent-test-token-1"),
    ]
    assert [item.status for item in evidence.attempts] == ["failed", "success"]
    assert evidence.attempts[0].error_code == "delivery_issuance_response_invalid"
    assert evidence.attempts[0].response_body_sha256 is not None
    assert evidence.delivery_observed_wire_bytes == sum(
        item.observed_wire_bytes for item in evidence.attempts
    )
    assert evidence.delivery_accounted_wire_bytes == sum(
        item.accounted_wire_bytes for item in evidence.attempts
    )

    def unexpected_network(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("a validated durable delivery result must be reused")

    restarted = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state_path,
        request_headers=_per_origin_headers(origins),
        transport=httpx.MockTransport(unexpected_network),
        resolver=_public_resolver,
    )
    recovered = await AuthenticatedMirrorDeliveryIssuer(policy, restarted)(context, work)
    assert recovered == result


@pytest.mark.asyncio
async def test_post_selection_delivery_resumes_after_a_reserved_attempt_crash(tmp_path) -> None:
    origins = ["https://mirror-a.example", "https://mirror-b.example"]
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path, origins=origins)
    context, commitment = _delivery_context(policy, work)
    state_path = tmp_path / "reserved-delivery-crash.sqlite3"
    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state_path,
        request_headers=_per_origin_headers(origins),
        resolver=_public_resolver,
    )
    request, request_bytes = source._load_or_create_delivery_request(work, context)
    resource_key = f"delivery-issuance:{hashlib.sha256(request_bytes).hexdigest()}"
    reservation = (
        len(request_bytes)
        + policy.limits.maximum_manifest_bytes
        + 2 * policy.limits.maximum_http_header_bytes
        + 8_192
        + 64
    )
    assert (
        source._reserve_attempt(
            work,
            resource_key,
            origins[0] + DEFAULT_DELIVERY_ISSUANCE_PATH,
            reservation,
        )
        == 0
    )

    calls: list[str] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        calls.append(http_request.headers["host"])
        parsed = VideoDeliveryIssuanceRequest.model_validate_json(http_request.content)
        return _raw_response(_delivery_response(parsed, commitment))

    restarted = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state_path,
        request_headers=_per_origin_headers(origins),
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    result = await AuthenticatedMirrorDeliveryIssuer(policy, restarted)(context, work)
    evidence = VideoDeliveryIssuanceEvidence.model_validate_json(result.evidence_bytes)
    assert request == VideoDeliveryIssuanceRequest.model_validate_json(result.request_bytes)
    assert calls == ["mirror-b.example"]
    assert [item.status for item in evidence.attempts] == [
        "pending_after_restart",
        "success",
    ]
    validate_delivery_issuance(
        policy=policy,
        window=work.window.plan,
        expected_commitments=context.selected_video_commitments,
        result=result,
    )


@pytest.mark.asyncio
async def test_post_selection_delivery_serializes_independent_process_instances(tmp_path) -> None:
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path)
    context, commitment = _delivery_context(policy, work)
    state_path = tmp_path / "concurrent-delivery.sqlite3"
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        parsed = VideoDeliveryIssuanceRequest.model_validate_json(request.content)
        return _raw_response(_delivery_response(parsed, commitment))

    sources = [
        DurablePoolMirrorSource(
            policy=policy,
            discovery_rule_bytes=discovery_bytes,
            state_path=state_path,
            request_headers={"Authorization": "Bearer test-token"},
            transport=httpx.MockTransport(handler),
            resolver=_public_resolver,
        )
        for _index in range(2)
    ]
    first = asyncio.create_task(
        AuthenticatedMirrorDeliveryIssuer(policy, sources[0])(context, work)
    )
    await entered.wait()
    second = asyncio.create_task(
        AuthenticatedMirrorDeliveryIssuer(policy, sources[1])(context, work)
    )
    await asyncio.sleep(0.1)
    assert calls == 1
    release.set()
    first_result, second_result = await asyncio.gather(first, second)
    assert first_result == second_result
    assert calls == 1


@pytest.mark.asyncio
async def test_post_selection_delivery_cancellation_releases_lease_after_durable_reservation(
    tmp_path,
) -> None:
    origins = ["https://mirror-a.example", "https://mirror-b.example"]
    policy, discovery_bytes, work = _mirror_policy_and_work(tmp_path, origins=origins)
    context, commitment = _delivery_context(policy, work)
    state_path = tmp_path / "cancelled-delivery.sqlite3"
    entered = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "mirror-a.example":
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("cancelled request resumed unexpectedly")
        parsed = VideoDeliveryIssuanceRequest.model_validate_json(request.content)
        return _raw_response(_delivery_response(parsed, commitment))

    first_source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state_path,
        request_headers=_per_origin_headers(origins),
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    first = asyncio.create_task(
        AuthenticatedMirrorDeliveryIssuer(policy, first_source)(context, work)
    )
    await entered.wait()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    restarted = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=state_path,
        request_headers=_per_origin_headers(origins),
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    result = await AuthenticatedMirrorDeliveryIssuer(policy, restarted)(context, work)
    evidence = VideoDeliveryIssuanceEvidence.model_validate_json(result.evidence_bytes)
    assert [item.status for item in evidence.attempts] == [
        "pending_after_restart",
        "success",
    ]


def _quicknet_transport(*, tampered: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/info"):
            return _raw_response(canonical_json_bytes(info_record()))
        pulse = pulse_record()
        if tampered:
            pulse["randomness"] = "00" * 32
        return _raw_response(canonical_json_bytes(pulse))

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_quicknet_stage_adapters_verify_round_timing_and_tamper(tmp_path) -> None:
    fixture = PoolFixture(tmp_path)
    selection = QuicknetSelectionPulseAdapter(
        fixture.policy,
        QuicknetClient(transport=_quicknet_transport()),
    )
    selection_bytes = await selection(fixture.work)
    assert (
        DrandPulse.from_json(__import__("json").loads(selection_bytes), expected_round=ROUND).round
        == ROUND
    )

    reveal_plan = replace(
        fixture.work.window.plan,
        selection_round=ROUND - 3,
        issue_close_round=ROUND - 2,
        response_close_round=ROUND - 1,
        reveal_round=ROUND,
    )
    reveal_work = replace(
        fixture.work,
        window=replace(
            fixture.work.window,
            plan=reveal_plan,
            stage=WindowStage.REVEAL_AND_SCORE,
        ),
    )
    reveal = QuicknetRevealPulseAdapter(
        fixture.policy,
        QuicknetClient(transport=_quicknet_transport()),
    )
    assert await reveal(reveal_work) == selection_bytes

    unpublished_plan = replace(
        reveal_plan,
        selection_round=10**12 - 3,
        issue_close_round=10**12 - 2,
        response_close_round=10**12 - 1,
        reveal_round=10**12,
    )
    unpublished_work = replace(
        reveal_work,
        window=replace(reveal_work.window, plan=unpublished_plan),
    )
    with pytest.raises(StagePending, match="quicknet_reveal_pulse_pending"):
        await reveal(unpublished_work)

    tampered = QuicknetSelectionPulseAdapter(
        fixture.policy,
        QuicknetClient(transport=_quicknet_transport(tampered=True)),
    )
    with pytest.raises(QuicknetPortError, match="quicknet_selection_verification_failed"):
        await tampered(fixture.work)


@pytest.mark.asyncio
async def test_tle_decrypt_requires_exact_verified_reveal_pulse(monkeypatch) -> None:
    policy = shadow_fixture()[0].policy
    plaintext = b"opened response"
    calls = []

    def open_exact(sealed, **kwargs):
        calls.append((sealed, kwargs))
        return plaintext

    monkeypatch.setattr("umi.validator_live_ports.decrypt_response", open_exact)
    portable = b"opaque-portable-test-envelope"
    sealed = SealedResponse(
        portable_bytes=portable,
        portable_b64=base64url_encode(portable),
        reveal_round=ROUND,
        sha256_hex=hashlib.sha256(portable).hexdigest(),
    )
    pulse = DrandPulse.from_json(pulse_record(), expected_round=ROUND)
    adapter = TLERevealDecryptAdapter(policy)
    assert await adapter(sealed, pulse) == plaintext
    assert calls[0][1] == {
        "reveal_round": ROUND,
        "sha256_hex": sealed.sha256_hex,
        "wait": False,
        "timeout": None,
    }

    later = SealedResponse(
        portable_bytes=portable,
        portable_b64=base64url_encode(portable),
        reveal_round=ROUND + 1,
        sha256_hex=hashlib.sha256(portable).hexdigest(),
    )
    with pytest.raises(TimelockRevealPortError, match="timelock_reveal_round_mismatch"):
        await adapter(later, pulse)

    invalid = DrandPulse(round=ROUND, randomness="00" * 32, signature=SIGNATURE)
    with pytest.raises(TimelockRevealPortError, match="timelock_reveal_pulse_invalid"):
        await adapter(sealed, invalid)


class _BoundaryPort:
    def __init__(self, value: VerifiedRevealAuditReleaseBoundary) -> None:
        self.value = value

    async def __call__(self, _work, _reason):
        return self.value


class _FinalityHarness:
    def __init__(self, policy: ScoringPolicy, block: VerifiedFinalizedBlock) -> None:
        self.chain_observation = policy.implementation_pins.live_chain
        self.finality_verifier_sha256 = FINALITY_VERIFIER
        self.block = block
        self.head = block.height

    async def finalized_head_height(self) -> int:
        return self.head

    async def verified_block_at(self, height: int):
        return self.block if height == self.block.height else None


def _reveal_release_fixture():
    policy = _live_policy()
    _announcement_ms, schedule = _schedule(policy)
    plan = WindowPlan.from_schedule(schedule, scoring_policy_hash=scoring_policy_hash(policy))
    pool_fixture = shadow_fixture()[0]
    # Reuse only the strict work/control-plane model; all identities come from
    # the live policy and its newly derived window.
    from tests.test_validator_pool_effect import _work as pool_work

    work = pool_work(plan)
    work = replace(work, window=replace(work.window, stage=WindowStage.REVEAL_AND_SCORE))
    release_height = plan.closing_block + 100
    reveal_time = QUICKNET_GENESIS_MS + (plan.reveal_round - 1) * QUICKNET_PERIOD_MS
    finality_evidence = b"verified-finality-attestation"
    block = VerifiedFinalizedBlock(
        height=release_height,
        block_hash="0x" + "77" * 32,
        state_root="0x" + "88" * 32,
        timestamp_ms=reveal_time + 1,
        scoring_policy_hash=scoring_policy_hash(policy),
        chain_observation=policy.implementation_pins.live_chain,
        finality_verifier_sha256=FINALITY_VERIFIER,
        finality_evidence=finality_evidence,
        finality_evidence_sha256=hashlib.sha256(finality_evidence).hexdigest(),
    )
    boundary_evidence = b"proof-derived-weight-commit-close-boundary"
    boundary = VerifiedRevealAuditReleaseBoundary(
        fact=RevealAuditReleaseBoundary(
            schema=REVEAL_RELEASE_BOUNDARY_SCHEMA,
            window_id=plan.window_id,
            scoring_policy_hash=scoring_policy_hash(policy),
            reason_code="canary_hit",
            audit_release_block=release_height,
            derivation_profile="umi-weight-commit-close-boundary/1",
            derivation_evidence_sha256=hashlib.sha256(boundary_evidence).hexdigest(),
        ),
        evidence_bytes=boundary_evidence,
    )
    del pool_fixture
    return policy, work, block, boundary


@pytest.mark.asyncio
async def test_finalized_reveal_audit_release_waits_and_retains_exact_proofs() -> None:
    policy, work, block, boundary = _reveal_release_fixture()
    finality = _FinalityHarness(policy, block)
    adapter = FinalizedRevealAuditReleaseAdapter(
        policy,
        finality,
        _BoundaryPort(boundary),
    )
    verified = await adapter(work, "canary_hit")
    assert verified.fact.audit_release_block == block.height
    assert boundary.evidence_bytes in verified.evidence_bytes
    assert block.finality_evidence in verified.evidence_bytes

    finality.head = block.height - 1
    with pytest.raises(StagePending, match="reveal_audit_release_finality_pending"):
        await adapter(work, "canary_hit")


@pytest.mark.asyncio
async def test_finalized_reveal_audit_release_rejects_early_or_changed_boundary() -> None:
    policy, work, block, boundary = _reveal_release_fixture()
    early = replace(
        block,
        timestamp_ms=(
            QUICKNET_GENESIS_MS + (work.window.plan.reveal_round - 1) * QUICKNET_PERIOD_MS - 1
        ),
    )
    adapter = FinalizedRevealAuditReleaseAdapter(
        policy,
        _FinalityHarness(policy, early),
        _BoundaryPort(boundary),
    )
    with pytest.raises(RevealAuditReleasePortError, match="before_reveal"):
        await adapter(work, "canary_hit")

    changed = replace(
        boundary,
        fact=boundary.fact.model_copy(update={"reason_code": "ground_truth_invalid"}),
    )
    changed_adapter = FinalizedRevealAuditReleaseAdapter(
        policy,
        _FinalityHarness(policy, block),
        _BoundaryPort(changed),
    )
    with pytest.raises(RevealAuditReleasePortError, match="boundary_mismatch"):
        await changed_adapter(work, "canary_hit")


@pytest.mark.asyncio
async def test_reveal_release_boundary_reuses_exact_replayable_weight_schedule(
    tmp_path: Path,
) -> None:
    fixture = weight_fixture(tmp_path)
    work = replace(
        fixture.work,
        window=replace(fixture.work.window, stage=WindowStage.REVEAL_AND_SCORE),
    )

    async def schedule(_work):
        return fixture.capture

    adapter = ProofBackedRevealAuditReleaseBoundaryPort(
        policy=fixture.policy,
        schedule=schedule,
    )
    boundary = await adapter(work, "canary_hit")
    evidence = WeightCommitScheduleEvidence.model_validate_json(boundary.evidence_bytes)

    assert boundary.fact.reason_code == "canary_hit"
    assert boundary.fact.audit_release_block == evidence.weight_commit_close_block
    assert (
        boundary.fact.derivation_evidence_sha256
        == hashlib.sha256(boundary.evidence_bytes).hexdigest()
    )
    assert canonical_json_bytes(evidence) == boundary.evidence_bytes


def test_live_builders_preserve_existing_port_bundle_types(tmp_path) -> None:
    policy, discovery_bytes, _work = _mirror_policy_and_work(tmp_path)
    source = DurablePoolMirrorSource(
        policy=policy,
        discovery_rule_bytes=discovery_bytes,
        state_path=tmp_path / "builder.sqlite3",
        request_headers={"Authorization": "Bearer test-token"},
        resolver=_public_resolver,
    )
    client = QuicknetClient(transport=_quicknet_transport())

    async def closing(_work):
        raise AssertionError

    async def prepared(_context, _work):
        raise AssertionError

    pool_ports = build_live_pool_effect_ports(
        policy=policy,
        source=source,
        closing_snapshot=closing,
        delivery_issuance=lambda _context, _work: None,
        prepared_assignments=prepared,
        quicknet_client=client,
    )
    assert isinstance(pool_ports.selection_pulse, QuicknetSelectionPulseAdapter)

    live_policy, _live_work, block, boundary = _reveal_release_fixture()
    release = FinalizedRevealAuditReleaseAdapter(
        live_policy,
        _FinalityHarness(live_policy, block),
        _BoundaryPort(boundary),
    )
    reveal_ports = build_live_reveal_effect_ports(
        policy=live_policy,
        quicknet_client=client,
        audit_release=release,
    )
    assert isinstance(reveal_ports.reveal_pulse, QuicknetRevealPulseAdapter)
    assert isinstance(reveal_ports.decrypt, TLERevealDecryptAdapter)
