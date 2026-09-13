from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest

from umi.competition_artifacts import preserve_bundle, verify_preserved_bundle
from umi.competition_retrieval import (
    ArtifactRetrievalLimits,
    CompetitionRetrievalError,
    PinnedHTTPSArtifactTransport,
    retrieve_signed_model_bundle,
)
from umi.open_competition import (
    BundleFile,
    CompetitionPolicy,
    Evaluator,
    ModelBundle,
    SignedSubmission,
    Submission,
    digest,
    sign_object,
)


def _wallet(name: str):
    key = bt.sp_core.Keypair.create_from_uri("//" + name, crypto_type=bt.sp_core.CRYPTO_SR25519)
    return SimpleNamespace(hotkey=key, coldkey=key, coldkeypub=key)


@pytest.fixture
def policy() -> CompetitionPolicy:
    return CompetitionPolicy(
        schema="umi-open-competition-policy/1",
        network="finney",
        netuid=78,
        sequence=1,
        predecessor_sha256=None,
        valid_from_block=100,
        valid_through_block=1000,
        endpoint_reward_bps=7000,
        model_reward_bps=3000,
        minimum_score_bps=1000,
        promotion_margin_bps=100,
        minimum_cases_per_stratum=1,
        maximum_inference_ms=1000,
        maximum_output_bytes=100,
        maximum_bundle_bytes=100_000,
        maximum_bundle_files=20,
        minimum_submission_interval_blocks=5,
        maximum_submission_lifetime_blocks=900,
        maximum_snapshot_age_blocks=10,
        maximum_uids=256,
        evaluators=(
            Evaluator(hotkey=_wallet("RetrieverEvaluator").hotkey.ss58_address, control_group="a"),
        ),
        required_evaluator_groups=1,
        contribution_terms_sha256="a1" * 32,
        accepted_model_licenses=("CC-BY-SA-4.0",),
        evaluation_runtime_sha256="a2" * 32,
    )


def _bundle(marker: bytes = b"candidate") -> tuple[ModelBundle, dict[str, bytes]]:
    paths = {
        "config/model.json": marker + b" config",
        "environment.txt": marker + b" environment",
        "inference.py": marker + b" inference",
        "LICENSE": b"",
        "processor.json": marker + b" processor",
        "provenance.txt": marker + b" provenance",
        "weights/model.bin": marker + b" weights",
    }
    roles = {
        "config/model.json": "config",
        "environment.txt": "environment",
        "inference.py": "inference",
        "LICENSE": "license",
        "processor.json": "processor",
        "provenance.txt": "provenance",
        "weights/model.bin": "weights",
    }
    records = tuple(
        BundleFile(
            path=path,
            role=roles[path],
            sha256=hashlib.sha256(body).hexdigest(),
            size_bytes=len(body),
        )
        for path, body in sorted(paths.items())
    )
    return (
        ModelBundle(
            schema="umi-model-bundle/1",
            profile="offline_bundle/1",
            parent_baseline_sha256=None,
            license_id="CC-BY-SA-4.0",
            files=records,
        ),
        paths,
    )


def _signed(
    policy: CompetitionPolicy,
    bundle: ModelBundle,
    **changes,
) -> SignedSubmission:
    wallet = _wallet("RetrieverMiner")
    values = {
        "schema": "umi-competition-submission/1",
        "network": "finney",
        "netuid": 78,
        "policy_sha256": digest(policy),
        "hotkey": wallet.hotkey.ss58_address,
        "track": "model",
        "sequence": 1,
        "valid_from_block": 100,
        "valid_through_block": 900,
        "model_revision": digest(bundle),
        "endpoint_url": None,
        "model_bundle": bundle,
        "accepted_terms_sha256": policy.contribution_terms_sha256,
    }
    values.update(changes)
    submission = Submission(**values)
    return SignedSubmission(submission=submission, signature=sign_object(submission, wallet))


def _limits(**changes) -> ArtifactRetrievalLimits:
    values = {
        "maximum_files": 20,
        "maximum_file_bytes": 10_000,
        "maximum_total_bytes": 100_000,
        "request_timeout_seconds": 1.0,
        "total_download_timeout_seconds": 2.0,
    }
    values.update(changes)
    return ArtifactRetrievalLimits(**values)


class StaticTransport:
    def __init__(self, bodies: dict[str, bytes]) -> None:
        self.bodies = bodies
        self.calls: list[tuple[str, int, int]] = []

    async def stream_file(
        self,
        url: str,
        *,
        maximum_bytes: int,
        expected_size_bytes: int,
        consume,
    ) -> None:
        self.calls.append((url, maximum_bytes, expected_size_bytes))
        path = url.split("/bundle/", 1)[1]
        body = self.bodies[path]
        midpoint = len(body) // 2
        await consume(body[:midpoint])
        await consume(body[midpoint:])


@pytest.mark.asyncio
async def test_signed_bundle_streams_to_private_atomic_archive(policy, tmp_path: Path) -> None:
    bundle, bodies = _bundle()
    signed = _signed(policy, bundle)
    transport = StaticTransport(bodies)
    archive = tmp_path / "archive"

    result = await retrieve_signed_model_bundle(
        signed,
        source_base_url="https://models.example/bundle",
        archive=archive,
        policy=policy,
        limits=_limits(),
        transport=transport,
    )

    assert result == archive / digest(bundle)
    assert verify_preserved_bundle(bundle, archive, policy) == digest(bundle)
    assert len(transport.calls) == len(bundle.files)
    assert transport.calls[0][0] == "https://models.example/bundle/LICENSE"
    assert all(not os.stat(result / "model" / item.path).st_mode & 0o111 for item in bundle.files)
    assert not list(archive.glob(".retrieval-*"))


@pytest.mark.asyncio
async def test_existing_verified_archive_is_idempotent_without_network(
    policy, tmp_path: Path
) -> None:
    bundle, bodies = _bundle()
    source = tmp_path / "source"
    for path, body in bodies.items():
        target = source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    archive = tmp_path / "archive"
    expected = preserve_bundle(bundle, source, archive, policy)

    class NoNetwork:
        async def stream_file(self, *args, **kwargs):
            raise AssertionError("verified retry must not use the network")

    assert (
        await retrieve_signed_model_bundle(
            _signed(policy, bundle),
            source_base_url="https://models.example/bundle",
            archive=archive,
            policy=policy,
            limits=_limits(),
            transport=NoNetwork(),
        )
        == expected
    )


@pytest.mark.asyncio
async def test_bad_hash_cleans_stage_and_preserves_an_existing_bundle(
    policy, tmp_path: Path
) -> None:
    previous, previous_bodies = _bundle(b"previous")
    previous_source = tmp_path / "previous"
    for path, body in previous_bodies.items():
        target = previous_source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    archive = tmp_path / "archive"
    preserved = preserve_bundle(previous, previous_source, archive, policy)

    candidate, candidate_bodies = _bundle(b"candidate")
    candidate_bodies["weights/model.bin"] = b"x" * len(candidate_bodies["weights/model.bin"])
    with pytest.raises(CompetitionRetrievalError, match="artifact_file_sha256_mismatch"):
        await retrieve_signed_model_bundle(
            _signed(policy, candidate),
            source_base_url="https://models.example/bundle",
            archive=archive,
            policy=policy,
            limits=_limits(),
            transport=StaticTransport(candidate_bodies),
        )

    assert preserved.exists()
    assert verify_preserved_bundle(previous, archive, policy) == digest(previous)
    assert not (archive / digest(candidate)).exists()
    assert not list(archive.glob(".retrieval-*"))


class AsyncChunks(httpx.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self):
        yield self.body[:1]
        yield self.body[1:]


@pytest.mark.asyncio
async def test_default_adapter_accepts_unknown_length_and_zero_byte_objects(
    policy, tmp_path: Path
) -> None:
    bundle, bodies = _bundle()
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path.split("/bundle/", 1)[1]
        return httpx.Response(200, stream=AsyncChunks(bodies[path]), request=request)

    transport = PinnedHTTPSArtifactTransport(
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )
    result = await retrieve_signed_model_bundle(
        _signed(policy, bundle),
        source_base_url="https://models.example/bundle",
        archive=tmp_path / "archive",
        policy=policy,
        limits=_limits(),
        transport=transport,
    )

    assert result.exists()
    assert len(requests) == 7
    assert all("content-length" not in request.headers for request in requests)


@pytest.mark.asyncio
async def test_default_adapter_rejects_redirect_and_private_dns(policy, tmp_path: Path) -> None:
    bundle, _ = _bundle()

    async def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://other.example/model"},
            request=request,
        )

    with pytest.raises(CompetitionRetrievalError, match="artifact_https_status_invalid"):
        await retrieve_signed_model_bundle(
            _signed(policy, bundle),
            source_base_url="https://models.example/bundle",
            archive=tmp_path / "redirect-archive",
            policy=policy,
            limits=_limits(),
            transport=PinnedHTTPSArtifactTransport(
                timeout_seconds=1,
                transport=httpx.MockTransport(redirect),
            ),
        )

    async def private_resolver(_hostname: str, _port: int):
        return ("93.184.216.34", "127.0.0.1")

    async def consume(_chunk: bytes) -> None:
        pass

    pinned = PinnedHTTPSArtifactTransport(
        timeout_seconds=1,
        resolver=private_resolver,
        transport=httpx.AsyncHTTPTransport(),
    )
    with pytest.raises(
        CompetitionRetrievalError,
        match="artifact_https_dns_address_not_global",
    ):
        await pinned.stream_file(
            "https://models.example/bundle/file",
            maximum_bytes=1,
            expected_size_bytes=0,
            consume=consume,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source",
    [
        "http://models.example/bundle",
        "https://user@models.example/bundle",
        "https://models.example:444/bundle",
        "https://models.example/bundle/",
        "https://models.example/a/../bundle",
        "https://models.example/%2e%2e/bundle",
        "https://models.example/bundle?token=secret",
        "https://models.example/bundle#fragment",
        "https://models.example\n/bundle",
    ],
)
async def test_source_must_be_canonical_credential_free_https(
    policy, tmp_path: Path, source: str
) -> None:
    bundle, bodies = _bundle()
    transport = StaticTransport(bodies)
    with pytest.raises(CompetitionRetrievalError, match="artifact_source_url_invalid"):
        await retrieve_signed_model_bundle(
            _signed(policy, bundle),
            source_base_url=source,
            archive=tmp_path / "archive",
            policy=policy,
            limits=_limits(),
            transport=transport,
        )
    assert transport.calls == []


@pytest.mark.asyncio
async def test_manifest_operational_limits_fail_before_filesystem_or_network(
    policy, tmp_path: Path
) -> None:
    bundle, bodies = _bundle()
    signed = _signed(policy, bundle)

    for limits, reason in (
        (_limits(maximum_files=6), "artifact_file_count_limit"),
        (_limits(maximum_file_bytes=1), "artifact_file_size_limit"),
        (_limits(maximum_total_bytes=80, maximum_file_bytes=80), "artifact_total_size_limit"),
    ):
        transport = StaticTransport(bodies)
        archive = tmp_path / reason
        with pytest.raises(CompetitionRetrievalError, match=reason):
            await retrieve_signed_model_bundle(
                signed,
                source_base_url="https://models.example/bundle",
                archive=archive,
                policy=policy,
                limits=limits,
                transport=transport,
            )
        assert transport.calls == []
        assert not archive.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"accepted_terms_sha256": "ff" * 32}, "artifact_terms_mismatch"),
        ({"valid_from_block": 99}, "artifact_submission_lifetime_invalid"),
        ({"valid_through_block": 1001}, "artifact_submission_lifetime_invalid"),
    ],
)
async def test_signed_terms_and_policy_interval_are_checked_before_io(
    policy, tmp_path: Path, changes: dict, reason: str
) -> None:
    bundle, bodies = _bundle()
    transport = StaticTransport(bodies)
    archive = tmp_path / reason
    with pytest.raises(CompetitionRetrievalError, match=reason):
        await retrieve_signed_model_bundle(
            _signed(policy, bundle, **changes),
            source_base_url="https://models.example/bundle",
            archive=archive,
            policy=policy,
            limits=_limits(),
            transport=transport,
        )
    assert transport.calls == []
    assert not archive.exists()


@pytest.mark.asyncio
async def test_streaming_aggregate_limit_is_enforced_defensively(policy, tmp_path: Path) -> None:
    bundle, bodies = _bundle()
    total = sum(len(body) for body in bodies.values())
    bodies["weights/model.bin"] += b"x"
    with pytest.raises(CompetitionRetrievalError, match="artifact_total_body_limit"):
        await retrieve_signed_model_bundle(
            _signed(policy, bundle),
            source_base_url="https://models.example/bundle",
            archive=tmp_path / "archive",
            policy=policy,
            limits=_limits(maximum_total_bytes=total, maximum_file_bytes=total),
            transport=StaticTransport(bodies),
        )
    assert not list((tmp_path / "archive").glob(".retrieval-*"))


@pytest.mark.asyncio
async def test_timeout_and_cancellation_finish_transport_cleanup(policy, tmp_path: Path) -> None:
    bundle, _ = _bundle()

    class BlockingTransport:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def stream_file(self, *args, **kwargs) -> None:
            self.started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled.set()

    timed = BlockingTransport()
    with pytest.raises(CompetitionRetrievalError, match="artifact_total_timeout"):
        await retrieve_signed_model_bundle(
            _signed(policy, bundle),
            source_base_url="https://models.example/bundle",
            archive=tmp_path / "timed",
            policy=policy,
            limits=_limits(total_download_timeout_seconds=0.01),
            transport=timed,
        )
    assert timed.cancelled.is_set()
    assert not list((tmp_path / "timed").glob(".retrieval-*"))

    cancelled = BlockingTransport()
    task = asyncio.create_task(
        retrieve_signed_model_bundle(
            _signed(policy, bundle),
            source_base_url="https://models.example/bundle",
            archive=tmp_path / "cancelled",
            policy=policy,
            limits=_limits(),
            transport=cancelled,
        )
    )
    await cancelled.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.cancelled.is_set()
    assert not list((tmp_path / "cancelled").glob(".retrieval-*"))


@pytest.mark.asyncio
async def test_archive_must_be_private_and_cannot_be_symlinked(policy, tmp_path: Path) -> None:
    bundle, bodies = _bundle()
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(CompetitionRetrievalError, match="artifact_archive_permissions_unsafe"):
        await retrieve_signed_model_bundle(
            _signed(policy, bundle),
            source_base_url="https://models.example/bundle",
            archive=public,
            policy=policy,
            limits=_limits(),
            transport=StaticTransport(bodies),
        )

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(CompetitionRetrievalError, match="artifact_archive_unsafe"):
        await retrieve_signed_model_bundle(
            _signed(policy, bundle),
            source_base_url="https://models.example/bundle",
            archive=linked,
            policy=policy,
            limits=_limits(),
            transport=StaticTransport(bodies),
        )
