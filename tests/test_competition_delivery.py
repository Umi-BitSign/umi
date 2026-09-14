from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_delivery as delivery
from umi.competition_package import CompetitionReleaseIdentity
from umi.competition_supervisor import (
    SuccessorSupervisorDirectivePage,
    parse_canonical_successor_supervisor_directive_history,
    parse_canonical_successor_supervisor_directive_page,
    successor_continuation_bytes,
    verify_signed_successor_supervisor_directive,
)
from umi.competition_supervisor_runtime import SuccessorWorkerSelection
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    COMMON_SUPERVISOR_CHANNELS,
    COMMON_SUPERVISOR_RELEASE_ORIGIN,
    ValidatorSupervisorError,
)
from umi.validator_supervisor_adapters import PinnedHTTPSClient, ValidatorSupervisorAdapterError

from .test_competition_materialization import case as material_case  # noqa: F401
from .test_competition_materialization import package_case as package_case
from .test_competition_materialization import package_limits as package_limits
from .test_competition_materialization import policy as policy
from .test_competition_materialization import replay_limits as replay_limits
from .test_competition_materialization import successor_case as successor_case
from .test_competition_materialization import successor_chain as successor_chain
from .test_competition_materialization import successor_release as successor_release
from .test_competition_materialization import v3_predecessor as v3_predecessor
from .test_competition_materialization import worker_capacity as worker_capacity
from .test_competition_supervisor import _consent, _directive, _signed, _signed_continuation

_BUNDLE = b"inert synthetic release; separate OCI tests authenticate real archives"


@pytest.fixture
def release_identity():
    return CompetitionReleaseIdentity(
        schema="umi-competition-replay-release-identity/1",
        umi_revision="ab" * 20,
        release_manifest_sha256="cd" * 32,
        release_bundle_sha256=hashlib.sha256(_BUNDLE).hexdigest(),
        target_triple="x86_64-unknown-linux-gnu",
    )


class Responses:
    def __init__(self, objects):
        self.objects = objects
        self.requests = []

    async def handle(self, request):
        url = str(request.url)
        self.requests.append(url)
        result = self.objects.get(url)
        if isinstance(result, Exception):
            raise result
        if callable(result):
            return await result(request)
        if result is None:
            return httpx.Response(404)
        # Explicit stream exercises raw streamed-body bounds in the real client.
        return httpx.Response(200, stream=httpx.ByteStream(result))


@pytest.fixture
def initial_history_case(successor_case):
    case = successor_case
    records = [case.signed, *_signed_continuation(case.signed, 68)]
    base = case.predecessor.config.directive_url + "/successor"
    cursor = (
        3,
        case.predecessor.signed.directive.sequence,
        case.predecessor.signed.directive_sha256,
    )
    objects = {}
    for offset in range(0, len(records), 16):
        batch = records[offset : offset + 16]
        page = SuccessorSupervisorDirectivePage(
            schema="umi-validator-supervisor-directive-page/4",
            after_version=cursor[0],
            after_sequence=cursor[1],
            after_directive_sha256=cursor[2],
            directives=batch,
            head=batch[-1],
            more=offset + len(batch) < len(records),
        )
        objects[f"{base}/after/{cursor[0]}/{cursor[1]}/{cursor[2]}.json"] = canonical_json_bytes(
            page
        )
        cursor = (4, batch[-1].directive.sequence, batch[-1].directive_sha256)
    responses = Responses(objects)
    client = PinnedHTTPSClient(timeout_seconds=1, transport=httpx.MockTransport(responses.handle))
    fetcher = delivery.HTTPSSuccessorDirectiveFetcher(case.predecessor.config, client=client)
    return SimpleNamespace(
        records=records,
        responses=responses,
        fetcher=fetcher,
        arguments=dict(
            legacy_signed_bytes=case.predecessor.body,
            operator_consent=case.consent,
            finalized_block=150,
        ),
    )


async def test_initial_history_collects_multiple_bounded_network_pages(initial_history_case):
    case = initial_history_case
    body = await case.fetcher.fetch_initial_history(**case.arguments)
    parsed = parse_canonical_successor_supervisor_directive_history(body)
    assert parsed.after_version == 3
    assert parsed.directives == case.records
    assert parsed.head == case.records[-1]
    assert parsed.schema_ == "umi-validator-supervisor-directive-history/1"
    assert len(case.responses.requests) == 5
    with pytest.raises(ValidatorSupervisorError):
        parse_canonical_successor_supervisor_directive_page(body)


@pytest.mark.parametrize(
    "change", ["cursor", "signature", "missing", "record_budget", "byte_budget"]
)
async def test_initial_history_rejects_untrusted_or_over_budget_pages(initial_history_case, change):
    import json

    case = initial_history_case
    urls = list(case.responses.objects)
    arguments = dict(case.arguments)
    if change == "cursor":
        case.responses.objects[urls[1]] = case.responses.objects[urls[0]]
    elif change == "signature":
        value = json.loads(case.responses.objects[urls[1]])
        value["directives"][0]["signatures"][0]["signature"] = "0x" + "00" * 64
        case.responses.objects[urls[1]] = canonical_json_bytes(value)
    elif change == "missing":
        del case.responses.objects[urls[1]]
    elif change == "record_budget":
        arguments["maximum_records"] = 1
    else:
        arguments["maximum_bytes"] = 1024
    with pytest.raises(
        (delivery.SuccessorDeliveryError, ValidatorSupervisorError, ValidatorSupervisorAdapterError)
    ):
        await case.fetcher.fetch_initial_history(**arguments)
    assert len(case.responses.requests) <= 2


async def test_initial_history_timeout_cancels_pending_fetch(initial_history_case, monkeypatch):
    case = initial_history_case
    cancelled = []

    async def stall(**_kwargs):
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.append(True)

    monkeypatch.setattr(case.fetcher, "fetch_directive_page", stall)
    with pytest.raises(TimeoutError):
        await case.fetcher.fetch_initial_history(**case.arguments, timeout_seconds=1)
    assert cancelled == [True]


async def test_initial_history_wrong_legacy_binding_never_fetches(initial_history_case):
    case = initial_history_case
    arguments = dict(case.arguments)
    arguments["operator_consent"] = arguments["operator_consent"].model_copy(
        update={"predecessor_signed_directive_sha256": "00" * 32}
    )
    with pytest.raises(ValueError, match="differs from operator consent"):
        await case.fetcher.fetch_initial_history(**arguments)
    assert not case.responses.requests


@pytest.mark.skipif(sys.platform != "linux", reason="initial control publication uses renameat2")
def test_initial_history_cli_stages_exact_bytes_without_overwriting(
    initial_history_case, tmp_path, monkeypatch, policy
):
    from umi.competition_cli import _parser, execute

    case = initial_history_case
    monkeypatch.setattr(delivery, "HTTPSSuccessorDirectiveFetcher", lambda config: case.fetcher)
    paths = {}
    for name, body in (
        ("config", canonical_json_bytes(case.fetcher.config)),
        ("accepted-directive", case.arguments["legacy_signed_bytes"]),
        ("consent", canonical_json_bytes(case.arguments["operator_consent"])),
        ("policy", canonical_json_bytes(policy)),
    ):
        path = tmp_path / (name + ".json")
        path.write_bytes(body)
        paths[name] = str(path)
    output = tmp_path / "initial-successor-directive-page.json"
    arguments = ["--policy", paths["policy"], "fetch-initial-successor-history"]
    for name in ("config", "accepted-directive", "consent"):
        arguments.extend(["--" + name, paths[name]])
    arguments.extend(["--current-block", "150", "--output", str(output)])
    args = _parser().parse_args(arguments)
    result = execute(args)
    body = output.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o400
    assert result["history_sha256"] == hashlib.sha256(body).hexdigest()
    assert result["history_size_bytes"] == len(body)
    assert result["directive_count"] == 69
    assert result["host_upgrade_authorized"] is False
    assert result["chain_submission_authorized"] is False
    assert parse_canonical_successor_supervisor_directive_history(body).directives == case.records
    with pytest.raises(FileExistsError):
        execute(args)
    assert output.read_bytes() == body


@pytest.mark.skipif(sys.platform != "linux", reason="initial control publication uses renameat2")
async def test_initial_history_failed_write_never_publishes(
    initial_history_case, tmp_path, monkeypatch
):
    case = initial_history_case
    body = await case.fetcher.fetch_initial_history(**case.arguments)
    output = tmp_path / "initial-successor-directive-page.json"

    def fail_write(*_args):
        raise OSError("injected failed write")

    monkeypatch.setattr(delivery.os, "write", fail_write)
    with pytest.raises(OSError, match="injected"):
        delivery.write_initial_history(output, body)
    assert not output.exists()
    assert len(list(tmp_path.glob(".initial-history-*.partial"))) == 1


@pytest.mark.skipif(sys.platform != "linux", reason="initial control publication uses renameat2")
async def test_initial_history_refuses_public_parent(initial_history_case, tmp_path):
    case = initial_history_case
    body = await case.fetcher.fetch_initial_history(**case.arguments)
    parent = tmp_path / "public"
    parent.mkdir(mode=0o755)
    with pytest.raises(delivery.SuccessorDeliveryError, match="ownership or mode"):
        delivery.write_initial_history(parent / "history.json", body)
    assert not list(parent.iterdir())


def test_common_platform_successor_routes_are_disjoint_and_wrong_page_is_rejected(
    successor_case,
):
    predecessor = successor_case.predecessor

    def platform_predecessor(platform):
        channel = COMMON_SUPERVISOR_CHANNELS[platform]
        suffix = platform.replace("/", "-")
        config = predecessor.config.model_copy(
            update={
                "channel_id": channel,
                "target_platform": platform,
                "directive_url": (
                    f"{COMMON_SUPERVISOR_RELEASE_ORIGIN}/validator-supervisor/channels/"
                    f"{channel}/{suffix}"
                ),
            }
        )
        return SimpleNamespace(
            config=config,
            state=predecessor.state.model_copy(update={"channel_id": channel}),
            body=predecessor.body,
        )

    amd64 = platform_predecessor("linux/amd64")
    arm64 = platform_predecessor("linux/arm64")
    amd64_fetcher = delivery.HTTPSSuccessorDirectiveFetcher(amd64.config, client=object())
    arm64_fetcher = delivery.HTTPSSuccessorDirectiveFetcher(arm64.config, client=object())
    assert amd64_fetcher.base != arm64_fetcher.base
    assert amd64_fetcher.base.endswith("/linux-amd64/successor")
    assert arm64_fetcher.base.endswith("/linux-arm64/successor")

    amd64_consent = _consent(amd64)
    amd64_directive = _directive(
        amd64,
        successor_case.target,
        successor_case.release,
        successor_case.chain,
        amd64_consent,
    )
    amd64_signed = _signed(amd64_directive)
    page = SuccessorSupervisorDirectivePage(
        schema="umi-validator-supervisor-directive-page/4",
        after_version=3,
        after_sequence=amd64.state.accepted_sequence,
        after_directive_sha256=amd64.state.accepted_directive_sha256,
        directives=[amd64_signed],
        more=False,
        head=amd64_signed,
    )
    parsed = parse_canonical_successor_supervisor_directive_page(canonical_json_bytes(page))
    assert (
        verify_signed_successor_supervisor_directive(
            parsed.head,
            config=amd64.config,
            operator_consent=amd64_consent,
            finalized_block=150,
        )
        == amd64_signed.directive_sha256
    )

    with pytest.raises(ValidatorSupervisorError) as error:
        verify_signed_successor_supervisor_directive(
            parsed.head,
            config=arm64.config,
            operator_consent=_consent(arm64),
            finalized_block=150,
        )
    assert error.value.reason_code == "successor_channel_mismatch"


@pytest.fixture
def case(material_case, monkeypatch):  # noqa: F811
    if sys.platform != "linux":

        def portable_noreplace(parent, source, destination):
            # Explicit Mac OS port, not evidence of the production Linux syscall.
            os.link(
                source, destination, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False
            )
            os.unlink(source, dir_fd=parent)

        monkeypatch.setattr(delivery, "_publish_noreplace", portable_noreplace)
    item = material_case
    directive = item.selection.signed.directive
    signed = _signed(
        directive.model_copy(
            update={
                "release": directive.release.model_copy(
                    update={"release_bundle_size_bytes": len(_BUNDLE)}
                )
            }
        )
    )
    selection = SuccessorWorkerSelection(signed)
    page = item.page.model_copy(update={"directives": [signed], "head": signed})
    base = item.config.directive_url + "/successor"
    control_base = base + "/directives/" + signed.directive_sha256
    objects = {
        control_base + "/page.json": canonical_json_bytes(page),
        control_base + "/execution.json": item.files.worker_execution_bytes,
        directive.release.release_bundle_url: _BUNDLE,
    }
    for path in item.package_case.path.iterdir():
        objects[base + "/packages/" + directive.replay_package.package_sha256 + "/" + path.name] = (
            path.read_bytes()
        )
    responses = Responses(objects)
    client = PinnedHTTPSClient(timeout_seconds=1, transport=httpx.MockTransport(responses.handle))
    limits = delivery.SuccessorDeliveryLimits(
        maximum_cached_objects=9, maximum_cache_bytes=50_000_000, total_fetch_timeout_seconds=10
    )
    args = dict(
        config=item.config,
        operator_consent=item.consent,
        worker_limits=item.worker_limits,
        limits=limits,
        client=client,
    )
    fetcher = delivery.HTTPSSuccessorArtifactDelivery(**args)
    return SimpleNamespace(
        item=item,
        selection=selection,
        page=page,
        base=base,
        responses=responses,
        fetcher=fetcher,
        args=args,
        control_base=control_base,
    )


async def test_fetch_replays_exact_package_without_activation_and_reuses_after_restart(case):
    result = await case.fetcher.fetch(case.selection)
    assert result.release_bundle_path.read_bytes() == _BUNDLE
    assert result.package_path.stat().st_mode & 0o777 == 0o500
    assert result.authorization_bytes is None
    assert not (case.item.state / "successor-v4" / "activation-source").exists()
    assert not hasattr(result, "chain_submission_authorized")
    requests = list(case.responses.requests)
    restarted = delivery.HTTPSSuccessorArtifactDelivery(**case.args)
    assert await restarted.fetch(case.selection) == result
    assert case.responses.requests == requests


async def test_retained_multi_page_history_is_used_without_remote_page_and_survives_restart(case):
    import hashlib
    import json

    anchor = case.selection.signed
    records = _signed_continuation(anchor)
    body = successor_continuation_bytes(anchor, records)
    selected = SuccessorWorkerSelection(records[-1], body)
    control_base = case.base + "/directives/" + selected.directive_sha256
    case.responses.objects[control_base + "/execution.json"] = (
        case.item.files.worker_execution_bytes
    )
    result = await case.fetcher.fetch(selected)
    assert result.current_directive_page_bytes == body
    controls = case.fetcher.root / ("controls-" + selected.directive_sha256)
    assert not (controls / "history.json").exists()
    binding = (controls / "history-binding.json").read_bytes()
    assert len(binding) < 1024
    assert json.loads(binding) == {
        "schema": "umi-successor-delivery-history-binding/1",
        "directive_sha256": selected.directive_sha256,
        "history_sha256": hashlib.sha256(body).hexdigest(),
        "history_size_bytes": len(body),
    }
    assert not any(url.endswith("/page.json") for url in case.responses.requests)
    requests = list(case.responses.requests)
    restarted = delivery.HTTPSSuccessorArtifactDelivery(**case.args)
    assert await restarted.fetch(selected) == result
    assert case.responses.requests == requests


@pytest.mark.parametrize("fault", ["changed_history", "corrupt_binding"])
async def test_retained_history_binding_cannot_be_replaced_on_restart(case, fault):
    records = _signed_continuation(case.selection.signed, 2)
    body = successor_continuation_bytes(case.selection.signed, records)
    selected = SuccessorWorkerSelection(records[-1], body)
    control_base = case.base + "/directives/" + selected.directive_sha256
    case.responses.objects[control_base + "/execution.json"] = (
        case.item.files.worker_execution_bytes
    )
    await case.fetcher.fetch(selected)
    requests = list(case.responses.requests)
    if fault == "changed_history":
        selected = SuccessorWorkerSelection(
            records[-1], successor_continuation_bytes(records[0], records[1:])
        )
    else:
        binding = (
            case.fetcher.root / ("controls-" + selected.directive_sha256) / "history-binding.json"
        )
        binding.chmod(0o600)
        binding.write_bytes(b"{}")
        binding.chmod(0o400)
    restarted = delivery.HTTPSSuccessorArtifactDelivery(**case.args)
    with pytest.raises(delivery.SuccessorDeliveryError, match="cached continuation differs"):
        await restarted.fetch(selected)
    assert case.responses.requests == requests


async def test_retained_legacy_history_is_preserved_and_checked_on_refetch(case):
    records = _signed_continuation(case.selection.signed, 2)
    body = successor_continuation_bytes(case.selection.signed, records)
    selected = SuccessorWorkerSelection(records[-1], body)
    control_base = case.base + "/directives/" + selected.directive_sha256
    case.responses.objects[control_base + "/execution.json"] = (
        case.item.files.worker_execution_bytes
    )
    result = await case.fetcher.fetch(selected)
    controls = case.fetcher.root / ("controls-" + selected.directive_sha256)
    legacy = controls / "history.json"
    legacy.write_bytes(body)
    legacy.chmod(0o400)
    identity = legacy.stat()
    restarted = delivery.HTTPSSuccessorArtifactDelivery(**case.args)
    assert await restarted.fetch(selected) == result
    assert legacy.read_bytes() == body
    assert delivery._identity(legacy.stat()) == delivery._identity(identity)
    # Corrupt the old file while preserving its size. The new binding must not
    # hide corruption in evidence retained by an earlier release.
    legacy.chmod(0o600)
    legacy.write_bytes(b" " * len(body))
    legacy.chmod(0o400)
    with pytest.raises(delivery.SuccessorDeliveryError, match="cached input hash differs"):
        await restarted.fetch(selected)


async def test_retained_history_forged_signature_fails_before_package_fetch(case):
    anchor = case.selection.signed
    records = _signed_continuation(anchor)
    signatures = [
        item.model_copy(update={"signature": "0x" + "00" * 64}) for item in records[3].signatures
    ]
    records[3] = records[3].model_copy(update={"signatures": signatures})
    selected = SuccessorWorkerSelection(records[-1], successor_continuation_bytes(anchor, records))
    with pytest.raises(ValidatorSupervisorError):
        await case.fetcher.fetch(selected)
    assert case.responses.requests == []


@pytest.mark.parametrize("name", ["manifest.json", "evidence.json", "policy.json"])
async def test_wrong_package_bytes_never_download_release(case, name):
    url = (
        case.base
        + "/packages/"
        + case.selection.signed.directive.replay_package.package_sha256
        + "/"
        + name
    )
    case.responses.objects[url] += b" "
    with pytest.raises((delivery.SuccessorDeliveryError, ValidatorSupervisorAdapterError)):
        await case.fetcher.fetch(case.selection)
    assert case.selection.signed.directive.release.release_bundle_url not in case.responses.requests


async def test_wrong_cached_release_is_never_replaced(case):
    result = await case.fetcher.fetch(case.selection)
    result.release_bundle_path.chmod(0o600)
    result.release_bundle_path.write_bytes(b"x" * len(_BUNDLE))
    result.release_bundle_path.chmod(0o400)
    requests = list(case.responses.requests)
    with pytest.raises(delivery.SuccessorDeliveryError, match="archive content"):
        await case.fetcher.fetch(case.selection)
    assert case.responses.requests == requests
    assert result.release_bundle_path.read_bytes() == b"x" * len(_BUNDLE)


async def test_changed_package_rechecked_on_cached_retry(case):
    result = await case.fetcher.fetch(case.selection)
    path = result.package_path / "policy.json"
    path.chmod(0o600)
    path.write_bytes(b"{}")
    path.chmod(0o400)
    with pytest.raises(delivery.SuccessorDeliveryError):
        await case.fetcher.fetch(case.selection)


async def test_oversized_execution_fails_before_release(case):
    case.responses.objects[case.control_base + "/execution.json"] = b"x" * (128 * 1024 + 1)
    with pytest.raises(ValidatorSupervisorAdapterError, match="body_limit"):
        await case.fetcher.fetch(case.selection)
    assert case.selection.signed.directive.release.release_bundle_url not in case.responses.requests


async def test_bad_directive_signature_rejected_before_network_or_disk(case):
    signed = case.selection.signed.model_copy(update={"directive_sha256": "00" * 32})
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        await case.fetcher.fetch(SuccessorWorkerSelection(signed))
    assert case.responses.requests == []
    assert not case.fetcher.root.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("after_version", True),
        ("after_version", 5),
        ("after_sequence", False),
        ("after_sequence", 0),
        ("after_sequence", 2**53),
        ("after_directive_sha256", "../secret"),
        ("after_directive_sha256", "FF" * 32),
    ],
)
async def test_feed_cursor_rejected_before_network(case, field, value):
    fetcher = delivery.HTTPSSuccessorDirectiveFetcher(case.item.config, client=case.args["client"])
    args = dict(after_version=3, after_sequence=7, after_directive_sha256="ab" * 32)
    args[field] = value
    with pytest.raises(delivery.SuccessorDeliveryError, match="cursor"):
        await fetcher.fetch_directive_page(**args)
    assert not case.responses.requests


async def test_feed_uses_versioned_cursor_and_missing_page_is_not_an_empty_history(case):
    fetcher = delivery.HTTPSSuccessorDirectiveFetcher(case.item.config, client=case.args["client"])
    cursor = dict(after_version=4, after_sequence=8, after_directive_sha256="ab" * 32)
    with pytest.raises(ValidatorSupervisorAdapterError, match="not_found"):
        await fetcher.fetch_directive_page(**cursor)
    assert case.responses.requests == [case.base + "/after/4/8/" + "ab" * 32 + ".json"]


async def test_redirect_never_followed(case):
    async def redirect(request):
        return httpx.Response(302, headers={"Location": "https://other.example/private"})

    case.responses.objects[case.control_base + "/page.json"] = redirect
    with pytest.raises(ValidatorSupervisorAdapterError, match="status_invalid"):
        await case.fetcher.fetch(case.selection)
    assert len(case.responses.requests) == 1


async def test_capacity_preserves_cached_objects(case):
    result = await case.fetcher.fetch(case.selection)
    args = dict(case.args, limits=replace(case.args["limits"], maximum_cache_bytes=1024))
    with pytest.raises(delivery.SuccessorDeliveryError, match="byte limit"):
        await delivery.HTTPSSuccessorArtifactDelivery(**args).fetch(case.selection)
    assert result.release_bundle_path.read_bytes() == _BUNDLE


async def test_interrupted_release_retries_only_unverified_partial(case):
    original = case.args["client"].download_file

    async def interrupt(url, *, destination, **kwargs):
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, b"partial")
        os.close(fd)
        raise asyncio.CancelledError()

    case.args["client"].download_file = interrupt
    with pytest.raises(asyncio.CancelledError):
        await case.fetcher.fetch(case.selection)
    case.args["client"].download_file = original
    result = await case.fetcher.fetch(case.selection)
    assert result.release_bundle_path.read_bytes() == _BUNDLE
    assert not result.release_bundle_path.with_name("release.bundle.partial").exists()


async def test_symlink_in_cache_never_followed(case, tmp_path):
    result = await case.fetcher.fetch(case.selection)
    outside = tmp_path / "outside"
    outside.write_bytes(b"do not touch")
    result.release_bundle_path.parent.joinpath("release.bundle.partial").symlink_to(outside)
    with pytest.raises(delivery.SuccessorDeliveryError, match="unsafe delivery"):
        await case.fetcher.fetch(case.selection)
    assert outside.read_bytes() == b"do not touch"


@pytest.mark.parametrize(
    "field,value",
    [
        ("maximum_cached_objects", True),
        ("maximum_cache_bytes", -1),
        ("total_fetch_timeout_seconds", float("nan")),
    ],
)
def test_bad_limits_rejected(field, value):
    args = dict(
        maximum_cached_objects=9, maximum_cache_bytes=1_000_000, total_fetch_timeout_seconds=30
    )
    args[field] = value
    with pytest.raises(ValueError):
        delivery.SuccessorDeliveryLimits(**args)


@pytest.mark.parametrize("fault", ["fifo", "hardlink", "symlink", "bytes", "size", "mode"])
async def test_download_partial_is_verified_before_chmod_or_publication(case, tmp_path, fault):
    outside = tmp_path / "outside-download"
    outside.write_bytes(_BUNDLE)
    outside.chmod(0o600)
    before = outside.stat().st_mode

    async def unsafe(url, *, destination, **kwargs):
        if fault == "fifo":
            os.mkfifo(destination, 0o600)
        elif fault == "hardlink":
            os.link(outside, destination)
        elif fault == "symlink":
            destination.symlink_to(outside)
        else:
            destination.write_bytes(
                b"x" * len(_BUNDLE) if fault == "bytes" else b"x" if fault == "size" else _BUNDLE
            )
            destination.chmod(0o666 if fault == "mode" else 0o600)

    case.args["client"].download_file = unsafe
    with pytest.raises((OSError, delivery.SuccessorDeliveryError)):
        await case.fetcher.fetch(case.selection)
    assert outside.read_bytes() == _BUNDLE and outside.stat().st_mode == before
    release_root = case.fetcher.root / (
        "release-" + case.selection.signed.directive.release.release_bundle_sha256
    )
    assert not (release_root / "release.bundle").exists()


async def test_racing_completed_archive_is_never_overwritten(case, monkeypatch):
    original = delivery._publish_noreplace
    retained = b"independent completed bytes must survive"

    def race(parent, source, destination):
        if destination == "release.bundle":
            fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o400, dir_fd=parent)
            os.write(fd, retained)
            os.close(fd)
        original(parent, source, destination)

    monkeypatch.setattr(delivery, "_publish_noreplace", race)
    with pytest.raises(FileExistsError):
        await case.fetcher.fetch(case.selection)
    target = case.fetcher.root / (
        "release-" + case.selection.signed.directive.release.release_bundle_sha256
    )
    assert (target / "release.bundle").read_bytes() == retained
    assert (target / "release.bundle.partial").read_bytes() == _BUNDLE


async def test_replaced_lock_during_fetch_prevents_cache_write(case):
    async def replace_lock(request):
        old = case.fetcher.root / ".lock"
        old.rename(case.fetcher.root / "lock-retained-for-test")
        old.write_bytes(b"")
        old.chmod(0o600)
        return httpx.Response(200, stream=httpx.ByteStream(canonical_json_bytes(case.page)))

    case.responses.objects[case.control_base + "/page.json"] = replace_lock
    with pytest.raises(delivery.SuccessorDeliveryError, match="lease identity"):
        await case.fetcher.fetch(case.selection)
    assert not (
        case.fetcher.root / ("controls-" + case.selection.directive_sha256) / "page.json"
    ).exists()


async def test_unknown_cache_file_is_not_silently_accepted(case):
    files = await case.fetcher.fetch(case.selection)
    unknown = files.release_bundle_path.parent / "unrelated-private-file"
    unknown.write_bytes(b"retain me")
    unknown.chmod(0o600)
    with pytest.raises(delivery.SuccessorDeliveryError, match="filename"):
        await case.fetcher.fetch(case.selection)
    assert unknown.read_bytes() == b"retain me"


async def test_partial_cleanup_rejects_any_completed_name(case):
    files = await case.fetcher.fetch(case.selection)
    with (
        case.fetcher._locked(),
        pytest.raises(delivery.SuccessorDeliveryError, match="fixed download"),
    ):
        case.fetcher._discard_partial(files.release_bundle_path, len(_BUNDLE))
    assert files.release_bundle_path.read_bytes() == _BUNDLE


async def test_whole_fetch_timeout_cancels_download_and_releases_cache_lock(case):
    cancelled = asyncio.Event()
    original = case.args["client"].download_file

    async def blocked(url, *, destination, **kwargs):
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, b"partial")
        os.close(fd)
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    case.args["client"].download_file = blocked
    args = dict(case.args, limits=replace(case.args["limits"], total_fetch_timeout_seconds=1))
    timed = delivery.HTTPSSuccessorArtifactDelivery(**args)
    with pytest.raises(asyncio.TimeoutError):
        await timed.fetch(case.selection)
    assert cancelled.is_set()
    assert timed._lease is None
    case.args["client"].download_file = original
    result = await case.fetcher.fetch(case.selection)
    assert result.release_bundle_path.read_bytes() == _BUNDLE


async def test_partial_cleanup_cannot_escape_fixed_cache_even_with_plausible_name(case, tmp_path):
    await case.fetcher.fetch(case.selection)
    elsewhere = tmp_path / ("release-" + "ab" * 32)
    elsewhere.mkdir(mode=0o700)
    partial = elsewhere / "release.bundle.partial"
    partial.write_bytes(b"retained outside cache")
    partial.chmod(0o600)
    with case.fetcher._locked(), pytest.raises(delivery.SuccessorDeliveryError, match="outside"):
        case.fetcher._discard_partial(partial, 1024)
    assert partial.read_bytes() == b"retained outside cache"
