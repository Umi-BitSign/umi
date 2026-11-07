"""Tiny prospective bound/reuse cases; these do not qualify native RSS budgets."""

import asyncio
import hashlib
import json
import os
import sqlite3
from copy import deepcopy
from functools import partial
from pathlib import Path

import pytest

from umi import host_memory_request_bounds as legacy
from umi import host_memory_workload_profile as workload

from .test_host_memory_admission import provisioned as provisioned


def profile_body(
    tmp_path,
    protocol_policy_sha256="1" * 64,
    evaluation_runtime_sha256="2" * 64,
    series_sha256=None,
    authority_sha256=None,
):
    directory = tmp_path / "workload-counts"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    return dict(
        schema="umi-host-memory-workload-profile/1",
        roles=["intake", "phase_reviewer", "settlement"],
        protocol_policy_sha256=protocol_policy_sha256,
        evaluation_runtime_sha256=evaluation_runtime_sha256,
        series_sha256=series_sha256,
        authority_sha256=authority_sha256,
        qualification_sha256="3" * 64,
        maximum_queued_input_bytes=1024**2,
        maximum_http_inflight=2,
        maximum_preparation_workers=2,
        maximum_receipt_entries=32,
        receipt_directories={str(os.getuid()): str(directory)},
        bounds=dict(
            maximum_records=2,
            maximum_objects=3,
            maximum_services=2,
            maximum_orders=2,
            maximum_inventory_entries=2,
            maximum_participants=2,
            maximum_catalogs=2,
            maximum_input_bytes=1024**2,
            maximum_object_bytes=16384,
            maximum_declaration_bytes=65536,
            maximum_json_values=128,
            maximum_json_depth=8,
        ),
    )


def write_profile(path, body):
    if path.exists():
        path.chmod(0o600)
    raw = json.dumps(body).encode()
    path.write_bytes(raw)
    path.chmod(0o440)
    return workload.WorkloadProfileSelection(path=str(path), sha256=hashlib.sha256(raw).hexdigest())


@pytest.fixture
def profile(tmp_path, provisioned):
    body = profile_body(tmp_path)
    selection = write_profile(tmp_path / "workload-profile.json", body)
    binding = dict(
        role="phase_reviewer",
        protocol_policy_sha256=body["protocol_policy_sha256"],
        evaluation_runtime_sha256=body["evaluation_runtime_sha256"],
        series_sha256=None,
        authority_sha256=None,
    )
    loaded = workload.load_workload_profile(selection, binding)
    return loaded, selection, binding, body


def identity(raw, revision="original"):
    return workload.trusted_workload_identity(
        "authenticated-test-snapshot", {"revision": revision, "stamp": [1, 2, 3]}, len(raw)
    )


def test_profile_selection_requires_root_file_and_exact_scope(profile):
    loaded, selected, binding, _ = profile
    assert loaded.role == "phase_reviewer"
    for name in (
        "protocol_policy_sha256",
        "evaluation_runtime_sha256",
        "series_sha256",
        "authority_sha256",
    ):
        with pytest.raises(workload.WorkloadQualificationPending, match="scope"):
            workload.load_workload_profile(selected, dict(binding, **{name: "9" * 64}))
    with pytest.raises(workload.WorkloadQualificationPending, match="scope"):
        workload.load_workload_profile(selected, dict(binding, role="reward_writer"))
    with pytest.raises(workload.WorkloadQualificationPending, match="selection"):
        workload.load_workload_profile(selected.model_copy(update={"sha256": "0" * 64}), binding)
    Path(selected.path).chmod(0o640)
    with pytest.raises(
        (ValueError, workload.WorkloadQualificationPending), match=r"immutable|profile"
    ):
        workload.load_workload_profile(selected, binding)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"objects":[1,2,3,4]}',
        b'{"records":[1,2,3]}',
        b"[" * 9 + b"0" + b"]" * 9,
        json.dumps(list(range(128))).encode(),
        b'{"broken":[1,}',
    ],
)
def test_predecode_refusal_is_pending_not_quality_value_error(profile, raw):
    with (
        workload.workload_runtime(profile[0]),
        pytest.raises(workload.WorkloadQualificationPending) as caught,
    ):
        workload.check_workload_input(raw)
    assert isinstance(caught.value, OSError)
    assert not isinstance(caught.value, ValueError)
    assert caught.value.reason_code == "workload_qualification_pending"


def test_kind_byte_bounds_precede_scanner(profile, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("over-limit bytes reached JSON scanner")

    monkeypatch.setattr(workload, "count_json_shape", forbidden)
    with (
        workload.workload_runtime(profile[0]),
        pytest.raises(workload.WorkloadQualificationPending, match="byte_bound"),
    ):
        workload.check_workload_input(b" " * 16385, "object")


def test_warm_native_identity_reuses_durable_count_without_payload_hash_or_scan(
    profile, monkeypatch
):
    loaded, selection, binding, _ = profile
    raw = b'{"records":[{"result":"unchanged"}]}'
    trusted = identity(raw)
    with workload.workload_runtime(loaded):
        expected = workload.check_workload_input(raw, identity=trusted)
    native_hash = hashlib.sha256

    def no_payload_hash(value=b"", *args, **kwargs):
        assert value != raw, "unchanged payload was hashed"
        return native_hash(value, *args, **kwargs)

    def no_scan(*args, **kwargs):
        pytest.fail("unchanged authenticated input was rescanned")

    monkeypatch.setattr(workload.hashlib, "sha256", no_payload_hash)
    monkeypatch.setattr(workload, "count_json_shape", no_scan)
    restarted = workload.load_workload_profile(selection, binding)
    with workload.workload_runtime(restarted):
        assert workload.check_workload_input(raw, identity=trusted) == expected


def test_new_native_identity_is_checked_once_and_changed_profile_is_separate(profile, monkeypatch):
    loaded, selection, binding, body = profile
    raw = b'{"records":[1,2]}'
    scans = []
    native = workload.count_json_shape

    def counted(data, **kwargs):
        scans.append(data)
        return native(data, **kwargs)

    monkeypatch.setattr(workload, "count_json_shape", counted)
    with workload.workload_runtime(loaded):
        for revision in ("a", "a", "b", "b"):
            workload.check_workload_input(raw, identity=identity(raw, revision))
    assert len(scans) == 2
    body["bounds"]["maximum_records"] = 3
    updated = write_profile(Path(selection.path), body)
    with workload.workload_runtime(workload.load_workload_profile(updated, binding)):
        workload.check_workload_input(raw, identity=identity(raw, "a"))
    assert len(scans) == 3


def test_raw_caller_digest_is_not_reuse_authority(profile):
    raw = b"[1,2,3]"
    with workload.workload_runtime(profile[0]):
        with pytest.raises(workload.WorkloadQualificationPending, match="untrusted"):
            workload.check_workload_input(raw, identity={"sha256": hashlib.sha256(raw).hexdigest()})
        with pytest.raises(workload.WorkloadQualificationPending, match="changed"):
            workload.check_workload_input(raw, identity=identity(raw + b" "))


def test_complete_graph_budget_counts_native_identity_once_and_refuses_other_input(profile):
    raw = json.dumps(list(range(80))).encode()
    first, second = identity(raw, "first"), identity(raw, "second")
    with workload.workload_runtime(profile[0]), workload.workload_input_budget():
        count = workload.check_workload_input(raw, identity=first)
        assert count == 81
        assert workload.check_workload_input(raw, identity=first) == count
        with pytest.raises(workload.WorkloadQualificationPending, match="aggregate"):
            workload.check_workload_input(raw, identity=second)
    with workload.workload_runtime(profile[0]), workload.workload_input_budget():
        assert workload.check_workload_input(raw, identity=second) == count


@pytest.mark.parametrize("damage", ["missing_count", "modified_count", "missing_database"])
def test_damaged_completion_is_explicit_repair_not_rescan(profile, monkeypatch, damage):
    loaded = profile[0]
    raw = b"[1,2,3]"
    trusted = identity(raw)
    with workload.workload_runtime(loaded):
        workload.check_workload_input(raw, identity=trusted)
    if damage == "missing_database":
        loaded.counts.path.unlink()
    else:
        with sqlite3.connect(loaded.counts.path) as db:
            if damage == "missing_count":
                db.execute("DELETE FROM counts")
            else:
                db.execute("UPDATE counts SET body=?", (b"{}",))
    monkeypatch.setattr(
        workload, "count_json_shape", lambda *a, **kw: pytest.fail("repair rescanned payload")
    )
    with workload.workload_runtime(loaded), pytest.raises(workload.WorkloadQualificationPending):
        workload.check_workload_input(raw, identity=trusted)


def test_receipt_limit_does_not_evict_completed_work(profile):
    loaded = profile[0]
    loaded.counts.maximum = 1
    raw = b"[1]"
    with workload.workload_runtime(loaded):
        workload.check_workload_input(raw, identity=identity(raw, "a"))
        with pytest.raises(workload.WorkloadQualificationPending, match="capacity"):
            workload.check_workload_input(raw, identity=identity(raw, "b"))
        assert workload.check_workload_input(raw, identity=identity(raw, "a")) == 2


def test_legacy_shape_and_native_verification_contexts_are_unchanged(profile, monkeypatch):
    # Selecting prospective bounds must not alter the context hash used by
    # completed native proof/shape receipts, including unbounded legacy readers.
    before = legacy.stage_shape_identity()
    assert legacy.stage_bounds() is None
    with workload.workload_runtime(profile[0]), workload.workload_input_budget():
        assert legacy.stage_bounds() is None
        assert legacy.stage_shape_identity() == before
        assert workload.check_workload_input(b"[1]") == 2
    assert legacy.stage_shape_identity() == before


@pytest.mark.asyncio
async def test_explicit_runtime_propagates_to_owned_tasks_and_threads(profile):
    from umi.concurrency import run_owned_thread

    async def child():
        assert workload.selected_workload() is profile[0]
        return await run_owned_thread(workload.check_workload_input, b"[1]")

    with workload.workload_runtime(profile[0]):
        assert await asyncio.create_task(child()) == 2
    assert workload.selected_workload() is None


def test_no_profile_preserves_legacy_reader_behavior():
    assert workload.check_workload_input(b"legacy input is not scanned") is None


def test_receipt_ancestry_must_be_protected_not_merely_without_symlinks(profile, tmp_path):
    _, selection, binding, body = profile
    unsafe = tmp_path / "writable-parent"
    unsafe.mkdir(mode=0o770)
    unsafe.chmod(0o770)
    leaf = unsafe / "private"
    leaf.mkdir(mode=0o700)
    body["receipt_directories"] = {str(os.getuid()): str(leaf)}
    updated = write_profile(Path(selection.path), body)
    with pytest.raises(workload.WorkloadQualificationPending, match="ancestry"):
        workload.load_workload_profile(updated, binding)


def test_preparation_worker_bound_must_be_explicit_and_positive(profile):
    _, _, _, body = profile
    for value in (None, 0, -1, 65, True):
        candidate = dict(body, maximum_preparation_workers=value)
        with pytest.raises(ValueError):
            workload.WorkloadProfile.model_validate(candidate)
    candidate = dict(body)
    del candidate["maximum_preparation_workers"]
    with pytest.raises(ValueError):
        workload.WorkloadProfile.model_validate(candidate)


@pytest.mark.asyncio
async def test_owned_threads_share_atomic_budget_and_do_not_oversubscribe(profile):
    from umi.concurrency import run_owned_thread

    loaded = profile[0]
    raw = json.dumps(list(range(80))).encode()
    with workload.workload_runtime(loaded), workload.workload_input_budget():
        results = await asyncio.gather(
            *(
                run_owned_thread(
                    partial(workload.check_workload_input, raw, identity=identity(raw, str(i)))
                )
                for i in range(4)
            ),
            return_exceptions=True,
        )
    assert results.count(81) == 1
    assert sum(isinstance(result, workload.WorkloadQualificationPending) for result in results) == 3


@pytest.mark.asyncio
async def test_independent_loaded_stores_serialize_first_scan_and_keep_completion(
    profile, monkeypatch
):
    from umi.concurrency import run_owned_thread

    loaded, selected, binding, _ = profile
    profiles = [loaded, workload.load_workload_profile(selected, binding)]
    raw = b'{"records":[1,2]}'
    trusted = identity(raw)
    scans = []
    original = workload.count_json_shape

    def counted(data, **kwargs):
        scans.append(data)
        return original(data, **kwargs)

    monkeypatch.setattr(workload, "count_json_shape", counted)

    async def one(index):
        with workload.workload_runtime(profiles[index % 2]), workload.workload_input_budget():
            return await run_owned_thread(
                partial(workload.check_workload_input, raw, identity=trusted)
            )

    results = await asyncio.gather(*(one(i) for i in range(8)))
    assert len(set(results)) == 1
    assert scans == [raw]


@pytest.mark.parametrize("aggregate", [False, True])
def test_private_and_aggregate_readers_refuse_before_model_decode(profile, tmp_path, aggregate):
    from umi.competition_cohort_aggregate_files import read_aggregate_model
    from umi.private_files import read_private_model

    class ForbiddenDecode:
        @staticmethod
        def model_validate_json(raw):
            pytest.fail("unqualified graph reached typed decoding")

    path = tmp_path / "oversized-graph.json"
    path.write_bytes(b'{"records":[1,2,3]}')
    path.chmod(0o600)
    read = read_aggregate_model if aggregate else read_private_model
    with (
        workload.workload_runtime(profile[0]),
        pytest.raises(workload.WorkloadQualificationPending),
    ):
        read(path, ForbiddenDecode, maximum_bytes=1024**2)


def test_private_generation_reuse_and_changed_file_rescan(profile, tmp_path, monkeypatch):
    from umi.private_files import read_private_model
    from umi.protocol import StrictProtocolModel

    class Record(StrictProtocolModel):
        records: tuple[int, ...]

    path = tmp_path / "retained.json"
    path.write_bytes(b'{"records":[1,2]}')
    path.chmod(0o600)
    scans = []
    original = workload.count_json_shape

    def counted(data, **kwargs):
        scans.append(data)
        return original(data, **kwargs)

    monkeypatch.setattr(workload, "count_json_shape", counted)
    with workload.workload_runtime(profile[0]):
        assert read_private_model(path, Record).records == (1, 2)
        assert read_private_model(path, Record).records == (1, 2)
        assert len(scans) == 1
        path.write_bytes(b'{"records":[2,3]}')
        assert read_private_model(path, Record).records == (2, 3)
    assert len(scans) == 2


def test_private_stat_generation_preserves_nanoseconds_outside_json_integer_domain(
    profile, tmp_path, monkeypatch
):
    from umi.private_files import _read_bounded_private_bytes

    path = tmp_path / "nanosecond-identity.json"
    raw = b"[1]"
    path.write_bytes(raw)
    path.chmod(0o600)
    timestamp = 1_793_597_954_387_064_935
    os.utime(path, ns=(timestamp, timestamp))
    identities = []
    original = workload.trusted_workload_identity

    def capture(namespace, metadata, size):
        identities.append(metadata)
        return original(namespace, metadata, size)

    monkeypatch.setattr(workload, "trusted_workload_identity", capture)
    with workload.workload_runtime(profile[0]):
        assert _read_bounded_private_bytes(path, maximum_bytes=1024, workload_kind="input") == raw
        os.utime(path, ns=(timestamp, timestamp + 1))
        assert _read_bounded_private_bytes(path, maximum_bytes=1024, workload_kind="input") == raw
    assert all(type(value) is str for metadata in identities for value in metadata[1])
    assert identities[0][1][-2] == str(timestamp)
    assert identities[1][1][-2] == str(timestamp + 1)
    assert identities[0] != identities[1]


@pytest.mark.asyncio
async def test_review_ingress_reports_pending_before_schema_decoding(profile):
    from fastapi import HTTPException, Request

    from umi.competition_cohort_review_http import phase_review_routes

    from .test_host_memory_admission import Exporter

    class ForbiddenDecode:
        @staticmethod
        def model_validate_json(raw):
            pytest.fail("unqualified request reached typed decoding")

    async def receive():
        return dict(type="http.request", body=b'{"records":[1,2,3]}', more_body=False)

    request = Request(
        dict(
            type="http",
            method="POST",
            path="/export",
            headers=[
                (b"authorization", b"Bearer " + b"s" * 32),
                (b"content-type", b"application/json"),
            ],
        ),
        receive,
    )
    exporter = Exporter()
    router = phase_review_routes(
        exporter, token="s" * 32, path="/export", request_model=ForbiddenDecode
    )
    with workload.workload_runtime(profile[0]), pytest.raises(HTTPException) as caught:
        await router.routes[0].endpoint(request)
    assert caught.value.status_code == 503
    assert exporter.calls == 0


def test_legacy_profile_serialization_preserves_exact_fields(profile):
    assert profile[0].profile.model_dump(mode="json", by_alias=True) == profile[3]


def test_http_only_profile_reuses_original_counts_across_restart_and_later_selection(
    profile, tmp_path, monkeypatch
):
    loaded, original, binding, body = profile
    raw = b'{"records":[{"result":"unchanged"}]}'
    trusted = identity(raw)
    with workload.workload_runtime(loaded):
        count = workload.check_workload_input(raw, identity=trusted)
    native_hash = hashlib.sha256

    def no_payload_hash(value=b"", *args, **kwargs):
        assert value != raw
        return native_hash(value, *args, **kwargs)

    monkeypatch.setattr(workload.hashlib, "sha256", no_payload_hash)
    monkeypatch.setattr(
        workload, "count_json_shape", lambda *a, **k: pytest.fail("completed input rescanned")
    )
    for inflight in (3, 4):
        candidate = dict(
            body,
            maximum_http_inflight=inflight,
            maximum_queued_input_bytes=inflight * body["maximum_queued_input_bytes"],
            qualification_sha256=str(inflight) * 64,
            count_reuse_profile=original.model_dump(),
        )
        selected = write_profile(tmp_path / f"http-{inflight}.json", candidate)
        for _ in range(2):
            restarted = workload.load_workload_profile(selected, binding)
            assert restarted.sha256 == selected.sha256 != original.sha256
            assert restarted.count_profile_sha256 == original.sha256
            with workload.workload_runtime(restarted):
                assert workload.check_workload_input(raw, identity=trusted) == count


@pytest.mark.parametrize(
    "field",
    [
        "bounds",
        "receipt_directories",
        "maximum_receipt_entries",
        "roles",
        "maximum_preparation_workers",
    ],
)
def test_http_count_reuse_refuses_changed_non_http_dependencies(profile, tmp_path, field):
    _, original, binding, body = profile
    candidate = deepcopy(body)
    candidate["count_reuse_profile"] = original.model_dump()
    if field == "bounds":
        candidate[field]["maximum_records"] += 1
    elif field == "receipt_directories":
        candidate[field][str(os.getuid())] = str(tmp_path / "other-counts")
    elif field == "roles":
        candidate[field] = ["phase_reviewer"]
    else:
        candidate[field] += 1
    selected = write_profile(tmp_path / "changed.json", candidate)
    with pytest.raises(workload.WorkloadQualificationPending, match="dependencies_changed"):
        workload.load_workload_profile(selected, binding)


def test_http_count_reuse_refuses_changed_original_and_reference_chains(profile, tmp_path):
    _, original, binding, body = profile
    successor_body = dict(body, count_reuse_profile=original.model_dump(), maximum_http_inflight=3)
    successor = write_profile(tmp_path / "successor.json", successor_body)
    chained = write_profile(
        tmp_path / "chained.json", dict(body, count_reuse_profile=successor.model_dump())
    )
    with pytest.raises(workload.WorkloadQualificationPending, match="dependencies_changed"):
        workload.load_workload_profile(chained, binding)
    write_profile(Path(original.path), dict(body, qualification_sha256="9" * 64))
    with pytest.raises(workload.WorkloadQualificationPending, match="profile_changed"):
        workload.load_workload_profile(successor, binding)


def test_http_count_reuse_keeps_damaged_completion_an_explicit_repair(
    profile, tmp_path, monkeypatch
):
    loaded, original, binding, body = profile
    raw = b"[1]"
    with workload.workload_runtime(loaded):
        workload.check_workload_input(raw, identity=identity(raw))
    with sqlite3.connect(loaded.counts.path) as db:
        db.execute("DELETE FROM counts")
    selected = write_profile(
        tmp_path / "http.json",
        dict(body, count_reuse_profile=original.model_dump(), maximum_http_inflight=3),
    )
    monkeypatch.setattr(
        workload, "count_json_shape", lambda *a, **k: pytest.fail("repair rescanned")
    )
    with (
        workload.workload_runtime(workload.load_workload_profile(selected, binding)),
        pytest.raises(workload.WorkloadQualificationPending),
    ):
        workload.check_workload_input(raw, identity=identity(raw))
