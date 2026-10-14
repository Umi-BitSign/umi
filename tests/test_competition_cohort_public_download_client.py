"""Local HTTP fixtures exercise legacy chunks, C6 ranges and durable recovery."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from umi import competition_cohort_public_download_client as client
from umi.open_competition import ModelBundle, digest

COHORT = "c" * 64
SECRET = "capability-value-must-not-appear-in-logs"
ROLES = ("config", "environment", "inference", "license", "processor", "provenance", "weights")


class Interrupted(BaseException):
    pass


class Fixture:
    def __init__(self, kind="preserved_chunks", weights=None):
        self.kind = kind
        self.contents = {
            f"{i}/{role}.bin": (role.encode() * 3 if role != "license" else b"")
            for i, role in enumerate(ROLES)
        }
        self.contents["6/weights.bin"] = b"weights" * 19 if weights is None else weights
        self.bundle = ModelBundle.model_validate_json(
            json.dumps(
                {
                    "schema": "umi-model-bundle/1",
                    "profile": "offline_bundle/1",
                    "parent_baseline_sha256": None,
                    "license_id": "MIT",
                    "files": [
                        {
                            "path": path,
                            "role": role,
                            "size_bytes": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                        }
                        for (path, data), role in zip(self.contents.items(), ROLES, strict=True)
                    ],
                }
            )
        )
        self.model = digest(self.bundle)
        self.payload = b"".join(self.contents.values())
        self.chunks = {}
        self.downloads = Counter()
        self.metadata_requests = Counter()
        self.expire_once = False
        self.corrupt = False
        self.missing = False
        self.change_on_refresh = False
        self.range_wrong = False
        self.range_ignored = False
        self.encoding = None
        self.oversized = False
        self.manifest_mutator = None
        self.page_mutator = None
        self.generation = 0
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                split = urlsplit(self.path)
                if split.path.endswith("/download"):
                    fixture.metadata_requests["descriptor"] += 1
                    self.reply(200, fixture.descriptor())
                elif split.path.endswith("/download-files"):
                    query = parse_qs(split.query)
                    index, offset = int(query["file_index"][0]), int(query["offset"][0])
                    fixture.metadata_requests[index, offset] += 1
                    self.reply(200, fixture.page(index, offset))
                else:
                    fixture.downloads[split.path, self.headers.get("Range")] += 1
                    if fixture.expire_once:
                        fixture.expire_once = False
                        fixture.generation += 1
                        self.reply(403, {"error": SECRET})
                        return
                    if fixture.missing:
                        self.reply(404, {})
                        return
                    value = (
                        fixture.payload if split.path == "/payload" else fixture.chunks[split.path]
                    )
                    status, headers = 200, {}
                    requested = self.headers.get("Range")
                    if requested and not fixture.range_ignored:
                        first, last = map(int, requested.removeprefix("bytes=").split("-"))
                        headers["Content-Range"] = f"bytes {first}-{last}/{len(value)}"
                        if fixture.range_wrong:
                            headers["Content-Range"] = f"bytes {first + 1}-{last + 1}/{len(value)}"
                        value = value[first : last + 1]
                        status = 206
                    if fixture.corrupt and value:
                        value = bytes([value[0] ^ 1]) + value[1:]
                    if fixture.oversized:
                        value += b"unexpected"
                    if fixture.encoding:
                        headers["Content-Encoding"] = fixture.encoding
                    self.reply(status, value, headers)

            def reply(self, status, body, headers=None):
                content = json.dumps(body).encode() if isinstance(body, dict) else body
                self.send_response(status)
                self.send_header("Content-Length", str(len(content)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(content)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def descriptor(self):
        value = {
            "schema": "umi-public-model-download-response/1",
            "cohort_sha256": COHORT,
            "model_sha256": self.model,
            "format": self.kind,
            "bundle": self.bundle.model_dump(mode="json", by_alias=True),
            "files_url": f"/v1/competition/cohorts/{COHORT}/models/{self.model}/download-files",
            "method": "GET",
            "chain_submission_authorized": False,
            "archive": None,
            "payload": None
            if self.kind == "preserved_chunks"
            else {
                "sha256": hashlib.sha256(self.payload).hexdigest(),
                "size_bytes": len(self.payload),
                "url": f"{self.base}/payload?secret={SECRET}",
            },
        }
        if self.manifest_mutator:
            self.manifest_mutator(value)
        return value

    def page(self, index, offset):
        file = self.bundle.files[index]
        data = self.contents[file.path]
        if self.kind == "preserved_chunks":
            pieces = [
                data[start : start + client.CHUNK_BYTES]
                for start in range(0, len(data), client.CHUNK_BYTES)
            ]
            items = []
            for n, piece in enumerate(pieces):
                path = f"/chunks/{index}-{n}"
                self.chunks[path] = piece
                sha = hashlib.sha256(piece).hexdigest()
                if self.change_on_refresh and self.generation:
                    sha = "0" * 64
                items.append(
                    {
                        "sha256": sha,
                        "size_bytes": len(piece),
                        "url": f"{self.base}{path}?secret={SECRET}&generation={self.generation}",
                    }
                )
        else:
            start = sum(f.size_bytes for f in self.bundle.files[:index])
            items = (
                []
                if not data
                else [
                    {
                        "range_start": start,
                        "size_bytes": len(data),
                        "sha256": file.sha256,
                        "url": f"{self.base}/payload?secret={SECRET}",
                    }
                ]
            )
        total = len(items)
        value = {
            "model_sha256": self.model,
            "file_index": index,
            "file": file.model_dump(),
            "method": "GET",
            "segments": {
                "total": total,
                "offset": offset,
                "next_offset": offset + 128 if offset + 128 < total else None,
                "items": items[offset : offset + 128],
            },
        }
        if self.page_mutator:
            self.page_mutator(value)
        return value

    def download(self, output, **options):
        return client.download_model(self.base, COHORT, self.model, output, **options)

    def assert_model(self, path):
        assert ModelBundle.model_validate_json((path / "manifest.json").read_bytes()) == self.bundle
        for name, data in self.contents.items():
            assert (path / "model" / name).read_bytes() == data


@pytest.fixture
def fixture():
    value = Fixture()
    yield value
    value.close()


@pytest.mark.parametrize("kind", ["preserved_chunks", "concatenated_payload"])
def test_native_bundle_download_and_completed_verdict_reuse(tmp_path, kind, monkeypatch):
    fixture = Fixture(kind)
    events = []
    try:
        if kind == "concatenated_payload":
            monkeypatch.setattr(client, "CHUNK_BYTES", 32)
        target = fixture.download(tmp_path / "output", report=events.append)
        fixture.assert_model(target)
        requested = fixture.downloads.copy()
        # Completed native verification must not reopen model payloads.
        original = Path.open

        def forbid_payload(path, *args, **kwargs):
            if "model" in path.parts or path.suffix == ".part":
                raise AssertionError("completed model bytes reopened")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", forbid_payload)
        fixture.download(target, report=events.append)
        assert fixture.downloads == requested
        assert events[-1]["status"] == "completed"
        assert events[-1]["eta_seconds"] == 0
        assert events[-1]["restored_bytes"] == len(fixture.payload)
        assert all("elapsed_seconds" in e and "eta_basis" in e for e in events)
        assert SECRET not in json.dumps(events)
        for path in (target / ".umi-download").rglob("*"):
            if path.is_file():
                assert SECRET.encode() not in path.read_bytes()
    finally:
        fixture.close()


def test_actual_legacy_eight_mib_geometry_and_chunk_hashes(tmp_path):
    fixture = Fixture(weights=b"w" * (8 * 1024**2 + 37))
    try:
        output = fixture.download(tmp_path / "legacy")
        fixture.assert_model(output)
        assert fixture.downloads["/chunks/6-0", None] == 1
        assert fixture.downloads["/chunks/6-1", None] == 1
    finally:
        fixture.close()


def test_url_expiry_renews_same_piece_without_persisting_secret(fixture, tmp_path, caplog):
    fixture.expire_once = True
    with caplog.at_level(logging.DEBUG):
        output = fixture.download(tmp_path / "renew")
    fixture.assert_model(output)
    assert fixture.downloads["/chunks/0-0", None] == 2
    assert fixture.metadata_requests[0, 0] == 2
    assert SECRET not in caplog.text


@pytest.mark.parametrize(
    "failure", ["missing", "corrupt", "change_on_refresh", "oversized", "encoding"]
)
def test_bad_missing_changed_and_encoded_chunks_fail_closed(fixture, tmp_path, failure):
    setattr(fixture, failure, "gzip" if failure == "encoding" else True)
    fixture.expire_once = failure == "change_on_refresh"
    with pytest.raises(client.PublicDownloadError):
        fixture.download(tmp_path / "bad", refresh_attempts=1)
    assert not (tmp_path / "bad/model/0/config.bin").exists()
    if failure == "change_on_refresh":
        assert sum(fixture.downloads.values()) == 1


def test_interrupted_append_rolls_back_only_pending_piece(tmp_path, monkeypatch):
    fixture = Fixture("concatenated_payload", weights=b"w" * 133)
    monkeypatch.setattr(client, "CHUNK_BYTES", 32)
    save = client.DownloadState.save
    fired = False

    def interrupted(state, index, body):
        nonlocal fired
        if (
            index == 6
            and body["phase"] == "writing"
            and body["pieces"] == 2
            and body["pending"] is None
            and not fired
        ):
            fired = True
            raise Interrupted()
        return save(state, index, body)

    try:
        monkeypatch.setattr(client.DownloadState, "save", interrupted)
        with pytest.raises(Interrupted):
            fixture.download(tmp_path / "resume")
        first = sum(f.size_bytes for f in fixture.bundle.files[:6])
        first_range = f"bytes={first}-{first + 31}"
        pending_range = f"bytes={first + 32}-{first + 63}"
        monkeypatch.setattr(client.DownloadState, "save", save)
        output = fixture.download(tmp_path / "resume")
        fixture.assert_model(output)
        assert fixture.downloads["/payload", first_range] == 1
        assert fixture.downloads["/payload", pending_range] == 2
    finally:
        fixture.close()


def test_publication_interruption_adopts_same_verified_inode(fixture, tmp_path, monkeypatch):
    rename = os.rename
    fired = False

    def interrupted(source, target):
        nonlocal fired
        rename(source, target)
        if str(source).endswith("0.part") and not fired:
            fired = True
            raise Interrupted()

    monkeypatch.setattr(os, "rename", interrupted)
    with pytest.raises(Interrupted):
        fixture.download(tmp_path / "publish")
    target = tmp_path / "publish/model/0/config.bin"
    inode = target.stat().st_ino
    monkeypatch.setattr(os, "rename", rename)
    fixture.download(tmp_path / "publish")
    assert target.stat().st_ino == inode
    assert fixture.downloads["/chunks/0-0", None] == 1


@pytest.mark.parametrize("restore_mtime", [False, True])
def test_interrupted_publication_changed_bytes_require_scoped_repair(
    fixture, tmp_path, monkeypatch, restore_mtime
):
    rename = os.rename
    output = tmp_path / "publish-changed"

    def interrupted(source, target):
        rename(source, target)
        if str(source).endswith("6.part"):
            raise Interrupted()

    monkeypatch.setattr(os, "rename", interrupted)
    with pytest.raises(Interrupted):
        fixture.download(output)
    target = output / "model/6/weights.bin"
    original = target.stat()
    target.write_bytes(b"x" * original.st_size)
    if restore_mtime:
        os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    before = fixture.downloads.copy()
    monkeypatch.setattr(os, "rename", rename)
    with pytest.raises(client.PublicDownloadError, match=r"repair_.*required"):
        fixture.download(output)
    assert fixture.downloads == before
    with sqlite3.connect(output / ".umi-download/state.sqlite3") as db:
        body = json.loads(db.execute("SELECT body FROM files WHERE idx=6").fetchone()[0])
        assert body["phase"] == "publishing"
    fixture.download(output, repair_files=["6/weights.bin"])
    fixture.assert_model(output)
    before["/chunks/6-0", None] += 1
    assert fixture.downloads == before


def test_clock_qualification_precedes_final_native_read(fixture, tmp_path, monkeypatch):
    original_open = Path.open
    qualified = set()
    output = tmp_path / "clock"

    def qualify(ctime_ns, progress):
        paths = set((output / "model").rglob("*.bin")) - qualified
        assert len(paths) == 1
        path = paths.pop()
        assert path.stat().st_ctime_ns == ctime_ns
        qualified.add(path)
        return True

    def checked_open(path, mode="r", *args, **kwargs):
        if "model" in path.parts and mode == "rb":
            assert path in qualified, "native read preceded final identity clock qualification"
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(client, "verification_tick", qualify)
    monkeypatch.setattr(Path, "open", checked_open)
    fixture.download(output)
    assert len(qualified) == len(fixture.bundle.files)


def test_unqualified_clock_keeps_native_checks_without_redownload(fixture, tmp_path, monkeypatch):
    from umi import competition_transport_verification as transport

    monkeypatch.setattr(transport, "_publication_clock_ns", lambda: None)
    events = []
    output = fixture.download(tmp_path / "clock-unqualified", report=events.append)
    before = fixture.downloads.copy()
    events.clear()
    fixture.download(output, report=events.append)
    assert fixture.downloads == before
    native = [
        event
        for event in events
        if event["stage"] == "public_model_native_file_verification"
        and event["status"] == "completed"
    ]
    assert len(native) == len(fixture.bundle.files)
    assert sum(event["completed_bytes"] for event in native) == len(fixture.payload)
    assert any(
        event["reason_code"] == "byte_identity_clock_unqualified_reuse_disabled" for event in events
    )


def test_same_tick_change_during_verification_wait_refuses(fixture, tmp_path, monkeypatch):
    output = tmp_path / "tick-change"

    def mutate_before_check(ctime_ns, progress):
        target = output / "model/0/config.bin"
        info = target.stat()
        assert ctime_ns == info.st_ctime_ns
        target.write_bytes(b"x" * info.st_size)
        os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns))
        return True

    monkeypatch.setattr(client, "verification_tick", mutate_before_check)
    with pytest.raises(client.PublicDownloadError, match="native_digest_invalid"):
        fixture.download(output)
    with sqlite3.connect(output / ".umi-download/state.sqlite3") as db:
        body = json.loads(db.execute("SELECT body FROM files WHERE idx=0").fetchone()[0])
        assert body["phase"] == "publishing"


def test_earlier_file_change_during_later_transfer_prevents_success(fixture, tmp_path, monkeypatch):
    verify = client.DownloadState.verify

    def change_earlier(state, index, body, **options):
        verify(state, index, body, **options)
        if index == 6:
            target = state.path(0, published=True)
            target.write_bytes(b"x" * target.stat().st_size)

    monkeypatch.setattr(client.DownloadState, "verify", change_earlier)
    with pytest.raises(client.PublicDownloadError, match="final_file_changed"):
        fixture.download(tmp_path / "late-change")


def test_changed_completed_file_requires_explicit_scoped_repair(fixture, tmp_path):
    output = fixture.download(tmp_path / "repair")
    before = fixture.downloads.copy()
    file = output / "model/0/config.bin"
    file.write_bytes(b"damaged")
    with pytest.raises(client.PublicDownloadError, match="repair_required"):
        fixture.download(output)
    assert fixture.downloads == before
    fixture.download(output, repair_files=["0/config.bin"])
    fixture.assert_model(output)
    before["/chunks/0-0", None] += 1
    assert fixture.downloads == before


def test_missing_completed_verdict_is_not_cache_miss(fixture, tmp_path):
    output = fixture.download(tmp_path / "missing")
    with sqlite3.connect(output / ".umi-download/state.sqlite3") as db:
        db.execute("DELETE FROM files WHERE idx=0")
    with pytest.raises(client.PublicDownloadError, match="checkpoint_missing"):
        fixture.download(output)
    fixture.download(output, repair_files=["0/config.bin"])
    fixture.assert_model(output)


@pytest.mark.parametrize("wrong", ["range_wrong", "range_ignored"])
def test_c6_range_response_must_match_exact_payload_geometry(tmp_path, wrong):
    fixture = Fixture("concatenated_payload")
    setattr(fixture, wrong, True)
    try:
        with pytest.raises(client.PublicDownloadError):
            fixture.download(tmp_path / "wrong-range")
    finally:
        fixture.close()


def test_c6_corruption_fails_native_file_hash(tmp_path):
    fixture = Fixture("concatenated_payload")
    fixture.corrupt = True
    try:
        with pytest.raises(client.PublicDownloadError, match="native_digest_invalid"):
            fixture.download(tmp_path / "corrupt-range")
    finally:
        fixture.close()


def test_manifest_and_api_endpoint_binding_refused(fixture, tmp_path):
    fixture.manifest_mutator = lambda body: body.update(files_url="https://other.invalid/metadata")
    with pytest.raises(client.PublicDownloadError, match="manifest_invalid"):
        fixture.download(tmp_path / "untrusted")
    assert not (tmp_path / "untrusted").exists()


def test_symlink_and_hardlink_payloads_are_never_followed(fixture, tmp_path):
    output = fixture.download(tmp_path / "safe")
    target = output / "model/0/config.bin"
    outside = tmp_path / "unrelated"
    outside.write_bytes(b"unrelated data")
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises(ValueError):
        fixture.download(output, repair_files=["0/config.bin"])
    assert outside.read_bytes() == b"unrelated data"
    target.unlink()
    os.link(outside, target)
    with pytest.raises(client.PublicDownloadError):
        fixture.download(output, repair_files=["0/config.bin"])
    assert outside.read_bytes() == b"unrelated data"


def test_transport_exception_chain_does_not_disclose_url(fixture):
    def fail(request):
        raise httpx.ConnectError(f"failed {request.url}", request=request)

    with (
        httpx.Client(transport=httpx.MockTransport(fail)) as session,
        pytest.raises(client.PublicDownloadError) as error,
    ):
        client._metadata(session, fixture.base + "/metadata?secret=" + SECRET)
    assert SECRET not in str(error.value)
    assert error.value.__suppress_context__


def test_legacy_pagination_renews_only_current_bounded_page(tmp_path, monkeypatch):
    # Production geometry is covered separately at the real 8MiB boundary.
    # Shrinking the local fixture pieces exercises multiple 128-entry pages.
    monkeypatch.setattr(client, "CHUNK_BYTES", 8)
    fixture = Fixture(weights=b"w" * (8 * 260 + 1))
    try:
        output = fixture.download(tmp_path / "pages")
        fixture.assert_model(output)
        assert fixture.metadata_requests[6, 0] == 1
        assert fixture.metadata_requests[6, 128] == 1
        assert fixture.metadata_requests[6, 256] == 1

    finally:
        fixture.close()


def test_partial_initial_metadata_publication_resumes(fixture, tmp_path, monkeypatch):
    rename = os.rename
    fired = False

    def interrupted(source, target):
        nonlocal fired
        if Path(source).name == "manifest.pending" and not fired:
            fired = True
            raise Interrupted()
        return rename(source, target)

    monkeypatch.setattr(os, "rename", interrupted)
    with pytest.raises(Interrupted):
        fixture.download(tmp_path / "initial")
    assert not fixture.downloads
    monkeypatch.setattr(os, "rename", rename)
    output = fixture.download(tmp_path / "initial")
    fixture.assert_model(output)


def test_partial_initial_database_creation_has_supported_resume(fixture, tmp_path, monkeypatch):
    connect = sqlite3.connect
    fired = False

    def interrupted(*args, **kwargs):
        nonlocal fired
        if not fired:
            fired = True
            raise Interrupted()
        return connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", interrupted)
    with pytest.raises(Interrupted):
        fixture.download(tmp_path / "database-init")
    monkeypatch.setattr(sqlite3, "connect", connect)
    output = fixture.download(tmp_path / "database-init")
    fixture.assert_model(output)


def test_bad_later_chunk_can_retry_without_redownloading_completed_files(fixture, tmp_path):
    def corrupt_late(page):
        if page["file_index"] == 6:
            fixture.corrupt = True

    fixture.page_mutator = corrupt_late
    with pytest.raises(client.PublicDownloadError, match="chunk_digest_invalid"):
        fixture.download(tmp_path / "late")
    before = fixture.downloads.copy()
    fixture.page_mutator, fixture.corrupt = None, False
    output = fixture.download(tmp_path / "late")
    fixture.assert_model(output)
    before["/chunks/6-0", None] += 1
    assert fixture.downloads == before


def test_metadata_traversal_and_nonempty_output_preserve_unrelated_work(fixture, tmp_path):
    def traversal(body):
        body["bundle"]["files"][0]["path"] = "../outside"

    fixture.manifest_mutator = traversal
    with pytest.raises(client.PublicDownloadError):
        fixture.download(tmp_path / "traversal")
    assert not (tmp_path / "traversal").exists()
    fixture.manifest_mutator = None
    root = tmp_path / "user-work"
    root.mkdir(mode=0o700)
    (root / "valuable.txt").write_text("keep this")
    with pytest.raises(client.PublicDownloadError, match="output_not_empty"):
        fixture.download(root)
    assert (root / "valuable.txt").read_text() == "keep this"


def test_missing_or_damaged_database_never_reinitializes_native_verdicts(fixture, tmp_path):
    output = fixture.download(tmp_path / "verdicts")
    database = output / ".umi-download/state.sqlite3"
    before = fixture.downloads.copy()
    database.write_bytes(b"damaged sqlite")
    with pytest.raises(client.PublicDownloadError, match="state_needs_repair"):
        fixture.download(output)
    database.unlink()
    with pytest.raises(client.PublicDownloadError, match="checkpoint_missing"):
        fixture.download(output)
    assert fixture.downloads == before
    fixture.assert_model(output)


def test_concurrent_owner_refuses_without_mutating_checkpoint(fixture, tmp_path):
    output = fixture.download(tmp_path / "locked")
    with httpx.Client() as session:
        descriptor = client.Download.fetch(session, fixture.base, COHORT, fixture.model)
        state = client.DownloadState(output, descriptor)
        before = fixture.downloads.copy()
        try:
            with pytest.raises(client.PublicDownloadError):
                fixture.download(output)
            assert fixture.downloads == before
        finally:
            state.close()


def test_cli_runs_same_safe_download_and_reports_progress(fixture, tmp_path):
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "umi.competition_cohort_public_download_cli",
            "--api",
            fixture.base,
            "--cohort",
            COHORT,
            "--model",
            fixture.model,
            "--output",
            str(tmp_path / "cli"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    fixture.assert_model(tmp_path / "cli")
    events = [json.loads(line) for line in result.stdout.splitlines()]
    assert events[-1]["status"] == "completed"
    assert all("local_available_bytes" in event for event in events)
    assert SECRET not in result.stdout + result.stderr


@pytest.mark.parametrize("kind", ["preserved_chunks", "concatenated_payload"])
def test_actual_public_api_producer_to_client_transport(tmp_path, kind):
    from fastapi.testclient import TestClient

    from umi.competition_cohort_public_api import (
        CohortPublicApiConfig,
        create_cohort_public_app,
        publish_cohort,
    )
    from umi.competition_cohort_public_downloads import PublicModelDownload
    from umi.competition_cohort_public_results import PublicModelCatalog, PublicModelEntry

    from .test_open_competition import wallet

    fixture = Fixture(kind)
    entry = PublicModelEntry(
        submission_sha256="d" * 64,
        model_sha256=fixture.model,
        uid=1,
        hotkey=wallet("Alice").hotkey.ss58_address,
        accepted_terms_sha256="a" * 64,
        license_id=fixture.bundle.license_id,
        file_count=len(fixture.bundle.files),
        total_bytes=len(fixture.payload),
        release="public_release_authorized",
        acceptance_sha256="e" * 64,
    )
    catalog = PublicModelCatalog(
        schema="umi-public-cohort-models/1",
        cohort_sha256=COHORT,
        policy_sha256="1" * 64,
        inventory_sha256="2" * 64,
        inventory_scope="all_admitted_model_submissions",
        items=(entry,),
    )
    declaration = {
        "schema": "umi-public-model-download/1",
        "cohort_sha256": COHORT,
        "model_sha256": fixture.model,
        "bundle": fixture.bundle.model_dump(mode="json", by_alias=True),
        "format": kind,
    }
    if kind == "preserved_chunks":
        declaration.update(
            package_sha256="3" * 64,
            files=[
                {
                    "path": file.path,
                    "chunks": []
                    if not file.size_bytes
                    else [{"sha256": file.sha256, "size_bytes": file.size_bytes}],
                }
                for file in fixture.bundle.files
            ],
        )
        for file in fixture.bundle.files:
            fixture.chunks["/chunkhash/" + file.sha256] = fixture.contents[file.path]
    else:
        declaration["payload"] = {
            "schema": "umi-direct-model-payload/1",
            "upload_sha256": "4" * 64,
            "model_sha256": fixture.model,
            "payload_sha256": hashlib.sha256(fixture.payload).hexdigest(),
            "total_bytes": len(fixture.payload),
            "file_count": len(fixture.bundle.files),
            "part_size_bytes": 8 * 1024**2,
            "total_parts": 1,
        }
    download = PublicModelDownload.model_validate_json(json.dumps(declaration))
    config = CohortPublicApiConfig(results={"directory": str(tmp_path / "public-api")})
    publish_cohort(config, catalog, None, (download,))

    class Signer:
        def presign(self, method, key, **_):
            assert method == "GET"
            path = (
                "/chunkhash/" + key.rsplit("/", 1)[-1] if kind == "preserved_chunks" else "/payload"
            )
            return fixture.base + path + "?secret=" + SECRET

    try:
        app = create_cohort_public_app(config, signer=Signer())
        with TestClient(app) as api, httpx.HTTPTransport() as local_transport:

            def route(request):
                if request.url.host == "api.test":
                    response = api.get(request.url.raw_path.decode())
                    return httpx.Response(
                        response.status_code,
                        headers=response.headers,
                        stream=httpx.ByteStream(response.content),
                    )
                return local_transport.handle_request(request)

            with httpx.Client(transport=httpx.MockTransport(route)) as session:
                output = client.download_model(
                    "https://api.test",
                    COHORT,
                    fixture.model,
                    tmp_path / "api-output",
                    client=session,
                )
            fixture.assert_model(output)
    finally:
        fixture.close()


def test_full_disk_preserves_append_intent_for_retry(fixture, tmp_path, monkeypatch):
    import errno

    transfer = client._transfer

    def full_disk(session, url, stream, *args):
        stream.write(b"partial")
        raise OSError(errno.ENOSPC, "fixture disk full")

    monkeypatch.setattr(client, "_transfer", full_disk)
    events = []
    with pytest.raises(client.PublicDownloadError, match="local_space_unavailable"):
        fixture.download(tmp_path / "space", report=events.append)
    assert events[-1]["reason_code"] == "download_local_space_unavailable_retry_unchanged"
    assert events[-1]["status"] == "retrying"
    monkeypatch.setattr(client, "_transfer", transfer)
    output = fixture.download(tmp_path / "space")
    fixture.assert_model(output)


def test_invalid_request_timeout_is_refused_before_io(tmp_path):
    for value in (float("inf"), float("nan"), 0, -1):
        with pytest.raises(client.PublicDownloadError, match="local_request_options_invalid"):
            client.download_model(
                "https://api.invalid", COHORT, "d" * 64, tmp_path / "unused", timeout=value
            )
    assert not (tmp_path / "unused").exists()
