from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi.public_pilot_campaign import CAMPAIGN_ID
from umi.public_pilot_github import (
    PublicPilotCaseReadyResult,
    public_pilot_automation_result_envelope,
)
from umi.public_pilot_upload import (
    UPLOAD_AUTHENTICATION_DOMAIN,
    load_hex_secret,
    upload_public_pilot_file,
    upload_public_pilot_result,
)

_MINER = "5CY4Y4S1AJpbj87CJpy7hyMrw1E4RZ8XKX7cszRpBHLzyqqK"
_COORDINATOR = "5GsPXiSyzpK3rRoeAmjT4F5Cqa1RmP1CyBvNpwNDsDejyNZ4"


def test_public_pilot_upload_authenticates_and_verifies_public_readback(tmp_path: Path) -> None:
    body = b"immutable sealed case"
    source = tmp_path / "sealed-case.tar.gz"
    source.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    secret = bytes.fromhex("42" * 32)
    path = f"/public-pilot-cases/{digest}/sealed-case.tar.gz"

    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            assert request.url == f"https://upload.example{path}"
            assert request.headers["content-length"] == str(len(body))
            assert request.headers["content-type"] == "application/gzip"
            assert request.headers["x-umi-content-sha256"] == digest
            timestamp = request.headers["x-umi-timestamp"]
            message = b"\n".join(
                (
                    UPLOAD_AUTHENTICATION_DOMAIN,
                    b"PUT",
                    path.encode(),
                    timestamp.encode(),
                    str(len(body)).encode(),
                    b"application/gzip",
                    digest.encode(),
                )
            )
            assert request.headers["authorization"] == (
                "UMI-HMAC-SHA256 " + hmac.new(secret, message, hashlib.sha256).hexdigest()
            )
            assert request.read() == body
            return httpx.Response(201, json={"status": "created"})
        assert request.method == "GET"
        assert request.url == f"https://public.example{path}"
        return httpx.Response(
            200,
            stream=httpx.ByteStream(body),
            headers={"Content-Length": str(len(body))},
        )

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        result = upload_public_pilot_file(
            source,
            path=path,
            content_type="application/gzip",
            maximum_bytes=1024,
            upload_origin="https://upload.example",
            public_origin="https://public.example",
            secret=secret,
            client=client,
            timestamp=1_788_609_600,
        )

    assert result == (digest, len(body), f"https://public.example{path}")


def test_public_pilot_upload_accepts_conflict_only_after_exact_readback(tmp_path: Path) -> None:
    body = b"expected immutable bytes"
    source = tmp_path / "evidence.tar.gz"
    source.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    path = f"/public-pilot-evidence/{digest}/evidence.tar.gz"

    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            request.read()
            return httpx.Response(409, json={"error": "object_exists"})
        return httpx.Response(200, stream=httpx.ByteStream(b"different immutable bytes"))

    with (
        httpx.Client(transport=httpx.MockTransport(handle)) as client,
        pytest.raises(RuntimeError, match="readback"),
    ):
        upload_public_pilot_file(
            source,
            path=path,
            content_type="application/gzip",
            maximum_bytes=1024,
            upload_origin="https://upload.example",
            public_origin="https://public.example",
            secret=bytes.fromhex("24" * 32),
            client=client,
            timestamp=1_788_609_600,
        )


def test_public_pilot_secret_loader_requires_owner_only_regular_file(tmp_path: Path) -> None:
    secret_file = tmp_path / "upload.secret"
    secret_file.write_text("ab" * 32 + "\n")
    secret_file.chmod(0o600)
    assert load_hex_secret(secret_file) == bytes.fromhex("ab" * 32)

    secret_file.chmod(0o640)
    with pytest.raises(ValueError, match="unsafe"):
        load_hex_secret(secret_file)

    secret_file.chmod(0o600)
    alias = tmp_path / "alias.secret"
    os.link(secret_file, alias)
    with pytest.raises(ValueError, match="unsafe"):
        load_hex_secret(secret_file)


def test_public_pilot_secret_loader_accepts_only_scoped_systemd_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential_directory = tmp_path / "credentials"
    credential_directory.mkdir()
    secret_file = credential_directory / "upload.secret"
    secret_file.write_text("ab" * 32 + "\n")
    secret_file.chmod(0o600)
    original_fstat = os.fstat
    systemd_metadata = {"mode": 0o440, "uid": 0, "gid": 0}

    def systemd_fstat(descriptor: int) -> SimpleNamespace:
        metadata = original_fstat(descriptor)
        return SimpleNamespace(
            st_mode=(metadata.st_mode & ~0o777) | systemd_metadata["mode"],
            st_nlink=metadata.st_nlink,
            st_uid=systemd_metadata["uid"],
            st_gid=systemd_metadata["gid"],
            st_size=metadata.st_size,
        )

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_directory))
    monkeypatch.setattr(os, "fstat", systemd_fstat)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert load_hex_secret(secret_file) == bytes.fromhex("ab" * 32)

    systemd_metadata["mode"] = 0o400
    assert load_hex_secret(secret_file) == bytes.fromhex("ab" * 32)
    systemd_metadata["mode"] = 0o440

    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    with pytest.raises(ValueError, match="unsafe"):
        load_hex_secret(secret_file)

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "credentials")
    with pytest.raises(ValueError, match="unsafe"):
        load_hex_secret(secret_file)

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "other-credentials"))
    with pytest.raises(ValueError, match="unsafe"):
        load_hex_secret(secret_file)

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_directory))
    for field, unsafe_value in (("mode", 0o640), ("mode", 0o444), ("uid", 1), ("gid", 1)):
        original_value = systemd_metadata[field]
        systemd_metadata[field] = unsafe_value
        with pytest.raises(ValueError, match="unsafe"):
            load_hex_secret(secret_file)
        systemd_metadata[field] = original_value


def test_result_upload_authenticates_envelope_and_path_binding() -> None:
    result_key = bytes.fromhex("31" * 32)
    payload = PublicPilotCaseReadyResult.model_validate(
        {
            "schema": "umi-public-pilot-automation-result/1",
            "authorization_id": "11" * 32,
            "action": "ready_for_case",
            "repository_id": 1_348_567_807,
            "repository_full_name": "Umi-BitSign/umi",
            "issue_id": 1,
            "issue_node_id": "I_node",
            "issue_number": 1,
            "campaign_id": CAMPAIGN_ID,
            "umi_revision": "ab" * 20,
            "coordinator_hotkey": _COORDINATOR,
            "miner_hotkey": _MINER,
            "expected_miner_uid": 249,
            "completed_at": "2026-09-07T20:00:00Z",
            "status": "case_ready",
            "case_manifest_sha256": "22" * 32,
            "case_archive_sha256": "33" * 32,
            "case_archive_size_bytes": 123,
            "case_archive_url": (
                f"https://public.example/public-pilot-cases/{'33' * 32}/sealed-case.tar.gz"
            ),
            "expected_origin": "https://8.8.8.8:443",
            "response_close_round": 100,
            "reveal_round": 101,
            "response_close_at": "2026-09-07T21:00:00Z",
            "reveal_at": "2026-09-07T21:05:00Z",
        }
    )
    body = public_pilot_automation_result_envelope(payload, hmac_key=result_key)

    with pytest.raises(ValueError, match="another authorization"):
        upload_public_pilot_result(
            body,
            authorization_id="44" * 32,
            result_hmac_key=result_key,
            upload_origin="https://upload.example",
            public_origin="https://public.example",
            secret=bytes.fromhex("42" * 32),
        )

    corrupted = body[:-2] + b"x}"
    with pytest.raises(ValueError, match="invalid public-pilot automation result"):
        upload_public_pilot_result(
            corrupted,
            authorization_id="11" * 32,
            result_hmac_key=result_key,
            upload_origin="https://upload.example",
            public_origin="https://public.example",
            secret=bytes.fromhex("42" * 32),
        )
