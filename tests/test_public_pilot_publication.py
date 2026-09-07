from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import umi.public_pilot_archive as archive_module
import umi.public_pilot_publication as publication_module
from umi.protocol import canonical_json_bytes
from umi.public_pilot_archive import create_evidence_archive, extract_evidence_archive
from umi.public_pilot_coordinator import replay_public_endpoint_pilot
from umi.public_pilot_publication import install_public_pilot

from .factories import dev_wallet
from .test_component_run import build_completed_bundle, install_replay_decryptor
from .test_public_pilot_evidence import (
    PILOT_VIDEO_BYTES,
    _attach,
    _campaign_inputs,
    _set_miner_origin,
)


async def _public_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    requests, truth = _campaign_inputs()
    bundle, _ = await build_completed_bundle(
        tmp_path,
        monkeypatch,
        requests=requests,
        truth_override=truth,
        video_bytes=PILOT_VIDEO_BYTES,
    )
    _set_miner_origin(bundle)
    install_replay_decryptor(bundle, monkeypatch)
    _attach(bundle)
    bundle.chmod(0o700)
    return bundle


@pytest.mark.asyncio
async def test_public_pilot_archive_is_deterministic_allowlisted_and_replayable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    first_digest = create_evidence_archive(bundle, first, archive_root="bundle")
    second_digest = create_evidence_archive(bundle, second, archive_root="bundle")

    assert first.read_bytes() == second.read_bytes()
    assert first_digest == second_digest
    extracted = extract_evidence_archive(first, tmp_path / "extracted", archive_root="bundle")
    assert replay_public_endpoint_pilot(extracted)["status"] == "public_endpoint_pilot_replay_ok"

    (bundle / "unexpected").write_text("not referenced", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected top-level"):
        create_evidence_archive(bundle, tmp_path / "rejected.tar.gz", archive_root="bundle")


@pytest.mark.asyncio
async def test_public_pilot_archive_rejects_link_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _public_bundle(tmp_path, monkeypatch)
    malicious = tmp_path / "malicious.tar.gz"
    with tarfile.open(malicious, "w:gz") as archive:
        root = tarfile.TarInfo("bundle")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        objects = tarfile.TarInfo("bundle/objects")
        objects.type = tarfile.DIRTYPE
        archive.addfile(objects)
        manifest = tarfile.TarInfo("bundle/manifest.json")
        manifest.size = 2
        archive.addfile(manifest, io.BytesIO(b"{}"))
        link = tarfile.TarInfo("bundle/objects/" + "a" * 64)
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)

    with pytest.raises(ValueError, match="disallowed member"):
        extract_evidence_archive(malicious, tmp_path / "bad", archive_root="bundle")


@pytest.mark.asyncio
async def test_public_pilot_archive_rejects_trailing_extended_and_amplified_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    canonical = tmp_path / "canonical.tar.gz"
    create_evidence_archive(bundle, canonical, archive_root="bundle")

    trailing = tmp_path / "trailing.tar.gz"
    trailing.write_bytes(canonical.read_bytes() + b"hidden-trailer")
    with pytest.raises(ValueError, match=r"trailing|canonical"):
        extract_evidence_archive(trailing, tmp_path / "trailing-output", archive_root="bundle")

    extended = tmp_path / "extended.tar.gz"
    with tarfile.open(extended, "w:gz", format=tarfile.PAX_FORMAT) as opened:
        root = tarfile.TarInfo("bundle")
        root.type = tarfile.DIRTYPE
        root.pax_headers = {"comment": "extended metadata"}
        opened.addfile(root)
    with pytest.raises(ValueError, match="extended"):
        extract_evidence_archive(extended, tmp_path / "extended-output", archive_root="bundle")

    amplified = tmp_path / "amplified.tar.gz"
    import gzip

    amplified.write_bytes(gzip.compress(b"x" * 2048))
    monkeypatch.setattr(archive_module, "MAX_PUBLIC_PILOT_UNCOMPRESSED_ARCHIVE_BYTES", 1024)
    with pytest.raises(ValueError, match="uncompressed"):
        extract_evidence_archive(amplified, tmp_path / "amplified-output", archive_root="bundle")


@pytest.mark.asyncio
async def test_public_pilot_publication_is_locked_append_only_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    coordinator_hotkey = replay_public_endpoint_pilot(bundle)["coordinator_hotkey"]
    publication_root = tmp_path / "published"
    publication_root.mkdir(mode=0o700)
    config = tmp_path / "observer-pilot-feed.json"
    lock = tmp_path / "publication.lock"

    first = install_public_pilot(
        bundle,
        publication_root=publication_root,
        config_path=config,
        lock_path=lock,
        public_origin="https://api.umi.vision",
        expected_coordinator_hotkey=coordinator_hotkey,
    )
    second = install_public_pilot(
        bundle,
        publication_root=publication_root,
        config_path=config,
        lock_path=lock,
        public_origin="https://api.umi.vision",
        expected_coordinator_hotkey=coordinator_hotkey,
    )

    assert first.already_installed is False
    assert second.already_installed is True
    assert first.pilot_id == second.pilot_id
    assert first.configured_pilot_ids == (first.pilot_id,)
    assert (
        replay_public_endpoint_pilot(publication_root / first.pilot_id)["bundle_manifest_sha256"]
        == first.pilot_id
    )


def test_publication_retry_does_not_reinterpret_original_backup_as_a_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pilot_id = "11" * 32
    prior_pilot_id = "22" * 32
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    publication_root = tmp_path / "published"
    publication_root.mkdir(mode=0o700)
    config = tmp_path / "observer-pilot-feed.json"
    decoded = publication_module._base_config("https://api.umi.vision")
    prior_root = str(tmp_path / "prior-pilot")
    decoded["bundle_roots"] = [prior_root]
    initial_config = canonical_json_bytes(decoded)
    config.write_bytes(initial_config)

    def replay(_root: Path, _expected_coordinator_hotkey: str) -> dict[str, object]:
        return {"bundle_manifest_sha256": pilot_id}

    def copy_tree(
        _source: Path,
        destination: Path,
        *,
        expected_coordinator_hotkey: str,
    ) -> None:
        assert expected_coordinator_hotkey
        destination.mkdir(mode=0o700)

    def build_feed(path: Path) -> SimpleNamespace:
        document = json.loads(path.read_bytes())
        pilots = tuple(
            SimpleNamespace(pilot_id=prior_pilot_id if root == prior_root else pilot_id)
            for root in document["bundle_roots"]
        )
        return SimpleNamespace(pilots=pilots)

    monkeypatch.setattr(publication_module, "_replay_for_coordinator", replay)
    monkeypatch.setattr(publication_module, "_copy_verified_tree", copy_tree)
    monkeypatch.setattr(publication_module, "build_observer_pilot_feed", build_feed)
    arguments = {
        "publication_root": publication_root,
        "config_path": config,
        "lock_path": tmp_path / "publication.lock",
        "public_origin": "https://api.umi.vision",
        "expected_coordinator_hotkey": dev_wallet("//Coordinator").hotkey.ss58_address,
    }

    first = install_public_pilot(source, **arguments)
    backup = config.with_name(f"{config.name}.before-{pilot_id}")
    second = install_public_pilot(source, **arguments)

    assert first.already_installed is False
    assert second.already_installed is True
    assert backup.read_bytes() == initial_config
    assert second.configured_pilot_ids == (prior_pilot_id, pilot_id)


@pytest.mark.asyncio
async def test_public_pilot_publication_rejects_another_coordinator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    publication_root = tmp_path / "published"
    publication_root.mkdir(mode=0o700)

    with pytest.raises(ValueError, match="configured coordinator"):
        install_public_pilot(
            bundle,
            publication_root=publication_root,
            config_path=tmp_path / "observer-pilot-feed.json",
            lock_path=tmp_path / "publication.lock",
            public_origin="https://api.umi.vision",
            expected_coordinator_hotkey=dev_wallet("//AnotherPilotCoordinator").hotkey.ss58_address,
        )

    assert not any(publication_root.iterdir())
