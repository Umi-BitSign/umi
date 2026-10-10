"""Real transfer profiles, immutable recovery and native model verification."""

import hashlib
import shutil

import pytest

from umi.competition_artifacts import preserve_bundle, verify_preserved_bundle
from umi.competition_execution import read_case_video
from umi.open_competition import digest

from .cohort_replication_support import Replica
from .test_open_competition import bundle_at
from .test_open_competition import policy as policy


@pytest.mark.parametrize(
    ("profile", "names"),
    [
        ("reward", ["registration/a.json", "objects/b.json", "opportunities/c.json"]),
        (
            "requests",
            [
                "objects/a.json",
                "orders/b/c.json",
                "terminals/d/e.json",
                "partials/f/g/h/00001.json",
                "inventories/f/g/h/0000000000000100-00001-a.json",
            ],
        ),
        (
            "settlement",
            [
                "history/a/b.json",
                "inputs/a-reference.json",
                "inputs/a.json",
                "requests/a/reference_reveal-progress.json",
                "votes/a/b/c.json",
                "quality/a/b/c.json",
                "service/a/b.json",
                "objects/a.json",
            ],
        ),
        (
            "model-evidence",
            [
                "objects/a.json",
                "model-acceptance-proposals/a/b.json",
                "model-reward-acceptances/a/b.json",
                "model-reward-preparation/a/b.json",
            ],
        ),
        ("documents", ["a.json", "a-reference.json"]),
    ],
)
def test_copy_profiles_recover_originals_without_copying_state(tmp_path, profile, names):
    replica = Replica(tmp_path / "tool")
    source, target = tmp_path / "source", tmp_path / "target"
    expected = {name: b'{"original":true}' for name in names}
    excluded = {
        "wallet/key",
        "journal.sqlite3",
        "journal.sqlite3-wal",
        ".pending-a.json",
        "objects/.pending-b.json",
        "objects/.publish.lock",
        "inputs/a.json.partial",
        "suite/references.json",
    }
    for name, data in {**expected, **dict.fromkeys(excluded, b"excluded")}.items():
        path = source / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
    (source / "objects" / "link.json").symlink_to(source / "suite/references.json")
    replica.copy(source, target, profile)
    actual = {
        p.relative_to(target).as_posix(): p.read_bytes() for p in target.rglob("*") if p.is_file()
    }
    assert actual == expected
    assert all(not p.stat().st_mode & 0o077 for p in target.rglob("*"))
    changed = source / names[0]
    changed.write_bytes(b'{"original":false}')
    with pytest.raises(AssertionError):
        replica.copy(source, target, profile)
    assert (target / names[0]).read_bytes() == expected[names[0]]
    changed.write_bytes(expected[names[0]])
    replica.copy(source, target, profile)
    # Producer loss does not delete retained data. A new consumer restores it.
    shutil.rmtree(source)
    replica.copy(source, target, profile)
    recovered = tmp_path / "recovered"
    replica.copy(target, recovered, profile)
    assert {
        p.relative_to(recovered).as_posix(): p.read_bytes() for p in recovered.rglob("*.json")
    } == expected


def test_model_and_video_delivery_restore_native_verified_inputs(tmp_path, policy):
    replica = Replica(tmp_path / "tool")
    p = policy
    bundle = bundle_at(tmp_path / "model")
    # A declared hidden file is legitimate model content, unlike pending roots.
    record = next(r for r in bundle.files if r.role == "config")
    (tmp_path / "model" / record.path).rename(tmp_path / "model" / ".config")
    bundle = bundle.model_copy(
        update={
            "files": tuple(
                sorted(
                    (
                        r.model_copy(update={"path": ".config"}) if r == record else r
                        for r in bundle.files
                    ),
                    key=lambda r: r.path,
                )
            )
        }
    )
    archive, remote, restored = (tmp_path / n for n in ("archive", "remote", "restored"))
    preserve_bundle(bundle, tmp_path / "model", archive, p)
    pending = archive / (".pending-" + digest(bundle))
    pending.mkdir(mode=0o700)
    (pending / "manifest.json").write_bytes(b"partial")
    (archive / "wallet.json").write_bytes(b"unrelated")
    replica.copy(archive, remote, "models")
    shutil.rmtree(archive)
    shutil.rmtree(tmp_path / "model")
    replica.copy(remote, restored, "models")
    assert sorted(x.name for x in restored.iterdir()) == [digest(bundle)]
    verify_preserved_bundle(bundle, restored, p)
    damaged = restored / digest(bundle) / "model" / ".config"
    original = damaged.read_bytes()
    damaged.write_bytes(b"X" * len(original))
    with pytest.raises(ValueError, match="immutable manifest"):
        verify_preserved_bundle(bundle, restored, p)
    damaged.unlink()
    replica.copy(remote, restored, "models")
    verify_preserved_bundle(bundle, restored, p)
    video = b"inert video input"
    key = hashlib.sha256(video).hexdigest()
    videos = tmp_path / "videos"
    videos.mkdir(mode=0o700)
    (videos / (key + ".mp4")).write_bytes(video)
    (videos / (key + ".mp4.partial")).write_bytes(b"partial")
    (videos / "labels.json").write_bytes(b"private")
    imported = tmp_path / "imported-videos"
    replica.copy(videos, imported, "videos")
    assert [f.name for f in imported.iterdir()] == [key + ".mp4"]
    assert read_case_video(imported, key, 1024) == video
