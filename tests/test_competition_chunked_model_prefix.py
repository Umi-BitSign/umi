"""Installed preservation namespaces survive verification, retry and cold reuse."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from umi.competition_chunked_model_backup import ChunkedBackupBinding, ChunkedModelBackupReader
from umi.protocol import canonical_json_bytes

from .test_competition_chunked_model_backup import (
    other_cohort,
    reader,
    restore,
    selected,
    selection,
)
from .test_open_competition import policy as policy

PREFIX = "preservation/v1/"


def test_omitted_prefix_preserves_old_binding_bytes_and_namespace(policy, tmp_path):
    case = selected(policy)
    raw = canonical_json_bytes(case.binding)
    assert b"object_key_prefix" not in raw
    assert canonical_json_bytes(ChunkedBackupBinding.model_validate_json(raw)) == raw
    assert reader(case, tmp_path)._namespace() == {
        "endpoint": case.binding.endpoint,
        "bucket": case.binding.bucket,
    }


@pytest.mark.parametrize(
    "prefix", ["/root/", "../", "a/../", "a//", "a", "a?x/", "a\\b/", "a/\n", "a" * 129 + "/"]
)
def test_unsafe_or_ambiguous_prefix_refuses(policy, prefix):
    value = selected(policy).binding.model_dump(mode="json", by_alias=True)
    value["object_key_prefix"] = prefix
    with pytest.raises(ValueError):
        ChunkedBackupBinding.model_validate_json(json.dumps(value))


async def test_prefixed_native_verify_retry_restore_and_cold_reuse(policy, tmp_path):
    case = selected(policy, object_key_prefix=PREFIX)
    native = reader(case, tmp_path)
    snapshot = await native.verify(document_paths=("license.txt",))
    native.require_verified(snapshot)
    assert all(v.key.startswith(PREFIX + "chunks/sha256/") for v in snapshot.objects)
    assert native._namespace()["object_key_prefix"] == PREFIX
    first_reads = tuple(case.remote.reads)
    assert await reader(case, tmp_path).verify(document_paths=("license.txt",)) == snapshot
    assert tuple(case.remote.reads) == first_reads
    index = next(i for i, r in enumerate(case.bundle.files) if r.role == "weights")
    assert (
        await native.read_verified_range(snapshot, file_index=index, offset=1, size_bytes=3)
        == b"eig"
    )
    archive = await restore(native, tmp_path / "cache")
    assert (archive / "model" / "weights.txt").read_bytes() == b"weights"
    assert all(k.startswith(PREFIX) for k in case.remote.heads + case.remote.reads)
    script = """
import asyncio, json, sys
from pathlib import Path
from umi.open_competition import CompetitionPolicy
from tests.test_competition_chunked_model_backup import selected, reader
async def main():
    policy = CompetitionPolicy.model_validate_json(sys.argv[2])
    case = selected(policy, object_key_prefix=sys.argv[3])
    native = reader(case, Path(sys.argv[1]))
    snapshot = await native.verify(document_paths=('license.txt',))
    native.require_verified(snapshot)
    print(json.dumps({'reads': len(case.remote.reads)}))
asyncio.run(main())
"""
    process = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            script,
            str(tmp_path),
            canonical_json_bytes(policy).decode(),
            PREFIX,
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout) == {"reads": 0}


async def test_prefix_is_part_of_receipts_and_cannot_borrow_root_namespace_facts(policy, tmp_path):
    old = selected(policy)
    old_reader = reader(old, tmp_path)
    old_snapshot = await old_reader.verify()
    prefixed = selected(policy, object_key_prefix=PREFIX)
    target = reader(prefixed, tmp_path)
    assert old_reader._store(None).root != target._store(None).root
    snapshot = await target.verify()
    assert prefixed.remote.reads
    assert snapshot.namespace_sha256 != old_snapshot.namespace_sha256
    with pytest.raises(ValueError, match="selected source"):
        target.require_verified(old_snapshot)


async def test_prefixed_export_import_keeps_completed_bytes_and_original_context(policy, tmp_path):
    case = selected(policy, object_key_prefix=PREFIX)
    source = reader(case, tmp_path / "source")
    await source.verify(document_paths=("license.txt",))
    pin = await source.export_completed()
    case.remote.reads.clear()
    target = ChunkedModelBackupReader(
        selection(other_cohort(case)),
        policy=policy,
        multipart=case.remote,
        verification_root=tmp_path / "target",
        byte_store_imports=(pin,),
    )
    result = await target.verify(document_paths=("license.txt",))
    target.require_verified(result)
    assert not case.remote.reads
    assert result.documents == {"license.txt": b"license".hex()}


async def test_interrupted_prefixed_pass_resumes_only_unfinished_file(policy, tmp_path):
    case = selected(policy, object_key_prefix=PREFIX)
    key = next(k for k, raw in case.remote.objects.items() if raw == b"weights")
    case.remote.fail = key
    with pytest.raises(OSError, match="interrupted"):
        await reader(case, tmp_path).verify()
    case.remote.fail = None
    case.remote.reads.clear()
    result = await reader(case, tmp_path).verify()
    reader(case, tmp_path).require_verified(result)
    assert case.remote.reads == [key]
