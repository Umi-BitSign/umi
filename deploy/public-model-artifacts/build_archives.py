"""Build verified, deterministic archives for the public C5 comparator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath

HEX = re.compile(r"[0-9a-f]{64}\Z")
BUFFER_BYTES = 1024 * 1024


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while block := stream.read(BUFFER_BYTES):
            total += len(block)
            digest.update(block)
    return digest.hexdigest(), total


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("unsafe_bundle_path")
    return path


def tar_info(name: str, size: int, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode & 0o777
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


class HashingReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        block = self.stream.read(size)
        self.digest.update(block)
        self.total += len(block)
        return block


def build_model_archive(source: Path, model: str, target: Path) -> dict:
    if HEX.fullmatch(model) is None or source.name != model or source.is_symlink():
        raise ValueError("model_source_identity_invalid")
    manifest_path = source / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != "umi-model-bundle/1" or not isinstance(manifest.get("files"), list):
        raise ValueError("model_manifest_invalid")

    records = []
    seen = set()
    for record in manifest["files"]:
        if set(record) != {"path", "role", "sha256", "size_bytes"}:
            raise ValueError("model_record_shape_invalid")
        path = safe_relative(record["path"])
        if str(path) in seen or HEX.fullmatch(record["sha256"]) is None:
            raise ValueError("model_record_identity_invalid")
        if type(record["size_bytes"]) is not int or record["size_bytes"] < 0:
            raise ValueError("model_record_size_invalid")
        seen.add(str(path))
        records.append((str(path), record))

    expected_files = {Path("model", path) for path, _ in records} | {Path("manifest.json")}
    actual_files = {
        path.relative_to(source)
        for path in source.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if expected_files != actual_files:
        raise ValueError("model_source_tree_differs")

    temporary = target.with_suffix(target.suffix + ".partial")
    temporary.unlink(missing_ok=True)
    with temporary.open("xb") as output:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
            archive.addfile(
                tar_info(f"{model}/manifest.json", len(manifest_bytes), 0o644),
                fileobj=__import__("io").BytesIO(manifest_bytes),
            )
            for path, record in sorted(records):
                candidate = source / "model" / path
                before = candidate.lstat()
                if (
                    candidate.is_symlink()
                    or not stat.S_ISREG(before.st_mode)
                    or before.st_size != record["size_bytes"]
                ):
                    raise ValueError("model_source_file_invalid")
                descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        reader = HashingReader(stream)
                        archive.addfile(
                            tar_info(
                                f"{model}/model/{path}",
                                record["size_bytes"],
                                stat.S_IMODE(before.st_mode),
                            ),
                            fileobj=reader,
                        )
                        after = os.fstat(stream.fileno())
                    if (
                        reader.total != record["size_bytes"]
                        or reader.digest.hexdigest() != record["sha256"]
                        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    ):
                        raise ValueError("model_source_file_changed")
                finally:
                    os.close(descriptor)
        output.flush()
        os.fsync(output.fileno())
    archive_sha, archive_bytes = sha256_file(temporary)
    os.replace(temporary, target)
    return {
        "schema": "umi-public-model-archive/1",
        "model_sha256": model,
        "archive_format": "tar",
        "archive_sha256": archive_sha,
        "archive_bytes": archive_bytes,
        "files": len(records),
    }


def build_runtime_archive(index_path: Path, chunks: Path, runtime: str, target: Path) -> dict:
    if HEX.fullmatch(runtime) is None:
        raise ValueError("runtime_identity_invalid")
    index = json.loads(index_path.read_bytes())
    if (
        index.get("schema") != "umi-preserved-cpu-runtime/1"
        or index.get("runtime_sha256") != runtime
        or index.get("archive_format") != "oci-archive"
        or HEX.fullmatch(index.get("archive_sha256", "")) is None
    ):
        raise ValueError("runtime_index_invalid")
    temporary = target.with_suffix(target.suffix + ".partial")
    temporary.unlink(missing_ok=True)
    complete = hashlib.sha256()
    total = 0
    with temporary.open("xb") as output:
        for record in index["chunks"]:
            if set(record) != {"sha256", "size_bytes"} or HEX.fullmatch(record["sha256"]) is None:
                raise ValueError("runtime_chunk_record_invalid")
            source = chunks / record["sha256"]
            digest = hashlib.sha256()
            held = 0
            with source.open("rb") as stream:
                while block := stream.read(BUFFER_BYTES):
                    held += len(block)
                    digest.update(block)
                    complete.update(block)
                    output.write(block)
            if held != record["size_bytes"] or digest.hexdigest() != record["sha256"]:
                raise ValueError("runtime_chunk_invalid")
            total += held
        output.flush()
        os.fsync(output.fileno())
    if total != index["archive_bytes"] or complete.hexdigest() != index["archive_sha256"]:
        raise ValueError("runtime_archive_invalid")
    os.replace(temporary, target)
    return {
        "schema": "umi-public-runtime-archive/1",
        "runtime_sha256": runtime,
        "archive_format": "oci-archive",
        "archive_sha256": index["archive_sha256"],
        "archive_bytes": total,
        "oci_manifest_sha256": index["oci_manifest_sha256"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-source", required=True, type=Path)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--runtime-index", required=True, type=Path)
    parser.add_argument("--runtime-chunks", required=True, type=Path)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    model_output = args.output / "umi-model-bundle.tar"
    runtime_output = args.output / "offline-cpu-runtime.oci.tar"
    result = {
        "schema": "umi-public-c5-comparator-archives/1",
        "model": build_model_archive(args.model_source, args.model_sha256, model_output),
        "runtime": build_runtime_archive(
            args.runtime_index,
            args.runtime_chunks,
            args.runtime_sha256,
            runtime_output,
        ),
    }
    receipt = args.output / "archives.json"
    receipt.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    receipt.chmod(0o600)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
