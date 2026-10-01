"""Upload and read back the verified public comparator archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

HEX = re.compile(r"[0-9a-f]{64}\Z")
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.@_-]{0,254}\Z")


def credentials(path: Path) -> dict[str, str]:
    info = path.lstat()
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("private_credentials_required")
    result = {}
    for line in path.read_text().splitlines():
        if not line:
            continue
        key, separator, value = line.partition("=")
        if separator != "=" or not key or key in result:
            raise ValueError("credential_file_invalid")
        result[key] = value.strip().strip('"').strip("'")
    if set(result) != {"TOKEN_VALUE", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY", "DEFAULT_ENDPOINT"}:
        raise ValueError("credential_file_invalid")
    if not re.fullmatch(r"https://[0-9a-f]{32}[.]r2[.]cloudflarestorage[.]com", result["DEFAULT_ENDPOINT"]):
        raise ValueError("credential_endpoint_invalid")
    return result


def aws_environment(values: dict[str, str]) -> dict[str, str]:
    result = os.environ.copy()
    result.update(
        AWS_ACCESS_KEY_ID=values["ACCESS_KEY_ID"],
        AWS_SECRET_ACCESS_KEY=values["SECRET_ACCESS_KEY"],
        AWS_DEFAULT_REGION="auto",
        AWS_EC2_METADATA_DISABLED="true",
        AWS_PAGER="",
    )
    return result


def aws_json(arguments: list[str], env: dict[str, str], *, missing_ok: bool = False):
    result = subprocess.run(
        ["aws", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        timeout=120,
    )
    if missing_ok and result.returncode != 0:
        return None
    if result.returncode != 0:
        raise ValueError("r2_metadata_request_failed")
    return json.loads(result.stdout)


def head(bucket: str, key: str, endpoint: str, env: dict[str, str]):
    return aws_json(
        [
            "s3api", "head-object", "--bucket", bucket, "--key", key,
            "--endpoint-url", endpoint, "--output", "json",
        ],
        env,
        missing_ok=True,
    )


def verify_head(value, expected: dict) -> None:
    metadata = value.get("Metadata", {}) if isinstance(value, dict) else {}
    if (
        value is None
        or value.get("ContentLength") != expected["archive_bytes"]
        or metadata != {
            "sha256": expected["archive_sha256"],
            "identity": expected["identity"],
            "kind": expected["kind"],
        }
        or value.get("ContentType") != "application/x-tar"
    ):
        raise ValueError("r2_public_artifact_metadata_differs")


def upload(host: str, source: Path, bucket: str, key: str, expected: dict, endpoint: str, env: dict[str, str]):
    remote = subprocess.Popen(
        ["ssh", "-o", "BatchMode=yes", host, "cat", "--", str(source)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert remote.stdout is not None
    command = [
        "aws", "s3", "cp", "-", f"s3://{bucket}/{key}",
        "--endpoint-url", endpoint,
        "--expected-size", str(expected["archive_bytes"]),
        "--content-type", "application/x-tar",
        "--cache-control", "public, max-age=31536000, immutable",
        "--metadata", (
            f"sha256={expected['archive_sha256']},"
            f"identity={expected['identity']},kind={expected['kind']}"
        ),
        "--only-show-errors", "--no-progress",
    ]
    stored = subprocess.run(
        command,
        stdin=remote.stdout,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    remote.stdout.close()
    remote_status = remote.wait(timeout=60)
    if stored.returncode != 0 or remote_status != 0:
        raise ValueError("r2_public_artifact_upload_failed")


def readback(bucket: str, key: str, expected: dict, endpoint: str, env: dict[str, str]):
    process = subprocess.Popen(
        [
            "aws", "s3", "cp", f"s3://{bucket}/{key}", "-",
            "--endpoint-url", endpoint, "--only-show-errors", "--no-progress",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    assert process.stdout is not None
    digest = hashlib.sha256()
    total = 0
    while block := process.stdout.read(1024 * 1024):
        total += len(block)
        digest.update(block)
    if process.wait(timeout=120) != 0:
        raise ValueError("r2_public_artifact_readback_failed")
    if total != expected["archive_bytes"] or digest.hexdigest() != expected["archive_sha256"]:
        raise ValueError("r2_public_artifact_readback_differs")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-host", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--credentials", required=True, type=Path)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if HOST.fullmatch(args.source_host) is None or not args.source_root.is_absolute():
        raise ValueError("source_location_invalid")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", args.bucket):
        raise ValueError("bucket_invalid")

    raw = subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", args.source_host, "cat", "--", str(args.source_root / "archives.json")],
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    source = json.loads(raw)
    values = credentials(args.credentials)
    env = aws_environment(values)
    endpoint = values["DEFAULT_ENDPOINT"]
    records = []
    specifications = (
        (
            "model", source["model"], "model_sha256", "umi-model-bundle.tar",
            f"public/v1/models/{source['model']['model_sha256']}/umi-model-bundle.tar",
        ),
        (
            "runtime", source["runtime"], "runtime_sha256", "offline-cpu-runtime.oci.tar",
            f"public/v1/runtimes/{source['runtime']['runtime_sha256']}/offline-cpu-runtime.oci.tar",
        ),
    )
    for kind, record, identity_key, filename, key in specifications:
        expected = {
            "kind": kind,
            "identity": record[identity_key],
            "archive_sha256": record["archive_sha256"],
            "archive_bytes": record["archive_bytes"],
        }
        if HEX.fullmatch(expected["identity"]) is None or HEX.fullmatch(expected["archive_sha256"]) is None:
            raise ValueError("archive_receipt_invalid")
        current = head(args.bucket, key, endpoint, env)
        if current is None:
            upload(args.source_host, args.source_root / filename, args.bucket, key, expected, endpoint, env)
            current = head(args.bucket, key, endpoint, env)
        verify_head(current, expected)
        readback(args.bucket, key, expected, endpoint, env)
        records.append({**expected, "key": key, "readback_verified": True})

    result = {
        "schema": "umi-public-model-artifact-upload/1",
        "bucket": args.bucket,
        "artifacts": records,
    }
    args.receipt.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
