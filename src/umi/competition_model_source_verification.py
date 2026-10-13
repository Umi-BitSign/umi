"""Durable per-file verification for unchanged local model upload sources."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .competition_artifacts import _artifact, _check_tree, _copy_verified, _directory
from .competition_transport_verification import (
    ByteCheckpoints,
    ProgressReader,
    TransferProgress,
    verification_tick,
    verifier_semantics,
)
from .file_identity import file_fingerprint
from .open_competition import digest, validate_bundle_policy
from .protocol import canonical_json_bytes


def source_checkpoint_root(source, bundle):
    selected = os.environ.get("UMI_MODEL_VERIFICATION_DIRECTORY")
    root = Path(selected) if selected else Path.home() / ".local/state/umi/model-verification"
    key = hashlib.sha256(canonical_json_bytes([str(source), digest(bundle)])).hexdigest()
    return root / key


def _file_identity(root, info):
    return {
        "root": [str(root.st_dev), str(root.st_ino), str(root.st_uid)],
        "file": [str(v) for v in file_fingerprint(info)],
    }


def verify_model_source(source, bundle, policy, fingerprint, report=None):
    """Recheck only affected files; preserve successful first-pass checkpoints.

    Missing/damaged records emit repair_required and receive a scoped native repair
    in this owned pass. The original tree and bytes are never changed. Unchanged
    completed files need descriptor metadata checks, not reads or hashes.
    """
    validate_bundle_policy(bundle, policy)
    context = {
        "source": str(source),
        "bundle": digest(bundle),
        "policy": digest(policy),
        "owner_uid": os.getuid(),
        "semantics": verifier_semantics(),
        "authority_scope": "local_model_bytes_only",
    }
    total = sum(record.size_bytes for record in bundle.files)
    with (
        TransferProgress("model_source_verification", total, report) as progress,
        ByteCheckpoints(source_checkpoint_root(source, bundle), context, progress) as saved,
        _directory(source) as descriptor,
    ):
        root = os.fstat(descriptor)
        _check_tree(descriptor, bundle)
        result = []
        identities = []
        for record in bundle.files:
            with _artifact(descriptor, record) as (stream, info):
                expected = _file_identity(root, info)
                verified = saved.load(record.path, expected)
                if verified == record.sha256:
                    progress.advance(record.size_bytes, restored=True)
                else:
                    if verified is not None:
                        progress.emit("repair_required", reason="model_file_digest_binding_changed")
                    progress.emit("running")
                    reusable = verification_tick(info.st_ctime_ns, progress)
                    _copy_verified(ProgressReader(stream, progress), record, None)
                    if _file_identity(root, os.fstat(stream.fileno())) != expected:
                        raise ValueError("model source changed during verification")
                    if reusable:
                        saved.remember(record.path, expected, record.sha256)
                result.append(fingerprint(info))
                identities.append(expected)
        _check_tree(descriptor, bundle)
        with _directory(source) as current:
            if (os.fstat(current).st_dev, os.fstat(current).st_ino) != (root.st_dev, root.st_ino):
                raise ValueError("model source directory changed during verification")
        # Validate the complete final identity after all first-pass saves, so a
        # changed earlier file cannot be accepted while a later file is checked.
        for record, expected in zip(bundle.files, identities, strict=True):
            with _artifact(descriptor, record) as (_, info):
                if _file_identity(root, info) != expected:
                    raise ValueError("model source changed during verification")
        return tuple(result)


def model_payload_digest(source, bundle, fingerprints, fingerprint, policy, report=None):
    """Reuse the distinct direct-upload concatenated SHA256 across restarts.

    Per-file SHA256 cannot be combined into this digest. This checkpoint proves
    only the complete concatenation, never an R2 object or remote preservation.
    """
    context = {
        "source": str(source),
        "bundle": digest(bundle),
        "policy": digest(policy),
        "owner_uid": os.getuid(),
        "semantics": verifier_semantics(),
        "authority_scope": "local_direct_payload_sha256_only",
    }
    total = sum(record.size_bytes for record in bundle.files)
    with (
        TransferProgress("model_payload_digest", total, report) as progress,
        ByteCheckpoints(
            source_checkpoint_root(source, bundle) / "direct-payload", context, progress
        ) as saved,
        _directory(source) as descriptor,
    ):
        root = os.fstat(descriptor)
        _check_tree(descriptor, bundle)
        identities = []
        for record, expected in zip(bundle.files, fingerprints, strict=True):
            with _artifact(descriptor, record) as (_, info):
                if fingerprint(info) != expected:
                    raise ValueError("model source changed after verification")
                identities.append(_file_identity(root, info))
        prior = saved.load("concatenated-sha256", identities)
        if prior is not None:
            progress.advance(total, restored=True)
        else:
            reusable = verification_tick(
                max(int(value["file"][-1]) for value in identities), progress
            )
            value = hashlib.sha256()
            for record, expected in zip(bundle.files, identities, strict=True):
                with _artifact(descriptor, record) as (stream, info):
                    if _file_identity(root, info) != expected:
                        raise ValueError("model source changed during payload hashing")
                    remaining = record.size_bytes
                    while remaining:
                        data = stream.read(min(8 * 1024**2, remaining))
                        if not data:
                            raise ValueError("model source ended before its signed manifest")
                        value.update(data)
                        remaining -= len(data)
                        progress.advance(len(data))
                    if _file_identity(root, os.fstat(stream.fileno())) != expected:
                        raise ValueError("model source changed during payload hashing")
            prior = value.hexdigest()
        # Match the original source even if an earlier file changed while a
        # later file was read, before publishing a successful receipt.
        _check_tree(descriptor, bundle)
        for record, expected in zip(bundle.files, identities, strict=True):
            with _artifact(descriptor, record) as (_, info):
                if _file_identity(root, info) != expected:
                    raise ValueError("model source changed during payload hashing")
        with _directory(source) as current:
            if (os.fstat(current).st_dev, os.fstat(current).st_ino) != (root.st_dev, root.st_ino):
                raise ValueError("model source directory changed during payload hashing")
        if progress.native and reusable:
            saved.remember("concatenated-sha256", identities, prior)
        return prior
