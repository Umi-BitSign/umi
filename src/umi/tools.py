"""Read-only command-line tools for UMI policy and artifact verification."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .artifacts import (
    PublicBatchManifest,
    PublisherCapacityStatement,
    public_batch_manifest_hash,
    publisher_capacity_digest,
    validate_public_batch_manifest,
    validate_publisher_capacity_statement,
    validate_revealed_batch_shape,
)
from .audit_bundle import verify_audit_bundle
from .crypto import verify_response_signature
from .media import inspect_media
from .policy import ScoringPolicy, activation_equivalence_digest, scoring_policy_hash
from .protocol import GroundTruthPayload, canonical_json_bytes
from .shadow import MAX_SHADOW_EVIDENCE_BYTES, run_shadow_rehearsal

_Model = TypeVar("_Model", bound=BaseModel)
_MAX_POLICY_BYTES = 4 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


def _read_regular_file(path: Path, maximum_bytes: int) -> bytes:
    if maximum_bytes <= 0:
        raise ValueError("file byte ceiling must be positive")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"input cannot be opened safely: {path}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"input is not a regular file: {path}")
        if metadata.st_size > maximum_bytes:
            raise ValueError(f"input exceeds its byte ceiling: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError(f"input exceeds its byte ceiling: {path}")
            chunks.append(chunk)
        if total != metadata.st_size:
            raise ValueError(f"input changed while it was read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_canonical_model(path: Path, model: type[_Model], maximum_bytes: int) -> _Model:
    raw = _read_regular_file(path, maximum_bytes)
    try:
        value = model.model_validate_json(raw)
    except ValidationError as error:
        raise ValueError(f"input is not a valid {model.__name__}: {path}") from error
    if canonical_json_bytes(value) != raw:
        raise ValueError(f"input is not RFC 8785 canonical JSON: {path}")
    return value


def _policy(path: Path) -> ScoringPolicy:
    return _load_canonical_model(path, ScoringPolicy, _MAX_POLICY_BYTES)


def _print_record(record: Any) -> None:
    print(canonical_json_bytes(record).decode("utf-8"))


def _policy_hash(args: argparse.Namespace) -> dict[str, Any]:
    policy = _policy(args.policy)
    return {
        "schema": "umi-policy-inspection/1",
        "policy_sha256": scoring_policy_hash(policy),
        "activation_equivalence_digest": activation_equivalence_digest(policy),
        "translation_weights_active": policy.translation_weights_active,
        "protocol_conformance": False,
        "activation_evidence": False,
    }


def _verify_public_batch(args: argparse.Namespace) -> dict[str, Any]:
    policy = _policy(args.policy)
    manifest = _load_canonical_model(
        args.manifest,
        PublicBatchManifest,
        policy.limits.maximum_manifest_bytes,
    )
    validate_public_batch_manifest(manifest, policy)

    ciphertext_verified = False
    if args.ciphertext is not None:
        ciphertext = _read_regular_file(
            args.ciphertext,
            policy.limits.maximum_ground_truth_envelope_bytes,
        )
        if hashlib.sha256(ciphertext).hexdigest() != manifest.ciphertext_sha256:
            raise ValueError("ground-truth ciphertext does not match the public manifest")
        ciphertext_verified = True

    revealed_shape_validated = False
    if args.ground_truth is not None:
        ground_truth = _load_canonical_model(
            args.ground_truth,
            GroundTruthPayload,
            policy.limits.maximum_ground_truth_envelope_bytes,
        )
        validate_revealed_batch_shape(manifest, ground_truth, policy)
        revealed_shape_validated = True

    return {
        "schema": "umi-public-batch-inspection/1",
        "policy_sha256": scoring_policy_hash(policy),
        "public_manifest_sha256": public_batch_manifest_hash(manifest),
        "ciphertext_hash_verified": ciphertext_verified,
        "revealed_shape_validated": revealed_shape_validated,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
    }


def _verify_capacity(args: argparse.Namespace) -> dict[str, Any]:
    policy = _policy(args.policy)
    statement = _load_canonical_model(
        args.statement,
        PublisherCapacityStatement,
        policy.limits.maximum_manifest_bytes,
    )
    validate_publisher_capacity_statement(statement, policy)
    digest = publisher_capacity_digest(statement)
    if not verify_response_signature(
        digest,
        hotkey_ss58=statement.administrator,
        scheme=args.scheme,
        signature=args.signature,
    ):
        raise ValueError("publisher capacity signature does not verify")
    return {
        "schema": "umi-publisher-capacity-inspection/1",
        "policy_sha256": scoring_policy_hash(policy),
        "capacity_digest": digest.hex(),
        "administrator_signature_verified": True,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
    }


def _inspect_media(args: argparse.Namespace) -> dict[str, Any]:
    inspection = inspect_media(args.video)
    profile = inspection.profile
    decoded = inspection.frames
    return {
        "schema": "umi-media-inspection/1",
        "video_sha256": inspection.video_sha256,
        "size_bytes": profile.size_bytes,
        "duration": {
            "numerator": profile.duration.numerator,
            "denominator": profile.duration.denominator,
        },
        "width": profile.width,
        "height": profile.height,
        "frame_rate": {
            "numerator": profile.frame_rate.numerator,
            "denominator": profile.frame_rate.denominator,
        },
        "codec_name": profile.codec_name,
        "format_names": list(profile.format_names),
        "frame_digest": decoded.frame_digest,
        "frame_count": decoded.frame_count,
        "decoder_sha256": decoded.decoder_sha256,
        "protocol_conformance": False,
        "activation_evidence": False,
    }


def _verify_rehearsal_bundle(args: argparse.Namespace) -> dict[str, Any]:
    manifest = verify_audit_bundle(args.bundle)
    return {
        "schema": "umi-shadow-rehearsal-inspection/1",
        "window_id": manifest.window_id,
        "highest_stage": manifest.highest_stage,
        "terminal_classification": manifest.terminal_classification,
        "audit_bundle_bytes": manifest.audit_bundle_bytes,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
    }


def _run_shadow_rehearsal(args: argparse.Namespace) -> dict[str, Any]:
    raw = _read_regular_file(args.input, MAX_SHADOW_EVIDENCE_BYTES)
    run = run_shadow_rehearsal(raw, args.output)
    return {
        "schema": "umi-shadow-rehearsal-run/1",
        "report": run.report.model_dump(mode="json", by_alias=True),
        "audit_manifest_sha256": hashlib.sha256(
            canonical_json_bytes(run.audit_manifest)
        ).hexdigest(),
        "bundle_directory": str(args.output),
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect UMI policy and protocol artifacts")
    subcommands = parser.add_subparsers(dest="command", required=True)

    policy_hash = subcommands.add_parser("policy-hash", help="hash one canonical policy")
    policy_hash.add_argument("--policy", type=Path, required=True)
    policy_hash.set_defaults(handler=_policy_hash)

    batch = subcommands.add_parser(
        "verify-public-batch",
        help="verify one public batch and optional post-reveal material",
    )
    batch.add_argument("--policy", type=Path, required=True)
    batch.add_argument("--manifest", type=Path, required=True)
    batch.add_argument("--ciphertext", type=Path)
    batch.add_argument("--ground-truth", type=Path)
    batch.set_defaults(handler=_verify_public_batch)

    capacity = subcommands.add_parser(
        "verify-capacity",
        help="verify a publisher capacity statement and administrator signature",
    )
    capacity.add_argument("--policy", type=Path, required=True)
    capacity.add_argument("--statement", type=Path, required=True)
    capacity.add_argument("--scheme", choices=("sr25519", "ed25519"), required=True)
    capacity.add_argument("--signature", required=True)
    capacity.set_defaults(handler=_verify_capacity)

    media = subcommands.add_parser("inspect-media", help="inspect and frame-hash one clip")
    media.add_argument("--video", type=Path, required=True)
    media.set_defaults(handler=_inspect_media)

    bundle = subcommands.add_parser(
        "verify-rehearsal-bundle",
        help="verify an offline rehearsal bundle's hashes and safety boundary",
    )
    bundle.add_argument("--bundle", type=Path, required=True)
    bundle.set_defaults(handler=_verify_rehearsal_bundle)

    shadow = subcommands.add_parser(
        "run-shadow-rehearsal",
        help="replay one canonical offline shadow fixture without chain writes",
    )
    shadow.add_argument("--input", type=Path, required=True)
    shadow.add_argument("--output", type=Path, required=True)
    shadow.set_defaults(handler=_run_shadow_rehearsal)
    return parser


def main() -> None:
    args = _parser().parse_args()
    _print_record(args.handler(args))


if __name__ == "__main__":
    main()
