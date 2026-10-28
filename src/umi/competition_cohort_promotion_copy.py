"""Private proof of an owner-created copy of already verified immutable bytes.

R2 does not implement UploadPartCopy source conditions. This path therefore
applies only to the owner's completed unique attempt keys: miner capabilities
address the closed source upload, and the owner never overwrites that key.
Existing destinations without this journal remain on native byte verification.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

from .competition_cohort_direct_model_upload import (
    DirectModelUploadPart,
    SignedDirectModelUploadCompletion,
)
from .competition_remote_model_verification import (
    model_byte_store,
    remember_model_bytes,
    remote_identity,
    require_remote_model_bytes,
)
from .competition_transport_verification import (
    TransferProgress,
    owned_byte_checkpoint,
    verifier_semantics,
)
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .protocol import canonical_json_bytes
from .r2_multipart import R2ObjectHead


def multipart_etag(parts):
    """R2 multipart identity on our standard, non-SSE-C client path.

    https://developers.cloudflare.com/r2/objects/upload-objects/#etags
    This binds provider copy lineage, never substitutes for source SHA256.
    """
    raw = b"".join(bytes.fromhex(part.etag) for part in parts)
    return hashlib.md5(raw, usedforsecurity=False).hexdigest() + "-" + str(len(parts))


def _part(raw, number, payload):
    value = DirectModelUploadPart.model_validate_json(canonical_json_bytes(raw))
    expected_size = min(
        payload.part_size_bytes, payload.total_bytes - (number - 1) * payload.part_size_bytes
    )
    if value.part_number != number or value.size_bytes != expected_size:
        raise ValueError("promotion copy part geometry differs")
    return value


async def verified_promotion_copy(
    owner,
    acceptance,
    bundle,
    payload,
    reservation,
    source_key,
    destination_key,
    source_head,
    destination_head,
    copy_parts,
):
    """Return a copied destination head, or None for the unchanged legacy path."""
    journal, multipart = owner.journal, owner.multipart
    key = digest(acceptance)
    intent = journal.get("direct-copy-intent", key)
    proof = journal.get("direct-copy-proof", key)
    if destination_head is not None and intent is None:
        if proof is not None:
            raise ValueError("completed promotion copy intent is missing")
        return None

    root = Path(owner.config.directory) / "byte-verification"
    context = owner._byte_context()
    source_result = await run_owned_thread(
        lambda: require_remote_model_bytes(
            multipart, source_key, bundle, payload, root=root, context=context, head=source_head
        )
    )
    completion_raw = journal.get("direct-completion", reservation)
    if completion_raw is None:
        raise ValueError("promotion copy source completion is missing")
    signed_completion = SignedDirectModelUploadCompletion.model_validate_json(
        canonical_json_bytes(completion_raw)
    )
    completion = signed_completion.completion
    if (
        completion.reservation_sha256 != reservation
        or completion.generation != acceptance.direct_artifact.reservation.generation
        or identity(signed_completion.signature.hotkey) != identity(acceptance.recipient_hotkey)
        or len(completion.parts) != payload.total_parts
    ):
        raise ValueError("promotion copy source completion differs")
    originals = tuple(_part(p.model_dump(), n, payload) for n, p in enumerate(completion.parts, 1))
    if source_head.etag != multipart_etag(originals):
        raise ValueError("promotion copy source provider completion differs")
    binding = {
        "schema": "umi-private-model-copy-binding/1",
        "acceptance": key,
        "reservation": reservation,
        "source": remote_identity(multipart, source_key, source_head),
        "destination_key_sha256": hashlib.sha256(destination_key.encode()).hexdigest(),
        "bundle": digest(bundle),
        "payload": digest(payload),
        "authority": context,
        "semantics": verifier_semantics(),
        "source_result": digest(source_result),
        "source_parts": digest([part.model_dump(mode="json") for part in originals]),
    }
    if intent is None:
        # Absent destination is part of the ownership proof; an unrelated older
        # preserved object cannot be adopted from its name or HEAD alone.
        intent = {"binding": binding}
        journal.put("direct-copy-intent", key, intent)
    elif intent != {"binding": binding}:
        raise ValueError("promotion copy dependencies changed")
    intent_digest = digest(intent)
    provider = journal.get("direct-copy-upload", key)
    manifest = journal.get("direct-copy-manifest", key)

    def load_part(number):
        raw = journal.get("direct-copy-part", digest([intent_digest, number]))
        if raw is None:
            return None
        if set(raw) != {"intent", "part"} or raw["intent"] != intent_digest:
            raise ValueError("promotion copy retained part differs")
        part = _part(raw["part"], number, payload)
        if part != originals[number - 1]:
            raise ValueError("promotion copy provider part differs from verified source")
        return part

    def save_part(part):
        if part != originals[part.part_number - 1]:
            raise ValueError("promotion copy provider part differs from verified source")
        journal.put(
            "direct-copy-part",
            digest([intent_digest, part.part_number]),
            {"intent": intent_digest, "part": part.model_dump(mode="json")},
        )

    if provider is None:
        if manifest is not None or proof is not None or destination_head is not None:
            raise ValueError("promotion copy provider identity is missing")
        provider = {"intent": intent_digest, "upload_id": await multipart.create(destination_key)}
        journal.put("direct-copy-upload", key, provider)
    if (
        set(provider) != {"intent", "upload_id"}
        or provider["intent"] != intent_digest
        or not isinstance(provider["upload_id"], str)
        or not 1 <= len(provider["upload_id"]) <= 2048
        or any(ord(c) < 33 for c in provider["upload_id"])
    ):
        raise ValueError("promotion copy provider identity differs")
    if destination_head is None and not await multipart.multipart_exists(
        destination_key, upload_id=provider["upload_id"]
    ):
        with TransferProgress(
            "model_promotion_copy", payload.total_parts, unit="parts"
        ) as progress:
            progress.emit("repair_required", reason="promotion_copy_provider_upload_missing")
        raise OSError("promotion copy provider upload is missing; retained lineage requires repair")

    if manifest is None:
        if proof is not None or destination_head is not None:
            raise ValueError("completed promotion copy manifest is missing")
        # Keep the same upload and completed part receipts across transient
        # failures and cancellation. The helper drains every in-flight wave.
        with TransferProgress(
            "model_promotion_copy",
            payload.total_parts,
            unit="parts",
            identity={
                "source_object_key_sha256": binding["source"]["key_sha256"],
                "model_sha256": payload.model_sha256,
                "object_role": "copy_proof",
            },
        ) as progress:
            parts = await copy_parts(
                multipart,
                destination_key,
                source_key,
                provider["upload_id"],
                payload,
                min(4, owner.config.delivery.maximum_concurrent_parts),
                SimpleNamespace(advance=lambda: progress.advance(1)),
                load_part=load_part,
                save_part=save_part,
                restored_progress=lambda: progress.advance(1, restored=True),
            )
        manifest = {
            "intent": intent_digest,
            "provider": digest(provider),
            "parts": [p.model_dump(mode="json") for p in parts],
        }
        journal.put("direct-copy-manifest", key, manifest)
    parts = tuple(load_part(n) for n in range(1, payload.total_parts + 1))
    if any(p is None for p in parts) or manifest != {
        "intent": intent_digest,
        "provider": digest(provider),
        "parts": [p.model_dump(mode="json") for p in parts],
    }:
        raise ValueError("promotion copy completion manifest differs")
    expected = R2ObjectHead(size_bytes=payload.total_bytes, etag=multipart_etag(parts))
    expected_proof = {
        "schema": "umi-private-model-copy-proof/1",
        "intent": intent_digest,
        "manifest": digest(manifest),
        "destination": remote_identity(multipart, destination_key, expected),
    }
    if proof is not None and proof != expected_proof:
        raise ValueError("promotion copy proof differs")
    if destination_head is None:
        if proof is not None:
            raise ValueError("completed promotion copy destination disappeared")
        try:
            etag = await multipart.complete(
                destination_key, upload_id=provider["upload_id"], parts=parts
            )
        except OSError:
            # Exact durable part receipts and expected provider identity bind a
            # successful completion whose response was lost. A bare HEAD cannot.
            destination_head = await multipart.head(destination_key)
            if destination_head is None:
                raise
        else:
            if etag != expected.etag:
                raise ValueError("promotion copy provider completion differs")
            destination_head = await multipart.head(destination_key)
    if destination_head is None or (destination_head.size_bytes, destination_head.etag) != (
        expected.size_bytes,
        expected.etag,
    ):
        raise ValueError("promotion copy destination changed")
    final_source = await multipart.head(source_key)
    if final_source is None or (final_source.size_bytes, final_source.etag) != (
        source_head.size_bytes,
        source_head.etag,
    ):
        raise ValueError("promotion copy source changed")
    # Retain the independently validated copy lineage before ordinary byte
    # completion. Neither source cleanup nor admission can precede both facts.
    journal.put("direct-copy-proof", key, expected_proof)
    with TransferProgress("model_promotion_byte_reuse", 1, unit="objects") as progress:
        async with owned_byte_checkpoint(
            model_byte_store(root, destination_key, bundle, payload, context, (), progress),
            progress,
        ) as saved:
            await run_owned_thread(
                _publish_destination_bytes,
                saved,
                expected_proof["destination"],
                source_result,
                payload,
            )
            progress.advance(1, restored=True)
    return expected


def _publish_destination_bytes(saved, remote, source_result, payload):
    """Bounded compact persistence under the asynchronously owned checkpoint."""
    prior = saved.load("object", remote)
    expected_result = canonical_json_bytes(source_result)
    try:
        result_path = saved.root / "result.json"
        if result_path.lstat().st_size > 64 * 1024**2:
            raise ValueError("promotion destination byte result exceeds its metadata bound")
        result_raw = saved._read(result_path)
    except FileNotFoundError:
        result_raw = None
    if saved.repairs or (result_raw is not None and result_raw != expected_result):
        raise ValueError("promotion destination byte completion requires repair")
    if prior is not None:
        if result_raw != expected_result or prior != digest(source_result):
            raise ValueError("promotion destination byte completion differs")
    else:
        remember_model_bytes(saved, remote, payload, {})
