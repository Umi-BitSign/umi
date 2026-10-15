"""Copy checkpoint-bound compact history without expanding verified evidence.

The original checkpoint, complete source revision set and live owner remain the
authority. Exported frames are transport only. No caller-supplied hash can create
a reusable native result, and export completion is still committed by the owner.
"""

from __future__ import annotations

from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    MAX_RECIPE_BYTES,
    checked_digest,
    inspect_recipe,
)
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_proof_archive import history_archive_key


def export_completed_checkpoint(reader, value, *, field_limits):
    """Return false only for an existing incompatible destination representation.

    The caller then uses its original decode/encode/conflict path. A missing or
    changed native source never falls back to treating new bytes as verified.
    """
    height = value["snapshot"]["block_number"]
    if reader.checkpoints.load(height) != value:
        raise HistoryCheckpointRepairRequired("checkpoint changed before compact export")
    with reader.journal.read_transaction() as db:
        reader.checkpoints.check_sources(value["sources"], db)
        keys = {("control_history_block", str(height))}
        frame = reader.remote_sources.get("control_history_block", str(height), db=db)
        if type(frame) is not dict or set(frame) != set(field_limits):
            raise HistoryCheckpointRepairRequired("verified history lost compact export source")
        fields = {}
        for name, maximum in field_limits.items():
            refs = frame[name]
            if (
                type(refs) is not list
                or not 0 < len(refs) <= (maximum + MAX_EVIDENCE_BYTES - 1) // MAX_EVIDENCE_BYTES
            ):
                raise ValueError("control history frame exceeds its chunk bound")
            parts = []
            total = 0
            for sha in refs:
                checked_digest(sha)
                keys.add(("control_history_chunk", sha))
                chunk = reader.remote_sources.get("control_history_chunk", sha, db=db)
                if type(chunk) is not dict or set(chunk) != {"length", "recipe_hex"}:
                    raise ValueError("control history chunk is missing or malformed")
                length, recipe = chunk["length"], chunk["recipe_hex"]
                if type(length) is not int or not 0 < length <= MAX_EVIDENCE_BYTES:
                    raise ValueError("control history chunk length exceeds its bound")
                total += length
                if total > maximum:
                    raise ValueError("control history frame expansion exceeds its bound")
                if type(recipe) is not str or not 0 < len(recipe) <= 2 * MAX_RECIPE_BYTES:
                    raise ValueError("control history recipe exceeds its bound")
                raw = bytes.fromhex(recipe)
                if raw.hex() != recipe:
                    raise ValueError("control history recipe is not canonical")
                for _, object_sha, _ in inspect_recipe(raw, expanded_bytes=length, kind="proof"):
                    keys.add(("control_history_object", object_sha))
                parts.append((sha, length, raw))
            fields[name] = tuple(parts)
        # The result must cover exactly this frame, every recipe and all its
        # objects. This is a retained native success, never a hash-only claim.
        if reader.checkpoints.sources(keys, db) != value["sources"]:
            raise HistoryCheckpointRepairRequired("compact export source coverage changed")
        copied = reader.export_archive.copy_encoded_transport(
            "history",
            history_archive_key(reader.config_sha256, reader.hotkey, height),
            context=reader._archive_context(height),
            fields=fields,
            resolve=lambda sha, size: reader._object(sha, size, db=db),
        )
        reader.checkpoints.check_sources(value["sources"], db)
    # Publication can precede a rejected identity check, but it never advances
    # native history. The owner's later remember() checks the revisions again.
    if reader.checkpoints.load(height) != value:
        raise HistoryCheckpointRepairRequired("checkpoint changed during compact export")
    return copied
