"""Transport checkpoint-bound coverage recipes without expanding proof bytes.

Native endpoint completion and its full source revisions remain the authority.
The original archive writer remains the compatibility path when an existing
destination uses a different valid encoding. Transport never issues native
coverage or interval credit.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from .competition_evidence_codec import MAX_RECIPE_BYTES, checked_digest, inspect_recipe
from .competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
from .competition_reward_coverage_intervals import CoveragePoint
from .competition_reward_proof_archive import RewardProofArchive
from .open_competition import identity

if TYPE_CHECKING:
    from .competition_reward_coverage_journal import RewardCoverageJournal


def export_completed_endpoint(
    journal: RewardCoverageJournal,
    key: str,
    archive: RewardProofArchive,
    *,
    field_kinds: Mapping[str, str],
) -> bool:
    value = journal.checkpoints.load(key)
    if value is None:
        return False
    point = CoveragePoint.model_validate(value["point"])
    if point.key() != key:
        raise CoverageCheckpointRepairRequired("coverage compact export changed endpoint identity")
    with journal.journal.read_transaction() as db:
        if (
            journal.checkpoints.sources(((v[0], v[1]) for v in value["sources"]), db)
            != value["sources"]
        ):
            raise CoverageCheckpointRepairRequired("coverage compact export sources changed")

        def source(kind, sha):
            return journal.externalized.get(kind, sha, db=db)

        frame = source("coverage_endpoint", key)
        if (
            type(frame) is not dict
            or set(frame) != {"point", "validator_hotkey", "package", "blobs"}
            or CoveragePoint.model_validate(frame["point"]) != point
            or frame["package"] != value["package_sha256"]
            or identity(frame["validator_hotkey"]) != point.validator_account_id
            or type(frame["blobs"]) is not dict
            or set(frame["blobs"]) != set(field_kinds)
        ):
            raise CoverageCheckpointRepairRequired(
                "coverage compact export lost its original frame"
            )
        keys = {("coverage_endpoint", key)}
        fields = {}
        for name, kind in field_kinds.items():
            sha = checked_digest(frame["blobs"][name])
            tag = "coverage_blob_" + kind
            keys.add((tag, sha))
            blob = source(tag, sha)
            if (
                type(blob) is not dict
                or set(blob) != {"length", "recipe_hex"}
                or type(blob["recipe_hex"]) is not str
                or not 0 < len(blob["recipe_hex"]) <= 2 * MAX_RECIPE_BYTES
            ):
                raise CoverageCheckpointRepairRequired("coverage compact export recipe is damaged")
            recipe = bytes.fromhex(blob["recipe_hex"])
            if recipe.hex() != blob["recipe_hex"]:
                raise CoverageCheckpointRepairRequired(
                    "coverage compact export recipe is not canonical"
                )
            for _, object_sha, _ in inspect_recipe(
                recipe, expanded_bytes=blob["length"], kind=kind
            ):
                keys.add(("coverage_object", object_sha))
            fields[name] = ((sha, blob["length"], recipe),)
        if journal.checkpoints.sources(keys, db) != value["sources"]:
            raise CoverageCheckpointRepairRequired(
                "coverage compact export source coverage changed"
            )

        def resolve(sha, size):
            raw = source("coverage_object", sha)
            if (
                type(raw) is not dict
                or set(raw) != {"hex"}
                or type(raw["hex"]) is not str
                or len(raw["hex"]) != 2 * size
            ):
                raise CoverageCheckpointRepairRequired("coverage compact export object is damaged")
            data = bytes.fromhex(raw["hex"])
            if data.hex() != raw["hex"]:
                raise CoverageCheckpointRepairRequired(
                    "coverage compact export object is not canonical"
                )
            return data

        copied = archive.copy_encoded_transport(
            "endpoint",
            key,
            context={
                "point": frame["point"],
                "package": frame["package"],
                "validator_hotkey": frame["validator_hotkey"],
            },
            fields=fields,
            resolve=resolve,
        )
        if (
            journal.checkpoints.sources(((v[0], v[1]) for v in value["sources"]), db)
            != value["sources"]
        ):
            raise CoverageCheckpointRepairRequired("coverage compact export sources changed")
    if journal.checkpoints.load(key) != value:
        raise CoverageCheckpointRepairRequired("coverage checkpoint changed during compact export")
    return copied
