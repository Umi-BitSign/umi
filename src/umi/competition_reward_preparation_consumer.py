"""Restore local consumer bindings without changing historical native facts."""

from __future__ import annotations

from .competition_reward_coverage_models import CoverageModelDependencies
from .competition_reward_preparation_checkpoint import PreparationCheckpointRepairRequired
from .open_competition import digest
from .protocol import canonical_json_bytes


def completed_consumer_dependencies(store, historical, consumer):
    """Return the consumer dependency key only for identical completed work.

    The historical record supplies the allocation and original review time.
    The consumer record supplies an independently completed local binding, which
    may be newer. Neither immutable record is replaced or backdated. The caller
    must restore the returned dependencies against its actual selected verifier.
    """
    local_fields = {"package_identity", "model_verifier_sha256", "reviewed_at_block"}
    if (
        set(historical) != set(consumer)
        or historical.get("schema") != "umi-standing-preparation-native/1"
        or any(historical[k] != consumer[k] for k in historical.keys() - local_fields)
    ):
        raise PreparationCheckpointRepairRequired(
            "historical preparation and consumer have different native results"
        )
    models = []
    keys = []
    for fact in (historical, consumer):
        key = store.key(fact["activation_sha256"], fact["reviewed_at_block"])
        completion = store.load_completion(key)
        if (
            completion is None
            or set(completion) != {"schema", "models"}
            or completion["schema"] != "umi-standing-preparation-dependencies/1"
        ):
            raise PreparationCheckpointRepairRequired(
                "consumer restoration requires both original dependency completions"
            )
        try:
            value = CoverageModelDependencies.model_validate_json(
                canonical_json_bytes(completion["models"])
            )
        except ValueError as error:
            raise PreparationCheckpointRepairRequired(
                "consumer restoration has unsupported model dependency metadata"
            ) from error
        if (
            value.mode == "native_required"
            or (None if value.context is None else digest(value.context))
            != fact["model_verifier_sha256"]
        ):
            raise PreparationCheckpointRepairRequired(
                "consumer restoration lacks bound reusable model dependencies"
            )
        models.append(value)
        keys.append(key)
    before, after = models
    if (before.schema_, before.mode, before.items) != (after.schema_, after.mode, after.items):
        raise PreparationCheckpointRepairRequired("consumer restoration changes model receipts")
    if (before.context is None) != (after.context is None):
        raise PreparationCheckpointRepairRequired("consumer restoration changes model selection")
    if before.context is not None:
        excluded = {"receipts_path", "receipts_identity"}
        if before.context.model_dump(exclude=excluded) != after.context.model_dump(
            exclude=excluded
        ):
            raise PreparationCheckpointRepairRequired(
                "consumer restoration changes model verification semantics"
            )
    return keys[1]
