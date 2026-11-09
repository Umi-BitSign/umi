"""Historical allocation and current consumer bindings remain distinct facts."""

from copy import deepcopy

import pytest

from umi.competition_cohort_direct_model_upload import preserved_model_object_key
from umi.competition_reward_preparation_checkpoint import (
    PreparationCheckpointRepairRequired,
    PreparationCheckpoints,
)
from umi.competition_reward_preparation_consumer import completed_consumer_dependencies
from umi.open_competition import digest
from umi.protocol import sha256_hex


def records(tmp_path, change=None):
    store = PreparationCheckpoints(tmp_path / "facts", {"owner": "test"})
    activation, package = "01" * 32, "02" * 32
    store.begin(activation, package)
    context = {
        "policy_sha256": "03" * 32,
        "standing_review_sha256": "04" * 32,
        "namespace_sha256": "05" * 32,
        "source_owner": None,
        "receipts_path": "/old/receipts",
        "receipts_identity": [1, 2, 3],
        "semantics_sha256": "06" * 32,
    }
    historical = {
        "schema": "umi-standing-preparation-native/1",
        "activation_sha256": activation,
        "package_sha256": package,
        "package_identity": {"path": "/old/package"},
        "model_verifier_sha256": digest(context),
        "reviewed_at_block": 100,
        "allocation": {"retained": "original"},
        "policy_sha256": context["policy_sha256"],
    }
    cohort, model, payload = "11" * 32, "12" * 32, "13" * 32
    object_key = preserved_model_object_key(cohort, model, payload)
    item = {
        "cohort_sha256": cohort,
        "submission_sha256": "14" * 32,
        "authority_sha256": "15" * 32,
        "source_owner": "16" * 32,
        "object_key": object_key,
        "receipt": {
            "schema": "umi-direct-model-settlement-verification/2",
            "review_request_sha256": "17" * 32,
            "acceptance_sha256": "18" * 32,
            "source_object_key_sha256": sha256_hex(object_key.encode()),
            "model_sha256": model,
            "payload_sha256": payload,
            "total_bytes": 1024,
            "provider_etag": "original-generation",
        },
    }
    completion = {
        "schema": "umi-standing-preparation-dependencies/1",
        "models": {
            "schema": "umi-coverage-model-dependencies/1",
            "mode": "direct",
            "context": context,
            "items": [item],
        },
    }
    consumer, current = deepcopy(historical), deepcopy(completion)
    consumer.update(reviewed_at_block=200, package_identity={"path": "/current/package"})
    current["models"]["context"].update(
        receipts_path="/current/receipts", receipts_identity=[1, 4, 3]
    )
    if change:
        change(consumer, current)
    consumer["model_verifier_sha256"] = digest(current["models"]["context"])
    for fact, dependencies in ((historical, completion), (consumer, current)):
        store.retain_native(activation, fact["reviewed_at_block"], fact)
        store.retain_completion(store.key(activation, fact["reviewed_at_block"]), dependencies)
    return store, historical, consumer


def test_consumer_relocation_preserves_original_historical_authority(tmp_path):
    store, historical, consumer = records(tmp_path)
    before = store.status(historical["activation_sha256"], 150)
    context = {k: v for k, v in consumer.items() if k not in {"reviewed_at_block", "allocation"}}
    assert store.consumer_fact(historical["activation_sha256"], context=context) == consumer
    with pytest.raises(PreparationCheckpointRepairRequired, match="consumer context"):
        store.status(historical["activation_sha256"], 150, context=context)
    assert completed_consumer_dependencies(store, historical, consumer).endswith(":200")
    reopened = PreparationCheckpoints(store.root, {"owner": "test"})
    assert completed_consumer_dependencies(reopened, historical, consumer).endswith(":200")
    assert reopened.status(historical["activation_sha256"], 150) == before == historical
    assert reopened.status(historical["activation_sha256"], 99) is None


@pytest.mark.parametrize(
    "change",
    [
        lambda f, c: f.update(allocation={"retained": "changed"}),
        lambda f, c: f.update(policy_sha256="09" * 32),
        lambda f, c: c["models"]["context"].update(namespace_sha256="09" * 32),
        lambda f, c: c["models"]["context"].update(standing_review_sha256="09" * 32),
        lambda f, c: c["models"]["context"].update(semantics_sha256="09" * 32),
        lambda f, c: c["models"]["context"].update(source_owner="09" * 32),
        lambda f, c: c["models"].update(mode="native_required", items=[]),
        lambda f, c: c["models"]["items"][0]["receipt"].update(provider_etag="changed"),
        lambda f, c: c["models"]["items"][0]["receipt"].update(total_bytes=2048),
        lambda f, c: c["models"]["items"][0]["receipt"].update(acceptance_sha256="19" * 32),
        lambda f, c: c["models"].update(mode="empty", items=[]),
        lambda f, c: c["models"].update(schema="umi-coverage-model-dependencies/unknown"),
    ],
)
def test_consumer_relocation_rejects_changed_results_or_semantics(tmp_path, change):
    store, historical, consumer = records(tmp_path, change)
    with pytest.raises(PreparationCheckpointRepairRequired):
        completed_consumer_dependencies(store, historical, consumer)


def test_consumer_relocation_requires_original_dependency_completion(tmp_path):
    _store, historical, consumer = records(tmp_path)
    other = PreparationCheckpoints(tmp_path / "unfinished", {"owner": "test"})
    other.begin(historical["activation_sha256"], historical["package_sha256"])
    for fact in (historical, consumer):
        other.retain_native(fact["activation_sha256"], fact["reviewed_at_block"], fact)
    with pytest.raises(PreparationCheckpointRepairRequired, match="both original"):
        completed_consumer_dependencies(other, historical, consumer)
