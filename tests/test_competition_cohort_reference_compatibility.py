"""Historical reference commitments survive wrappers without changing their bytes."""

import hashlib
import json

import pytest

from umi.competition_cohort_endpoint_archive import JournalEndpointObjects, read_endpoint_object
from umi.competition_cohort_object_codec import (
    endpoint_object_bytes,
    validate_endpoint_object_bytes,
)
from umi.competition_cohort_reward_package import ReplayObjectCollector, RewardPackageObject
from umi.competition_cohort_service_quality import ServiceReference
from umi.competition_cohort_service_reference import ServiceReference as ExtractedServiceReference
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


def materializer_bytes(value):
    """Historical producer encoding, deliberately independent of the new codec."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def reference_value(text="hello", **changes):
    return {
        "schema": "umi-cohort-service-reference/1",
        "case_id": "91" * 32,
        "video_sha256": "92" * 32,
        "stratum": "fingerspelling",
        "salt": "41" * 32,
        "reference": text,
    } | changes


@pytest.mark.parametrize("text", ["hello world", "café 世界 👋 e\u0301"])
@pytest.mark.parametrize("encoding", ["typed", "historical"])
def test_exact_reference_commitment_survives_all_storage_boundaries(tmp_path, text, encoding):
    value = reference_value(text)
    reference = ServiceReference.model_validate(value)
    raw = canonical_json_bytes(reference) if encoding == "typed" else materializer_bytes(value)
    key = digest(reference) if encoding == "typed" else hashlib.sha256(raw).hexdigest()
    assert ServiceReference is ExtractedServiceReference
    assert endpoint_object_bytes(json.loads(raw), key) == raw
    validate_endpoint_object_bytes(raw, key)
    assert read_endpoint_object({key: raw}.__getitem__, key) == raw

    collector = ReplayObjectCollector({key: raw}.__getitem__, maximum_bytes=1024**2)
    assert collector(key) == collector(key) == raw
    assert collector.used == len(raw)
    assert collector.values == {key: raw}
    item = RewardPackageObject(sha256=key, value=json.loads(collector(key)))
    wrapper = canonical_json_bytes(item)
    decoded = RewardPackageObject.model_validate_json(wrapper)
    assert decoded.sha256 == key
    assert endpoint_object_bytes(decoded.value, decoded.sha256) == raw

    journal_root = tmp_path / "journal"
    binding = {"fixture": "historical-service-reference"}
    journal = RoundJournal(journal_root, binding)
    journal.put("endpoint_replay_object", key, decoded.value)
    objects = JournalEndpointObjects(journal)
    assert read_endpoint_object(objects, key) == raw
    reopened = JournalEndpointObjects(RoundJournal(journal_root, binding))
    assert read_endpoint_object(reopened, key) == raw
    assert journal.get("endpoint_replay_object", key) == value
    if encoding == "typed":
        assert reopened.put(reference) == key

    files = SettlementEvidenceFiles(tmp_path / "delivery")
    files.publish(key, reopened)
    path = files.root / (key + ".json")
    original = path.read_bytes()
    files.publish(key, collector)  # Recovery of a lost acknowledgement is idempotent.
    assert path.read_bytes() == original
    assert SettlementEvidenceFiles(files.root)(key) == raw
    replica = ReplayObjectCollector(files, maximum_bytes=1024**2)
    assert replica(key) == raw
    assert ServiceReference.model_validate_json(replica(key)) == reference
    assert path.read_bytes() == original


def test_mixed_typed_and_historical_reference_inventory_keeps_both_identities(tmp_path):
    value = reference_value("café 世界")
    typed, historical = canonical_json_bytes(value), materializer_bytes(value)
    typed_key, historical_key = digest(value), hashlib.sha256(historical).hexdigest()
    assert typed_key != historical_key and typed != historical
    originals = {typed_key: typed, historical_key: historical}
    files = SettlementEvidenceFiles(tmp_path / "mixed")
    for key in originals:
        files.publish(key, originals.__getitem__)
    items = tuple(RewardPackageObject(sha256=k, value=json.loads(v)) for k, v in originals.items())
    reconstructed = {item.sha256: endpoint_object_bytes(item.value, item.sha256) for item in items}
    assert reconstructed == originals
    assert {key: read_endpoint_object(files, key) for key in originals} == originals


@pytest.mark.parametrize("damage", ["value", "wrapper_key", "typed_substitution"])
def test_delivered_reference_wrapper_cannot_change_original_commitment(tmp_path, damage):
    value = reference_value("café 世界")
    raw = materializer_bytes(value)
    key = hashlib.sha256(raw).hexdigest()
    files = SettlementEvidenceFiles(tmp_path / "delivery")
    files.publish(key, {key: raw}.__getitem__)
    path = files.root / (key + ".json")
    wrapper = json.loads(path.read_bytes())
    if damage == "value":
        wrapper["value"]["reference"] = "changed"
    elif damage == "wrapper_key":
        wrapper["sha256"] = "00" * 32
    else:
        # A valid typed identity for the same answer cannot replace the catalog's
        # original raw commitment in a delivery slot.
        wrapper["sha256"] = digest(value)
    path.write_bytes(canonical_json_bytes(wrapper))
    changed = path.read_bytes()
    with pytest.raises(ValueError):
        SettlementEvidenceFiles(files.root)(key)
    assert path.read_bytes() == changed  # Readers never repair untrusted evidence.


@pytest.mark.parametrize(
    "damage",
    ["unknown_schema", "extra", "missing", "invalid_stratum", "empty", "blank", "type", "hex"],
)
def test_legacy_exception_requires_exact_valid_reference_schema(damage):
    value = reference_value()
    if damage == "unknown_schema":
        value["schema"] = "umi-cohort-service-reference/2"
    elif damage == "extra":
        value["chain_submission_authorized"] = True
    elif damage == "missing":
        del value["salt"]
    else:
        field, replacement = {
            "invalid_stratum": ("stratum", "other"),
            "empty": ("reference", ""),
            "blank": ("reference", "   "),
            "type": ("reference", 123),
            "hex": ("case_id", "AA" * 32),
        }[damage]
        value[field] = replacement
    raw = materializer_bytes(value)
    key = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        validate_endpoint_object_bytes(raw, key)
    if damage != "unknown_schema":
        with pytest.raises(ValueError):
            endpoint_object_bytes(value, key)


@pytest.mark.parametrize("value", [{"reference": "hello"}, ["hello"], "hello", 7, None])
def test_raw_hash_compatibility_does_not_admit_arbitrary_objects(value):
    raw = materializer_bytes(value)
    key = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        read_endpoint_object({key: raw}.__getitem__, key)
    # Existing domain-separated object identities still work.
    typed = canonical_json_bytes(value)
    assert read_endpoint_object({digest(value): typed}.__getitem__, digest(value)) == typed


@pytest.mark.parametrize("encoding", ["typed", "historical"])
@pytest.mark.parametrize("damage", ["answer", "salt", "newline", "pretty", "duplicate", "key"])
def test_tampering_is_rejected_before_collection_or_delivery(tmp_path, encoding, damage):
    value = reference_value("café 世界")
    raw = canonical_json_bytes(value) if encoding == "typed" else materializer_bytes(value)
    key = digest(value) if encoding == "typed" else hashlib.sha256(raw).hexdigest()
    files = SettlementEvidenceFiles(tmp_path / "delivery")
    files.publish(key, {key: raw}.__getitem__)
    path = files.root / (key + ".json")
    original = path.read_bytes()
    if damage in {"answer", "salt"}:
        changed = value | ({"reference": "changed"} if damage == "answer" else {"salt": "42" * 32})
        raw = canonical_json_bytes(changed) if encoding == "typed" else materializer_bytes(changed)
    elif damage == "newline":
        raw += b"\n"
    elif damage == "pretty":
        raw = json.dumps(value, indent=2, sort_keys=True).encode()
    elif damage == "duplicate":
        raw = raw[:-1] + b',"reference":"substituted"}'
    else:
        key = "00" * 32
    collector = ReplayObjectCollector({key: raw}.__getitem__, maximum_bytes=1024**2)
    with pytest.raises(ValueError):
        collector(key)
    assert collector.values == {} and collector.used == 0
    with pytest.raises(ValueError):
        files.publish(key, {key: raw}.__getitem__)
    assert path.read_bytes() == original


@pytest.mark.parametrize("encoding", ["typed", "historical"])
def test_unicode_representation_cannot_be_substituted_under_original_key(encoding):
    value = reference_value("café 世界")
    typed, historical = canonical_json_bytes(value), materializer_bytes(value)
    key = digest(value) if encoding == "typed" else hashlib.sha256(historical).hexdigest()
    changed = historical if encoding == "typed" else typed
    with pytest.raises(ValueError):
        validate_endpoint_object_bytes(changed, key)


@pytest.mark.parametrize("damage", ["newline", "pretty", "duplicate", "utf8"])
def test_self_hashed_nonhistorical_encoding_does_not_expand_the_legacy_exception(damage):
    value = reference_value("café 世界")
    raw = materializer_bytes(value)
    raw = {
        "newline": raw + b"\n",
        "pretty": json.dumps(value, indent=2, sort_keys=True).encode(),
        "duplicate": raw[:-1] + b',"salt":"' + value["salt"].encode() + b'"}',
        "utf8": canonical_json_bytes(value),
    }[damage]
    with pytest.raises(ValueError):
        validate_endpoint_object_bytes(raw, hashlib.sha256(raw).hexdigest())
