"""Receipt compatibility reuses original dependency checks without calculation."""

import json

import pytest

from umi import competition_verification_reuse as reuse
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Result(StrictProtocolModel):
    value: int


@pytest.fixture
def native(tmp_path, monkeypatch):
    monkeypatch.delenv("UMI_NATIVE_VERIFICATION_DIRECTORY", raising=False)
    monkeypatch.setattr(reuse, "runtime_identity", lambda: "a" * 64)
    monkeypatch.setattr(reuse, "admitted_policy_sha256s", lambda policy: (policy,))
    monkeypatch.setattr(reuse, "stage_bounds", lambda: None)
    owner = reuse.VerificationReuse(tmp_path / "native", owner={"owner": "local"})
    calls, restored = [], []
    key = "b" * 64
    objects = {key: b"old-proof"}

    @reuse.verified_replay("original", Result)
    def original(policy, objects, *, suffix=0):
        calls.append("original")
        return Result(value=len(objects(key)) + suffix)

    def restore(policy, objects, *, suffix=0):
        restored.append(True)
        with reuse.cached_verification_only():
            return original(policy, objects, suffix=suffix)

    @reuse.verified_replay("compatible", Result, restore=restore)
    def compatible(policy, objects, *, suffix=0):
        calls.append("compatible")
        raise AssertionError("compatibility may never re-execute original calculation")

    return owner, original, compatible, calls, restored, objects


def test_compatible_result_uses_original_receipt_and_keeps_exact_dependency(native):
    owner, original, compatible, calls, restored, objects = native
    with owner.selected():
        expected = original("policy", objects.__getitem__)
        result = compatible("policy", objects.__getitem__)
    assert result == expected and calls == ["original"] and restored == [True]
    receipts = [json.loads(path.read_bytes()) for path in owner.directory.glob("*.json")]
    assert len(receipts) == 2
    assert receipts[0]["dependencies"] == receipts[1]["dependencies"]
    assert len(receipts[0]["dependencies"]) == 1
    restarted = reuse.VerificationReuse(owner.directory, owner={"owner": "local"})
    with restarted.selected():
        assert compatible("policy", objects.__getitem__) == expected
    assert calls == ["original"] and restored == [True]


def test_cache_only_missing_dependency_cannot_calculate_or_publish(native):
    owner, _, compatible, calls, restored, objects = native
    with owner.selected(), pytest.raises(reuse.VerificationReceiptUnavailable):
        compatible("policy", objects.__getitem__)
    assert not calls and restored == [True]
    assert not list(owner.directory.glob("*.json"))


def test_cache_only_missing_owner_cannot_calculate(native):
    _, original, _, calls, _, objects = native
    with reuse.cached_verification_only(), pytest.raises(reuse.VerificationReceiptUnavailable):
        original("policy", objects.__getitem__)
    assert not calls


def test_changed_dependency_during_restore_never_falls_back(native):
    owner, original, compatible, calls, restored, objects = native
    with owner.selected():
        original("policy", objects.__getitem__)
        objects[next(iter(objects))] = b"changed-proof"
        with pytest.raises(reuse.VerificationReceiptUnavailable, match="dependency changed"):
            compatible("policy", objects.__getitem__)
    assert calls == ["original"] and restored == [True]
    assert len(list(owner.directory.glob("*.json"))) == 1


def test_completed_outer_receipt_damage_requires_repair_not_restoration(native):
    owner, original, compatible, calls, restored, objects = native
    with owner.selected():
        original("policy", objects.__getitem__)
        before = set(owner.directory.glob("*.json"))
        compatible("policy", objects.__getitem__)
        (outer,) = set(owner.directory.glob("*.json")) - before
        outer.unlink()  # Its durable completion marker still exists.
        with pytest.raises(reuse.VerificationReceiptUnavailable, match="needs repair"):
            compatible("policy", objects.__getitem__)
    assert calls == ["original"] and restored == [True]


def test_new_native_work_can_decline_migration_without_changing_receipt_key(native):
    owner, _, _, calls, _, objects = native

    @reuse.verified_replay("genuine_first", Result, restore=lambda *a, **kw: None)
    def first(policy, objects, *, suffix=2):
        calls.append("first")
        return Result(value=len(objects("b" * 64)) + suffix)

    with owner.selected():
        assert first("policy", objects.__getitem__).value == 11
    expected_context = reuse._identity(
        {
            "arguments": {"policy": "policy", "suffix": 2},
            "bounds": None,
            "lineage": ("policy",),
            "owner": owner.owner,
            "runtime": owner.runtime,
            "stage": "genuine_first",
        }
    )
    expected_key = reuse._sha(canonical_json_bytes(expected_context))
    assert (owner.directory / (expected_key + ".json")).is_file()
    assert calls == ["first"]
