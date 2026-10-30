"""Package lifetimes across prefix entries; native authentication tested separately."""

import weakref
from functools import partial
from types import SimpleNamespace

import pytest

from umi import competition_reward_control_publisher as publisher_module
from umi import competition_reward_coordinator as coordinator_module
from umi.open_competition import digest
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Activation(StrictProtocolModel):
    package_sha256: str
    allocation_sha256: str
    reward_adoption_sha256: str | None = None


class Decision(StrictProtocolModel):
    activation: Activation
    admission_adoption_sha256: str | None = None


class Signed(StrictProtocolModel):
    decision: Decision


class Package(StrictProtocolModel):
    allocation: str


@pytest.mark.parametrize("operation", ["readback", "delivered"])
@pytest.mark.parametrize("changed", [False, True])
def test_prefix_drops_old_graph_before_loading_next(monkeypatch, operation, changed):
    prefix = tuple(
        Signed(
            decision=Decision(
                activation=Activation(
                    package_sha256=key,
                    allocation_sha256=digest("allocation-" + key),
                )
            )
        )
        for key in ("one", "two")
    )
    decisions = {digest(item.decision): canonical_json_bytes(item) for item in prefix}
    references, loaded = [], []

    def package(key):
        assert all(ref() is None for ref in references), "previous graph overlaps next decode"
        result = Package(allocation="changed" if changed and key == "two" else "allocation-" + key)
        references.append(weakref.ref(result))
        loaded.append(key)
        return result

    files = SimpleNamespace(verified_package=package, decision=decisions.__getitem__)
    if operation == "readback":
        owner = SimpleNamespace(readback=files, publisher=SimpleNamespace(files=files))
        run = partial(coordinator_module.StandingRewardCoordinator._readback, owner, prefix)
    else:
        # Only signature-envelope parsing is substituted: the test isolates
        # lifetime while retaining actual allocation digest comparisons.
        monkeypatch.setattr(publisher_module, "SignedRewardControlDecision", Signed)
        owner = SimpleNamespace(files=files)
        run = partial(publisher_module.StandingControlPublisher._delivered, owner, prefix)
    if changed:
        with pytest.raises(ValueError, match="allocation"):
            run()
    else:
        run()
        assert all(ref() is None for ref in references)
    assert loaded == ["one", "two"]
