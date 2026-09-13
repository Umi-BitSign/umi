from __future__ import annotations

import pytest

from umi import competition_host_activation as activation
from umi import competition_host_upgrade as host


def test_worker_inputs_entrypoint_delegates_to_fixed_loader(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(activation, "load_successor_worker_inputs", lambda: sentinel)
    assert host.load_successor_worker_inputs() is sentinel


def test_activation_entrypoint_preserves_owned_observation(monkeypatch):
    observation, sentinel = object(), object()

    def load(*, owned_observation):
        assert owned_observation is observation
        return sentinel

    monkeypatch.setattr(activation, "load_authenticated_successor_activation", load)
    assert host.load_authenticated_successor_activation(owned_observation=observation) is sentinel


def test_activation_entrypoint_does_not_replace_missing_proof(monkeypatch):
    def load(*, owned_observation):
        assert owned_observation is None
        raise activation.HostActivationError("owned observation required")

    monkeypatch.setattr(activation, "load_authenticated_successor_activation", load)
    with pytest.raises(activation.HostActivationError, match="owned observation required"):
        host.load_authenticated_successor_activation()


def test_activation_validation_preserves_every_binding(monkeypatch):
    sentinel = object()
    expected = dict(
        validator_hotkey="test-hotkey",
        directive_sha256="a" * 64,
        package_sha256="b" * 64,
        authorization_sha256="c" * 64,
        expected_profile="competition_weights",
    )

    def validate(value, **bindings):
        assert value is sentinel
        assert bindings == expected
        raise activation.HostActivationError("not an authority capability")

    monkeypatch.setattr(activation, "validate_authenticated_successor_activation", validate)
    with pytest.raises(activation.HostActivationError, match="not an authority capability"):
        host.validate_authenticated_successor_activation(sentinel, **expected)
