"""First-install consent and later maintenance select one explicit worker source."""

from types import SimpleNamespace

import pytest

from umi import competition_supervisor_cli as cli
from umi import competition_worker_maintenance as maintenance
from umi.competition_reward_continuity import UNTIL_SUPERSEDED_BLOCK
from umi.competition_supervisor import parse_canonical_successor_operator_consent
from umi.competition_worker_overlay_scope import WorkerSourceOverlayScope
from umi.protocol import canonical_json_bytes

from .test_competition_supervisor import _consent
from .test_competition_supervisor import v3_predecessor as v3_predecessor


def scope():
    return WorkerSourceOverlayScope(
        package_sha256="a1" * 32,
        release_bundle_sha256="a2" * 32,
        recipient_amendment_sha256="a3" * 32,
    )


def test_historical_consent_bytes_unchanged(v3_predecessor):
    original = _consent(v3_predecessor)
    payload = canonical_json_bytes(original)
    assert b"worker_source_overlay" not in payload
    assert canonical_json_bytes(parse_canonical_successor_operator_consent(payload)) == payload
    added = _consent(
        v3_predecessor,
        reward_continuity_sha256="ab" * 32,
        valid_through_block=UNTIL_SUPERSEDED_BLOCK,
        worker_source_overlay=scope(),
    )
    payload = canonical_json_bytes(added)
    assert parse_canonical_successor_operator_consent(payload).worker_source_overlay == scope()
    assert b"successor_recipient_amendment_sha256" not in payload


@pytest.mark.parametrize(
    "change", [{"reward_continuity_sha256": None}, {"allowed_modes": ["competition_replay"]}]
)
def test_initial_overlay_requires_continuity_weights(v3_predecessor, change):
    values = dict(
        reward_continuity_sha256="ab" * 32,
        valid_through_block=UNTIL_SUPERSEDED_BLOCK,
        worker_source_overlay=scope(),
    )
    with pytest.raises(ValueError, match="requires reward continuity consent"):
        _consent(v3_predecessor, **(values | change))


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("maintenance_scope", [False, True])
def test_original_overlay_survives_host_only_maintenance(monkeypatch, present, maintenance_scope):
    calls = []
    installation = SimpleNamespace(operator_consent=SimpleNamespace(worker_source_overlay=scope()))
    original, replacement, signed = object(), object(), object()
    monkeypatch.setattr(cli.Path, "exists", lambda path: present)
    monkeypatch.setattr(cli, "_root_control", lambda path, maximum: b"root-owned")
    monkeypatch.setattr(cli, "_installed_signed_host", lambda value: signed)

    def maintained(payload, **kwargs):
        assert payload == b"root-owned" and kwargs["installation"] is installation
        calls.append("maintenance")
        return replacement if maintenance_scope else None

    def initial(**kwargs):
        assert kwargs == {"installation": installation, "signed_host": signed}
        calls.append("initial")
        return original

    monkeypatch.setattr(maintenance, "approved_worker_source_overlay", maintained)
    monkeypatch.setattr(maintenance, "approved_initial_worker_source_overlay", initial)
    selected = cli._worker_source_overlay(installation)
    assert selected is (replacement if present and maintenance_scope else original)
    assert calls == (["maintenance"] if present else []) + (
        [] if present and maintenance_scope else ["initial"]
    )


@pytest.mark.parametrize("present", [False, True])
def test_invalid_explicit_overlay_never_falls_back(monkeypatch, present):
    installation = SimpleNamespace(operator_consent=SimpleNamespace(worker_source_overlay=scope()))
    monkeypatch.setattr(cli.Path, "exists", lambda path: present)
    monkeypatch.setattr(cli, "_root_control", lambda path, maximum: b"bad-approval")
    monkeypatch.setattr(cli, "_installed_signed_host", lambda value: object())

    def denied(*args, **kwargs):
        raise ValueError("invalid explicit approval")

    monkeypatch.setattr(maintenance, "approved_worker_source_overlay", denied)
    monkeypatch.setattr(maintenance, "approved_initial_worker_source_overlay", denied)
    with pytest.raises(ValueError, match="invalid explicit approval"):
        cli._worker_source_overlay(installation)
