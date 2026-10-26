"""Publication diagnostics survive restart without touching native package bodies."""

import builtins
import json
import os
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from umi.competition_cohort_publication_progress import NativePublicationProgress
from umi.competition_verification_reuse import metadata_completion

SERIES, COHORT, EVALUATOR, PREFIX = (letter * 64 for letter in "abcd")


def publication(tmp_path, **kwargs):
    return NativePublicationProgress(
        tmp_path / "metadata",
        tmp_path / "native-package.json",
        series=SERIES,
        cohort=COHORT,
        evaluator=kwargs.pop("evaluator", EVALUATOR),
        maximum_package_bytes=1024,
        **kwargs,
    )


def output(tmp_path):
    path = tmp_path / "native-package.json"
    path.write_bytes(b"native package payload must not be read")
    path.chmod(0o600)
    return path


def forbid_package_reads(monkeypatch, path):
    original_open, original_path_open, original_os_open = builtins.open, Path.open, os.open

    def checked(original):
        def guard(file, *args, **kwargs):
            if isinstance(file, (str, bytes, os.PathLike)) and Path(file) == path:
                raise AssertionError("publication diagnostics read the package payload")
            return original(file, *args, **kwargs)

        return guard

    monkeypatch.setattr(builtins, "open", checked(original_open))
    monkeypatch.setattr(Path, "open", checked(original_path_open))
    monkeypatch.setattr(os, "open", checked(original_os_open))


def test_native_prefix_required_and_restart_preserves_original_receipt(tmp_path, monkeypatch):
    path = output(tmp_path)
    p = publication(tmp_path)
    forbid_package_reads(monkeypatch, path)
    assert p.observe(None) is None
    assert not p.path.exists()
    first = p.observe(PREFIX)
    raw = p.path.read_bytes()
    assert json.loads(raw)["schema"] == "umi-native-publication-observation/1"
    assert first["state"] == "completed" and first["output_current"]
    assert first["basis"] == "selected_native_certification_and_owned_output"
    restarted = publication(tmp_path)
    assert restarted.observe(PREFIX) == first
    assert p.path.read_bytes() == raw
    # A crash after the receipt rename but before its marker is recoverable
    # without replacing the original publication observation.
    metadata_completion(p.path).unlink()
    assert restarted.observe(PREFIX) == first
    assert metadata_completion(p.path).exists()
    assert p.path.read_bytes() == raw


@pytest.mark.parametrize(
    "fault", ["output_missing", "output_changed", "binding", "receipt", "damaged"]
)
def test_completed_fact_faults_are_explicit_repairs(tmp_path, fault):
    path = output(tmp_path)
    p = publication(tmp_path)
    first = p.observe(PREFIX)
    original = p.path.read_bytes()
    if fault == "output_missing":
        path.unlink()
    elif fault == "output_changed":
        path.write_bytes(b"replacement")
    elif fault == "binding":
        p = publication(tmp_path, evaluator="f" * 64)
    elif fault == "receipt":
        p.path.unlink()
    else:
        body = json.loads(original)
        body["observed_unix_ms"] += 1
        p.path.write_text(json.dumps(body))
    reason = {
        "output_missing": "publication_output_missing",
        "output_changed": "publication_output_changed",
        "binding": "publication_native_binding_changed",
        "receipt": "publication_receipt_missing",
        "damaged": "publication_receipt_damaged",
    }[fault]
    result = p.observe(PREFIX)
    assert result["state"] == "repair_required" and result["reason_code"] == reason
    assert not result["output_current"]
    if fault in {"output_missing", "output_changed"}:
        assert result["observed_unix_ms"] == first["observed_unix_ms"]
        assert p.path.read_bytes() == original


@pytest.mark.parametrize("fault", ["empty", "oversized", "public", "symlink", "hardlink"])
def test_legacy_adoption_requires_bounded_owned_private_output(tmp_path, fault):
    path = output(tmp_path)
    if fault == "empty":
        path.write_bytes(b"")
    elif fault == "oversized":
        path.write_bytes(b"x" * 1025)
    elif fault == "public":
        path.chmod(0o644)
    elif fault == "symlink":
        path.rename(tmp_path / "original")
        path.symlink_to(tmp_path / "original")
    else:
        os.link(path, tmp_path / "additional")
    p = publication(tmp_path)
    assert p.observe(PREFIX)["reason_code"] == "publication_output_identity_invalid"
    assert not p.path.exists()


def test_first_publication_still_pending_is_not_a_repair(tmp_path):
    p = publication(tmp_path)
    assert p.observe(PREFIX) is None
    assert not p.path.exists()


async def test_owner_binding_follows_native_history_selection_only(monkeypatch):
    from umi import competition_cohort_settlement_service as service

    node = object.__new__(service.CohortSettlementService)
    node.config = NS(role="coordinator")
    events = []
    node.public_progress = NS(bind_publication=lambda prefix: events.append(("bound", prefix)))
    closure = NS(phase="certification", operation="close_phase")
    selected = NS(transitions=(NS(transition=closure),))

    async def handoff():
        events.append("handoff")
        return "unselected"

    async def receive(value):
        assert value == "unselected"
        events.append("authenticated_native_selection")
        return selected

    node._handoff, node._receive_history = handoff, receive
    monkeypatch.setattr(service, "digest", lambda value: PREFIX if value is closure else None)
    original = service.CohortSettlementService._selected_history.__wrapped__
    assert await original(node) is selected
    assert events == ["handoff", "authenticated_native_selection", ("bound", PREFIX)]
    events.clear()
    selected.transitions = ()
    assert await original(node) is selected
    assert events == ["handoff", "authenticated_native_selection"]
    events.clear()
    selected.transitions = (NS(transition=closure),)
    node.config.role = "reviewer"
    assert await original(node) is selected
    assert events == ["handoff", "authenticated_native_selection"]
