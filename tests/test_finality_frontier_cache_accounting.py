"""Native audit metadata remains compatible with weight-cache consumers."""

import os

import pytest

from umi.competition_chain_state import _cache_usage
from umi.grandpa_finality_supervisor import DurableGrandpaFinalityPort
from umi.protocol import canonical_json_bytes

from .test_grandpa_finality_supervisor import _audit_history, _port
from .test_grandpa_finality_supervisor import chain_observation as chain_observation
from .test_grandpa_finality_supervisor import observer as observer


def native_cache(tmp_path, observer, chain_observation, namespaced):
    root = tmp_path / "cache"
    root.mkdir(mode=0o700)
    namespace = "ab" * 32
    folder = root / namespace if namespaced else root
    folder.mkdir(mode=0o700, exist_ok=True)
    if namespaced:
        budget = folder / "namespace-budget.json"
        budget.write_bytes(
            canonical_json_bytes(
                {
                    "schema": "umi-competition-weight-cache-budget/1",
                    "configuration_sha256": namespace,
                    "maximum_namespace_bytes": 1024**2,
                }
            )
        )
        budget.chmod(0o400)
    port = _port(folder, observer, chain_observation)
    _audit_history(port, observer)
    return root, folder, port


@pytest.mark.parametrize("namespaced", [False, True])
def test_real_finality_metadata_is_charged_and_unpublished_files_released(
    tmp_path, observer, chain_observation, monkeypatch, namespaced
):
    root, folder, port = native_cache(tmp_path, observer, chain_observation, namespaced)
    expected = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    assert sum(_cache_usage(root, 2 * 1024**2).values()) == expected
    pending = port._frontier.root / ".completion-interrupted"
    pending.write_bytes(b"unpublished metadata")
    pending.chmod(0o600)
    assert sum(_cache_usage(root, 2 * 1024**2).values()) == expected + pending.stat().st_size
    monkeypatch.setattr(
        DurableGrandpaFinalityPort,
        "_audit_snapshot",
        lambda *a, **k: pytest.fail("unchanged finality was replayed during temp cleanup"),
    )
    assert _port(folder, observer, chain_observation).persisted_head() == port.persisted_head()
    assert not pending.exists()
    assert sum(_cache_usage(root, 2 * 1024**2).values()) == expected


@pytest.mark.parametrize(
    "unsafe", ["directory", "symlink", "hardlink", "public", "oversized", "unknown"]
)
def test_unsafe_frontier_cannot_bypass_cache_accounting(
    tmp_path, observer, chain_observation, unsafe
):
    root, _, port = native_cache(tmp_path, observer, chain_observation, True)
    path = port._frontier.root / "audit-progress.json"
    path.unlink(missing_ok=True)
    if unsafe == "directory":
        path.mkdir(mode=0o700)
    elif unsafe == "symlink":
        path.symlink_to(port._frontier.record)
    elif unsafe == "hardlink":
        os.link(port._frontier.record, path)
    else:
        if unsafe == "unknown":
            path = path.with_name("unexpected")
        path.write_bytes(b"x" * (65537 if unsafe == "oversized" else 1))
        path.chmod(0o644 if unsafe == "public" else 0o600)
    with pytest.raises((ValueError, OSError)):
        _cache_usage(root, 2 * 1024**2)
