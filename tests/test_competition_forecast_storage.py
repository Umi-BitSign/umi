"""Independent forecast transport preserves existing native proof selection."""

from pathlib import Path

import pytest

from umi import competition_forecast_storage as module
from umi.competition_remote_proof_store import MAX_PROOF_OBJECT_BYTES, ProofArchiveStores


def selection(**changes):
    return module.ForecastArchiveConfig.model_validate(
        {
            "schema": "umi-r2-proof-archive/2",
            "credentials_file": "/private/r2.json",
            "bucket": "forecast-evidence",
            "prefix": "forecast-owner",
            "read_only": False,
            "maximum_cache_bytes": MAX_PROOF_OBJECT_BYTES,
            "maximum_index_bytes": 1024**2,
            **changes,
        }
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"read_only": True},
        {"legacy_read_through": True},
        {
            "read_only": True,
            "legacy_read_through": True,
            "receipt_source_directory": "/private/old",
        },
    ],
)
def test_forecast_storage_refuses_read_only_or_native_migration(changes):
    with pytest.raises(ValueError):
        selection(**changes)


def test_dedicated_selection_does_not_mutate_or_migrate_fallback(tmp_path, monkeypatch):
    fallback, selected = object(), selection()
    called = []

    def create(root, config):
        called.append((root, config))
        return "selected forecast store"

    monkeypatch.setattr(module, "RemoteProofStore", create)
    assert module.forecast_remote(tmp_path, None, fallback) is fallback
    assert module.forecast_remote(tmp_path, selected, fallback) == "selected forecast store"
    assert called == [(tmp_path / "forecast-archive", selected)]
    assert module.forecast_credential_paths(selected, None) == (Path("/private/r2.json"),)
    proofs = ProofArchiveStores.model_validate(
        {
            "schema": "umi-proof-archive-stores/1",
            "exported": selected.model_dump(by_alias=True),
        }
    )
    assert module.forecast_credential_paths(selected, proofs) == ()
