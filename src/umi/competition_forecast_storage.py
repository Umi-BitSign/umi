"""Select forecast archival independently of native proof transport migration."""

from pathlib import Path

from pydantic import model_validator

from .competition_remote_proof_store import ProofArchiveR2Config, RemoteProofStore


class ForecastArchiveConfig(ProofArchiveR2Config):
    @model_validator(mode="after")
    def forecast_owner(self):
        if (
            self.read_only
            or self.legacy_read_through
            or self.receipt_source_directory is not None
            or self.source_release_batch_records
            or self.archive_backfill_batch_frames
            or self.archive_release_batch_files
            or self.imported_object_release_batch_files
        ):
            raise ValueError("forecast archive requires a writable independent receipt owner")
        return self


def forecast_remote(root, selection, fallback):
    if selection is None:
        return fallback
    return RemoteProofStore(root / "forecast-archive", selection)


def forecast_credential_paths(selection, proof_stores):
    if selection is None:
        return ()
    existing = () if proof_stores is None else proof_stores.credential_paths()
    path = Path(selection.credentials_file)
    return () if path in existing else (path,)
