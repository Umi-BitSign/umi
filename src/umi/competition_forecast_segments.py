"""Archive publication shares one transaction owner with forecast summaries.

The only staged payload is a bounded SQLite blob committed atomically with its
verified event identities and summaries. R2 completion receipts remain after
local payload release, so restart never replays completed publication work.
"""

from pathlib import Path

from .competition_forecast_archive import MAX_SEGMENT_BYTES, decode_segment
from .competition_forecast_index import ForecastIndex
from .competition_transport_verification import TransferProgress
from .private_files import ensure_private_directory


class ForecastSegments:
    def __init__(self, root, ledger_sha256, remote, *, maximum_index_bytes=512 * 1024**2):
        self.root = Path(root)
        if self.root.exists() and not (self.root / "index").exists():
            raise ValueError("forecast archive index missing; explicit repair required")
        ensure_private_directory(self.root)
        self.index = ForecastIndex(
            self.root / "index", ledger_sha256, maximum_bytes=maximum_index_bytes
        )
        self.ledger_sha256, self.remote = ledger_sha256, remote
        self.lock = self.index.lock

    def close(self):
        self.index.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def stage(self, segment):
        with TransferProgress("forecast_segment_sealing", len(segment.rows), unit="events") as work:
            result = self.index.stage_archive(segment)
            work.advance(len(segment.rows))
            return result

    def publish(self, first_sequence):
        metadata, receipt, _ = self.index.archive_state(first_sequence)
        with TransferProgress("forecast_segment_replication", metadata["bytes"]) as progress:
            if receipt is None:
                receipt = self.remote.reference_for_path(metadata["remote_path"])
            if receipt is None:
                # If this blob is damaged, the transport checksum will not
                # match the original verified segment. Never release it.
                raw = self.index.archive_body(first_sequence)
                receipt = self.remote.put_bytes(raw, path=metadata["remote_path"])
            self.remote.validate_reference(receipt)
            self.index.retain_archive_receipt(first_sequence, receipt)
            progress.advance(metadata["bytes"])
            return receipt

    def release(self, first_sequence):
        """Release staged bytes only; the owning ledger handles original rows."""
        with self.lock:
            _, receipt, released = self.index.archive_state(first_sequence)
            if receipt is None:
                raise ValueError("forecast segment has no completed durable publication")
            self.remote.validate_reference(receipt)
            if not released:
                with TransferProgress("forecast_segment_local_release", 1, unit="segments") as work:
                    self.index.release_archive(first_sequence)
                    work.advance(1)

    def read(self, first_sequence):
        with self.lock:
            metadata, receipt, _ = self.index.archive_state(first_sequence)
            if receipt is None:
                raise ValueError("forecast segment is not durably published")
        raw = self.remote.read_bytes(receipt, maximum=MAX_SEGMENT_BYTES)
        return decode_segment(
            raw,
            **{
                key: metadata[key]
                for key in ("ledger_sha256", "first_sequence", "previous_sha256", "last_sha256")
            },
        )
