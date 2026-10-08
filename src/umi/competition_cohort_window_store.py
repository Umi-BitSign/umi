"""Private dispatch reservations shared across cohorts and service queues.

Callers must authenticate the original grant and its exact request before using
this operational store. A reservation permits scheduling only: it cannot admit
a grant, extend signed clocks, authorize a replacement, or establish a reward.
Unknown sends survive restart until the miner signs their execution fence.
"""

from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_round_journal import RoundJournal
from .config import Limits
from .endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from .open_competition import Hotkey, digest, identity
from .protocol import Hex32, StrictProtocolModel, TranslationRequest, canonical_json_bytes


class WindowRequest(StrictProtocolModel):
    schema_: Literal["umi-cohort-window-request/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    miner_hotkey: Hotkey
    evaluator_hotkey: Hotkey
    grant_sha256: Hex32
    request: TranslationRequest


class WindowAdmissionHeld(RuntimeError):
    """The selected request remains pending; no transmission is authorized."""


_BOOTSTRAP = digest(["umi-cohort-window-bootstrap/1"])


class CohortMinerWindowStore:
    def __init__(
        self,
        directory: Path,
        *,
        cohorts: tuple[str, ...],
        evaluators: tuple[str, ...],
        transports: Mapping[str, Limits],
        bootstrap_sources: tuple[str, ...],
    ):
        if not cohorts or not evaluators or not transports or not bootstrap_sources:
            raise ValueError("window owner requires its complete configured scope")
        if len(set(bootstrap_sources)) != len(bootstrap_sources) or any(
            not isinstance(source, str) or not 1 <= len(source) <= 128
            for source in bootstrap_sources
        ):
            raise ValueError("window bootstrap sources must be distinct bounded identities")
        self.cohorts = frozenset(cohorts)
        self.evaluators = frozenset(identity(key) for key in evaluators)
        self.windows = {key: limits.maximum_active_windows for key, limits in transports.items()}
        self.sources = frozenset(bootstrap_sources)
        self.journal = RoundJournal(
            directory,
            {
                "schema": "umi-cohort-window-store/1",
                "cohorts": sorted(self.cohorts),
                "evaluators": sorted(self.evaluators),
                "transport_window_limits": self.windows,
                "bootstrap_sources": sorted(self.sources),
            },
            maximum_rounds=65536,
            maximum_bytes=1024**3,
            maximum_record_bytes=128 * 1024,
        )
        with self.journal.transaction() as db:
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='miner_windows'"
            ).fetchone()
            if (
                not exists
                and db.execute(
                    "SELECT 1 FROM records WHERE kind='window_request' LIMIT 1"
                ).fetchone()
            ):
                raise ValueError("window reservation index is missing; retain original state")
            db.execute(
                "CREATE TABLE IF NOT EXISTS miner_windows "
                "(request TEXT PRIMARY KEY, miner TEXT NOT NULL, window TEXT NOT NULL, "
                "retired INTEGER NOT NULL CHECK(retired IN (0,1)))"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS miner_windows_active ON miner_windows(miner,retired)"
            )

    def _selected(self, value):
        value = WindowRequest.model_validate_json(canonical_json_bytes(value))
        if (
            value.cohort_sha256 not in self.cohorts
            or identity(value.evaluator_hotkey) not in self.evaluators
            or value.request.scoring_policy_hash not in self.windows
        ):
            raise ValueError("window request is outside the configured owner scope")
        key = digest(
            [
                "umi-cohort-window-key/1",
                identity(value.miner_hotkey),
                identity(value.evaluator_hotkey),
                digest(value.request),
            ]
        )
        return key, value

    def _retain(self, value, *, importing=False, receipt=None):
        key, value = self._selected(value)
        if receipt is not None:
            receipt = verify_retirement_receipt(
                receipt,
                request=value.request,
                grant_sha256=value.grant_sha256,
                miner_hotkey=value.miner_hotkey,
                evaluator_hotkey=value.evaluator_hotkey,
            )
        result = "reserved"

        def index(db):
            nonlocal result
            sealed = self.journal.get("window_bootstrap", _BOOTSTRAP, db=db) is not None
            if importing and sealed:
                raise ValueError("window bootstrap is already sealed")
            if not importing and receipt is None and not sealed:
                raise WindowAdmissionHeld("window_bootstrap_pending")
            prior = db.execute(
                "SELECT miner,window,retired FROM miner_windows WHERE request=?", (key,)
            ).fetchone()
            miner, window = identity(value.miner_hotkey), value.request.window_id
            if prior is not None:
                if prior[:2] != (miner, window):
                    raise ValueError("window reservation index changed its request binding")
                result = "retired" if prior[2] or receipt is not None else "reserved"
            else:
                active = {
                    row[0]
                    for row in db.execute(
                        "SELECT DISTINCT window FROM miner_windows WHERE miner=? AND retired=0",
                        (miner,),
                    )
                }
                if (
                    not importing
                    and receipt is None
                    and window not in active
                    and len(active) >= self.windows[value.request.scoring_policy_hash]
                ):
                    raise WindowAdmissionHeld("miner_window_retirement_pending")
                db.execute(
                    "INSERT INTO miner_windows VALUES (?,?,?,?)",
                    (key, miner, window, int(receipt is not None)),
                )
            if receipt is not None:
                db.execute("UPDATE miner_windows SET retired=1 WHERE request=?", (key,))
                result = "retired"

        records = [("window_request", key, value)]
        if receipt is not None:
            records.append(("window_retirement", key, receipt))
        self.journal.put_many(records, index=index)
        return result

    def reserve(self, value: WindowRequest) -> str:
        return self._retain(value)

    def retire(self, value: WindowRequest, receipt: SignedEndpointRetirementReceipt) -> str:
        # Release/recovery never queues behind new-window admission. The native
        # request/response consumers separately validate absence and scoring.
        return self._retain(value, receipt=receipt)

    def import_request(self, value: WindowRequest, receipt=None) -> str:
        # Used only by the stopped-writer migration. Existing overlapping sends
        # must all be represented, even when they exceed today's window ceiling.
        return self._retain(value, importing=True, receipt=receipt)

    def seal_bootstrap(self, source_receipts: Mapping[str, str]) -> None:
        if set(source_receipts) != self.sources:
            raise ValueError("window bootstrap is missing a configured dispatch source")
        if any(
            len(pin) != 64 or any(char not in "0123456789abcdef" for char in pin)
            for pin in source_receipts.values()
        ):
            raise ValueError("window bootstrap requires exact source receipt digests")
        self.journal.put("window_bootstrap", _BOOTSTRAP, dict(source_receipts))
