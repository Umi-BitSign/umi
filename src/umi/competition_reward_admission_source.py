"""Small original native admission records, never a remote admission witness.

The root-sealed prospective selection authenticates the existing private owner.
No journal constructor is used here: absent state must not be created by a read.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .competition_reward_admission_provenance import (
    load_provenance,
    provenance_selection_digest,
    validate_state_identities,
)
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

_MAX_RECORD_BYTES = 64 * 1024


def _record(db, kind, key):
    if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
        raise HistoryCheckpointRepairRequired("original admission record has a conflict hold")
    row = db.execute(
        "SELECT TYPEOF(body),LENGTH(body) FROM records WHERE kind=? AND id=?", (kind, key)
    ).fetchone()
    if row is None or row[0] != "blob" or not 0 < row[1] <= _MAX_RECORD_BYTES:
        raise HistoryCheckpointRepairRequired("original completed admission record is absent")
    raw = db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()[0]
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECORD_BYTES:
        raise HistoryCheckpointRepairRequired("original admission record storage changed")
    value = json.loads(raw)
    if canonical_json_bytes(value) != raw:
        raise HistoryCheckpointRepairRequired("original admission record is not canonical")
    return value


def read_admission_source(selection, *, include_handoff=False):
    """Read one consistent bounded snapshot of existing original owner records."""
    validate_state_identities(selection)
    path = Path(selection["paths"]["decisions_database"])
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            rows = db.execute("SELECT TYPEOF(body),LENGTH(body) FROM binding LIMIT 2").fetchall()
            if len(rows) != 1 or rows[0][0] != "blob" or not 0 < rows[0][1] <= _MAX_RECORD_BYTES:
                raise HistoryCheckpointRepairRequired("original admission binding is absent")
            raw = db.execute("SELECT body FROM binding").fetchone()[0]
            if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECORD_BYTES:
                raise HistoryCheckpointRepairRequired("original admission binding storage changed")
            expected = {
                "schema": "umi-reward-decision-journal/1",
                "series": selection["series_sha256"],
                "signer": identity(selection["signer_hotkey"]),
                "chain_config": selection["chain_config_sha256"],
            }
            if raw != canonical_json_bytes(expected):
                raise HistoryCheckpointRepairRequired("original admission journal binding changed")
            intent = _record(db, "reward_intent", "0000")
            vote_key = digest(
                ["umi-reward-decision-vote/1", "0000", identity(selection["signer_hotkey"])]
            )
            vote = _record(db, "reward_vote", vote_key)
            result = {"binding": expected, "intent": intent, "vote": vote}
            if include_handoff:
                result["handoff"] = {
                    kind: {
                        "count": row[0],
                        "first_key": row[1],
                        "last_key": row[2],
                    }
                    for kind in ("reward_intent", "reward_certificate")
                    for row in (
                        db.execute(
                            "SELECT COUNT(*),MIN(id),MAX(id) FROM records "
                            "WHERE kind=? AND id!='0000'",
                            (kind,),
                        ).fetchone(),
                    )
                }
        validate_state_identities(selection)
        return result
    except HistoryCheckpointRepairRequired:
        raise
    except (OSError, ValueError, TypeError, RecursionError, sqlite3.DatabaseError) as error:
        raise HistoryCheckpointRepairRequired(
            "original admission source requires explicit repair"
        ) from error


def check_retained_admission_source(value):
    """Unchanged small owner records suffice; old block payloads are not read."""
    selection = load_provenance(Path(value["provenance_path"]))
    if provenance_selection_digest(selection) != value["provenance_sha256"]:
        raise HistoryCheckpointRepairRequired("completed admission provenance changed")
    source = read_admission_source(selection)
    if digest(source) != value["source_sha256"]:
        raise HistoryCheckpointRepairRequired("completed original admission result changed")
    return selection, source
