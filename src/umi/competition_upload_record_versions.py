"""Native mutation identities for unchanged legacy upload metadata.

The first check still reads and validates the original record. Subsequent reads
use a small owner-bound receipt and current conflict/mutation fences. Old writers
advance the same SQL triggers, and old readers keep their unchanged record format.
No token grants payload, admission, allocation, or model-release authority.
"""

from __future__ import annotations

import os

from .competition_transport_verification import TransferProgress
from .competition_verification_reuse import VerificationReuse, metadata_completion
from .open_competition import digest

_TABLE = (
    "CREATE TABLE upload_record_versions(kind TEXT NOT NULL,id TEXT NOT NULL,"
    "revision INTEGER NOT NULL,present INTEGER NOT NULL,PRIMARY KEY(kind,id))"
)
_KINDS = "'upload','bundle'"
_MARKER = "upload_record_version_owner"


class UploadRecordRepairRequired(OSError):
    """Restore missing source identities or explicitly repair a completed receipt."""


def _triggers():
    result = {}
    for action in ("INSERT", "UPDATE", "DELETE"):
        row = "OLD" if action == "DELETE" else "NEW"
        name = "upload_record_version_" + action.lower()
        result[name] = (
            f"CREATE TRIGGER {name} AFTER {action} ON records WHEN {row}.kind IN ({_KINDS}) "
            "BEGIN INSERT INTO upload_record_versions VALUES "
            f"({row}.kind,{row}.id,1,{int(action != 'DELETE')}) "
            "ON CONFLICT(kind,id) DO UPDATE SET revision=revision+1,"
            f"present={int(action != 'DELETE')}; END"
        )
    result["upload_record_version_rekey"] = (
        "CREATE TRIGGER upload_record_version_rekey AFTER UPDATE ON records "
        f"WHEN OLD.kind IN ({_KINDS}) AND (OLD.kind!=NEW.kind OR OLD.id!=NEW.id) "
        "BEGIN INSERT INTO upload_record_versions VALUES (OLD.kind,OLD.id,1,0) "
        "ON CONFLICT(kind,id) DO UPDATE SET revision=revision+1,present=0; END"
    )
    return result


class UploadRecordVersions:
    def __init__(self, journal, binding, *, report=None):
        self.journal = journal
        self.identities = self._identities()
        self.owner = digest(
            {"binding": binding, "path": str(journal.root.resolve()), "files": self.identities}
        )
        self.marker = {"schema": "umi-upload-record-versions/1", "owner": self.owner}
        self.triggers = _triggers()
        self._reuse = {}

        def initialize(db):
            installed = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='upload_record_versions'"
            ).fetchone()
            marker = journal.get(_MARKER, "owner", db=db)
            if not installed:
                remnants = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name GLOB 'upload_record_version_*'"
                ).fetchone()
                if remnants or marker != self.marker:
                    raise UploadRecordRepairRequired("upload record versions require restoration")
                total = db.execute(
                    f"SELECT COUNT(*) FROM records WHERE kind IN ({_KINDS})"
                ).fetchone()[0]
                with TransferProgress(
                    "upload_record_version_migration",
                    total,
                    report,
                    unit="records",
                    planning_unit_seconds=(0.00001, 0.01),
                ) as progress:
                    db.execute(_TABLE)
                    for kind in ("upload", "bundle"):
                        added = db.execute(
                            "INSERT INTO upload_record_versions SELECT kind,id,0,1 "
                            "FROM records WHERE kind=?",
                            (kind,),
                        ).rowcount
                        progress.advance(added)
                    for sql in self.triggers.values():
                        db.execute(sql)
            elif marker != self.marker:
                raise UploadRecordRepairRequired("upload record version owner changed")

        # Install the permanent marker in the same transaction as identities.
        # Inspect first so a missing table is not mistaken for a legacy journal
        # after the marker has been inserted by put_many.
        with journal.read_transaction() as db:
            installed = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='upload_record_versions'"
            ).fetchone()
            old = journal.get(_MARKER, "owner", db=db)
            if installed or old is not None:
                self.check(db)
                return
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB 'upload_record_version_*'"
            ).fetchone():
                raise UploadRecordRepairRequired(
                    "upload record mutation metadata requires restoration"
                )
        journal.put_many(((_MARKER, "owner", self.marker),), index=initialize)
        with journal.read_transaction() as db:
            self.check(db)

    def _identities(self):
        return [
            [s.st_dev, s.st_ino, s.st_uid]
            for s in (self.journal.root.stat(), self.journal.path.stat())
        ]

    def check(self, db):
        if self._identities() != self.identities:
            raise UploadRecordRepairRequired("upload record owner files changed")
        actual = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE name='upload_record_versions' "
                "OR (type='trigger' AND name GLOB 'upload_record_version_*')"
            )
        )
        if actual != {"upload_record_versions": _TABLE, **self.triggers}:
            raise UploadRecordRepairRequired("upload record mutation metadata requires restoration")
        if self.journal.get(_MARKER, "owner", db=db) != self.marker:
            raise UploadRecordRepairRequired("upload record version owner is missing or changed")

    def identity(self, kind, key, *, db):
        self.check(db)
        if kind not in {"upload", "bundle"}:
            raise ValueError("unsupported upload record kind")
        if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
            raise ValueError("round journal conflict held")
        row = db.execute(
            "SELECT revision,present FROM upload_record_versions WHERE kind=? AND id=?",
            (kind, key),
        ).fetchone()
        source = db.execute("SELECT 1 FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        if row is None and source is None:
            raise FileNotFoundError("model delivery is not reserved")
        if row is None or row[1] != 1 or type(row[0]) is not int or row[0] < 0:
            raise UploadRecordRepairRequired("upload record source identity is missing or damaged")
        if source is None:
            raise UploadRecordRepairRequired("upload record source is missing")
        return digest([self.owner, kind, key, row[0]])

    def inventory_identity(self):
        """Fence a bounded upload inventory without rereading original requests."""
        with self.journal.read_transaction() as db:
            self.check(db)
            count, revisions, present = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(revision),0),COALESCE(SUM(present),0) "
                "FROM upload_record_versions WHERE kind='upload'"
            ).fetchone()
            return self.owner, count, str(revisions), present

    def result(self, kind, key, profile, verify, *, db, validate=None, repair=False, report=None):
        token = self.identity(kind, key, db=db)
        reuse = self._reuse.get(profile)
        if reuse is None:
            reuse = VerificationReuse(
                self.journal.root / "upload-record-verification" / digest(profile),
                owner={"profile": profile, "source_owner": self.owner},
            )
            self._reuse[profile] = reuse
        identity = digest([reuse.owner, reuse.runtime, token])
        with reuse.exclusive():
            path = reuse.directory / (identity + ".json")
            existed = os.path.lexists(path) or metadata_completion(path).exists()
            receipt = reuse.load(identity)
            if receipt is not None and not receipt.dependencies:
                try:
                    if validate is not None:
                        validate(receipt.result_json)
                except ValueError:
                    pass
                else:
                    return receipt.result_json, False
            if existed and not repair:
                with TransferProgress("upload_record_verification_repair", 1, report) as progress:
                    progress.emit("repair_required", reason="completed_upload_record_check_damaged")
                raise UploadRecordRepairRequired("completed upload record check requires repair")
            with TransferProgress(
                "upload_record_verification_repair" if existed else "upload_record_verification",
                1,
                report,
                unit="records",
                planning_unit_seconds=(0.001, 2.0),
            ) as progress:
                result = verify(db)
                if validate is not None:
                    validate(result)
                reuse.remember(identity, (), result)
                progress.advance(1)
            return result, existed
